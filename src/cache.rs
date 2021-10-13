use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
// use std::borrow::Borrow;
use std::fs;
use std::io::Read;
use std::rc::Rc;
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
};

#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

#[derive(Clone, Debug, PartialEq)]
pub struct Proc(pub Pid);

impl Default for Proc {
    fn default() -> Proc {
        Proc(Pid::from_raw(0))
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum IO {
    Input,
    Output,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
    WriteOnly,
}

// Success and failure variants of
// input and output files.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum FileAccess {
    // PathBuf = full path to the file.
    // Option<Vec<u8>> = hash.
    // String = syscall name.
    // Some files we may not be able to get the full path.
    // So the full path is just whatever we got in the argument.
    // Example: /etc/ld.so.preload
    // When it's an output file, we don't get the hash
    // until the end of the execution, because the contents
    // of the file may change.
    // Some files (stuff in /etc/ or /dev/pts/ or dirs) aren't really
    // files, so they get no hash.
    // Failed accesses obviously don't get hashed.
    Success(PathBuf, Option<Vec<u8>>, String),
    Failure(PathBuf, String),
}

impl FileAccess {
    pub fn full_path(&self) -> PathBuf {
        match self {
            FileAccess::Success(path, _, _) => path.clone(),
            FileAccess::Failure(path, _) => path.clone(),
        }
    }
}
// Actual accesses to the file system performed by
// a successful execution.
// TODO: Handle stderr and stdout. I don't want to right
// now it's hard and my simplest example does not
// cover it.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ExecAccesses {
    input_files: Vec<FileAccess>,
    output_files: Vec<FileAccess>,
}

impl ExecAccesses {
    pub fn new() -> ExecAccesses {
        ExecAccesses {
            input_files: Vec::new(),
            output_files: Vec::new(),
        }
    }

    // Add new access to the struct.
    pub fn add_new_file_event(&mut self, caller_pid: Pid, file_access: FileAccess, io_type: IO) {
        let s = span!(Level::INFO, stringify!(add_new_file_event), pid=?caller_pid);
        let _ = s.enter();

        match io_type {
            IO::Input => {
                if !self
                    .output_files
                    .iter()
                    .any(|f| f.full_path() == file_access.full_path())
                {
                    s.in_scope(|| info!("Adding access to inputs that was NOT in outputs"));
                    self.input_files.push(file_access);
                } else {
                    s.in_scope(|| info!("Not adding access to inputs it is already in outputs"));
                    // TODO check for truncate, creation of a file?
                }
            }
            IO::Output => {
                if self
                    .output_files
                    .iter()
                    .any(|f| f.full_path() == file_access.full_path())
                {
                    panic!("Trying to add file to output files that is already there! (i.e. we have already written to this file! : {:?}", file_access.full_path())
                } else {
                    self.output_files.push(file_access);
                }
            }
        }

        drop(s);
    }

    // At the end of a successful execution, we get the hash of each output
    // file.
    pub fn add_output_file_hashes(&mut self, caller_pid: Pid) -> anyhow::Result<()> {
        let s = span!(Level::INFO, stringify!(add_output_file_hashes), pid=?caller_pid);
        let _ = s.enter();

        for output in self.output_files.iter_mut() {
            if let FileAccess::Success(full_path, hash, _) = output {
                let path = full_path.clone().into_os_string().into_string().unwrap();
                s.in_scope(|| info!("gonna generate an output hash"));
                let hash_value = generate_hash(caller_pid, path);
                *hash = Some(hash_value);
            }
        }

        drop(s);
        Ok(())
    }

    // Only want to copy output files that had successful
    // accesses to the cache.
    pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
        for output in self.output_files.iter() {
            if let FileAccess::Success(full_path, _, _) = output {
                let file_name = full_path
                    .file_name()
                    .expect("Can't get file name in copy_outputs_to_cache()!");

                let cache_dir = PathBuf::from("/home/kelly/research/IOTracker/cache");
                let cache_path = cache_dir.join(file_name);

                // TODO: What if it is already there?
                if cache_path.exists() {
                    panic!("Trying to copy a file to the cache that is already present in the cache, at least with the same filename! : {:?}", cache_path);
                } else {
                    fs::copy(full_path, cache_path)?;
                }
            }
        }
        Ok(())
    }

    fn inputs(&self) -> Vec<FileAccess> {
        self.input_files.clone()
    }

    fn outputs(&self) -> Vec<FileAccess> {
        self.output_files.clone()
    }
}

// Info about the execution that we want to keep around
// even if the execution fails (so we know it should fail
// if we see it again, it would be some kinda error if
// we expect it to fail... and it doesn't :o that's an
// existential and/or metaphysical crisis for future kelly)
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ExecMetadata {
    args: Vec<String>,
    // The cwd can change during the execution, this is fine.
    // I am tracking absolute paths anyways.
    // This DOES need to match at the beginning of the execution though.
    starting_cwd: PathBuf,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    executable: String,
    // We don't know the exit code until it exits.
    // So while an execution is running this is None.
    exit_code: Option<i32>,
    // I need the caller pid so I know which execution struct
    // to add info to. But, I don't want this serialized with
    // the rest of the metadata (obviously pids change from run
    // to run).
    #[serde(skip)]
    caller_pid: Proc,
}

impl ExecMetadata {
    pub fn new() -> ExecMetadata {
        ExecMetadata {
            args: Vec::new(),
            starting_cwd: PathBuf::new(),
            env_vars: Vec::new(),
            executable: String::new(),
            exit_code: None,
            caller_pid: Proc::default(),
        }
    }

    fn add_exit_code(&mut self, code: i32) {
        self.exit_code = Some(code);
    }

    fn add_identifiers(
        &mut self,
        args: Vec<String>,
        caller_pid: Pid,
        env_vars: Vec<String>,
        executable: String,
        starting_cwd: PathBuf,
    ) {
        self.args = args;
        self.starting_cwd = starting_cwd;
        self.env_vars = env_vars;
        self.executable = executable;

        let pid = Proc(caller_pid);
        self.caller_pid = pid;
    }

    fn args(&self) -> Vec<String> {
        self.args.clone()
    }

    fn caller_pid(&self) -> Pid {
        let Proc(actual_pid) = self.caller_pid;
        actual_pid
    }

    fn env_vars(&self) -> Vec<String> {
        self.env_vars.clone()
    }

    fn execution_name(&self) -> String {
        self.executable.clone()
    }

    fn starting_cwd(&self) -> PathBuf {
        self.starting_cwd.clone()
    }
}

pub type ChildExecutions = Vec<RcExecution>;
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Execution {
    Failed(ExecMetadata),
    // Before we find out if the root execution's "execve" call succeeds,
    // its kinda just pending. I want to know which one the root is
    // and doing it in the enum seems easiest.
    PendingRoot,
    Successful(ExecMetadata, ExecAccesses, ChildExecutions),
}

impl Execution {
    pub fn add_child_execution(&mut self, child_execution: RcExecution) {
        match self {
            Execution::Failed(_) => {
                panic!("Trying to add a child process to a failed execution!")
            }
            Execution::PendingRoot => {
                panic!("Trying to add a child process to a pending execution!")
            }
            Execution::Successful(_, _, child_execs) => {
                child_execs.push(child_execution);
            }
        }
    }

    pub fn add_exit_code(&mut self, exit_code: i32, pid: Pid) {
        match self {
            Execution::Failed(meta) | Execution::Successful(meta, _, _) => {
                // Only want the exit code if this is the process
                // that actually exec'd the process.
                let exec_pid = meta.caller_pid();
                if exec_pid == pid {
                    meta.add_exit_code(exit_code);
                }
            }
            _ => {
                panic!("Trying to add exit code to pending execution!")
            }
        }
    }

    pub fn add_identifiers(
        &mut self,
        args: Vec<String>,
        caller_pid: Pid,
        env_vars: Vec<String>,
        executable: String,
        starting_cwd: PathBuf,
    ) {
        match self {
            Execution::Failed(metadata) | Execution::Successful(metadata, _, _) => {
                metadata.add_identifiers(args, caller_pid, env_vars, executable, starting_cwd)
            }
            _ => panic!("Should not be adding identifiers to pending exec!"),
        }
    }

    pub fn add_new_file_event(&mut self, caller_pid: Pid, file_access: FileAccess, io_type: IO) {
        match self {
            Execution::Successful(_, accesses, _) => {
                accesses.add_new_file_event(caller_pid, file_access, io_type)
            }
            Execution::PendingRoot => {
                panic!("Should not be adding file event to pending execution!")
            }
            _ => panic!("Should not be adding file event to failed execution!"),
        }
    }

    pub fn add_output_file_hashes(&mut self, caller_pid: Pid) -> anyhow::Result<()> {
        match self {
            Execution::Successful(_, accesses, _) => accesses.add_output_file_hashes(caller_pid),
            // Should this be some fancy kinda error? Meh?
            _ => Ok(()),
        }
    }

    fn args(&self) -> Vec<String> {
        match self {
            Execution::Successful(metadata, _, _) | Execution::Failed(metadata) => metadata.args(),
            _ => panic!("Should not be getting args from pending execution!"),
        }
    }

    fn caller_pid(&self) -> Pid {
        match self {
            Execution::Successful(meta, _, _) | Execution::Failed(meta) => meta.caller_pid(),
            _ => panic!("Trying to get caller pid of pending root execution!"),
        }
    }

    fn child_executions(&self) -> Vec<RcExecution> {
        match self {
            Execution::Successful(_, _, children) => children.clone(),
            Execution::Failed(_) => {
                panic!("Should not be getting child execs from failed execution!")
            }
            Execution::PendingRoot => {
                panic!("Should not be trying to get child execs from pending root execution!")
            }
        }
    }

    pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
        match self {
            Execution::Successful(_, accesses, _) => accesses.copy_outputs_to_cache(),
            // Should this be some fancy kinda error? Meh?
            _ => Ok(()),
        }
    }

    fn env_vars(&self) -> Vec<String> {
        match self {
            Execution::Successful(metadata, _, _) | Execution::Failed(metadata) => {
                metadata.env_vars()
            }
            _ => panic!("Should not be getting execution name from pending execution!"),
        }
    }

    fn execution_name(&self) -> String {
        match self {
            Execution::Successful(metadata, _, _) | Execution::Failed(metadata) => {
                metadata.execution_name()
            }
            _ => panic!("Should not be getting execution name from pending execution!"),
        }
    }

    fn inputs(&self) -> Vec<FileAccess> {
        match self {
            Execution::Successful(_, accesses, _) => accesses.inputs(),
            Execution::Failed(_) => {
                panic!("Should not be getting inputs of failed execution!")
            }
            Execution::PendingRoot => {
                panic!("Should not be getting inputs of pending root execution!")
            }
        }
    }

    fn is_pending_root(&self) -> bool {
        matches!(self, Execution::PendingRoot)
    }

    pub fn is_successful(&self) -> bool {
        matches!(self, Execution::Successful(_, _, _))
    }

    fn outputs(&self) -> Vec<FileAccess> {
        match self {
            Execution::Successful(_, accesses, _) => accesses.outputs(),
            Execution::Failed(_) => {
                panic!("Should not be getting outputs of failed execution!")
            }
            Execution::PendingRoot => {
                panic!("Should not be getting outputs of pending root execution!")
            }
        }
    }

    fn starting_cwd(&self) -> PathBuf {
        match self {
            Execution::Successful(metadata, _, _) | Execution::Failed(metadata) => {
                metadata.starting_cwd()
            }
            _ => panic!("Should not be getting starting cwd from pending execution!"),
        }
    }
}
// Rc stands for reference counted.
// This is the wrapper around the Execution
// enum.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]

pub struct RcExecution {
    execution: Rc<RefCell<Execution>>,
}

impl RcExecution {
    pub fn new(execution: Execution) -> RcExecution {
        RcExecution {
            execution: Rc::new(RefCell::new(execution)),
        }
    }

    pub fn add_child_execution(&self, child_execution: RcExecution) {
        self.execution
            .borrow_mut()
            .add_child_execution(child_execution);
    }

    pub fn add_exit_code(&self, code: i32, exec_pid: Pid) {
        self.execution.borrow_mut().add_exit_code(code, exec_pid);
    }

    pub fn add_new_file_event(&self, caller_pid: Pid, file_access: FileAccess, io_type: IO) {
        self.execution
            .borrow_mut()
            .add_new_file_event(caller_pid, file_access, io_type);
    }

    pub fn add_output_file_hashes(&self, caller_pid: Pid) -> anyhow::Result<()> {
        self.execution
            .borrow_mut()
            .add_output_file_hashes(caller_pid)
    }

    fn args(&self) -> Vec<String> {
        self.execution.borrow().args()
    }

    pub fn caller_pid(&self) -> Pid {
        self.execution.borrow().caller_pid()
    }

    fn child_executions(&self) -> Vec<RcExecution> {
        self.execution.borrow().child_executions()
    }

    pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
        self.execution.borrow().copy_outputs_to_cache()
    }

    fn env_vars(&self) -> Vec<String> {
        self.execution.borrow().env_vars()
    }

    pub fn execution_name(&self) -> String {
        self.execution.borrow().execution_name()
    }

    fn inputs(&self) -> Vec<FileAccess> {
        self.execution.borrow().inputs()
    }

    pub fn is_pending_root(&self) -> bool {
        self.execution.borrow().is_pending_root()
    }

    pub fn is_successful(&self) -> bool {
        self.execution.borrow().is_successful()
    }

    fn outputs(&self) -> Vec<FileAccess> {
        self.execution.borrow().outputs()
    }

    pub fn starting_cwd(&self) -> PathBuf {
        self.execution.borrow().starting_cwd()
    }

    pub fn update_root(&self, new_root_exec: Execution) {
        // TODO: only do this if the current execution is pending root?
        *self.execution.borrow_mut() = new_root_exec;
    }
}

// When we deserialize the cache, this is what
// we will get.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct GlobalExecutions {
    pub executions: Vec<RcExecution>,
}

impl GlobalExecutions {
    pub fn new() -> GlobalExecutions {
        GlobalExecutions {
            executions: Vec::new(),
        }
    }

    pub fn add_new_execution(&mut self, new_execution: RcExecution) {
        self.executions.push(new_execution);
    }

    // Return number of execution structs in the global_executions
    // struct currently.
    // pub fn get_execution_count(&self) -> i32 {
    //     self.executions.borrow().len() as i32
    // }
}

// Return the cached execution if there exists a cached success.
// Else return None.
pub fn get_cached_root_execution(caller_pid: Pid, new_execution: Execution) -> Option<RcExecution> {
    let s = span!(Level::INFO, stringify!(get_cached_root_execution), pid=?caller_pid);
    let _ = s.enter();
    let cache_path = PathBuf::from("/home/kelly/research/IOTracker/cache/cache");
    if !cache_path.exists() {
        s.in_scope(|| info!("No cached exec bc cache doesn't exist"));
        None
    } else if !new_execution.is_successful() {
        s.in_scope(|| info!("No cached exec bc exec failed"));
        None
    } else {
        // TODO: Panic if a failed execution is let to run and it succeeds.
        let global_execs = deserialize_execs_from_cache();
        // Have to find the root exec in the list of global execs
        // in the cache.

        for cached_root_exec in global_execs.executions.iter() {
            // We check that the metadata matches
            // That the inputs and outputs match (all the way down the tree of child execs)
            // And that success or failure matches
            if exec_metadata_matches(cached_root_exec, caller_pid, &new_execution)
                && execution_matches(cached_root_exec, caller_pid)
            {
                // TODO: don't short circuit
                return Some(cached_root_exec.clone());
            }
        }
        None
    }
}

fn execution_matches(cached_root: &RcExecution, caller_pid: Pid) -> bool {
    let s = span!(Level::INFO, stringify!(execution_matches), pid=?caller_pid);
    let _ = s.enter();
    s.in_scope(|| info!("Checking inputs and outputs of children"));

    if !inputs_match(cached_root.clone(), caller_pid)
        || !outputs_match(caller_pid, cached_root.clone())
    {
        false
    } else {
        s.in_scope(|| {
            info!(
                "Number of cached children: {}",
                cached_root.child_executions().len()
            )
        });

        cached_root
            .child_executions()
            .iter()
            .all(|child| execution_matches(child, caller_pid))
    }
}

// It's a lot of logic to do all the metadata checking.
// Right now if an execution has child executions, all child
// executions must be skippable as well so we just skip the whole
// dang thing. This means we don't have to check the metadata of
// the child executions or their child executions.
fn exec_metadata_matches(cached_exec: &RcExecution, caller_pid: Pid, new_exec: &Execution) -> bool {
    let s = span!(Level::INFO, stringify!(exec_metadata_matches), pid=?caller_pid);
    let _ = s.enter();
    s.in_scope(|| info!("Checking inputs and outputs of children"));
    let new_executable = new_exec.execution_name();
    let new_starting_cwd = new_exec.starting_cwd();
    let new_args = new_exec.args();
    let new_env_vars = new_exec.env_vars();
    // Check if any execution struct existing in the cache matches this
    // We should skip it if:
    // - it WAS in the cache before (loop)
    // - it was successful
    // - execution name matches
    // - arguments match
    // - starting cwd matches
    // - env vars match
    let executable_matches = cached_exec.execution_name() == new_executable;
    s.in_scope(|| info!("Executable names match: {}", executable_matches));
    let success_failure_match = cached_exec.is_successful() == new_exec.is_successful();
    s.in_scope(|| info!("Success/Failure match: {}", success_failure_match));
    let args_match = new_args == cached_exec.args();
    s.in_scope(|| info!("Args match: {}", args_match));
    let cwd_matches = new_starting_cwd == cached_exec.starting_cwd();
    s.in_scope(|| info!("Cwd matches: {}", cwd_matches));
    let env_vars_match = new_env_vars == cached_exec.env_vars();
    s.in_scope(|| info!("Env vars match: {}", env_vars_match));

    executable_matches && success_failure_match && args_match && cwd_matches && env_vars_match
}

// The inputs in the cached execution match the
// new execution's inputs, the hashes match,
// and they are in the correct absolute path locations.

// Bruh, why is this so much programming???
fn inputs_match(cached_exec: RcExecution, caller_pid: Pid) -> bool {
    let s = span!(Level::INFO, stringify!(inputs_match), pid=?caller_pid);
    let _ = s.enter();
    s.in_scope(|| info!("Checking inputs and outputs of children"));
    let cached_inputs = cached_exec.inputs();
    // First, they must share the same inputs.
    // So get the keys of each and check that they are equal?
    for input in cached_inputs.into_iter() {
        if let FileAccess::Success(full_path, Some(old_hash), _) = input {
            // Only check these things if it's a true file.
            // If the hash is None, we can just move on.
            if !full_path.exists() {
                s.in_scope(|| {
                    info!(
                        "Inputs don't match because path doesn't exist: {:?}",
                        full_path
                    )
                });
                return false;
            } else {
                // Hash the file that is there right now.
                let full_path = full_path.clone().into_os_string().into_string().unwrap();
                let new_hash = generate_hash(caller_pid, full_path.clone());

                // Compare the new hash to the old hash.
                if !new_hash.iter().eq(old_hash.iter()) {
                    s.in_scope(|| {
                        info!(
                            "Inputs don't match new hash and old hash don't match: {:?}",
                            full_path
                        )
                    });
                    return false;
                }
            }
        }
    }
    true
}

// Check that output files are either:
// - Exist, in the right place, and the hash matches the hash we have in the cache.
// - OR, the file doesn't exist, which is great, because we have it in our cache
// and we can just copy it over.
fn outputs_match(caller_pid: Pid, curr_execution: RcExecution) -> bool {
    let s = span!(Level::INFO, stringify!(outputs_match), pid=?caller_pid);
    let _ = s.enter();
    s.in_scope(|| info!("Checking inputs and outputs of children"));
    let cached_outputs = curr_execution.outputs();

    for output in cached_outputs.into_iter() {
        if let FileAccess::Success(full_path, hash, _) = output {
            // If the output file does indeed exist and is in the correct spot
            // already, check if the hash matches the old one.
            // Then we won't have to copy this file over from the cache.
            if full_path.exists() {
                if let Some(old_hash) = hash {
                    let full_path = full_path.clone().into_os_string().into_string().unwrap();
                    let new_hash = generate_hash(caller_pid, full_path.clone());

                    // Compare the new hash to the old hash.
                    if !new_hash.iter().eq(old_hash.iter()) {
                        s.in_scope(|| {
                            info!(
                                "Output hashes don't match. Old :{:?}, New :{:?}",
                                new_hash, old_hash
                            )
                        });
                        return false;
                    }
                }
            }
            // If it doesn't exist, fantastic
            // MOVE ON it doesn't exist.
            // "I'm sorry for your loss. Move on."
        }
    }
    true
}

// Take in the root execution.
// Copy its outputs to the appropriate places.

pub fn serve_outputs_from_cache(
    caller_pid: Pid,
    root_execution: &RcExecution,
) -> anyhow::Result<()> {
    let s = span!(Level::INFO, stringify!(serve_outputs_from_cache), pid=?caller_pid);
    let _ = s.enter();
    s.in_scope(|| info!("Serving outputs from cache."));

    for output in root_execution.outputs() {
        if let FileAccess::Success(full_path, _, _) = output {
            s.in_scope(|| {
                info!(
                    "Cached successful output file access going to serve: {:?}",
                    full_path
                )
            });
            let file_name = full_path.file_name().unwrap();

            let cache_dir = PathBuf::from("/home/kelly/research/IOTracker/cache");
            let cached_output_path = cache_dir.join(file_name);

            if !full_path.exists() {
                fs::copy(cached_output_path, full_path)?;
            } else {
                s.in_scope(|| {
                    info!(
                        "Not copying from cache, file is already there: {:?}",
                        full_path
                    )
                });
            }
        }
    }

    root_execution
        .child_executions()
        .iter()
        .all(|child| serve_outputs_from_cache(caller_pid, child).is_ok());
    Ok(())
}

// ------ Hashing stuff ------
// Process the file and generate the hash.
fn process<D: Digest + Default, R: Read>(reader: &mut R) -> Vec<u8> {
    const BUFFER_SIZE: usize = 1024;
    let mut sh = D::default();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = reader
            .read(&mut buffer)
            .expect("Could not read buffer from reader processing hash!");
        sh.update(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }

    let final_array = &sh.finalize();
    final_array.to_vec()
}

// Wrapper for generating the hash.
// Opens the file and calls process() to get the hash.
pub fn generate_hash(caller_pid: Pid, path: String) -> Vec<u8> {
    let s = span!(Level::INFO, stringify!(generate_hash), pid=?caller_pid);
    let _ = s.enter();
    s.in_scope(|| info!("Made it to generate_hash for path: {}", path));
    let mut file = fs::File::open(&path).expect("Could not open file to generate hash");
    process::<Sha256, _>(&mut file)
}

// Serialize the execs and write them to the cache.
pub fn serialize_execs_to_cache(root_execution: RcExecution) -> anyhow::Result<()> {
    // OK. So.
    let cache_path = PathBuf::from("/home/kelly/research/IOTracker/cache/cache");
    let cache_copy_path = PathBuf::from("/home/kelly/research/IOTracker/cache/cache_copy");

    if Path::new("/home/kelly/research/IOTracker/cache/cache").exists() {
        // If the cache file exists:
        // - make a copy of cache/cache at cache/cache_copy (just in case)
        fs::copy(&cache_path, &cache_copy_path)?;
        // - deserialize existing structure from cache/cache
        let mut existing_global_execs = deserialize_execs_from_cache();
        // - add the new root_execution to the vector
        existing_global_execs.add_new_execution(root_execution);
        // - serialize again
        let serialized_execs = rmp_serde::to_vec(&existing_global_execs).unwrap();
        // - remove old cache/cache file
        fs::remove_file(&cache_path)?;
        // - make a new cache/cache file and write the updated serialized execs to it
        fs::write(cache_path, serialized_execs)?;
        // - delete cache/cache_copy
        fs::remove_file(cache_copy_path)?;
    } else {
        // If the cache file doesn't exist:
        // - make a new GlobalExecutions
        let mut global_execs = GlobalExecutions::new();
        // - put root_execution in it
        global_execs.add_new_execution(root_execution);
        // - serialize GlobalExecutions
        let serialized_execs = rmp_serde::to_vec(&global_execs).unwrap();
        // - and write the serialized_execs to the cache/cache file we are making
        //   right here because that's what the write() function here does, creates
        //   if it doesn't exist, and then writes.
        fs::write(
            "/home/kelly/research/IOTracker/cache/cache",
            serialized_execs,
        )?;
    }
    Ok(())
    // let serialized_execs = rmp_serde::to_vec(&root_exection).unwrap();
}

pub fn deserialize_execs_from_cache() -> GlobalExecutions {
    let exec_struct_bytes = fs::read("/home/kelly/research/IOTracker/cache/cache").expect("failed");
    if exec_struct_bytes.is_empty() {
        GlobalExecutions::new()
    } else {
        rmp_serde::from_read_ref(&exec_struct_bytes).unwrap()
    }
}
