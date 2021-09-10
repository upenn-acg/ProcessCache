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
    pub fn add_new_file_event(&mut self, file_access: FileAccess, io_type: IO) {
        match io_type {
            IO::Input => self.input_files.push(file_access),
            IO::Output => self.output_files.push(file_access),
        }
    }

    // At the end of a successful execution, we get the hash of each output
    // file.
    pub fn add_output_file_hashes(&mut self) -> anyhow::Result<()> {
        for output in self.output_files.iter_mut() {
            if let FileAccess::Success(full_path, hash, _) = output {
                let path = full_path.clone().into_os_string().into_string().unwrap();
                let hash_value = generate_hash(path);
                *hash = Some(hash_value);
            }
        }
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
                fs::copy(full_path, cache_path)?;
            }
        }
        println!("end of copy outputs to cache");
        Ok(())
    }

    fn inputs(&self) -> Vec<FileAccess> {
        self.input_files.clone()
    }

    fn outputs(&self) -> Vec<FileAccess> {
        self.output_files.clone()
    }

    // Copy output files from the cache to the appropriate
    // locations the program expects.
    pub fn serve_outputs_from_cache(&self) -> anyhow::Result<()> {
        for output in self.output_files.iter() {
            if let FileAccess::Success(full_path, _, _) = output {
                let file_name = full_path
                    .file_name()
                    .expect("Can't get file name for output file in serve_outputs_from_cache()!");
                let cache_dir = PathBuf::from("/home/kelly/research/IOTracker/cache");
                let cached_output_path = cache_dir.join(file_name);

                // 1) Check if the output file is there.
                if !full_path.exists() {
                    // 2) It's not, great! Then copy the file from the cache.
                    fs::copy(cached_output_path, full_path)?;
                }
                // Otherwise we don't need to do anything.
                // A separate function outputs_match() checks that
                // for each output:
                // - if it IS there, hash it, compare it to cached hash.
                // - if any of these checks fail, outputs_match() returns FALSE
                //   and we don't end up here, because skip_execution would also be FALSE.
            }
        }
        Ok(())
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
    Successful(ExecMetadata, ExecAccesses, ChildExecutions),
    // Before we find out if the root execution's "execve" call succeeds,
    // its kinda just pending. I want to know which one the root is
    // and doing it in the enum seems easiest.
    PendingRoot,
    FailedRoot(ExecMetadata),
    SuccessfulRoot(ExecMetadata, ExecAccesses, ChildExecutions),
}

impl Execution {
    pub fn add_child_execution(&mut self, child_execution: RcExecution) {
        match self {
            Execution::Failed(_) | Execution::FailedRoot(_) => {
                panic!("Trying to add a child process to a failed execution!")
            }
            Execution::PendingRoot => {
                panic!("Trying to add a child process to a pending execution!")
            }
            Execution::Successful(_, _, child_execs)
            | Execution::SuccessfulRoot(_, _, child_execs) => {
                child_execs.push(child_execution);
            }
        }
    }

    pub fn add_exit_code(&mut self, exit_code: i32, pid: Pid) {
        match self {
            Execution::Failed(meta)
            | Execution::FailedRoot(meta)
            | Execution::Successful(meta, _, _)
            | Execution::SuccessfulRoot(meta, _, _) => {
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
            Execution::Failed(metadata)
            | Execution::FailedRoot(metadata)
            | Execution::Successful(metadata, _, _)
            | Execution::SuccessfulRoot(metadata, _, _) => {
                metadata.add_identifiers(args, caller_pid, env_vars, executable, starting_cwd)
            }
            _ => panic!("Should not be adding identifiers to pending exec!"),
        }
    }

    pub fn add_new_file_event(&mut self, file_access: FileAccess, io_type: IO) {
        match self {
            Execution::Successful(_, accesses, _) => {
                accesses.add_new_file_event(file_access, io_type)
            }
            _ => panic!("Should not be adding file event to pending or failed execution!"),
        }
    }

    pub fn add_output_file_hashes(&mut self) -> anyhow::Result<()> {
        match self {
            Execution::Successful(_, accesses, _) => accesses.add_output_file_hashes(),
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

    fn child_executions(&self) -> Vec<RcExecution> {
        match self {
            Execution::Successful(_, _, children) | Execution::SuccessfulRoot(_, _, children) => {
                children.clone()
            }
            Execution::Failed(_) | Execution::FailedRoot(_) => {
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
            Execution::Successful(_, accesses, _) | Execution::SuccessfulRoot(_, accesses, _) => {
                accesses.inputs()
            }
            Execution::Failed(_) | Execution::FailedRoot(_) => {
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

    fn metadata(&self) -> ExecMetadata {
        match self {
            Execution::Failed(meta)
            | Execution::FailedRoot(meta)
            | Execution::Successful(meta, _, _)
            | Execution::SuccessfulRoot(meta, _, _) => meta.clone(),
            _ => panic!("Trying to get metadata from pending execution"),
        }
    }

    fn outputs(&self) -> Vec<FileAccess> {
        match self {
            Execution::Successful(_, accesses, _) | Execution::SuccessfulRoot(_, accesses, _) => {
                accesses.outputs()
            }
            Execution::Failed(_) | Execution::FailedRoot(_) => {
                panic!("Should not be getting outputs of failed execution!")
            }
            Execution::PendingRoot => {
                panic!("Should not be getting outputs of pending root execution!")
            }
        }
    }

    fn serve_outputs_from_cache(&self) -> anyhow::Result<()> {
        match self {
            Execution::Successful(_, accesses, _) => accesses.serve_outputs_from_cache(),
            // We shouldn't even get here if the execution is pending or failed, because
            // skip_execution is only ever set to true for successful executions.
            _ => Ok(()),
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

    pub fn add_identifiers(
        &self,
        args: Vec<String>,
        caller_pid: Pid,
        env_vars: Vec<String>,
        executable: String,
        starting_cwd: PathBuf,
    ) {
        self.execution.borrow_mut().add_identifiers(
            args,
            caller_pid,
            env_vars,
            executable,
            starting_cwd,
        );
    }

    pub fn add_new_file_event(&self, file_access: FileAccess, io_type: IO) {
        self.execution
            .borrow_mut()
            .add_new_file_event(file_access, io_type);
    }

    pub fn add_output_file_hashes(&self) -> anyhow::Result<()> {
        self.execution.borrow_mut().add_output_file_hashes()
    }

    fn args(&self) -> Vec<String> {
        self.execution.borrow().args()
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

    pub fn metadata(&self) -> ExecMetadata {
        self.execution.borrow().metadata()
    }

    fn outputs(&self) -> Vec<FileAccess> {
        self.execution.borrow().outputs()
    }

    pub fn serve_outputs_from_cache(&self) -> anyhow::Result<()> {
        self.execution.borrow().serve_outputs_from_cache()
    }

    pub fn starting_cwd(&self) -> PathBuf {
        self.execution.borrow().starting_cwd()
    }

    pub fn update_root(&self, new_root_exec: Execution) {
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
pub fn get_cached_root_execution(new_execution: RcExecution) -> Option<RcExecution> {
    let new_root_metadata = new_execution.metadata();
    // TODO: Panic if a failed execution is let to run and it succeeds.
    let global_execs = deserialize_execs_from_cache();
    // Have to find the root exec in the list of global execs
    // in the cache.
    // TODO use all()?
    for cached_root_exec in global_execs.executions.iter() {
        if exec_metadata_matches(&cached_root_exec, new_root_metadata.clone())
            && execution_matches(cached_root_exec)
        {
            return Some(cached_root_exec.clone());
        }
    }
    None
}

fn execution_matches(cached_root: &RcExecution) -> bool {
    if !inputs_match(cached_root.clone()) {
        return false;
    } else if !outputs_match(cached_root.clone()) {
        return false;
    } else {
        cached_root
            .child_executions()
            .iter()
            .all(|child| execution_matches(&child))
    }
}

// It's a lot of logic to do all the metadata checking.
// Right now if an execution has child executions, all child
// executions must be skippable as well so we just skip the whole
// dang thing. This means we don't have to check the metadata of
// the child executions or their child executions.
fn exec_metadata_matches(cached_exec: &RcExecution, new_exec_metadata: ExecMetadata) -> bool {
    let new_executable = new_exec_metadata.execution_name();
    let new_starting_cwd = new_exec_metadata.starting_cwd();
    let new_args = new_exec_metadata.args();
    let new_env_vars = new_exec_metadata.env_vars();
    // Check if any execution struct existing in the cache matches this
    // We should skip it if:
    // - it WAS in the cache before (loop)
    // - it was successful
    // - execution name matches
    // - arguments match
    // - starting cwd matches
    // - env vars match
    cached_exec.execution_name() == new_executable
        && cached_exec.is_successful()
        && new_args == cached_exec.args()
        && new_starting_cwd == cached_exec.starting_cwd()
        && new_env_vars == cached_exec.env_vars()
}

// The inputs in the cached execution match the
// new execution's inputs, the hashes match,
// and they are in the correct absolute path locations.

// Bruh, why is this so much programming???
fn inputs_match(cached_exec: RcExecution) -> bool {
    let cached_inputs = cached_exec.inputs();
    // First, they must share the same inputs.
    // So get the keys of each and check that they are equal?
    for input in cached_inputs.into_iter() {
        if let FileAccess::Success(full_path, Some(old_hash), _) = input {
            // Only check these things if it's a true file.
            // If the hash is None, we can just move on.
            if !full_path.exists() {
                return false;
            } else {
                // Hash the file that is there right now.
                let full_path = full_path.clone().into_os_string().into_string().unwrap();
                let new_hash = generate_hash(full_path.clone());

                // Compare the new hash to the old hash.
                if !new_hash.iter().eq(old_hash.iter()) {
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
fn outputs_match(curr_execution: RcExecution) -> bool {
    let cached_outputs = curr_execution.outputs();

    for output in cached_outputs.into_iter() {
        if let FileAccess::Success(full_path, hash, _) = output {
            // If the output file does indeed exist and is in the correct spot
            // already, check if the hash matches the old one.
            // Then we won't have to copy this file over from the cache.
            if full_path.exists() {
                if let Some(old_hash) = hash {
                    let full_path = full_path.clone().into_os_string().into_string().unwrap();
                    let new_hash = generate_hash(full_path.clone());

                    // Compare the new hash to the old hash.
                    if !new_hash.iter().eq(old_hash.iter()) {
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
pub fn generate_hash(path: String) -> Vec<u8> {
    println!("made it to generate_hash");
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

fn write_serialized_execs_to_cache(serialized_execs: Vec<u8>) {
    fs::write(
        "/home/kelly/research/IOTracker/cache/cache",
        serialized_execs,
    )
    .expect("Failed to write serialized executions to cache!");
}
