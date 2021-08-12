use nix::unistd::Pid;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
// use std::borrow::Borrow;
use std::fmt;
use std::fs;
use std::io::Read;
use std::rc::Rc;
use std::{cell::RefCell, path::PathBuf};
// All this crazy stuff here. There is a method to the madness!
// Because we just **have** to use nix::unistd::Pid, which is weird
// and doesn't implement Serialize or Deserialize, and even if I wanted
// to just skip it for serialization (which I do, I don't care about the
// persistent pid, it's gonna change anyway, I use it while creating the
// structures so I add to the correct struct, as multiple processes and thus
// multiple executions can be going on at once), it doesn't implement Default.
// So I just wrapped that sucker in ANOTHER struct and that thing can do
// Serialize, Deserialize, Default, whatever the heck you want. Are you happy
// now serde?
struct ProcVisitor;
#[derive(Clone, Debug, PartialEq)]
pub struct Proc(pub Pid);

impl Default for Proc {
    fn default() -> Proc {
        Proc(Pid::from_raw(0))
    }
}

impl Serialize for Proc {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // let Pid(actual_pid) = self.0;
        let actual_pid = self.0.as_raw();
        serializer.serialize_i32(actual_pid)
    }
}
impl<'de> Deserialize<'de> for Proc {
    fn deserialize<D>(deserializer: D) -> Result<Proc, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_i32(ProcVisitor)
    }
}

impl<'de> Visitor<'de> for ProcVisitor {
    type Value = Proc;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an integer between -2^31 and 2^31")
    }

    fn visit_i32<E>(self, value: i32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Proc(Pid::from_raw(value)))
    }
}

impl Proc {
    // pub fn new(pid: i32) -> Proc {
    //     Proc(pid)
    // }
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
// TODO: HASH SHOULD NOT TO BE AN OPTION
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum FileAccess {
    Success {
        // PathBuf here (in both cases) is the full path to the file.
        // Some files we may not be able to get the full path.
        // So the full path is just whatever we got in the argument.
        // Example: /etc/ld.so.preload
        full_path: PathBuf,
        // When it's an output file, we don't get the hash
        // until the end of the execution, because the contents
        // of the file may change.
        // Some files (stuff in /etc/ or /dev/pts/ or dirs) aren't really
        // files, so they get no hash. 
        hash: Option<Vec<u8>>,
        syscall_name: String,
    },
    Failure {
        // Some files we may not be able to get the full path.
        // Example: if fstat() fails, we can't get the full path.
        // So we just leave it empty.
        full_path: PathBuf,
        syscall_name: String,
    },
}

impl FileAccess {
    fn full_path(&self) -> PathBuf {
        match self {
            FileAccess::Success {
                full_path,
                hash: _,
                syscall_name: _,
            } => full_path.clone(),
            FileAccess::Failure {
                full_path,
                syscall_name: _,
            } => full_path.clone(),
        }
    }

    // Returns an option because we may:
    // - maybe haven't hashed yet because it is an output file
    // - maybe we shouldn't try to hash because it's unhashable
    //   (dirs, /etc/, /dev/pts are my current culprits)
    fn hash(&self) -> Option<Vec<u8>> {
        match *self {
            FileAccess::Success {
                full_path: _,
                hash,
                syscall_name: _,
            } => {
                hash
            }
            FileAccess::Failure {
                full_path: _,
                syscall_name: _,
            } => panic!("No hash for failed file access!"),
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
    // Stuff that doesn't acutally change the contents.
    pub fn add_new_file_event(&mut self, file_access: FileAccess, io_type: IO) {
        match io_type {
            // TODO: make this do nice error things
            // IO::Input => self.input_files.insert(full_path, file_access).map_or(Ok(()), |_| Err(())),
            IO::Input => self.input_files.push(file_access),
            IO::Output => self.output_files.push(file_access),
        }
    }

    // At the end of a successful execution, we get the hash of each output
    // file.
    pub fn add_output_file_hashes(&mut self) -> anyhow::Result<()> {
        for output in self.output_files.iter_mut() {
            println!("looping in add_output_file_hashes");
            println!("output: {:?}", output);
            if let FileAccess::Success {
                full_path,
                hash,
                syscall_name: _,
            } = output
            {
                let path = full_path.clone().into_os_string().into_string().unwrap();
                let hash_value = generate_hash(path);
                *hash = Some(hash_value);
            }
        }
        Ok(())
    }

    pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
        // Only want to copy output files that had successful
        // accesses to the cache.
        for output in self.output_files.iter() {
            if let FileAccess::Success {
                full_path,
                hash: _,
                syscall_name: _,
            } = output
            {
                let file_name = full_path
                    .file_name()
                    .expect("Can't get file name in copy_outputs_to_cache()!");
                println!("the file name is: {:?}", file_name);

                let cache_dir = PathBuf::from("/home/kelly/research/IOTracker/cache");
                let cache_path = cache_dir.join(file_name);
                println!("cache path: {:?}", cache_path);
                println!("full_path: {:?}", full_path);
                fs::copy(full_path, cache_path)?;
            }
        }
        println!("end of copy outputs to cache");
        Ok(())
    }

    pub fn serve_outputs_from_cache(&self) -> anyhow::Result<()> {
        println!("beginning of serve_outputs_from_cache");
        println!("size of inputs: {}", self.input_files.len());
        println!("Size of outputs: {}", self.output_files.len());
        for output in self.output_files.iter() {
            println!("output: {:?}", output);
            if let FileAccess::Success {
                full_path,
                hash: _,
                syscall_name: _,
            } = output
            {
                println!("hi i am here");
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
                //   and we don't end up here, because skip_execution would also be FALSE.S
            }
        }
        Ok(())
    }

    fn inputs(&self) -> Vec<FileAccess> {
        self.input_files.clone()
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
    // child_processes: Vec<Pid>, TODO: deal with child / dependent executions
    // The cwd can change during the execution, this is fine.
    // I am tracking absolute paths anyways.
    // This does need to match at the beginning of the execution though.
    starting_cwd: PathBuf,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    executable: String,
    // We don't know the exit code until it exits.
    // So while an execution is running this is None.
    exit_code: Option<i32>,
    #[serde(skip)]
    caller_pid: Proc,
}

impl ExecMetadata {
    pub fn new() -> ExecMetadata {
        ExecMetadata {
            args: Vec::new(),
            // child_processes: Vec::new(),
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

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Execution {
    Failed(ExecMetadata),
    Pending, // At time of creation, we don't know what the heck it is!
    // A successful execution has both metadata and
    // potentially file system accesses.
    Successful(ExecMetadata, ExecAccesses),
}

impl Execution {
    pub fn add_exit_code(&mut self, exit_code: i32, pid: Pid) {
        match self {
            Execution::Failed(meta) | Execution::Successful(meta, _) => {
                // Only want the exit code if this is the process
                // that actually exec'd the process.
                let exec_pid = meta.caller_pid();
                if exec_pid == pid {
                    meta.add_exit_code(exit_code);
                }
            }
            Execution::Pending => {
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
            Execution::Failed(metadata) | Execution::Successful(metadata, _) => {
                metadata.add_identifiers(args, caller_pid, env_vars, executable, starting_cwd)
            }
            Execution::Pending => panic!("Should not be adding identifiers to pending exec!"),
        }
    }

    pub fn add_new_file_event(&mut self, file_access: FileAccess, io_type: IO) {
        match self {
            Execution::Successful(_, accesses) => accesses.add_new_file_event(file_access, io_type),
            _ => panic!("Should not be adding file event to pending or failed execution!"),
        }
    }

    pub fn add_output_file_hashes(&mut self) -> anyhow::Result<()> {
        match self {
            Execution::Successful(_, accesses) => accesses.add_output_file_hashes(),
            // Should this be some fancy kinda error? Meh?
            _ => Ok(()),
        }
    }

    fn args(&self) -> Vec<String> {
        match self {
            Execution::Successful(metadata, _) | Execution::Failed(metadata) => metadata.args(),
            _ => panic!("Should not be getting args from pending execution!"),
        }
    }

    fn caller_pid(&self) -> Pid {
        match self {
            Execution::Successful(metadata, _) | Execution::Failed(metadata) => {
                metadata.caller_pid()
            }
            _ => panic!("Should not be getting caller pid from pending execution!"),
        }
    }

    pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
        match self {
            Execution::Successful(_, accesses) => accesses.copy_outputs_to_cache(),
            // Should this be some fancy kinda error? Meh?
            _ => Ok(()),
        }
    }

    fn env_vars(&self) -> Vec<String> {
        match self {
            Execution::Successful(metadata, _) | Execution::Failed(metadata) => metadata.env_vars(),
            _ => panic!("Should not be getting execution name from pending execution!"),
        }
    }

    fn execution_name(&self) -> String {
        match self {
            Execution::Successful(metadata, _) | Execution::Failed(metadata) => {
                metadata.execution_name()
            }
            _ => panic!("Should not be getting execution name from pending execution!"),
        }
    }

    fn inputs(&self) -> Vec<FileAccess> {
        match self {
            Execution::Successful(_, accesses) => accesses.inputs(),
            Execution::Failed(_) => panic!("Should not be getting inputs of failed execution!"),
            Execution::Pending => panic!("Should not be getting inputs of pending execution!"),
        }
    }

    fn is_successful(&self) -> bool {
        matches!(self, Execution::Successful(_, _))
    }

    fn metadata(&self) -> ExecMetadata {
        match self {
            Execution::Successful(metadata, _) | Execution::Failed(metadata) => metadata.clone(),
            _ => panic!("Should not be getting metadata of pending execution"),
        }
    }

    fn serve_outputs_from_cache(&self) -> anyhow::Result<()> {
        match self {
            Execution::Successful(_, accesses) => accesses.serve_outputs_from_cache(),
            // We shouldn't even get here if the execution is pending or failed, because
            // skip_execution is only ever set to true for successful executions.
            _ => Ok(()),
        }
    }

    fn starting_cwd(&self) -> PathBuf {
        match self {
            Execution::Successful(metadata, _) | Execution::Failed(metadata) => {
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

    pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
        println!("in copy outputs to cache");
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

    fn is_successful(&self) -> bool {
        self.execution.borrow().is_successful()
    }

    fn metadata(&self) -> ExecMetadata {
        self.execution.borrow().metadata()
    }

    pub fn serve_outputs_from_cache(&self) -> anyhow::Result<()> {
        self.execution.borrow().serve_outputs_from_cache()
    }

    pub fn starting_cwd(&self) -> PathBuf {
        self.execution.borrow().starting_cwd()
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct GlobalExecutions {
    pub executions: Rc<RefCell<Vec<RcExecution>>>,
}

impl GlobalExecutions {
    pub fn new() -> GlobalExecutions {
        GlobalExecutions {
            executions: Rc::new(RefCell::new(Vec::new())),
        }
    }

    // Add new execution if it is not cached.
    // Return true if we should skip the execution.
    pub fn add_new_execution(&self, execution: RcExecution) {
        self.executions.borrow_mut().push(execution);
    }

    // Return number of execution structs in the global_executions
    // struct currently.
    pub fn get_execution_count(&self) -> i32 {
        self.executions.borrow().len() as i32
    }

    // Return bool whether the execution name shows up in the cache.
    pub fn get_cached_success(&self, new_exec: RcExecution) -> Option<RcExecution> {
        // Don't want to skip if it isn't successful.
        // For now, really just want to deal with SUCCESS.
        // TODO: What if the new execution is a failure?
        // TODO: What if the cached execution is a failure?
        // And all that other crap.
        if new_exec.is_successful() {
            for cached_exec in self.executions.borrow().iter() {
                let metadata_match = exec_metadata_matches(cached_exec.clone(), new_exec.clone());
                let inputs_match = inputs_match(cached_exec.clone());
                println!("metadata match: {}", metadata_match);
                println!("inputs_match: {}", inputs_match);
                    // TODO: Check outputs
                
                if metadata_match && inputs_match {
                    return Some(cached_exec.clone());
                }
            }
            println!("Metadata doesn't match!");
            None
        } else {
            // TODO: deal with failed executions...
            None
        }
    }
}

// It's a lot of logic to do all the metadata checking
fn exec_metadata_matches(cached_exec: RcExecution, new_exec: RcExecution) -> bool {
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
    cached_exec.execution_name() == new_executable
        && cached_exec.is_successful()
        // TODO: Is checking Vec<String> (args and env_vars)
        // against another vector by just straight equals
        // okay here?
        && new_args == cached_exec.args()
        && new_starting_cwd == cached_exec.starting_cwd()
        && new_env_vars == cached_exec.env_vars()
}

// The inputs in the cached execution match the
// new execution's inputs, the hashes match,
// and they are in the correct absolute path locations.

// Can't just pass in "new_exec" this has no info about the inputs!
// We have to check the fs (cwd) for this stuff!
// Bruh, why is this so much programming???
fn inputs_match(cached_exec: RcExecution) -> bool {
    let cached_inputs = cached_exec.inputs();
    // First, they must share the same inputs.
    // So get the keys of each and check that they are equal?
    // TODO: Check hashes
    for cached_inp in cached_inputs.into_iter() {
        let full_path = cached_inp.full_path();
        println!("Checking cached input: {:?}", full_path.clone());

        // Get the old hash
        let thats_old_hash = cached_inp.hash();
        // Only check these things if it's a true file.
        // If the hash is None, we can just move on.
        if let Some(old_hash) = thats_old_hash {
            if !full_path.exists() {
                println!("gonna return false b/c full path doesn't exist");
                return false;
            } else {
                // 1) Hash the file that is there right now.
                let full_path = full_path.clone().into_os_string().into_string().unwrap();
                println!("Checking input file full path hash: {}", full_path.clone());
                let new_hash = generate_hash(full_path.clone());
    
                // 3) Compare the new hash to the old hash.
                if !(new_hash.iter().all(|x| old_hash.contains(x))) {
                    println!("gonna return false b/c hashes don't match");
                    return false;
                }
            }
        }


    }
    println!("All inputs match!");
    true
}

fn outputs_match() {
    // TODO: output files are not there OR are there and match hashes we have in the cache.
}
// ------ Hashing stuff ------

/// Print digest result as hex string and name pair
// fn print_result(sum: &[u8], name: &str) {
//     for byte in sum {
//         print!("{:02x}", byte);
//     }
//     println!("\t{}", name);
// }

// Process the file and generate the hash.
fn process<D: Digest + Default, R: Read>(reader: &mut R) -> Vec<u8> {
    const BUFFER_SIZE: usize = 1024;
    let mut sh = D::default();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        // let n = match reader.read(&mut buffer) {
        //     Ok(n) => n,
        //     Err(_) => return,
        // };
        let n = reader
            .read(&mut buffer)
            .expect("Could not read buffer from reader processing hash!");
        sh.update(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
        // println!("n is: {}", n);
        // println!("in process() loop");
    }

    let final_array = &sh.finalize();
    final_array.to_vec()
    // print_result(&sh.finalize(), name);
}

pub fn generate_hash(path: String) -> Vec<u8> {
    println!("made it to generate_hash");
    let mut file = fs::File::open(&path).expect("Could not open file to generate hash");
    process::<Sha256, _>(&mut file)
}

pub fn serialize_execs_to_cache(global_executions: GlobalExecutions) {
    // Serialize the executions.
    let serialized_execs = rmp_serde::to_vec(&global_executions).unwrap();

    // Write the serialized execs to a file.
    // I am just writing them to /home/kelly/research/IOTracker/cache/cache
    write_serialized_execs_to_cache(serialized_execs);

    // let buf = rmp_serde::to_vec(&(42, "the Answer")).unwrap();
}

pub fn deserialize_execs_from_cache() -> GlobalExecutions {
    // is read_to_end() needed?
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
