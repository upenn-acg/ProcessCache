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
        // Some files we may not be able to get the full path.
        // So the full path is just whatever we got in the argument.
        // Example: /etc/ld.so.preload
        full_path: PathBuf,
        // When it's an output file, we don't get the hash
        // until the end of the execution, because the contents
        // of the file may change.
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
            IO::Input => self.input_files.push(file_access),
            IO::Output => self.output_files.push(file_access),
        }
    }

    // At the end of a successful execution, we get the hash of each output
    // file.
    pub fn add_output_file_hashes(&mut self) -> anyhow::Result<()> {
        for output in self.output_files.iter_mut() {
            println!("looping in add_output_file_hashes");
            println!("file name: {:?}", output);
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
                let cache_dir = PathBuf::from("/home/kelly/research/IOTracker");
                let cache_path = cache_dir.join(file_name);
                println!("cache path: {:?}", cache_path);
                println!("full_path: {:?}", full_path);
                // fs::copy(full_path, cache_path)?;
            }
        }
        println!("end of copy outputs");
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
    // child_processes: Vec<Pid>, TODO: deal with child / dependent executions
    cwd: PathBuf,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    executable: String,
    // We don't know the exit code until it exits.
    // So while an execution is running this is None.
    exit_code: Option<i32>,
    #[serde(skip)]
    pid: Proc,
}

impl ExecMetadata {
    pub fn new() -> ExecMetadata {
        ExecMetadata {
            args: Vec::new(),
            // child_processes: Vec::new(),
            cwd: PathBuf::new(),
            env_vars: Vec::new(),
            executable: String::new(),
            exit_code: None,
            pid: Proc::default(),
        }
    }

    // fn add_child_process(&mut self, child_pid: Pid) {
    //     self.child_processes.push(child_pid);
    // }

    fn add_exit_code(&mut self, code: i32) {
        self.exit_code = Some(code);
    }

    fn add_identifiers(
        &mut self,
        args: Vec<String>,
        cwd: PathBuf,
        env_vars: Vec<String>,
        executable: String,
        pid: Pid,
    ) {
        self.args = args;
        self.cwd = cwd;
        self.env_vars = env_vars;
        self.executable = executable;

        let pid = Proc(pid);
        self.pid = pid;
    }

    fn get_execution_name(&self) -> String {
        self.executable.clone()
    }

    fn get_pid(&self) -> Pid {
        let Proc(actual_pid) = self.pid;
        actual_pid
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
    // pub fn add_child_process(&mut self, child_pid: Pid) {
    //     match self {
    //         Execution::Successful(metadata, _) => metadata.add_child_process(child_pid),
    //         _ => panic!("Trying to add child process to failed or pending execution!"),
    //     }
    // }

    pub fn add_exit_code(&mut self, exit_code: i32, pid: Pid) {
        match self {
            Execution::Failed(meta) | Execution::Successful(meta, _) => {
                // Only want the exit code if this is the process
                // that actually exec'd the process.
                let exec_pid = meta.get_pid();
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
        cwd: PathBuf,
        env_vars: Vec<String>,
        executable: String,
        pid: Pid,
    ) {
        match self {
            Execution::Failed(metadata) | Execution::Successful(metadata, _) => {
                metadata.add_identifiers(args, cwd, env_vars, executable, pid)
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

    pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
        match self {
            Execution::Successful(_, accesses) => accesses.copy_outputs_to_cache(),
            // Should this be some fancy kinda error? Meh?
            _ => Ok(()),
        }
    }

    pub fn get_execution_name(&self) -> String {
        match self {
            Execution::Successful(metadata, _) | Execution::Failed(metadata) => {
                metadata.get_execution_name()
            }
            _ => panic!("Should not be getting execution name from pending execution!"),
        }
    }

    fn is_successful(&self) -> bool {
        matches!(self, Execution::Successful(_, _))
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
        cwd: PathBuf,
        env_vars: Vec<String>,
        executable: String,
        pid: Pid,
    ) {
        self.execution
            .borrow_mut()
            .add_identifiers(args, cwd, env_vars, executable, pid);
    }

    pub fn add_new_file_event(&self, file_access: FileAccess, io_type: IO) {
        self.execution
            .borrow_mut()
            .add_new_file_event(file_access, io_type);
    }

    pub fn add_output_file_hashes(&self) -> anyhow::Result<()> {
        self.execution.borrow_mut().add_output_file_hashes()
    }
    pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
        println!("in copy outputs");
        self.execution.borrow().copy_outputs_to_cache()
    }

    pub fn get_execution_name(&self) -> String {
        self.execution.borrow().get_execution_name()
    }

    fn is_successful(&self) -> bool {
        self.execution.borrow().is_successful()
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
    pub fn has_cached_success(&self, command_line_executable: String) -> bool {
        for exec in self.executions.borrow().iter() {
            // Check if any execution struct existing in the cache matches this
            // We should skip it if:
            // - it WAS in the cache before (we didn't add it now)
            // - it was successful
            // TODO: WAY better checking.
            if exec.get_execution_name() == command_line_executable && exec.is_successful() {
                return true;
            }
        }
        false
    }
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

// For testing: let's you look at the files before you serialize them.
// let original_output_files = global_executions
// .executions
// .borrow_mut()
// .iter()
// .flat_map(|ex| match *ex.execution.borrow() {
//     Execution::Successful(_, ref accesses) => accesses
//         .output_files
//         .iter()
//         .filter_map(|f| match f {
//             IOFile::OutputFile(
//                 FileAccess::Failure {
//                     full_path: _,
//                     syscall_name: _,
//                     file_name,
//                 }
//                 | FileAccess::Success {
//                     full_path: _,
//                     hash: _,
//                     syscall_name: _,
//                     file_name,
//                 },
//             ) => Some(file_name.to_str().unwrap().to_owned()),
//             _ => None,
//         })
//         .collect::<Vec<String>>(),
//     _ => vec![],
// })
// .collect::<Vec<String>>();
// println!("Before serialize:  {:?}", original_output_files);

// For testing: let's you look at the execs a
// println!("serialized execs: {:?}", serialized_execs);
// let global_execs: GlobalExecutions = rmp_serde::from_read_ref(&serialized_execs).unwrap();
// let final_output_files = global_execs
// .executions
// .borrow_mut()
// .iter()
// .flat_map(|ex| match *ex.execution.borrow() {
//     Execution::Successful(_, ref accesses) => accesses
//         .output_files
//         .iter()
//         .filter_map(|f| match f {
//             IOFile::OutputFile(
//                 FileAccess::Failure {
//                     full_path: _,
//                     syscall_name: _,
//                     file_name,
//                 }
//                 | FileAccess::Success {
//                     full_path: _,
//                     hash: _,
//                     syscall_name: _,
//                     file_name,
//                 },
//             ) => Some(file_name.to_str().unwrap().to_owned()),
//             _ => None,
//         })
//         .collect::<Vec<String>>(),
//     _ => vec![],
// })
// .collect::<Vec<String>>();
// println!("Final output files:  {:?}", final_output_files);
