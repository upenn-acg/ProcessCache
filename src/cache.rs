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
        file_name: PathBuf,
        full_path: PathBuf,
        hash: Option<Vec<u8>>,
        syscall_name: String,
    },
    Failure {
        file_name: PathBuf,
        full_path: PathBuf,
        syscall_name: String,
    },
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum IOFile {
    InputFile(FileAccess),
    OutputFile(FileAccess),
}

// #[derive(Debug)]
// // TODO: differentiate between ABSOLUTE PATH and REL PATH?
// pub enum FileAccess {
//     // Open, openat
//     FailedFileOpen {
//         open_mode: OpenMode,
//         path: PathBuf,
//         syscall_name: String,
//     },
//     // Read's parameter is an fd (same for successful file read).
//     // Read, pread64
//     FailedFileRead {
//         fd: i32,
//         syscall_name: String,
//     },
//     // Stat doesn't have an fd, fstat literally takes an fd
//     // Fstat doesn't have a path as a parameter, thus the option
//     // Access, stat, fstat, newfstatat64
//     FailedMetadataAccess {
//         fd: Option<i32>,
//         path: Option<PathBuf>,
//         syscall_name: String,
//     },
//     // Open, openat.
//     SuccessfulFileOpen {
//         fd: i32,
//         inode: u64,
//         open_mode: OpenMode,
//         path: PathBuf,
//         syscall_name: String,
//     },
//     // Read, pread64.
//     SuccessfulFileRead {
//         fd: i32,
//         inode: u64,
//         path: PathBuf,
//         syscall_name: String,
//     },
//     // Access, stat, fstat, newfstatat64
//     SuccessfulMetadataAccess {
//         fd: Option<i32>,
//         inode: u64,
//         path: Option<PathBuf>,
//         syscall_name: String,
//     },
// }

// #[derive(Debug)]
// pub enum FileModification {
//     // No need for open mode, we know it is WriteOnly.
//     // Creat, open, openat (same for successful file create).
//     FailedFileCreate {
//         path: PathBuf,
//         syscall_name: String,
//     },
//     // Write's parameter is an fd (same for successful file write).
//     // Write / writev (TODO)
//     FailedFileWrite {
//         fd: i32,
//         syscall_name: String,
//     },
//      // Want to know what they wrote to stderr.
//     Stderr(String),
//     // Want to know what they wrote to stdout.
//     Stdout(String),
//     // Creat, open, openat.
//     SuccessfulFileCreate {
//         fd: i32,
//         inode: u64,
//         path: PathBuf,
//         syscall_name: String,
//     },
//     // Write, writev (TODO).
//     SuccessfulFileWrite {
//         fd: i32,
//         inode: u64,
//         path: PathBuf,
//         syscall_name: String,
//     },
// }

// Actual accesses to the file system performed by
// a successful execution.
// TODO: Handle stderr and stdout. I don't want to right
// now it's hard and my simplest example does not
// cover it.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ExecAccesses {
    input_files: Vec<IOFile>,
    output_files: Vec<IOFile>,
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
    pub fn add_new_file_event(&mut self, file_access: IOFile) {
        match file_access {
            IOFile::InputFile(_) => self.input_files.push(file_access),
            IOFile::OutputFile(_) => self.output_files.push(file_access),
        }
    }

    // At the end of a successful execution, we get the hash of each output
    // file.1
    pub fn add_output_file_hashes(&mut self) -> anyhow::Result<()> {
        for output in self.output_files.iter_mut() {
            println!("looping in add_output_file_hashes");
            println!("file name: {:?}", output);
            if let IOFile::OutputFile(FileAccess::Success {
                file_name: _,
                full_path,
                hash,
                syscall_name: _,
            }) = output
            {
                if full_path.starts_with("/dev/") || full_path.is_dir() {
                    *hash = None;
                } else {
                    let path = full_path.clone().into_os_string().into_string().unwrap();
                    let hash_value = generate_hash(path)?;
                    *hash = Some(hash_value);
                }
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

    fn get_cwd(&self) -> PathBuf {
        self.cwd.clone()
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

    pub fn add_new_file_event(&mut self, file: IOFile) {
        match self {
            Execution::Successful(_, accesses) => accesses.add_new_file_event(file),
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

    pub fn get_cwd(&self) -> PathBuf {
        match self {
            Execution::Successful(metadata, _) | Execution::Failed(metadata) => metadata.get_cwd(),
            _ => panic!("Should not be getting cwd from pending execution!"),
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

    // pub fn add_child_process(&self, child_pid: Pid) {
    //     self.execution.borrow_mut().add_child_process(child_pid);
    // }

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

    pub fn add_new_file_event(&self, file: IOFile) {
        self.execution.borrow_mut().add_new_file_event(file);
    }

    pub fn add_output_file_hashes(&self) -> anyhow::Result<()> {
        self.execution.borrow_mut().add_output_file_hashes()
    }

    pub fn get_cwd(&self) -> PathBuf {
        // let execution = self.execution.borrow();
        self.execution.borrow().get_cwd()
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

    pub fn add_new_execution(&self, execution: RcExecution) {
        self.executions.borrow_mut().push(execution);
    }

    pub fn get_execution_count(&self) -> i32 {
        self.executions.borrow().len() as i32
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

/// Compute digest value for given `Reader` and print it
/// On any error simply return without doing anything
fn process<D: Digest + Default, R: Read>(reader: &mut R) -> anyhow::Result<Vec<u8>> {
    const BUFFER_SIZE: usize = 1024;
    let mut sh = D::default();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        // let n = match reader.read(&mut buffer) {
        //     Ok(n) => n,
        //     Err(_) => return,
        // };
        let n = reader.read(&mut buffer)?;
        sh.update(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
        // println!("n is: {}", n);
        // println!("in process() loop");
    }

    let final_array = &sh.finalize();
    let final_vec_hash = final_array.to_vec();
    Ok(final_vec_hash)
    // print_result(&sh.finalize(), name);
}

pub fn generate_hash(path: String) -> anyhow::Result<Vec<u8>> {
    println!("made it to generate_hash");
    let mut file = fs::File::open(&path)?;
    process::<Sha256, _>(&mut file)
}

pub fn serialize_execs_to_cache(global_executions: GlobalExecutions) {
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

    // Serialize the executions.
    let serialized_execs = rmp_serde::to_vec(&global_executions).unwrap();

    // Write the serialized execs to a file.
    // I am just writing them to /home/kelly/research/IOTracker/cache/cache
    write_serialized_execs_to_cache(serialized_execs);

    // let buf = rmp_serde::to_vec(&(42, "the Answer")).unwrap();

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
}

fn write_serialized_execs_to_cache(serialized_execs: Vec<u8>) {
    fs::write(
        "/home/kelly/research/IOTracker/cache/cache",
        serialized_execs,
    )
    .expect("Failed to write serialized executions to cache!");
    // write("/home/kelly/research/IOTracker/cache/cache", serialized_execs).unwrap();
}
