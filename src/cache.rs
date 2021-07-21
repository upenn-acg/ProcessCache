use nix::unistd::Pid;
use std::rc::Rc;
use std::{cell::RefCell, path::PathBuf};

#[derive(Debug)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
    WriteOnly,
}

// Success and failure variants of
// input and output files.
// TODO: HASH SHOULD NOT TO BE AN OPTION
#[derive(Debug)]
pub enum FileAccess {
    Success {
        file_name: PathBuf,
        full_path: PathBuf,
        hash: Vec<u8>,
        syscall_name: String,
    },
    Failure {
        file_name: PathBuf,
        full_path: PathBuf,
        syscall_name: String,
    },
}

#[derive(Debug)]
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
#[derive(Debug)]
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
}

// Info about the execution that we want to keep around
// even if the execution fails (so we know it should fail
// if we see it again, it would be some kinda error if
// we expect it to fail... and it doesn't :o that's an
// existential and/or metaphysical crisis for future kelly)
#[derive(Debug)]
pub struct ExecMetadata {
    args: Vec<String>,
    child_processes: Vec<Pid>,
    cwd: PathBuf,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    executable: String,
    // We don't know the exit code until it exits.
    // So while an execution is running this is None.
    exit_code: Option<i32>,
}

impl ExecMetadata {
    pub fn new() -> ExecMetadata {
        ExecMetadata {
            args: Vec::new(),
            child_processes: Vec::new(),
            cwd: PathBuf::new(),
            env_vars: Vec::new(),
            executable: String::new(),
            exit_code: None,
        }
    }

    fn add_child_process(&mut self, child_pid: Pid) {
        self.child_processes.push(child_pid);
    }

    fn add_exit_code(&mut self, code: i32) {
        self.exit_code = Some(code);
    }

    fn add_identifiers(
        &mut self,
        args: Vec<String>,
        cwd: PathBuf,
        env_vars: Vec<String>,
        executable: String,
    ) {
        self.args = args;
        self.cwd = cwd;
        self.env_vars = env_vars;
        self.executable = executable;
    }

    fn get_cwd(&self) -> PathBuf {
        self.cwd.clone()
    }
}

#[derive(Debug)]
pub enum Execution {
    Failed(ExecMetadata, Pid),
    Pending, // At time of creation, we don't know what the heck it is!
    // A successful execution has both metadata and
    // potentially file system accesses.
    Successful(ExecMetadata, ExecAccesses, Pid),
}

impl Execution {
    pub fn add_child_process(&mut self, child_pid: Pid) {
        match self {
            Execution::Successful(metadata, _, _) => metadata.add_child_process(child_pid),
            _ => panic!("Trying to add child process to failed or pending execution!"),
        }
    }

    pub fn add_exit_code(&mut self, exit_code: i32, pid: Pid) {
        match self {
            Execution::Failed(meta, exec_pid) | Execution::Successful(meta, _, exec_pid) => {
                // Only want the exit code if this is the process
                // that actually exec'd the process.
                if *exec_pid == pid {
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
    ) {
        match self {
            Execution::Failed(metadata, _) | Execution::Successful(metadata, _, _) => {
                metadata.add_identifiers(args, cwd, env_vars, executable)
            }
            Execution::Pending => panic!("Should not be adding identifiers to pending exec!"),
        }
    }

    pub fn add_new_file_event(&mut self, file: IOFile) {
        match self {
            Execution::Successful(_, accesses, _) => accesses.add_new_file_event(file),
            _ => panic!("Should not be adding file event to pending or failed execution!"),
        }
    }

    pub fn get_cwd(&self) -> PathBuf {
        match self {
            Execution::Successful(metadata, _, _) | Execution::Failed(metadata, _) => {
                metadata.get_cwd()
            }
            _ => panic!("Should not be getting cwd from pending execution!"),
        }
    }
}
// Rc stands for reference counted.
// This is the wrapper around the Execution
// enum.
#[derive(Clone, Debug)]
pub struct RcExecution {
    execution: Rc<RefCell<Execution>>,
}

impl RcExecution {
    pub fn new(execution: Execution) -> RcExecution {
        RcExecution {
            execution: Rc::new(RefCell::new(execution)),
        }
    }

    pub fn add_child_process(&self, child_pid: Pid) {
        self.execution.borrow_mut().add_child_process(child_pid);
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
    ) {
        self.execution
            .borrow_mut()
            .add_identifiers(args, cwd, env_vars, executable);
    }

    pub fn add_new_file_event(&self, file: IOFile) {
        self.execution.borrow_mut().add_new_file_event(file);
    }

    pub fn get_cwd(&self) -> PathBuf {
        self.execution.borrow().get_cwd()
    }
}
#[derive(Clone)]
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
