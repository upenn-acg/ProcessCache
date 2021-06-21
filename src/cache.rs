use std::rc::Rc;
use std::{cell::RefCell, path::PathBuf};

#[derive(Debug)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
    WriteOnly,
}

#[derive(Debug)]
// TODO: differentiate between ABSOLUTE PATH and REL PATH?
pub enum FileAccess {
    // No need for open mode, we know it is WriteOnly.
    // Creat, open, openat (same for successful file create).
    FailedFileCreate {
        path: PathBuf,
        syscall_name: String,
    },
    // Open, openat
    FailedFileOpen {
        open_mode: OpenMode,
        path: PathBuf,
        syscall_name: String,
    },
    // Read's parameter is an fd (same for successful file read).
    // Read, pread64
    FailedFileRead {
        fd: i32,
        syscall_name: String,
    },
    // Write's parameter is an fd (same for successful file write).
    // Write / writev (TODO)
    FailedFileWrite {
        fd: i32,
        syscall_name: String,
    },
    // Stat doesn't have an fd, fstat literally takes an fd
    // Fstat doesn't have a path as a parameter, thus the option
    // Access, stat, fstat, newfstatat64
    FailedMetadataAccess {
        fd: Option<i32>,
        path: Option<PathBuf>,
        syscall_name: String,
    },
    // Want to know what they wrote to stderr.
    Stderr(String),
    // Want to know what they wrote to stdout.
    Stdout(String),
    // Creat, open, openat.
    SuccessfulFileCreate {
        fd: i32,
        inode: u64,
        path: PathBuf,
        syscall_name: String,
    },
    // Open, openat.
    SuccessfulFileOpen {
        fd: i32,
        inode: u64,
        open_mode: OpenMode,
        path: PathBuf,
        syscall_name: String,
    },
    // Read, pread64.
    SuccessfulFileRead {
        fd: i32,
        inode: u64,
        path: PathBuf,
        syscall_name: String,
    },
    // Write, writev (TODO).
    SuccessfulFileWrite {
        fd: i32,
        inode: u64,
        path: PathBuf,
        syscall_name: String,
    },
    // Access, stat, fstat, newfstatat64
    SuccessfulMetadataAccess {
        fd: Option<i32>,
        inode: u64,
        path: Option<PathBuf>,
        syscall_name: String,
    },
}

// Actual accesses to the file system performed by
// a successful execution.
// TODO: stderr and stdout are going to be much more
// complicated than this. Pipes, dup, formatting,
// the execution writing more than once, ahhh there's
// a lotta stuff that can happen!
#[derive(Debug)]
pub struct ExecAccesses {
    files_accessed: Vec<FileAccess>,
    stderr: String,
    stdout: String,
}

impl ExecAccesses {
    pub fn new() -> ExecAccesses {
        ExecAccesses {
            files_accessed: Vec::new(),
            stderr: String::new(),
            stdout: String::new(),
        }
    }

    // Add new access to the struct.
    fn add_new_access(&mut self, file_access: FileAccess) {
        match file_access {
            FileAccess::Stderr(stderr) => self.stderr.push_str(&stderr),
            FileAccess::Stdout(stdout) => self.stdout.push_str(&stdout),
            _ => self.files_accessed.push(file_access),
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
            cwd: PathBuf::new(),
            env_vars: Vec::new(),
            executable: String::new(),
            exit_code: None,
        }
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
}

#[derive(Debug)]
pub enum Execution {
    Failed(ExecMetadata),
    Pending, // At time of creation, we don't know what the heck it is!
    // A successful execution has both metadata and
    // potentially file system accesses.
    Successful(ExecMetadata, ExecAccesses),
}

impl Execution {
    pub fn add_exit_code(&mut self, exit_code: i32) {
        match self {
            Execution::Successful(metadata, _) => metadata.add_exit_code(exit_code),
            Execution::Failed(metadata) => metadata.add_exit_code(exit_code),
            Execution::Pending => {
                panic!("Does it make sense to add an exit code to a pending execution...?")
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
            Execution::Failed(metadata) | Execution::Successful(metadata, _) => {
                metadata.add_identifiers(args, cwd, env_vars, executable)
            }
            Execution::Pending => panic!("Should not be adding identifiers to pending exec!"),
        }
    }

    pub fn add_new_access(&mut self, file_access: FileAccess) {
        match self {
            Execution::Successful(_, accesses) => accesses.add_new_access(file_access),
            _ => panic!("Should not be adding an access to a failed exec!"),
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

    pub fn add_exit_code(&self, code: i32) {
        self.execution.borrow_mut().add_exit_code(code);
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

    pub fn add_new_access(&self, file_access: FileAccess) {
        self.execution.borrow_mut().add_new_access(file_access);
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
