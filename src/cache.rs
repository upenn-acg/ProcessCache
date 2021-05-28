use std::rc::Rc;
use std::{cell::RefCell, path::PathBuf};

// File struct.
#[derive(Debug)]
pub struct FileAccess {
    fd: Option<i32>,
    inode: u64,
    path: Option<PathBuf>, // TODO:  handle absolute + relative, AT_FDCWD
    syscall_name: String,
}

impl FileAccess {
    pub fn new(
        fd: Option<i32>,
        inode: u64,
        path: Option<PathBuf>,
        syscall_name: String,
    ) -> FileAccess {
        FileAccess {
            fd,
            inode,
            path,
            syscall_name,
        }
    }
}

// TODO: stderr and stdout are going to be much more
// complicated than this. Pipes, dup, formatting,
// the execution writing more than once, ahhh there's
// a lotta stuff that can happen!
#[derive(Debug)]
pub struct ExecInfo {
    args: Vec<String>,
    cwd: PathBuf,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    executable: String,
    exit_code: Option<i32>,
    files_accessed: Vec<FileAccess>,
    files_created: Vec<FileAccess>,
    files_read: Vec<FileAccess>,
    files_written: Vec<FileAccess>,
    stderr: String,
    stdout: String,
}

impl ExecInfo {
    pub fn new() -> ExecInfo {
        ExecInfo {
            args: Vec::new(),
            cwd: PathBuf::new(),
            env_vars: Vec::new(),
            executable: String::new(),
            exit_code: None,
            files_accessed: Vec::new(),
            files_created: Vec::new(),
            files_read: Vec::new(),
            files_written: Vec::new(),
            stderr: String::new(),
            stdout: String::new(),
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
    
    // Add new file contents read (read, pread64).
    fn add_new_contents_read(&mut self, file: FileAccess) {
        self.files_read.push(file);
    }

    // Add new file contents write (write).
    fn add_new_contents_write(&mut self, file: FileAccess) {
        self.files_written.push(file);
    }

    // Add new file create (creat, open, openat)
    fn add_new_file_create(&mut self, file: FileAccess) {
        self.files_created.push(file);
    }

    // Add new file metadata access (open(at) [not creating file], access).
    fn add_new_metadata_access(&mut self, file: FileAccess) {
        self.files_accessed.push(file);
    }

    // Add the execution's output to stderr.
    fn add_stderr(&mut self, stderr: String) {
        let mut new_stderr = self.stderr.clone();
        new_stderr.push_str(&stderr);
        self.stderr = new_stderr;
    }

    // Add the execution's output to stdout.
    fn add_stdout(&mut self, stdout: String) {
        let mut new_stdout = self.stdout.clone();
        new_stdout.push_str(&stdout);
        self.stdout = new_stdout;
    }
}

#[derive(Clone, Debug)]
pub struct Execution {
    execution: Rc<RefCell<ExecInfo>>,
}

impl Execution {
    pub fn new(execution: ExecInfo) -> Execution {
        Execution {
            execution: Rc::new(RefCell::new(execution)),
        }
    }

    pub fn add_exit_code(&self, code: i32) {
        self.execution
            .borrow_mut()
            .add_exit_code(code);
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

    // Add new file contents read (read, pread64).
    pub fn add_new_contents_read(&self, file: FileAccess) {
        self.execution.borrow_mut().add_new_contents_read(file);
    }

    // Add new file contents write (write).
    pub fn add_new_contents_write(&self, file: FileAccess) {
        self.execution.borrow_mut().add_new_contents_write(file);
    }

    // Add new file create (creat, open, openat)
    pub fn add_new_file_create(&self, file: FileAccess) {
        self.execution.borrow_mut().add_new_file_create(file);
    }

    // Add new file metadata access (open(at) [not creating file], access).
    pub fn add_new_metadata_access(&self, file: FileAccess) {
        self.execution.borrow_mut().add_new_metadata_access(file);
    }

    // Add the execution's output to stderr.
    pub fn add_stderr(&self, stderr: String) {
        self.execution.borrow_mut().add_stderr(stderr);
    }

    // Add the execution's output to stdout.
    pub fn add_stdout(&self, stdout: String) {
        self.execution.borrow_mut().add_stdout(stdout);
    }
}
#[derive(Clone)]
pub struct GlobalExecutions {
    pub executions: Rc<RefCell<Vec<Execution>>>,
}

impl GlobalExecutions {
    pub fn new() -> GlobalExecutions {
        GlobalExecutions {
            executions: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub fn add_new_execution(&self, execution: Execution) {
        self.executions.borrow_mut().push(execution);
    }
}
