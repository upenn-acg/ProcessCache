use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

// TODO: use anyhow errors?

// Types of READ access to a resource.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AccessType {
    Metadata,
    ReadContents,
    WriteContents,
}
// File struct.
#[derive(Debug)]
pub struct RegFile {
    fd: Option<i32>,
    inode: u64,
    path: Option<String>, // TODO:  handle absolute + relative, AT_FDCWD
}

impl RegFile {
    pub fn new(
        fd: Option<i32>,
        inode: u64,
        path: Option<String>,
    ) -> RegFile {
        RegFile {
            fd,
            inode,
            path,
        }
    }
}

#[derive(Debug)]
pub struct Execution {
    args: Vec<String>,
    cwd: String,
    env_vars: Vec<String>,
    executable: String,
    exit_status: Option<u32>,
    files_accessed: Vec<RegFile>,
    files_read:Vec<RegFile>,
    files_written: Vec<RegFile>,
    stderr: Option<String>,
    stdout: Option<String>,
}

impl Execution {
    pub fn new(args: Vec<String>, cwd: String, env_vars: Vec<String>, executable: String) -> Execution {
        Execution {
            args,
            cwd,
            env_vars,
            executable,
            exit_status: None,
            files_accessed: Vec::new(),
            files_read: Vec::new(),
            files_written: Vec::new(),
            stderr: None,
            stdout: None,
        }
    }

    // Add new file contents read (read, pread64).
    pub fn add_new_contents_read(&mut self, file: RegFile) {
        self.files_read.push(file);
    }

    pub fn add_new_contents_write(&mut self, file: RegFile) {
        self.files_written.push(file);
    }

    // Add new file metadata access (open(at) [not creating file], access).
    pub fn add_new_metadata_access(&mut self, file: RegFile) {
        self.files_accessed.push(file);
    }
}
#[derive(Debug)]
pub struct Executions {
    // Executable that is currently running.
    // TODO: Handle this in some reasonable way.
    current_exec_idx: Option<u32>,
    pub execs: Vec<Execution>,
}

impl Executions {
    pub fn new() -> Executions {
        Executions {
            current_exec_idx: None,
            execs: Vec::new(),
        }
    }

    // TODO: I am assuming we should add this to current execution,
    // but the whole "curr exec" thing is probably going to need to
    // be fixed anyway because that just feels error prone.
    pub fn add_new_access(&mut self, access_type: AccessType, file: RegFile) {
        let idx = match self.current_exec_idx {
            Some(i) => i,
            // TODO: this seems error prone ;) 
            None => 0, 
        };

        if let Some(curr_entry) = self.execs.get_mut(idx as usize) {
            match access_type {
                AccessType::Metadata => {
                    curr_entry.add_new_metadata_access(file);
                }
                AccessType::ReadContents => {
                    curr_entry.add_new_contents_read(file);
                }
                AccessType::WriteContents => {
                    curr_entry.add_new_contents_write(file);
                }
            }
        } else {
            // TODO: this sucks as error handling
            panic!("No current execution");
        }
    }

    // Pushes the new exec onto the vector of execs
    // and updates the current_exec_idx.
    pub fn add_new_uniq_exec(&mut self, exec: Execution) {
        if let Some(idx) = self.current_exec_idx {
            self.current_exec_idx = Some(idx + 1);
        } else {
            self.current_exec_idx = Some(0);
        }
        self.execs.push(exec); 
    }
}

impl fmt::Display for Executions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, ":{:?}", self)
    }
}
// ¯\_(ツ)_/¯
#[derive(Clone)]
pub struct RcExecutions {
    // TODO: this shouldn't just be pub
    pub rc_execs: Rc<RefCell<Executions>>,
}

impl RcExecutions {
    pub fn new() -> RcExecutions {
        RcExecutions {
            rc_execs: Rc::new(RefCell::new(Executions::new())),
        }
    }

    // TODO: return err?
    pub fn add_new_uniq_exec(&self, exec: Execution) {
        self.rc_execs.borrow_mut().add_new_uniq_exec(exec);
    }

    pub fn add_new_access(&self, access_type: AccessType, file: RegFile) {
        self.rc_execs.borrow_mut().add_new_access(access_type, file);
    }
}
