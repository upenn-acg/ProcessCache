use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;

// TODO: use anyhow errors?

// Types of READ access to a resource.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AccessType {
    Contents,
    Metadata,
    Both,
}
// File struct.
#[derive(Debug)]
pub struct RegFile {
    access_type: AccessType,
    fd: Option<i32>,
    path: Option<String>, // TODO:  handle absolute + relative, AT_FDCWD
}

impl RegFile {
    pub fn new(
        access_type: AccessType,
        fd: Option<i32>,
        // inode: u64,
        path: Option<String>,
    ) -> RegFile {
        RegFile {
            access_type,
            fd,
            path,
        }
    }

    pub fn update_access_type(&mut self, new_access_type: AccessType) {
        let prev_access_type = self.access_type;
        if new_access_type != prev_access_type {
            self.access_type = AccessType::Both;
        } else {
            self.access_type = new_access_type;
        }
    }
}

// Outputs from a unique execution.
#[derive(Debug)]
pub struct Outputs {
    // TODO:
    // exit_code: Option<u32> or Option<Enum>?
    files_read: HashMap<u64, RegFile>,
    // TODO:
    // stderr: String,
    // stdout: String,
}

impl Outputs {
    pub fn new() -> Outputs {
        Outputs {
            files_read: HashMap::new(),
        }
    }

    pub fn add_new_file_access(&mut self, inode: u64, file: RegFile) {
        if let Some(prev_access) = self.files_read.get_mut(&inode) {
            prev_access.update_access_type(file.access_type);
        } else {
            self.files_read.insert(inode, file);
        }
    }
}

impl Default for Outputs {
    fn default() -> Self {
        Self::new()
    }
}
// A unique ID struct for a unique execution.
// We ID an execution by args, executable, cwd, env_vars (todo).
#[derive(Clone, Eq, Debug, Hash, PartialEq)]
pub struct ExecKey {
    args: Vec<String>,
    cwd: String,
    executable: String, // TODO: inode? How likely is it for the executable file itself to change?
                        // TODO: env_vars: Vec<String>,
}

impl ExecKey {
    pub fn new(
        args: Vec<String>,
        cwd: String,
        executable: String,
        // TODO: env_vars: Vec<String>,
    ) -> ExecKey {
        ExecKey {
            args,
            cwd,
            executable,
            // TODO: env_vars,
        }
    }

    // Pass in the access type because a process may stat a file (metadata)
    // and then read from it (contents), so it reads both. Or it might just read the contents
    // and not metadata. Or just the metadata but not the contents.
    //
    // May need to update the access type
    // May be able to add a path for this resource
    // May be able to add the fd for this resource
    // pub fn add_new_file_access(&mut self, inode: u64, new_file_access: RegFile) {
    //     if let Some(existing_resource_entry) = self.resources_accessed.get_mut(&inode) {
    //         existing_resource_entry.fd = new_resource_instance.fd;
    //         existing_resource_entry.path = new_resource_instance.path;
    //         existing_resource_entry.update_access_type(new_resource_instance.access_type);
    //     } else {
    //         // Insert the new resource.
    //         self.resources_accessed.insert(inode, new_resource_instance);
    //     }
    // }
}

#[derive(Debug)]
pub struct Executions {
    // Executable that is currently running.
    current_exec: ExecKey,
    // String here is the executable.
    // For now this is all I am ID-ing them by.

    // OBVIOUSLY TODO: Maybe we will have some kind
    // of dynamic map from pid -> exec (maybe pids will
    // be deterministic and make it even easier?), that
    // tells us which exec we are looking at, at the time
    // based on what pid is running. This way we don't add
    // a resource to an exec but oh wait! we had already
    // context switched! :O
    // For now, just one exec, we don't have to do this.
    //
    // TODO: this shouldn't just be pub
    pub execs: HashMap<ExecKey, Outputs>,
}

impl Executions {
    pub fn new(args: Vec<String>, current_executable: String, cwd: String) -> Executions {
        // We need to add the first exec so we don't miss it.
        // Silly me was only adding in the handle_execve() function,
        // which totally doesn't get called by the initial process, smdh
        let first_exec_key = ExecKey::new(args, cwd, current_executable);
        let mut execs = HashMap::new();
        execs.insert(first_exec_key.clone(), Outputs::new());
        Executions {
            current_exec: first_exec_key,
            execs,
        }
    }

    // TODO: I am assuming we should add this to current execution,
    // but the whole "curr exec" thing is probably going to need to
    // be fixed anyway because that just feels error prone.
    //
    // Pass in the access type because a process may stat a file (metadata)
    // and then read from it (contents), so it reads both. Or it might just read the contents
    // and not metadata. Or just the metadata but not the contents.
    //
    // May need to update the access type.
    // May be able to add a path for this resource.
    // May be able to add the fd for this resource.
    pub fn add_new_file_access(&mut self, inode: u64, file: RegFile) {
        if let Some(outputs) = self.execs.get_mut(&self.current_exec) {
            // TODO: handle adding other kinds of outputs
            outputs.add_new_file_access(inode, file);
        } else {
            // TODO: better error?
            panic!("Current exec is not found in execs!");
        }
    }

    pub fn add_new_uniq_exec(&mut self, exec_key: ExecKey) {
        // insert returns Some(entry) (the old value) if the
        // key was already in the map, and we want to panic
        // if that happens.
        if let Some(_) = self.execs.insert(exec_key, Outputs::new()) {
            panic!("We have already seen this execution!");
        }
    }

    // TODO: I guess this function assumes that the exec_key is
    // already in the map...
    pub fn change_curr_exec(&mut self, exec_key: ExecKey) {
        self.current_exec = exec_key;
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
    // TODO?: env vars?
    pub fn new(args: Vec<String>, executable: String, cwd: String) -> RcExecutions {
        RcExecutions {
            rc_execs: Rc::new(RefCell::new(Executions::new(args, executable, cwd))),
        }
    }

    // TODO: return err?
    pub fn add_new_uniq_exec(&self, exec_key: ExecKey) {
        self.rc_execs.borrow_mut().add_new_uniq_exec(exec_key);
    }

    // New access goes to current executable.
    // May need to update the access type
    // May be able to add a path for this resource
    // May be able to add the fd for this resource
    pub fn add_new_file_access(&self, inode: u64, file: RegFile) {
        self.rc_execs.borrow_mut().add_new_file_access(inode, file);
    }

    pub fn change_curr_exec(&self, exec_key: ExecKey) {
        self.rc_execs.borrow_mut().change_curr_exec(exec_key);
    }
}
