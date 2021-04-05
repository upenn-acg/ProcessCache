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
// Resource struct.
// Files basically.
#[derive(Debug)]
pub struct Resource {
    access_type: AccessType,
    fd: Option<i32>,
    // inode: u64 (inode is the ID of the resource)
    path: Option<String>, // TODO:  handle absolute + relative, AT_FDCWD
}

impl Resource {
    pub fn new(
        access_type: AccessType,
        fd: Option<i32>,
        // inode: u64,
        path: Option<String>,
    ) -> Resource {
        Resource {
            access_type,
            fd,
            path,
        }
    }

    pub fn update_access_type(&mut self, new_access_type: AccessType) {
        let prev_access_type = self.access_type;
        if new_access_type != prev_access_type {
            self.access_type = AccessType::Both;
        }
        self.access_type = new_access_type;
    }
}

// Unique execution in this overall program.
// Well the resources accessed can't really
// be a vector. Need to know what was actually
// accessed so it's going to change to a map
// inode --> resource
#[derive(Debug)]
pub struct Exec {
    args: Vec<String>,
    cwd: String,
    // TODO: env_vars: Vec<String>,
    resources_accessed: HashMap<u64, Resource>, // Read resource metadata and/or contents
}

impl Exec {
    pub fn new(
        args: Vec<String>,
        cwd: String,
        // TODO: env_vars: Vec<String>,
        resources_accessed: HashMap<u64, Resource>,
    ) -> Exec {
        Exec {
            args,
            cwd,
            // TODO: env_vars,
            resources_accessed,
        }
    }

    // Pass in the access type because a process may stat a file (metadata)
    // and then read from it (contents), so it reads both. Or it might just read the contents
    // and not metadata. Or just the metadata but not the contents.
    //
    // May need to update the access type
    // May be able to add a path for this resource
    // May be able to add the fd for this resource
    pub fn add_new_access(&mut self, inode: u64, resource: Resource) {
        if let Some(resource_entry) = self.resources_accessed.get_mut(&inode) {
            resource_entry.fd = resource.fd;
            resource_entry.path = resource.path;
            resource_entry.update_access_type(resource.access_type);
        } else {
            // Insert the new resource.
            self.resources_accessed.insert(inode, resource);
        }
    }
}

#[derive(Debug)]
pub struct Execs {
    // Executable that is currently running.
    current_exec: String,
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
    pub execs: HashMap<String, Exec>,
}

impl Execs {
    pub fn new(args: Vec<String>, current_exec: String) -> Execs {
        let mut execs = HashMap::new();
        // TODO: Fix this lmao it's abysmal
        let cwd = String::from("cwd");

        // We need to add the first exec so we don't miss it.
        // Silly me was only adding in the handle_execve() function,
        // which totally doesn't get called by the initial process, smdh
        let first_exec = Exec::new(args, cwd, HashMap::new());
        execs.insert(current_exec.clone(), first_exec);
        Execs {
            execs,
            current_exec,
        }
    }

    // Pass in the access type because a process may stat a file (metadata)
    // and then read from it (contents), so it reads both. Or it might just read the contents
    // and not metadata. Or just the metadata but not the contents.
    //
    // May need to update the access type
    // May be able to add a path for this resource
    // May be able to add the fd for this resource
    pub fn add_new_access(&mut self, inode: u64, resource: Resource) {
        let curr_exec = self.current_exec.clone();
        if let Some(exec_entry) = self.execs.get_mut(&curr_exec) {
            exec_entry.add_new_access(inode, resource);
        } else {
            // TODO: better error?
            panic!("Current exec is not found in execs!");
        }
    }

    pub fn add_new_exec(&mut self, executable_str: String, exec: Exec) {
        self.execs.insert(executable_str, exec);
    }

    pub fn update_curr_exec(&mut self, new_exec: String) {
        self.current_exec = new_exec;
    }
}

impl fmt::Display for Execs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, ":{:?}", self)
    }    
}
// ¯\_(ツ)_/¯
#[derive(Clone)]
pub struct RcExecs {
     // TODO: this shouldn't just be pub
    pub rc_execs: Rc<RefCell<Execs>>,
}

impl RcExecs {
    // TODO?: env vars?
    pub fn new(args: Vec<String>, executable: String) -> RcExecs {
        RcExecs {
            rc_execs: Rc::new(RefCell::new(Execs::new(args, executable))),
        }
    }

    // TODO: return err?
    pub fn add_new_exec(&self, exec: Exec, executable_str: String) {
        self.rc_execs
            .borrow_mut()
            .add_new_exec(executable_str, exec);
    }

    // New access goes to current executable.
    // May need to update the access type
    // May be able to add a path for this resource
    // May be able to add the fd for this resource
    pub fn add_new_access(&self, inode: u64, resource: Resource) {
        self.rc_execs.borrow_mut().add_new_access(inode, resource);
    }

    pub fn update_curr_exec(&self, executable_str: String) {
        self.rc_execs.borrow_mut().update_curr_exec(executable_str);
    }
}
// All the execs we have seen for the
// current whole program thing we are tracking.
// struct UniqExecs {
//     execs: Vec<Exec>,
// }

// impl UniqExecs {
//     fn add_new_exec(&mut self, exec: Exec) {
//         // TODO: check if we already have it!
//         // For now I'm going to assume it's not there already.
//         self.execs.insert(exec);
//     }
// }

// This is a wrapper around set of execs
// we have seen for this execution
// so that Rust is happy about this being used
// across futures.
// struct UniqExecsRc {
//     execs: Rc<RefCell<ExecsSet>>,
// }

// impl UniqExecsRc {
//     fn add_new_exec(&self, exec: Exec) {
//         self.execs.borrow_mut()
//     }
// }
