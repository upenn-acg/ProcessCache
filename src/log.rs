use nix::unistd::Pid;
use std::fmt;

#[derive(Debug)]
pub enum Mode {
    ReadOnly,
    ReadWrite,
    WriteOnly,
}

#[derive(Debug)]
pub struct AccessEvent {
    inode: Option<u64>,
    // Full path
    path: String,
    pid: Pid,
    successful: bool,
}

impl AccessEvent {
    pub fn new(inode: Option<u64>, path: String, pid: Pid, successful: bool) -> AccessEvent {
        AccessEvent {
            inode,
            path,
            pid,
            successful,
        }
    }
}

impl fmt::Display for AccessEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct ExecveEvent {
    args: Vec<String>,
    path_name: String,
}

impl ExecveEvent {
    pub fn new(args: Vec<String>, path_name: String) -> ExecveEvent {
        ExecveEvent { args, path_name }
    }
}

impl fmt::Display for ExecveEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct ForkEvent {
    child_pid: Pid,
    current_pid: Pid,
}

impl ForkEvent {
    pub fn new(child_pid: Pid, current_pid: Pid) -> ForkEvent {
        ForkEvent {
            child_pid,
            current_pid,
        }
    }
}

impl fmt::Display for ForkEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct OpenEvent {
    fd: i32,
    inode: Option<u64>,
    is_create: bool,
    mode: Mode,
    /// Full path if possible, else relative path.
    path: String,
    pid: Pid,
    syscall_name: String,
}

impl OpenEvent {
    pub fn new(
        fd: i32,
        inode: Option<u64>,
        is_create: bool,
        mode: Mode,
        path: String,
        pid: Pid,
        syscall_name: String,
    ) -> OpenEvent {
        OpenEvent {
            fd,
            inode,
            is_create,
            mode,
            path,
            pid,
            syscall_name,
        }
    }
}

impl fmt::Display for OpenEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct ReadEvent {
    fd: i32,
    inode: Option<u64>,
    path: Option<String>,
    pid: Pid,
    syscall_name: String,
}

impl ReadEvent {
    pub fn new(
        fd: i32,
        inode: Option<u64>,
        path: Option<String>,
        pid: Pid,
        syscall_name: String,
    ) -> ReadEvent {
        ReadEvent {
            fd,
            inode,
            path,
            pid,
            syscall_name,
        }
    }
}

impl fmt::Display for ReadEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{:?}", self)
    }
}
#[derive(Debug)]
pub struct StatEvent {
    /// For newfstatat check the flags
    at_symlink_nofollow: bool,
    fd: Option<i32>,
    /// Only want the inode if it was a successful call.
    inode: Option<u64>,
    is_symbolic_link: bool,
    path: Option<String>,
    pid: Pid,
    success: bool,
    syscall_name: String,
}

impl StatEvent {
    pub fn new(
        at_symlink_nofollow: bool,
        fd: Option<i32>,
        inode: Option<u64>,
        is_symbolic_link: bool,
        path: Option<String>,
        pid: Pid,
        success: bool,
        syscall_name: String,
    ) -> StatEvent {
        StatEvent {
            at_symlink_nofollow,
            fd,
            inode,
            is_symbolic_link,
            path,
            pid,
            success,
            syscall_name,
        }
    }
}

impl fmt::Display for StatEvent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{:?}", self)
    }
}
