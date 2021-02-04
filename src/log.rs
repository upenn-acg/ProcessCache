use nix::unistd::Pid;
use std::fmt;

pub enum Mode {
    ReadOnly,
    ReadWrite,
    WriteOnly,
}

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
        let mut log_string = String::new();

        log_string.push_str(&format!(
            "Execve event: {:?}, {:?}\n",
            self.path_name, self.args
        ));

        write!(f, "{}", log_string)
    }
}

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
        let mut log_string = String::new();

        log_string.push_str(&format!(
            "Fork Event. Creating task for new child: {}. Parent pid is: {}\n",
            self.child_pid, self.current_pid
        ));

        write!(f, "{}", log_string)
    }
}

pub struct OpenEvent {
    fd: i32,
    inode: Option<u64>,
    is_create: bool,
    mode: Mode,
    path: String, // Full path if possible, else relative path.
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
        let mut log_string = String::new();
        if self.is_create {
            log_string.push_str(&format!(
                "File create event ({}): opened for writing. ",
                self.syscall_name
            ));
        } else {
            log_string.push_str(&format!("File open event ({}): ", self.syscall_name));
        }

        match self.mode {
            Mode::ReadOnly => log_string.push_str("File opened for reading. "),
            Mode::WriteOnly => log_string.push_str("File opened for writing. "),
            Mode::ReadWrite => log_string.push_str("File open for reading/writing. "),
        }

        log_string.push_str(&format!(
            "Fd: {}, Path: {}, Pid: {}, ",
            self.fd, self.path, self.pid
        ));

        if let Some(ino) = self.inode {
            log_string.push_str(&format!("Inode: {} \n", ino));
        } else {
            log_string.push('\n');
        }

        write!(f, "{}", log_string)
    }
}

pub struct StatEvent {
    fd: Option<i32>,
    inode: Option<u64>,
    is_symbolic_link: bool,
    path: Option<String>,
    pid: Pid,
    success: bool,
    syscall_name: String,
}

impl StatEvent {
    pub fn new(
        fd: Option<i32>,
        inode: Option<u64>,
        is_symbolic_link: bool,
        path: Option<String>,
        pid: Pid,
        success: bool,
        syscall_name: String,
    ) -> StatEvent {
        StatEvent {
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
        let mut log_string = String::new();

        log_string.push_str(&format!(
            "File stat event ({}): Pid: {}, ",
            self.syscall_name, self.pid
        ));

        if self.success {
            log_string.push_str("Success, ");
        } else {
            log_string.push_str("Fail, ");
        }

        if self.is_symbolic_link {
            log_string.push_str("Symlink, ");
        } else {
            log_string.push_str("Hardlink, ");
        }

        if let Some(file_name) = self.path.clone() {
            log_string.push_str(&format!("Path: \"{}\", ", file_name));
        }

        if let Some(file_d) = self.fd {
            log_string.push_str(&format!("Fd: {}, ", file_d));
        }

        if let Some(ino) = self.inode {
            log_string.push_str(&format!("Inode: {}\n", ino));
        } else {
            log_string.push('\n');
        }

        write!(f, "{}", log_string)
    }
}
