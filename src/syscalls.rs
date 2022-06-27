use std::path::PathBuf;

use libc::c_int;
use nix::{fcntl::OFlag, unistd::Pid};
use serde::{Deserialize, Serialize};

use crate::condition_utils::FileType;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct MyStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
// We need to differentiate between when we need to call
// lstat to check or stat to check the precondition.
pub enum Stat {
    Lstat(MyStat),
    Stat(MyStat),
}
// Successful and failing events.
// "Open" meaning not using O_CREAT
// "Create" meaning using O_CREAT
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyscallEvent {
    Access(c_int, SyscallOutcome),
    Create(OFlag, SyscallOutcome), // Can fail because pathcomponentdoesntexist or failedtocreatefileexclusively, or accessdenied
    Delete(SyscallOutcome),
    DirectoryRead(PathBuf, Vec<(String, FileType)>, SyscallOutcome),
    FailedExec(SyscallFailure),
    ChildExec(Pid), // We want to know when our child processes have successfully called execve.
    Open(OFlag, Option<Vec<u8>>, SyscallOutcome), // Can fail because the file didn't exist or permission denied
    Rename(PathBuf, PathBuf, SyscallOutcome),     // Old, new, outcome
    Stat(Option<Stat>, SyscallOutcome), // Can fail access denied (exec/search on dir) or file didn't exist
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyscallFailure {
    AlreadyExists,
    FileDoesntExist,
    InvalArg,
    PermissionDenied,
}

// The i32 is the return value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyscallOutcome {
    Fail(SyscallFailure),
    Success,
}
