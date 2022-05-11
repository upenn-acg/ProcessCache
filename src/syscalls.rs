use std::path::PathBuf;

use libc::c_int;
use nix::fcntl::OFlag;
use serde::{Deserialize, Serialize};

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

// Successful and failing events.
// "Open" meaning not using O_CREAT
// "Create" meaning using O_CREAT
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyscallEvent {
    Access(c_int, SyscallOutcome),
    Create(OFlag, SyscallOutcome), // Can fail because pathcomponentdoesntexist or failedtocreatefileexclusively, or accessdenied
    Delete(SyscallOutcome),
    FailedExec(SyscallFailure),
    Open(OFlag, Option<Vec<u8>>, SyscallOutcome), // Can fail because the file didn't exist or permission denied
    Rename(PathBuf, PathBuf, SyscallOutcome),     // Old, new, outcome
    // TODO: Handle stat struct too
    Stat(Option<MyStat>, SyscallOutcome), // Can fail access denied (exec/search on dir) or file didn't exist
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyscallFailure {
    AlreadyExists,
    FileDoesntExist,
    PermissionDenied,
}

// The i32 is the return value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyscallOutcome {
    Fail(SyscallFailure),
    Success,
}
