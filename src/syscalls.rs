use std::path::PathBuf;

use crate::condition_utils::FileType;
use libc::c_int;
use nix::{fcntl::OFlag, unistd::Pid};
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
    // pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct MyStatFs {
    // pub filesystem_type: FsType,
    pub optimal_transfer_size: i64,
    pub block_size: i64,
    pub maximum_name_length: i64,
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
    pub files: u64,
    pub files_free: u64,
    // pub filesystem_id: fsid_t,
}

pub struct OpenFlags {
    pub creat_flag: bool,
    pub excl_flag: bool,
    pub file_existed_at_start: bool,
    pub offset_mode: Option<OffsetMode>,
    pub access_mode: AccessMode,
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
    DirectoryCreate(PathBuf, SyscallOutcome),
    DirectoryRead(PathBuf, Vec<(String, FileType)>, SyscallOutcome), // Root dir
    FailedExec(SyscallFailure),
    ChildExec(Pid), // We want to know when our child processes have successfully called execve.
    Open(
        AccessMode,
        Option<OffsetMode>,
        Option<CheckMechanism>,
        SyscallOutcome,
    ), // Can fail because the file didn't exist or permission denied
    Rename(PathBuf, PathBuf, SyscallOutcome), // Old, new, outcome
    Stat(Option<Stat>, SyscallOutcome), // Can fail access denied (exec/search on dir) or file didn't exist
    Statfs(Option<MyStatFs>, SyscallOutcome), // Can fail access denied (exec/search on dir) or dir doesn't exist.
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum CheckMechanism {
    DiffFiles,
    Mtime(i64),
    Hash(Vec<u8>),
}

// PRANOTI: I moved these here because I think they belong here.
// They fall more under syscallsrs I think than something related to
// execution_utils.rs (which is just a place for functions used in execution.rs)
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessMode {
    Read,
    Write,
    Both,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OffsetMode {
    Append,
    Trunc,
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
