use std::path::PathBuf;

use crate::condition_utils::FileType;
use libc::c_int;
use nix::{fcntl::OFlag, unistd::Pid};
use serde::{Deserialize, Serialize};

// Our own stat struct that contains everything that does not vary
// across Linux versions and is important.
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

// Our own statfs struct that contains everything that does not
// vary across Linux versions and is important.
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

// There are so many flags for the open system call.
// This struct helps us keep them all in one place.
pub struct OpenFlags {
    pub creat_flag: bool,
    pub excl_flag: bool,
    pub file_existed_at_start: bool,
    pub offset_mode: Option<OffsetMode>,
    pub access_mode: AccessMode,
}

// Enum of potential directory events (successful and failing).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirEvent {
    ChildExec(Pid), // We want to know when our child processes have successfully called execve.
    Create(PathBuf, SyscallOutcome),
    Delete(SyscallOutcome),
    Read(PathBuf, Vec<(String, FileType)>, SyscallOutcome), // Root dir
    Rename(PathBuf, PathBuf, SyscallOutcome),               // Old, new, outcome
    Statfs(Option<MyStatFs>, SyscallOutcome), // Can fail access denied (exec/search on dir) or file didn't exist
}

// Successful and failing events.
// "Open" meaning not using O_CREAT
// "Create" meaning using O_CREAT
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileEvent {
    Access(c_int, SyscallOutcome),
    Create(OFlag, SyscallOutcome), // Can fail because "path component doesn't exist", "failed to create file exclusively", "access denied"
    Delete(SyscallOutcome),
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
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
// We need to differentiate between when we need to call
// lstat to check or stat to check the precondition.
pub enum Stat {
    Lstat(MyStat),
    Stat(MyStat),
}

// Enum for toggling between the different input checking mechanisms.
// DiffFiles = we copy your input files to the cache, and we diff the cached
//             file with the current input file.
// Mtime = we get the mtime at time of access during the recording run,
//         and see if it has changed when we are checking whether to skip.
// Hash = we hash your input file, and then when deciding whether to skip,
//        we hash the current input file, and compare that to the cached hash.
// Trade-offs:
// DiffFiles = Very strong correctness guarantees. Not great for space or for speed.
// Mtime = Basic correctness guarantees. Grate for space AND speed.
// Hash = Very strong correctness guarantees. Not great for speed, but good for space.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum CheckMechanism {
    DiffFiles,
    Mtime(i64),
    Hash(Vec<u8>),
}

// Nicer enum to use than c_int's or whatever it is at the OS level.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessMode {
    Read,
    Write,
    Both,
}

// Nicer enum to use than c_int's or whatever it is at the OS level.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OffsetMode {
    Append,
    Trunc,
}

// Enum of the different types of syscall failures.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyscallFailure {
    AlreadyExists,
    FileDoesntExist,
    InvalArg,
    PermissionDenied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyscallOutcome {
    Fail(SyscallFailure),
    Success,
}
