use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    vec::Vec,
};

use libc::c_int;
use nix::fcntl::OFlag;
use serde::{Deserialize, Serialize};

use crate::syscalls::{Stat, SyscallEvent, SyscallFailure, SyscallOutcome};

pub type Conditions = HashMap<PathBuf, HashSet<Fact>>;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum FileType {
    Dir,
    File,
    Symlink,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Mod {
    Created,
    Deleted,
    Modified,
    Renamed(PathBuf, PathBuf),
    None,
}

pub struct LastMod(pub Mod);

impl LastMod {
    pub fn state(&self) -> &Mod {
        &self.0
    }

    pub fn update_based_on_syscall(&mut self, syscall_event: SyscallEvent) {
        match syscall_event {
            SyscallEvent::Create(_, SyscallOutcome::Success) => {
                self.0 = Mod::Created;
            }
            SyscallEvent::Delete(SyscallOutcome::Success) => {
                self.0 = Mod::Deleted;
            }
            SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, SyscallOutcome::Success) => {
                self.0 = Mod::Modified;
            }
            SyscallEvent::Rename(old_path, new_path, outcome) => {
                if outcome == SyscallOutcome::Success {
                    self.0 = Mod::Renamed(old_path, new_path);
                }
            }
            // No change
            _ => (),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Fact {
    DirEntriesMatch(Vec<(String, FileType)>),
    DoesntExist,
    Exists,
    FinalContents,
    // Then we can have one fact holding all the perms we need to check for?
    // c_int = AccessFlags
    HasDirPermission(c_int),
    HasPermission(c_int),
    NoDirPermission(c_int),
    NoPermission(c_int),
    Or(Box<Fact>, Box<Fact>),
    StartingContents(Vec<u8>),
    StatStructMatches(Stat),
}

#[derive(Clone, Eq, PartialEq)]
pub enum State {
    DoesntExist,
    Exists,
    None,
}

#[derive(Eq, PartialEq)]
pub struct FirstState(pub State);

impl FirstState {
    pub fn state(&self) -> State {
        self.0.clone()
    }

    pub fn update_based_on_syscall(&mut self, curr_file_path: &Path, syscall_event: SyscallEvent) {
        if self.0 == State::None {
            match syscall_event {
                SyscallEvent::Access(_, SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::Access(_, SyscallOutcome::Fail(SyscallFailure::PermissionDenied)) => {
                    // If you call access(R_OK) and the file doesn't exist, you will get ENOENT,
                    // and that will be a different kind of access event.
                    self.0 = State::Exists;
                }
                SyscallEvent::Access(_, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.0 = State::DoesntExist;
                }
                SyscallEvent::Access(_, SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!(
                        "updating first state struct, access failed because file already exists??"
                    );
                }
                SyscallEvent::ChildExec(_) => (),
                SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success) => {
                    self.0 = State::DoesntExist;
                }
                // Failed to create a file. Doesn't mean we know anything about whether it exists.
                SyscallEvent::Create(
                    OFlag::O_CREAT,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => (),
                SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Fail(failure)) => {
                    panic!("Failed to create for strange reason: {:?}", failure);
                }
                SyscallEvent::Create(OFlag::O_EXCL, SyscallOutcome::Success) => {
                    self.0 = State::DoesntExist;
                }
                SyscallEvent::Create(
                    OFlag::O_EXCL,
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists),
                ) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::Create(
                    OFlag::O_EXCL,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    panic!("Failed to create a file excl because file doesn't exist??");
                }
                SyscallEvent::Create(
                    OFlag::O_EXCL,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => (),
                SyscallEvent::Create(f, _) => panic!("Unexpected create flag: {:?}", f),
                SyscallEvent::DirectoryRead(
                    _,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    self.0 = State::DoesntExist;
                }
                SyscallEvent::DirectoryRead(_, _, SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::DirectoryRead(_, _, _) => (),
                SyscallEvent::Delete(SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::Delete(SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!("Failed to delete a file because it already exists??");
                }
                SyscallEvent::Delete(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::Delete(SyscallOutcome::Fail(SyscallFailure::PermissionDenied)) => (),
                SyscallEvent::Open(
                    OFlag::O_APPEND | OFlag::O_RDONLY,
                    _,
                    SyscallOutcome::Success,
                ) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::Open(OFlag::O_TRUNC, _, SyscallOutcome::Success) => (),
                SyscallEvent::Open(
                    OFlag::O_APPEND | OFlag::O_RDONLY,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    self.0 = State::DoesntExist;
                }
                SyscallEvent::Open(
                    OFlag::O_APPEND | OFlag::O_TRUNC,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::Open(OFlag::O_TRUNC, _, SyscallOutcome::Fail(fail)) => {
                    panic!("Failed to open trunc for strange reason: {:?}", fail)
                }
                SyscallEvent::Open(
                    OFlag::O_RDONLY,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::Open(
                    mode,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists),
                ) => {
                    panic!("Open for {:?} failed because file already exists??", mode)
                }
                SyscallEvent::Open(f, _, _) => panic!("Unexpected open flag: {:?}", f),
                SyscallEvent::Stat(_, SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::Stat(_, SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!("Failed to state because file already exists??");
                }
                SyscallEvent::Stat(_, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.0 = State::DoesntExist;
                }
                SyscallEvent::Stat(_, SyscallOutcome::Fail(SyscallFailure::PermissionDenied)) => (),
                SyscallEvent::Rename(old_path, new_path, SyscallOutcome::Success) => {
                    if *curr_file_path == old_path {
                        self.0 = State::Exists;
                    } else if *curr_file_path == new_path {
                        self.0 = State::DoesntExist;
                    }
                }
                SyscallEvent::Rename(
                    old_path,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    if *curr_file_path == old_path {
                        self.0 = State::DoesntExist;
                    }
                }
                SyscallEvent::Rename(_, _, _) => (),
                SyscallEvent::FailedExec(_) => (),
            }
        }
    }
}

pub fn no_mods_before_rename(file_name_list: Vec<SyscallEvent>) -> bool {
    let mut no_mods = true;
    for event in file_name_list {
        match event {
            SyscallEvent::Access(_, _) => (),
            SyscallEvent::Open(OFlag::O_RDONLY, _, _) => (),
            SyscallEvent::Stat(_, _) => (),
            SyscallEvent::Create(_, SyscallOutcome::Success)
            | SyscallEvent::Delete(SyscallOutcome::Success)
            | SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, SyscallOutcome::Success)
            | SyscallEvent::Rename(_, _, SyscallOutcome::Success) => {
                no_mods = false;
                break;
            }
            _ => (),
        }
    }
    no_mods
}
