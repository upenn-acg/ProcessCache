use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    vec::Vec,
};

use libc::c_int;
use nix::fcntl::OFlag;
use serde::{Deserialize, Serialize};

use crate::{
    condition_generator::Accessor,
    syscalls::{DirEvent, FileEvent, MyStatFs, Stat, SyscallFailure, SyscallOutcome},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Preconditions {
    dir: HashMap<PathBuf, HashSet<Fact>>,
    file: HashMap<PathBuf, HashSet<Fact>>,
}

impl Preconditions {
    pub fn dir_preconditions(&self) -> HashMap<PathBuf, HashSet<Fact>> {
        self.dir.clone()
    }

    pub fn file_preconditions(&self) -> HashMap<PathBuf, HashSet<Fact>> {
        self.file.clone()
    }
}
// Postconditions are a little different. We need to know
// if the accessor was the child, so we can just link
// that file baby. No copyin' required.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Postconditions {
    dir: HashMap<Accessor, HashSet<Fact>>,
    file: HashMap<Accessor, HashSet<Fact>>,
}

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

    pub fn update_based_on_dir_event(&mut self, dir_event: DirEvent) {
        match dir_event {
            DirEvent::Create(_, SyscallOutcome::Success) => {
                self.0 = Mod::Created;
            }
            DirEvent::Delete(SyscallOutcome::Success) => {
                self.0 = Mod::Deleted;
            }
            DirEvent::Rename(old_path, new_path, outcome) => {
                if outcome == SyscallOutcome::Success {
                    self.0 = Mod::Renamed(old_path, new_path);
                }
            }
            // No change
            _ => (),
        }
    }

    pub fn update_based_on_file_event(&mut self, file_event: FileEvent) {
        match file_event {
            FileEvent::Create(_, SyscallOutcome::Success) => {
                self.0 = Mod::Created;
            }
            FileEvent::Delete(SyscallOutcome::Success) => {
                self.0 = Mod::Deleted;
            }
            FileEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, SyscallOutcome::Success) => {
                self.0 = Mod::Modified;
            }
            FileEvent::Rename(old_path, new_path, outcome) => {
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
    HasDirPermission(c_int, Option<PathBuf>), // Optionally supply a root dir, otherwise assume parent dir
    HasPermission(c_int),
    InputFilesMatch,
    Mtime(i64),
    NoDirPermission(c_int, Option<PathBuf>),
    NoPermission(c_int),
    Or(Box<Fact>, Box<Fact>),
    StartingContents(Vec<u8>),
    StatFsStructMatches(MyStatFs),
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

    pub fn update_based_on_dir_event(&mut self, curr_file_path: &Path, dir_event: DirEvent) {
        if self.0 == State::None {
            match dir_event {
                DirEvent::ChildExec(_) => (),
                DirEvent::Create(_, outcome) => match outcome {
                    SyscallOutcome::Success => {
                        self.0 = State::DoesntExist;
                    }
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                        self.0 = State::Exists;
                    }
                    _ => (),
                }
                DirEvent::Delete(_) => todo!(),
                DirEvent::Read(_, _, outcome) => match outcome {
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        self.0 = State::DoesntExist;
                    }
                    SyscallOutcome::Success =>  {
                        self.0 = State::Exists;
                    }
                    _ => (),
                }
                DirEvent::Rename(old_path, new_path, outcome) => match outcome {
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        if *curr_file_path == old_path {
                            self.0 = State::DoesntExist;
                        }
                    }
                    SyscallOutcome::Success => {
                        if *curr_file_path == old_path {
                            self.0 = State::Exists;
                        } else if *curr_file_path == new_path {
                            self.0 = State::DoesntExist;
                        }
                    }
                    _ => ()
                }
                DirEvent::Statfs(_, outcome) => match outcome {
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        self.0 = State::DoesntExist;
                    }
                    SyscallOutcome::Success => {
                        self.0 = State::Exists;
                    }
                    _ => ()
                }
            }
        }
    }

    pub fn update_based_on_file_event(&mut self, curr_file_path: &Path, file_event: FileEvent) {
        if self.0 == State::None {
            match file_event {
                FileEvent::Access(_, SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::DirectoryRead(_, _, _) => (),
                SyscallEvent::FailedExec(_) => (),
                SyscallEvent::Open(_, _, _, SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                SyscallEvent::Open(
                    _,
                    _,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    self.0 = State::DoesntExist;
                }
                SyscallEvent::Open(_, _, _, _) => (),
                SyscallEvent::Rename(old_path, new_path, SyscallOutcome::Success) => {
                    if *curr_file_path == old_path {
                        self.0 = State::Exists;
                    } else if *curr_file_path == new_path {
                        self.0 = State::DoesntExist;
                    }
                }
                FileEvent::Rename(
                    old_path,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    if *curr_file_path == old_path {
                        self.0 = State::DoesntExist;
                    }
                }
                FileEvent::Rename(_, _, _) => (),
                FileEvent::Stat(_, SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                FileEvent::Stat(_, SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!("Failed to state because file already exists??");
                }
                FileEvent::Stat(_, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.0 = State::DoesntExist;
                }
                FileEvent::Stat(_, SyscallOutcome::Fail(_)) => (),
            }
        }
    }
}

pub fn no_mods_before_file_rename(file_name_list: Vec<FileEvent>) -> bool {
    let mut no_mods = true;
    for event in file_name_list {
        match event {
            SyscallEvent::Access(_, _) => (),
            //Not sure if O_RDONLY was used to specify Read access mode or
            //None offset mode here
            SyscallEvent::Open(AccessMode::Read, _, _, _) => (),
            SyscallEvent::Stat(_, _) => (),
            SyscallEvent::Create(_, SyscallOutcome::Success)
            | SyscallEvent::Delete(SyscallOutcome::Success)
            | SyscallEvent::Open(
                _,
                Some(OffsetMode::Append) | Some(OffsetMode::Trunc),
                _,
                SyscallOutcome::Success,
            )
            | SyscallEvent::Rename(_, _, SyscallOutcome::Success) => {
                no_mods = false;
                break;
            }
            _ => (),
        }
    }
    no_mods
}

pub fn no_mods_before_dir_rename(dir_list: Vec<DirEvent>) -> bool {
    todo!();
}