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
    syscalls::{DirEvent, FileEvent, MyStatFs, Stat, SyscallFailure, SyscallOutcome, AccessMode},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Preconditions {
    dir: HashMap<PathBuf, HashSet<Fact>>,
    file: HashMap<PathBuf, HashSet<Fact>>,
}

impl Preconditions {
    pub fn new(
        dir: HashMap<PathBuf, HashSet<Fact>>,
        file: HashMap<PathBuf, HashSet<Fact>>,
    ) -> Preconditions {
        Preconditions { dir, file }
    }

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

impl Postconditions {
    pub fn new(
        dir: HashMap<Accessor, HashSet<Fact>>,
        file: HashMap<Accessor, HashSet<Fact>>,
    ) -> Postconditions {
        Postconditions { dir, file }
    }

    pub fn dir_postconditions(&self) -> HashMap<Accessor, HashSet<Fact>> {
        self.dir.clone()
    }

    pub fn file_postconditions(&self) -> HashMap<Accessor, HashSet<Fact>> {
        self.file.clone()
    }
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
            FileEvent::Open(
                AccessMode::Both | AccessMode::Write,
                _,
                _,
                SyscallOutcome::Success,
            ) => {
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
    Renamed(PathBuf, PathBuf),
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
                },
                DirEvent::Delete(outcome) => match outcome {
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        self.0 = State::DoesntExist;
                    }
                    SyscallOutcome::Success => {
                        self.0 = State::Exists;
                    }
                    _ => (),
                },
                DirEvent::Read(_, _, outcome) => match outcome {
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        self.0 = State::DoesntExist;
                    }
                    SyscallOutcome::Success => {
                        self.0 = State::Exists;
                    }
                    _ => (),
                },
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
                    _ => (),
                },
                DirEvent::Statfs(_, outcome) => match outcome {
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        self.0 = State::DoesntExist;
                    }
                    SyscallOutcome::Success => {
                        self.0 = State::Exists;
                    }
                    _ => (),
                },
            }
        }
    }

    pub fn update_based_on_file_event(&mut self, curr_file_path: &Path, file_event: FileEvent) {
        if self.0 == State::None {
            match file_event {
                FileEvent::Access(_, SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                FileEvent::FailedExec(_) => (),
                FileEvent::Open(_, _, _, SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                FileEvent::Access(_, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.0 = State::DoesntExist;
                }
                FileEvent::Access(_, SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!(
                        "updating first state struct, access failed because file already exists??"
                    );
                }
                FileEvent::Access(_, _) => (),
                FileEvent::ChildExec(_) => (),
                FileEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success) => {
                    self.0 = State::DoesntExist;
                }
                // Failed to create a file. Doesn't mean we know anything about whether it exists.
                FileEvent::Create(
                    OFlag::O_CREAT,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => (),
                // This probably means some path component doesn't exist.
                // But we don't know and the user doesn't know which one.
                // And linux won't tell us.
                // So it gives us zero info about the first state of this resource.
                FileEvent::Create(
                    OFlag::O_CREAT,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => (),
                FileEvent::Create(
                    OFlag::O_CREAT,
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists),
                ) => {
                    self.0 = State::Exists;
                }
                FileEvent::Create(OFlag::O_CREAT, SyscallOutcome::Fail(failure)) => {
                    panic!("Failed to create for strange reason: {:?}", failure);
                }
                FileEvent::Create(OFlag::O_EXCL, SyscallOutcome::Success) => {
                    self.0 = State::DoesntExist;
                }
                FileEvent::Create(
                    OFlag::O_EXCL,
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists),
                ) => {
                    self.0 = State::Exists;
                }
                FileEvent::Create(
                    OFlag::O_EXCL,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    panic!("Failed to create a file excl because file doesn't exist??");
                }
                FileEvent::Create(
                    OFlag::O_EXCL,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => (),
                FileEvent::Create(f, _) => panic!("Unexpected create flag: {:?}", f),
                FileEvent::Delete(SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                FileEvent::Delete(SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!("Failed to delete a file because it already exists??");
                }
                FileEvent::Delete(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.0 = State::Exists;
                }
                FileEvent::Delete(SyscallOutcome::Fail(_)) => (),
                FileEvent::Open(_, _, _, SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                FileEvent::Open(
                    _,
                    _,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    self.0 = State::DoesntExist;
                }
                FileEvent::Open(_, _, _, _) => (),
                FileEvent::FailedExec(_) => (),

                FileEvent::Rename(old_path, new_path, SyscallOutcome::Success) => {
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

pub fn dir_created_by_exec(
    dir_path: PathBuf,
    dir_preconds: HashMap<PathBuf, HashSet<Fact>>,
) -> bool {
    if let Some(fact_set) = dir_preconds.get(&dir_path) {
        fact_set.contains(&Fact::DoesntExist)
    } else {
        false
    }
}

// pub fn no_mods_before_file_rename(file_name_list: Vec<FileEvent>) -> bool {
//     let mut no_mods = true;
//     for event in file_name_list {
//         match event {
//             SyscallEvent::Access(_, _) => (),
//             //Not sure if O_RDONLY was used to specify Read access mode or
//             //None offset mode here
//             SyscallEvent::Open(AccessMode::Read, _, _, _) => (),
//             SyscallEvent::Stat(_, _) => (),
//             SyscallEvent::Create(_, SyscallOutcome::Success)
//             | SyscallEvent::Delete(SyscallOutcome::Success)
//             | SyscallEvent::Open(
//                 _,
//                 Some(OffsetMode::Append) | Some(OffsetMode::Trunc),
//                 _,
//                 SyscallOutcome::Success,
//             )
//             | SyscallEvent::Rename(_, _, SyscallOutcome::Success) => {
//                 no_mods = false;
//                 break;
//             }
//             _ => (),
//         }
//     }
//     no_mods
// }

pub fn update_file_posts_with_renamed_dirs(
    file_posts: HashMap<Accessor, HashSet<Fact>>,
    renamed_dirs: HashMap<PathBuf, PathBuf>,
) -> HashMap<Accessor, HashSet<Fact>> {
    let mut updated_file_postconds: HashMap<Accessor, HashSet<Fact>> = HashMap::new();

    for (accessor, fact_set) in file_posts {
        let old_path = accessor.path();
        let parent_dir = old_path.parent().unwrap();
        let parent_dir = PathBuf::from(parent_dir);
        if let Some(renamed_to_this_path) = renamed_dirs.get(&parent_dir) {
            let file_name = old_path.file_name().unwrap();
            let new_path = renamed_to_this_path.join(file_name);
            let new_accessor = if let Some(cmd) = accessor.hashed_command() {
                Accessor::ChildProc(cmd, new_path)
            } else {
                Accessor::CurrProc(new_path)
            };
            updated_file_postconds.insert(new_accessor, fact_set);
        } else {
            updated_file_postconds.insert(accessor, fact_set);
        }
    }

    updated_file_postconds
}

// pub fn no_mods_before_dir_rename(dir_list: Vec<DirEvent>) -> bool {
//     let mut no_mods = true;
//     for event in dir_list {
//         match event {
//             DirEvent::Create(_, SyscallOutcome::Success)
//             | DirEvent::Delete(SyscallOutcome::Success)
//             | DirEvent::Rename(_, _, SyscallOutcome::Success) => {
//                 no_mods = false;
//                 break;
//             }
//             _ => (),
//         }
//     }
//     no_mods
// }
