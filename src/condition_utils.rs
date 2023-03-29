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
    syscalls::{AccessMode, DirEvent, FileEvent, MyStatFs, Stat, SyscallFailure, SyscallOutcome},
};

// Struct to house preconditions of an execution.
// A set of preconditions is a map:
// Full path to the resource --> set of precondition facts for the resource.
// We separate directory preconditions and file preconditions and handle them
// separately.
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

// Struct to house postconditions of an execution.
// A set of postconditions is a map, but it is a little different from
// preconditions.
// The key is:
// pub enum Accessor {
//     // String = hash of the child's command.
//     // We know hashing is slow, let's do it one time,
//     // and just pass the results around.
//     ChildProc(String, PathBuf),
//     CurrProc(PathBuf),
// }
// We need the Accessor enum so that we know when we can just hardlink
// files (ex: hardlink a child's output file from the child's cache subdir
// to the parent's cache, like this
// /cache/child/foo.txt --> /cache/parent/child/foo.txt)
// So the map is:
// Accessor --> set of postconditions facts for the resource.
// We separate directory postconditions and file postconditions and handle them
// separately.
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

// Handy enum for representing the different types of files we handle:
// Directories, files, and symlinks.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum FileType {
    Dir,
    File,
    Symlink,
}

// In the precondition generator, we use multiple pieces of state
// to iteratively generate the preconditions (in a state machine type fashion),
// for each resource:
// - the first state (enum State)
// - the current state of the resource (i.e. the last modification) (enum Mod)
// - whether the resource has been deleted (useful for rename)

// Mod = Modification.
// This is the last modification (current state) of the resource.
// It starts as None and is updated as events on a resource are processed.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Mod {
    Created,
    Deleted,
    Modified,
    Renamed(PathBuf, PathBuf),
    None,
}

// The struct that wraps the Mod enum so we can make updates to it easily.
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

// A catch-all for facts that can be true about a file or directory,
// in either the context of preconditions or postconditions.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Fact {
    // The directory has the same entries.
    DirEntriesMatch(Vec<(String, FileType)>),
    // Resource doesn't exist.
    DoesntExist,
    // Resource exists.
    Exists,
    // Resource's postconditions depend upon its final contents after
    // it has been modified during execution.
    FinalContents,
    // c_int = nix::unistd::AccessFlags
    // Has directory permissions.
    // Optionally supply a root dir, otherwise assume parent dir of resource.
    HasDirPermission(c_int, Option<PathBuf>),
    // c_int = nix::unistd::AccessFlags
    // Has file permissions.
    HasPermission(c_int),
    // Cached and current input files match based on diffing.
    InputFileDiffsMatch,
    // Cached and current input files match based on mtime.
    Mtime(i64),
    // c_int = nix::unistd::AccessFlags
    // Does NOT have directory permissions.
    // Optionally supply a root dir, otherwise assume parent dir of resource.
    NoDirPermission(c_int, Option<PathBuf>),
    // c_int = nix::unistd::AccessFlags
    // Does NOT have file permissions
    NoPermission(c_int),
    // One or both of these facts do NOT hold.
    // i.e. they can't both hold. Used for permissions checking.
    Or(Box<Fact>, Box<Fact>),
    // This resource has been renamed.
    // (Old full path, new full path)
    Renamed(PathBuf, PathBuf),
    // Hash of contents of cached input file and current input file match.
    // It is an option because if it is a read only file we will delay
    // generating the hash (moving it off the critical path).
    InputFileHashesMatch(Option<Vec<u8>>),
    // The statfs struct returned for the current file system matches
    // the cached statfs struct for this resource.
    StatFsStructMatches(MyStatFs),
    // The stat struct returned for the current file matches the cached
    // state struct for this resource.
    StatStructMatches(Stat),
}

// This is the state (well, the first state, when used) of the resource.
// It starts as None and is updated as events on a resource are processed.
#[derive(Clone, Eq, PartialEq)]
pub enum State {
    DoesntExist,
    Exists,
    None,
}

// The struct that wraps the State enum so we can make updates to it easily.
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
                    self.0 = State::DoesntExist;
                }
                FileEvent::Delete(SyscallOutcome::Fail(_)) => (),
                FileEvent::FailedExec(_) => (),
                FileEvent::Open(_, _, _, SyscallOutcome::Success) => {
                    self.0 = State::Exists;
                }
                FileEvent::Open(_, _, _, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.0 = State::DoesntExist;
                }
                FileEvent::Open(_, _, _, _) => (),
                FileEvent::Rename(old_path, new_path, SyscallOutcome::Success) => {
                    if *curr_file_path == old_path {
                        self.0 = State::Exists;
                    } else if *curr_file_path == new_path {
                        // TODO: The new path could have already existed. If they use NOREPLACE,
                        // and it fails for EEXIST we know that new path already existed.
                        // Otherwise, we don't really know it's true state, and idk how to handle
                        // that lol. Haven't seen it in practice yet.
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

// Helper function that returns true if the directory
// was indeed created by this exec.
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

// Helper function that returns true if a set of preconditions
// already contains a Fact::StatStructMatches fact
// A program may call stat more than once on a resource (and trust me,
// they do, all the time, for some reason...) and we only want to record
// the first one in the preconditions, and not overwrite the first one
// with subsequent calls.
pub fn preconditions_contain_stat_fact(fact_set: HashSet<Fact>) -> bool {
    for fact in fact_set {
        if let Fact::StatStructMatches(_) = fact {
            return true;
        }
    }
    false
}

// A process could rename a directory, changing the final full
// paths of other accessed resources in the process. So we must update
// their paths if appropriate.
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
