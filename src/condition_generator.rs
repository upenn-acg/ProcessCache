use nix::{
    fcntl::OFlag,
    unistd::{access, AccessFlags, Pid},
};
use serde::{Serialize, Deserialize};

use std::{
    collections::{HashMap, HashSet},
    fs::{self, read_dir},
    iter::FromIterator,
    os::unix::prelude::MetadataExt,
    path::PathBuf,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

use crate::{syscalls::{CheckMechanism, MyStat, SyscallEvent, SyscallFailure, SyscallOutcome}, cache_utils::Command, condition_utils::{Postconditions, Preconditions}};
use crate::{cache_utils::generate_hash, condition_utils::FileType};
use crate::{
    condition_utils::{no_mods_before_rename, Fact, FirstState, LastMod, Mod, State},
    syscalls::Stat,
};

const DONT_HASH_FILES: bool = false;

// Who done the accessin'?
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Accessor {
    ChildProc(Command, PathBuf),
    CurrProc(PathBuf),
}

// Actual accesses to the file system performed by
// a successful execution.
// Full path mapped to
// TODO: Handle stderr and stdout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecFileEvents(pub HashMap<Accessor, Vec<SyscallEvent>>);

impl ExecFileEvents {
    pub fn new(map: HashMap<Accessor, Vec<SyscallEvent>>) -> ExecFileEvents {
        ExecFileEvents(map)
    }

    // Add new access to the struct.
    pub fn add_new_file_event(
        &mut self,
        caller_pid: Pid,
        file_event: SyscallEvent,
        full_path: PathBuf,
    ) {
        let s = span!(Level::INFO, stringify!(add_new_file_event), pid=?caller_pid);
        let _ = s.enter();

        let fpath = full_path.clone().into_os_string().into_string().unwrap();
        if fpath.contains("tmp") {
            return;
        }

        s.in_scope(|| "in add_new_file_event");
        // First case, we already saw this file and now we are adding another event to it.
        if let Some(event_list) = self.0.get_mut(&Accessor::CurrProc(full_path.clone())) {
            s.in_scope(|| "adding to existing event list");
            event_list.push(file_event);
        } else {
            let event_list = vec![file_event];
            s.in_scope(|| "adding new event list");
            self.0.insert(Accessor::CurrProc(full_path), event_list);
        }
    }

    pub fn add_new_fork_exec(&mut self, child_pid: Pid) {
        for (_, list) in self.0.iter_mut() {
            list.push(SyscallEvent::ChildExec(child_pid));
        }
    }

    pub fn events(&self) -> HashMap<Accessor, Vec<SyscallEvent>> {
        self.0.clone()
    }

    pub fn update_events(&mut self, new_events: HashMap<Accessor, Vec<SyscallEvent>>) {
        self.0 = new_events;
    }
}

fn check_fact_holds(fact: Fact, path_name: PathBuf, pid: Pid) -> bool {
    debug!("Checking fact: {:?} for path: {:?}", fact, path_name);
    if path_name.starts_with("/proc") {
        true
    } else {
        match fact {
            Fact::DirEntriesMatch(entries) => {
                let mut curr_dir_entries = HashSet::new();

                let curr_entries = read_dir(path_name).unwrap();
                for entry in curr_entries {
                    let entry = entry.unwrap();
                    let file_name = entry.file_name();
                    let file_type = entry.file_type().unwrap();

                    let file_type = if file_type.is_dir() {
                        FileType::Dir
                    } else if file_type.is_file() {
                        FileType::File
                    } else if file_type.is_symlink() {
                        FileType::Symlink
                    } else {
                        panic!("What kind of file is this??");
                    };

                    curr_dir_entries.insert((file_name.into_string().unwrap(), file_type));
                }

                let mut old_set = HashSet::from_iter(entries);
                let up_one = String::from("..");
                let curr = String::from(".");
                let stdout_file = format!("stdout_{:?}", pid.as_raw());
                old_set.remove(&(up_one, FileType::Dir));
                old_set.remove(&(curr, FileType::Dir));
                old_set.remove(&(stdout_file, FileType::File));
                // let diff = old_set.difference(&curr_dir_entries);
                // let other_diff = curr_dir_entries.difference(&old_set);
                // println!("Diff: {:?}", diff);
                // println!("Other diff: {:?}", other_diff);

                old_set == curr_dir_entries
            }
            Fact::DoesntExist => !path_name.exists(),
            Fact::Exists => path_name.exists(),
            Fact::FinalContents => panic!("Final contents should not be a precondition!!"),
            Fact::InputFilesMatch => true,
            Fact::HasDirPermission(flags) => {
                debug!("Dir perm flags: {:?}", flags);
                let parent_dir = path_name.parent().unwrap();
                access(parent_dir, AccessFlags::from_bits(flags).unwrap()).is_ok()
            }
            Fact::Mtime(old_mtime) => {
                debug!("Old mtime: {:?}", old_mtime);
                let curr_metadata = fs::metadata(&path_name).unwrap();
                let curr_mtime = curr_metadata.mtime();
                debug!("New mtime: {:?}", curr_mtime);
                curr_mtime == old_mtime
            }
            Fact::NoDirPermission(flags) => {
                let parent_dir = path_name.parent().unwrap();
                debug!("Dir no perm flags: {:?}", flags);
                access(parent_dir, AccessFlags::from_bits(flags).unwrap()).is_err()
            }
            Fact::HasPermission(flags) => {
                debug!("Perm flags: {:?}", flags);
                access(&path_name, AccessFlags::from_bits(flags).unwrap()).is_ok()
                // if path_name.as_os_str() == "/lib/x86_64-linux-gnu/libdl.so.2" {
                //     true
                // } else {
                //     access(&path_name, AccessFlags::from_bits(flags).unwrap()).is_ok()
                // }
            }
            Fact::NoPermission(flags) => {
                debug!("No perm flags: {:?}", flags);
                access(&path_name, AccessFlags::from_bits(flags).unwrap()).is_ok()
            }
            Fact::Or(first, second) => {
                // This should be only when we need to check perms
                // of the dir and perms of the file.
                // Example is open append failing for perms:
                // write access OR exec dir access is missing
                let first_perms_hold = match *first {
                    Fact::HasDirPermission(_)
                    | Fact::HasPermission(_)
                    | Fact::NoDirPermission(_)
                    | Fact::NoPermission(_) => check_fact_holds(*first, path_name.clone(), pid),
                    e => panic!("Unexpected Fact in Fact::Or: {:?}", e),
                };
                let second_perms_hold = match *second {
                    Fact::HasDirPermission(_)
                    | Fact::HasPermission(_)
                    | Fact::NoDirPermission(_)
                    | Fact::NoPermission(_) => check_fact_holds(*second, path_name, pid),
                    e => panic!("Unexpected Fact in Fact::Or: {:?}", e),
                };

                first_perms_hold || second_perms_hold
            }
            Fact::StartingContents(old_hash) => {
                // Getdents: First the process will open the dir for reading,
                // but we don't handle checking this stuff here, we handle it
                // when they call getdents.
                if !old_hash.is_empty() {
                    let new_hash = generate_hash(path_name);
                    old_hash == new_hash
                } else {
                    true
                }
            }
            Fact::StatStructMatches(old_stat) => {
                // let metadata = fs::metadata(&path_name).unwrap();
                // let metadata_result = fs::metadata(&path_name);
                let (old_stat, new_metadata) = match old_stat {
                    Stat::Stat(stat) => {
                        let metadata = fs::metadata(&path_name).unwrap();
                        (stat, metadata)
                    }
                    Stat::Lstat(stat) => {
                        let symlink_metadata = fs::symlink_metadata(&path_name).unwrap();
                        (stat, symlink_metadata)
                    }
                };

                let new_stat = MyStat {
                    st_dev: new_metadata.dev(),
                    st_ino: new_metadata.ino(),
                    st_nlink: new_metadata.nlink(),
                    st_mode: new_metadata.mode(),
                    st_uid: new_metadata.uid(),
                    st_gid: new_metadata.gid(),
                    st_rdev: new_metadata.rdev(),
                    // st_size: new_metadata.size() as i64,
                    st_blksize: new_metadata.blksize() as i64,
                    st_blocks: new_metadata.blocks() as i64,
                };
                old_stat == new_stat
            }
        }
    }
}

// TODO: check env vars and starting cwd
pub fn check_preconditions(conditions: HashMap<PathBuf, HashSet<Fact>>, pid: Pid) -> bool {
    for (path_name, fact_set) in conditions {
        for fact in fact_set {
            if !check_fact_holds(fact.clone(), path_name.clone(), pid) {
                debug!("Fact that doesn't hold: {:?}, path: {:?}", fact, path_name);
                return false;
            }
        }
    }
    true
}

// Directory Preconditions (For now, just cwd), File Preconditions
// Takes in all the events for ONE RESOURCE and generates its preconditions.
// TODO: when we do the preconditions checking, take the FIRST stat only.
pub fn generate_preconditions(exec_file_events: ExecFileEvents) -> Preconditions {
    let sys_span = span!(Level::INFO, "generate_preconditions");
    let _ = sys_span.enter();
    let mut curr_file_preconditions: HashMap<PathBuf, HashSet<Fact>> = HashMap::new();
    for accessor in exec_file_events.events().keys() {
        // For preconditions, I am not concerned with with who accessed.
        let path = match accessor {
            Accessor::ChildProc(_, full_path) => full_path,
            Accessor::CurrProc(full_path) => full_path,
        };
        curr_file_preconditions.insert(path.to_path_buf(), HashSet::new());
    }

    for (accessor, event_list) in exec_file_events.events() {
        let full_path = match accessor {
            Accessor::ChildProc(_, path) => path,
            Accessor::CurrProc(path) => path,
        };
        
        let mut first_state_struct = FirstState(State::None);
        let mut curr_state_struct = LastMod(Mod::None);
        let mut has_been_deleted = false;

        // println!("Full path: {:?}", full_path);
        // println!("Events:");
        // for event in event_list.clone() {
        //     println!("{:?}", event);
        // }
        // let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

        for event in event_list {
            let first_state = first_state_struct.state();
            let curr_state = curr_state_struct.state();

            match (event.clone(), first_state, curr_state, has_been_deleted) {
                (_, _, Mod::None, true) => {
                    panic!("Last mod was none but was deleted is true??");
                }
                (_, State::Exists, Mod::Created, false) => {
                    panic!("Last mod was created, but was deleted is false, and file existed at start??");
                }
                (_, _, Mod::Deleted, false) => {
                    panic!("Last mod was deleted, but was deleted is false??, path: {:?}", full_path);
                }

                (SyscallEvent::Access(_, _), State::DoesntExist, _, _) => {
                    // Didn't exist, was created, this access depends on a file that was created during execution,
                    // does not contribute to preconditions.
                }
                // Your access depends on a file I don't know nothing about.
                (SyscallEvent::Access(_, _), State::Exists, _, true) => (),
                // It existed, it hasn't been deleted, these priveleges depend on a file from
                // BEFORE the execution :O
                (SyscallEvent::Access(flags, outcome), State::Exists, _, false) => {
                    // It existed, it hasn't been deleted, these priveleges depend on a file from
                    // BEFORE the execution :O
                    match outcome {
                        SyscallOutcome::Success => {
                            let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                            curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits()));
                            let flag_set = AccessFlags::from_bits(flags).unwrap();

                            if flag_set.contains(AccessFlags::F_OK) {
                                curr_set.insert(Fact::Exists);
                            } else {
                                curr_set.insert(Fact::HasPermission(flags));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                            curr_set.insert(Fact::NoPermission(flags));
                        }
                        o => panic!("Unexpected access syscall failure: {:?}", o),
                    }
                }
                (SyscallEvent::Access(_, _), State::None, Mod::Created, _) => {
                    panic!("No first state but last mod was created??");
                }
                (SyscallEvent::Access(_, _), State::None, Mod::Deleted, _) => {
                    panic!("No first state but last mod was deleted??");
                }
                (SyscallEvent::Access(_, _), State::None, Mod::Modified, _) => {
                    panic!("No first state but last mod was modified??");
                }
                (SyscallEvent::Access(_, _), State::None, Mod::Renamed(_,_), _) => {
                    panic!("No first state but last mod was renamed??");
                }
                (SyscallEvent::Access(flags, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits()));
                            let flag_set = AccessFlags::from_bits(flags).unwrap();
                            if flag_set.contains(AccessFlags::F_OK) {
                                curr_set.insert(Fact::Exists);
                            } else {
                                curr_set.insert(Fact::HasPermission(flags));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            // Either we don't have exec access to the dir
                            // Or we don't have these perms on this file
                            curr_set.insert(Fact::Or(Box::new(Fact::NoDirPermission((AccessFlags::X_OK).bits())), Box::new(Fact::NoPermission(flags))));
                        }
                        o => panic!("Unexpected access syscall failure: {:?}", o),
                    }
                }
                (SyscallEvent::ChildExec(_), _, _, _) => (),
                (SyscallEvent::Create(_, _), State::DoesntExist, Mod::Created, _) => (),
                (SyscallEvent::Create(_, _), State::DoesntExist, Mod::Deleted, true) => (),

                (SyscallEvent::Create(_, _), State::DoesntExist, Mod::Modified, true) => (),
                (SyscallEvent::Create(_, _), State::DoesntExist, Mod::Modified, false) => (),
                (SyscallEvent::Create(_, _), State::DoesntExist, Mod::Renamed(_, _), _) => (),
                (SyscallEvent::Create(mode, outcome), State::DoesntExist, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::DoesntExist);
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::HasDirPermission((flags).bits()));

                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            // Don't need OR because both facts are about the dir,
                            // so we can save an access call!
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::HasDirPermission((flags).bits()));
                        }
                        f => panic!("Unexpected create {:?} file failure, didn't exist at start no other changes: {:?}", mode, f),
                    }
                }

                (SyscallEvent::Create(_, _), State::Exists, Mod::Created, true) => (),
                (SyscallEvent::Create(_, _), State::Exists, Mod::Deleted, true) => (),
                (SyscallEvent::Create(_, _), State::Exists, Mod::Modified, true) => (),
                (SyscallEvent::Create(_, _), State::Exists, Mod::Modified, false) => (),
                (SyscallEvent::Create(_, _), State::Exists, Mod::Renamed(_, _), _) => (),
                (SyscallEvent::Create(_, _), State::Exists, Mod::None, false) => (),
                (SyscallEvent::Create(_, _), State::None, Mod::Created, _) => {
                    panic!("First state none but last mod created??");
                }
                (SyscallEvent::Create(_, _), State::None, Mod::Deleted, true) => {
                    panic!("First state none but last mod deleted??");
                }
                (SyscallEvent::Create(_, _), State::None, Mod::Modified, _) => {
                    panic!("First state none but last mod modified??");
                }
                (SyscallEvent::Create(_, _), State::None, Mod::Renamed(_, _), _) => {
                    panic!("First state none but last mod renamed??");
                }
                (SyscallEvent::Create(OFlag::O_CREAT, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::DoesntExist);
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::HasDirPermission((flags).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            // Both facts are about the dir so we can just make
                            // one access call.
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission((flags).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => (),
                        f => panic!("Unexpected create file failure, no state yet: {:?}", f),
                    }
                }
                (SyscallEvent::Create(OFlag::O_EXCL, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::DoesntExist);
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::HasDirPermission((flags).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission((flags).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            curr_set.insert(Fact::Exists);
                        }
                        f => panic!("Unexpected create file failure, no state yet: {:?}", f),
                    }
                }

                (SyscallEvent::Create(f, _), _, _, _) => panic!("Unexpected create flag: {:?}", f),
                (SyscallEvent::DirectoryRead(full_path, entries, outcome), _, _, _) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::DirEntriesMatch(entries));
                        }
                        _ => panic!("Unexpected outcome for directory read! {:?}", outcome),
                    }
                }
                (SyscallEvent::Delete(_), State::DoesntExist, Mod::Created, true) => (),
                (SyscallEvent::Delete(outcome), State::DoesntExist, Mod::Created, false) => {
                    if outcome == SyscallOutcome::Success {
                        has_been_deleted = true;
                    }
                }
                (SyscallEvent::Delete(_), State::DoesntExist, Mod::Deleted, true) => (),
                (SyscallEvent::Delete(_), State::DoesntExist, Mod::Modified, true) => (),
                // It didn't exist, was created, was modified, we might be deleting it now.
                (SyscallEvent::Delete(outcome), State::DoesntExist, Mod::Modified, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, was created, last mod modified, no delete yet: {:?}", f),
                    }
                }
                (SyscallEvent::Delete(outcome), State::DoesntExist, Mod::Renamed(_, new_path), _) => {
                    // old path? didnt exist, created, renamed. now trying to delete. won't succeed it doesnt exist anymore.
                    // newpath? didn't exist, rename made it exist, now it might get deleted.
                    match outcome {
                        SyscallOutcome::Success => {
                            if full_path == *new_path {
                                has_been_deleted = true;
                            }
                        }
                        f => panic!("Delete failed for unexpected reason, was created, last mod modified, no delete yet: {:?}", f),
                    }
                }
                (SyscallEvent::Delete(outcome), State::DoesntExist, Mod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, was created, last mod modified, no delete yet: {:?}", f),
                    }
                }
                (SyscallEvent::Delete(_), State::Exists, Mod::Created, true) => (),
                (SyscallEvent::Delete(_), State::Exists, Mod::Deleted, true) => (),
                (SyscallEvent::Delete(_), State::Exists, Mod::Modified, true) => (),
                (SyscallEvent::Delete(outcome), State::Exists, Mod::Modified, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, exists, last mod modified, no delete yet: {:?}", f),
                    }
                }
                (SyscallEvent::Delete(_), State::Exists, Mod::Renamed(_,_), true) => (),
                (SyscallEvent::Delete(outcome), State::Exists, Mod::Renamed(_, _), false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, exists, last mod renamed, no delete yet: {:?}", f),
                    }
                }
                (SyscallEvent::Delete(outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::HasDirPermission((flags).bits()));
                            has_been_deleted = true;
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission((flags).bits()));
                        }
                        f => panic!("Delete failed for unexpected reason, exists, no mods: {:?}", f),
                    }
                }
                (SyscallEvent::Delete(_), State::None, Mod::Created, _) => {
                    panic!("First state was none but last mod was created??");
                }
                (SyscallEvent::Delete(_), State::None, Mod::Deleted, _) => {
                    panic!("First state was none but last mod was deleted??");
                }
                // None state can be because TRUNC
                (SyscallEvent::Delete(_), State::None, Mod::Modified, true) => (),
                (SyscallEvent::Delete(outcome), State::None, Mod::Modified, false) => {
                    if outcome == SyscallOutcome::Success {
                        has_been_deleted = true;
                    }
                }
                (SyscallEvent::Delete(_), State::None, Mod::Renamed(_,_), _) => {
                    panic!("First state was none but last mod was renamed??");
                }
                (SyscallEvent::Delete(outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Exists);
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::HasDirPermission((flags).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission((flags).bits()));
                        }
                        f => panic!("Unexpected failure from delete event: {:?}", f),
                    }
                }
                (SyscallEvent::FailedExec(failure), _, _, _) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match failure {
                        SyscallFailure::FileDoesntExist => {
                            curr_set.insert(Fact::DoesntExist);
                        }
                        SyscallFailure::PermissionDenied => {
                            curr_set.insert(Fact::NoDirPermission((AccessFlags::X_OK).bits()));
                        }
                        _ => panic!("Unexpected failure from execve!: {:?}", failure),
                    }
                }
                (
                    SyscallEvent::Open(_,  _,outcome),
                    State::DoesntExist,
                    Mod::Created,
                    true,
                ) => {
                    // It didn't exist, was created, was deleted, was created. Oof.
                    // We already know x and w access, and the contents don't depend on file at the start.
                    // fail: already exists? makes no sense. doesn't exist? makes no sense. permission denied? makes no sense.
                    if let SyscallOutcome::Fail(f) = outcome {
                        panic!(
                            "Open append failed for strange reason, last mod created: {:?}",
                            f
                        );
                    }
                }

                (SyscallEvent::Open(_,  _,_), State::DoesntExist, Mod::Created, false) => {
                    // Created, so not contents. not exists. we made the file in the exec so perms depend
                    // on that. and we already know x dir because we created the file at some point.
                    // So this just gives us nothing. (append, read, or trunc)
                }

                (SyscallEvent::Open(_, _,_), State::DoesntExist, Mod::Deleted, true) => {
                    // We created it. We deleted it. So we already know x dir. The perms depend on making the file during the execution.
                    // Same with contents.(append, read, or trunc)
                }
                (SyscallEvent::Open(_,  _,_), State::DoesntExist, Mod::Modified, _) => {
                    // Doesn't exist. Created, modified, maybe deleted and the whole process repeated.
                }
                // TODO: fix this case, think about bar in the case of rename(foo, bar). what if we then append to bar?
                (SyscallEvent::Open(OFlag::O_APPEND, optional_check_mechanism, outcome), State::DoesntExist, Mod::Renamed(old_path, new_path), false) => {
                    if full_path == *new_path {
                        let old_path_preconds = curr_file_preconditions.get_mut(old_path).unwrap();

                        match outcome {
                            SyscallOutcome::Success => {
                                if let Some(check_mechanism) = optional_check_mechanism {
                                    match check_mechanism {
                                        CheckMechanism::DiffFiles => {
                                            old_path_preconds.insert(Fact::InputFilesMatch);
                                        }
                                        CheckMechanism::Hash(hash) => {
                                            let hash = if DONT_HASH_FILES {
                                                Vec::new()
                                            } else {
                                                hash
                                            };
                                            // This precondition needs to be added to the old path's preconds.
                                            old_path_preconds.insert(Fact::StartingContents(hash));
                                        }
                                        CheckMechanism::Mtime(mtime) => {
                                            old_path_preconds.insert(Fact::Mtime(mtime));
                                        }
                                    }
                                }

                                old_path_preconds.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                // This precondition needs to be added to the old path's precodns.
                                old_path_preconds.insert(Fact::NoPermission((AccessFlags::W_OK).bits()));
                            }
                            _ => (),
                        }
                    }
                }
                (SyscallEvent::Open(OFlag::O_APPEND, optional_check_mech, outcome), State::DoesntExist, Mod::Renamed(old_path, new_path), true) => {
                    if full_path == *new_path {
                        match outcome {
                            SyscallOutcome::Success => {
                                let old_path_preconds = curr_file_preconditions.get_mut(old_path).unwrap();
                                if let Some(check_mech) = optional_check_mech {
                                    match check_mech {
                                        CheckMechanism::DiffFiles => {
                                            old_path_preconds.insert(Fact::InputFilesMatch);
                                        }
                                        CheckMechanism::Hash(hash) => {
                                            let hash = if DONT_HASH_FILES {
                                                Vec::new()
                                            } else {
                                                hash
                                            };
                                            old_path_preconds.insert(Fact::StartingContents(hash));
                                        }
                                        CheckMechanism::Mtime(mtime) => {
                                            old_path_preconds.insert(Fact::Mtime(mtime));
                                        }
                                    }
                                }

                                old_path_preconds.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                let old_path_preconds = curr_file_preconditions.get_mut(old_path).unwrap();
                                old_path_preconds.insert(Fact::NoPermission((AccessFlags::W_OK).bits()));
                            }
                            _ => (),
                        }
                    }
                }

                (SyscallEvent::Open(OFlag::O_TRUNC, _, outcome), State::DoesntExist, Mod::Renamed(old_path, new_path), _) => {
                    if full_path == *new_path {
                        match outcome {
                            SyscallOutcome::Success => {
                                let old_path_preconds = curr_file_preconditions.get_mut(old_path).unwrap();
                                old_path_preconds.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                let old_path_preconds = curr_file_preconditions.get_mut(old_path).unwrap();
                                old_path_preconds.insert(Fact::NoPermission((AccessFlags::W_OK).bits()));
                            }
                            _ => (),
                        }
                    }
                }
                (SyscallEvent::Open(_, _, outcome), State::DoesntExist, Mod::None, false) => {
                    // We know this doesn't exist, we know we haven't created it.
                    // This will just fail.
                    if outcome != SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) {
                        panic!("Unexpected outcome open event, doesn't exist, no mods: {:?}", outcome);
                    }
                }

                (SyscallEvent::Open(_, _, _), State::Exists, Mod::Created, true) => {
                    // It existed, then it was deleted, then created. This open depends on
                    // contents that are created during the execution.
                }

                // This is just going to say "file doesn't exist".
                // Or the error won't make sense or it succeeds which also makes no sense.
                (SyscallEvent::Open(_, _,  _), State::Exists, Mod::Deleted, true) => (),
                // Ditto - ish
                (SyscallEvent::Open(_,  _,_), State::Exists, Mod::Modified, true) => (),
                (SyscallEvent::Open(_,  _,_), State::Exists, Mod::Modified, false) => (),
                (SyscallEvent::Open(_, _, _), State::Exists, Mod::Renamed(_, _), true) => (),
                // First state exists means this is the old path, which doesn't exist anymore, so this won't succeed and doesn't change the preconditions.
                (SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_RDONLY | OFlag::O_TRUNC, _, _), State::Exists, Mod::Renamed(_, _), false) => (),
                (SyscallEvent::Open(OFlag::O_APPEND, optional_check_mech, outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            if let Some(check_mech) = optional_check_mech {
                                match check_mech {
                                    CheckMechanism::DiffFiles => {
                                        curr_set.insert(Fact::InputFilesMatch);
                                    }
                                    CheckMechanism::Hash(hash) => {
                                        let hash = if DONT_HASH_FILES {
                                            Vec::new()
                                        } else {
                                            hash
                                        };
                                        curr_set.insert(Fact::StartingContents(hash));
                                    }
                                    CheckMechanism::Mtime(mtime) => {
                                        curr_set.insert(Fact::Mtime(mtime));
                                    }
                                }
                            }

                            curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits()));
                            curr_set.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::NoPermission((AccessFlags::W_OK).bits()));
                        }
                        f => panic!("Unexpected open append failure, file existed, {:?}", f),
                    }
                }
                (SyscallEvent::Open(OFlag::O_RDONLY, optional_check_mech, outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            if let Some(check_mech) = optional_check_mech {
                                match check_mech {
                                    CheckMechanism::DiffFiles => {
                                        curr_set.insert(Fact::InputFilesMatch);
                                    }
                                    CheckMechanism::Hash(hash) => {
                                        let hash = if DONT_HASH_FILES {
                                            Vec::new()
                                        } else {
                                            hash
                                        };
                                        curr_set.insert(Fact::StartingContents(hash));
                                    }
                                    CheckMechanism::Mtime(mtime) => {
                                        curr_set.insert(Fact::Mtime(mtime));
                                    }
                                }
                            }

                            curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits()));
                            curr_set.insert(Fact::HasPermission((AccessFlags::R_OK).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::NoPermission((AccessFlags::R_OK).bits()));
                        }
                        f => panic!("Unexpected open append failure, file existed, {:?}", f),
                    }
                }
                (SyscallEvent::Open(OFlag::O_TRUNC,  _,outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits()));
                            curr_set.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::NoPermission((AccessFlags::W_OK).bits()));
                        }
                        f => panic!("Unexpected open append failure, file existed, {:?}", f),
                    }
                }
                (SyscallEvent::Open(_,  _,_), State::None, Mod::Created, _) => {
                    panic!("First state none but last mod created??");
                }
                (SyscallEvent::Open(_,  _,_), State::None, Mod::Deleted, true) => {
                    panic!("First state none but last mod deleted??");
                }
                (SyscallEvent::Open(_,  _,_), State::None, Mod::Modified, _) => {
                    panic!("First state none but last mod modified??");
                }
                (SyscallEvent::Open(_,  _,_), State::None, Mod::Renamed(_,_), _) => {
                    panic!("First state none but last mod renamed??");
                }
                (SyscallEvent::Open(OFlag::O_APPEND,  optional_check_mech, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            if let Some(check_mech) = optional_check_mech {
                                match check_mech {
                                    CheckMechanism::DiffFiles => {
                                        curr_set.insert(Fact::InputFilesMatch);
                                    }
                                    CheckMechanism::Hash(hash) => {
                                        let hash = if DONT_HASH_FILES {
                                            Vec::new()
                                        } else {
                                            hash
                                        };
                                        curr_set.insert(Fact::StartingContents(hash));
                                    }
                                    CheckMechanism::Mtime(mtime) => {
                                        curr_set.insert(Fact::Mtime(mtime));
                                    }
                                }
                            }

                            curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits()));
                            curr_set.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            panic!("Open append, no info yet, failed because file already exists??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Or(
                                Box::new(Fact::NoPermission((AccessFlags::W_OK).bits())),
                                Box::new(Fact::NoDirPermission((AccessFlags::X_OK).bits())),
                            ));
                        }
                        SyscallOutcome::Fail(SyscallFailure::InvalArg) => (),
                    }
                }
                (SyscallEvent::Open(OFlag::O_RDONLY,  optional_check_mech, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            if let Some(check_mech) = optional_check_mech {
                                match check_mech {
                                    CheckMechanism::DiffFiles => {
                                        curr_set.insert(Fact::InputFilesMatch);
                                    }
                                    CheckMechanism::Hash(hash) => {
                                        let hash = if DONT_HASH_FILES {
                                            Vec::new()
                                        } else {
                                            hash
                                        };
                                        curr_set.insert(Fact::StartingContents(hash));
                                    }
                                    CheckMechanism::Mtime(mtime) => {
                                        curr_set.insert(Fact::Mtime(mtime));
                                    }
                                }
                            }

                            curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits()));
                            curr_set.insert(Fact::HasPermission((AccessFlags::R_OK).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            panic!("Open read only, no info yet, failed because file already exists??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Or(
                                Box::new(Fact::NoPermission((AccessFlags::R_OK).bits())),
                                Box::new(Fact::NoDirPermission((AccessFlags::X_OK).bits())),
                            ));
                        }
                        SyscallOutcome::Fail(SyscallFailure::InvalArg) => (),
                    }
                }
                (SyscallEvent::Open(OFlag::O_TRUNC, _, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            // TODO also write access to the file? but the program
                            // doesn't know whether it exists..
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::HasDirPermission((flags).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            panic!("Open trunc, no info yet, failed because file already exists??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            panic!("Open trunc failed because file doesn't exist? So??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission((flags).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::InvalArg) => (),
                    }
                }
                (SyscallEvent::Open(f,  _,_), _, _, _) => panic!("Unexpected open flag: {:?}", f),

                (
                    SyscallEvent::Rename(_, _, _),
                    State::DoesntExist,
                    Mod::Created,
                    _,
                ) => (),
                (SyscallEvent::Rename(_, _, _), State::DoesntExist, Mod::Deleted, true) => {
                    // Created. Deleted. Won't succeed because old path is deleted.
                    // Already exists no, doesn't exist, yes makes sense as an error.
                    // But doesn't contribute to the preconditions.
                    // Permission denied doesn't make sense either.
                }
                (SyscallEvent::Rename(_, _, _), State::DoesntExist, Mod::Modified, _) => {
                    // Created, deleted, created, modified. Oof.
                    // Already existe no, doesn't exist no, permissions no.
                    // Success tells us nothing new too.
                }
                (SyscallEvent::Rename(_, _, _), State::DoesntExist, Mod::Renamed(_,_), _) => {
                    // Created, deleted, created, renamed. Or Created, renamed.
                    // Already exists no, doesn't exist no, permissions no.
                    // Success tells us nothing for preconds.
                }
                (SyscallEvent::Rename(_, _, outcome), State::DoesntExist, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    // So, it doesn't exist. We can't rename it.
                    // So this can't succeed.
                    // Will fail because file doesn't exist which we already know.
                    // Fail for already exists? No.
                    // Could fail for permissions though.
                    if outcome == SyscallOutcome::Fail(SyscallFailure::PermissionDenied) {
                        let mut flags = AccessFlags::empty();
                        flags.insert(AccessFlags::W_OK);
                        flags.insert(AccessFlags::X_OK);
                        curr_set.insert(Fact::NoDirPermission((flags).bits()));
                    }
                }
                (SyscallEvent::Rename(_, _, _), State::Exists, Mod::Created, _) => {
                    // Existed. Deleted. Created! Or Existed. Created. Now renamin'.
                    // Already exists? no.
                    // Doesn't exist, no.
                    // Permissions denied, how?
                    // Success, cool.
                }
                (SyscallEvent::Rename(_, _, _), State::Exists, Mod::Deleted, true) => {
                    // Existed. Then was deleted.
                    // This will fail because the file doesn't exist.
                    // Success and already exist don't make sense. Same with permissions.
                    // Nothing contributes.
                }
                (SyscallEvent::Rename(_, _, _), State::Exists, Mod::Modified, _) => {
                    // Existed, Deleted, Created, Modified or Existed, Modified
                    // We should be able to rename this.
                    // Permissions no, doesn't exist no, already exists no.
                }
                (SyscallEvent::Rename(_, _, _), State::Exists, Mod::Renamed(_,_), _) => {
                    // Existed. Deleted. Created. Renamed. Or Existed, Renamed.
                    // Don't think this affects preconditions.
                    // Eventually we will handle rename flags where they don't wanna replace
                    // an existing file, and that will be a precondition.
                }
                (SyscallEvent::Rename(old_path, _, outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    // It exists, we haven't modified it.
                    // It exists so we know that we have x access to the cwd.
                    // So if it succeeds we have to add those preconditions.
                    // oldpath preconds: exists, x w access
                    // newpath preconds: none (not handling flags)
                    if old_path == full_path {
                        match outcome {
                            SyscallOutcome::Success => {
                                curr_set.insert(Fact::HasDirPermission((AccessFlags::W_OK).bits()));
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                // We may not have permission to write to the directory.
                                curr_set.insert(Fact::NoDirPermission((AccessFlags::W_OK).bits()));
                            }
                            o => panic!("Unexpected failure in rename syscall event: {:?}", o),
                        }
                    }
                }
                (SyscallEvent::Rename(_, _, _), State::None, Mod::Created, _) => {
                    panic!("No first state but last mod was created??");
                }
                (SyscallEvent::Rename(_, _, _), State::None, Mod::Deleted, _) => {
                    panic!("No first state but last mod was deleted??");
                }
                (SyscallEvent::Rename(_, _, _), State::None, Mod::Modified, _) => {
                    panic!("No first state but last mod was modified??");
                }
                (SyscallEvent::Rename(_, _, _), State::None, Mod::Renamed(_,_), _) => {
                    panic!("No first state but last mod was renamed??");
                }
                (SyscallEvent::Rename(old_path, _, outcome), State::None, Mod::None, false) => {
                    // No first state, no mods, haven't deleted. This is the first thing we are doing to this
                    // resource probably.
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            if old_path == full_path {
                                // First event is renaming and we see old path, add all the preconds.
                                curr_set.insert(Fact::Exists);
                                let mut flags = AccessFlags::empty();
                                flags.insert(AccessFlags::W_OK);
                                flags.insert(AccessFlags::X_OK);
                                curr_set.insert(Fact::HasDirPermission(flags.bits()));
                            } else {
                                // full_path = new path
                                curr_set.insert(Fact::DoesntExist);
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            // Old path doesn't exist cool.
                            curr_set.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission(flags.bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::InvalArg) => (),
                        o => panic!("Unexpected error for rename: {:?}", o),
                    }
                }

                (SyscallEvent::Stat(_, _), State::DoesntExist, Mod::Created, _) => {
                    // Didn't exist, created, deleted, created, this stat doesn't depend on
                    // a file that existed at the start. and obviously we have exec access to the dir.
                }
                (SyscallEvent::Stat(_, _), State::DoesntExist, Mod::Deleted, true) => {
                    // The file didn't exist. Then the file was created and deleted. Adds nothing.
                }
                (SyscallEvent::Stat(_, _), State::DoesntExist, Mod::Modified, _) => (),
                (SyscallEvent::Stat(_, _), State::DoesntExist, Mod::Renamed(_,_), _) => (),
                (SyscallEvent::Stat(_, outcome), State::DoesntExist, Mod::None, false) => {
                    match outcome {
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => (),
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                            curr_set.insert(Fact::NoDirPermission((AccessFlags::X_OK).bits()));
                        }
                        f => panic!("Unexpected failure by stat syscall, first state was doesn't exist, last mod none: {:?}", f),
                    }
                }
                // It existed at the start, but we have modified it, so this stat doesn't depend on
                // the file at the beginning of the computation.
                (SyscallEvent::Stat(_,_), State::Exists, Mod::Created, true) => (),
                (SyscallEvent::Stat(_,_), State::Exists, Mod::Deleted, true) => (),
                (SyscallEvent::Stat(_,_), State::Exists, Mod::Modified, true) => (),
                (SyscallEvent::Stat(_,_), State::Exists, Mod::Modified, false) => (),
                // This file has been deleted, no way the stat struct is gonna be the same.
                (SyscallEvent::Stat(_,_), State::Exists, Mod::Renamed(_,_), true) => (),
                (SyscallEvent::Stat(stat_struct, _), State::Exists, Mod::Renamed(old_path, new_path), false) => {
                    if *new_path == full_path {
                        // We actually have to add the stat struct matching to the old path's
                        if let Some(list) = exec_file_events.events().get(&Accessor::CurrProc(old_path.clone())) {
                            // &old_path.clone()
                            let no_mods_before_rename = no_mods_before_rename(list.to_vec());
                            if no_mods_before_rename {
                                let curr_set = curr_file_preconditions.get_mut(old_path).unwrap();
                                if let Some(stat_str) = stat_struct {
                                    curr_set.insert(Fact::StatStructMatches(stat_str.clone()));
                                } else {
                                    panic!("No stat struct found for successful stat event!");
                                }
                            }
                        }

                    }
                }
                (SyscallEvent::Stat(option_stat, outcome), State::Exists, Mod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                            // TODO: don't add if there's already a stat struct, they'll conflict.
                            // Just going to check for duplicates in check_preconditions()?

                            curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits()));
                            if let Some(stat) = option_stat {
                                curr_set.insert(Fact::StatStructMatches(stat.clone()));
                            } else {
                                panic!("No stat struct found for successful stat syscall!");
                            }
                        }
                        f => panic!("Unexpected failure of stat call, file exists: {:?}", f),
                    }
                }

                (SyscallEvent::Stat(_, _), State::None, Mod::Created, _) => {
                    panic!("First state was none but last mod was created??");
                }
                (SyscallEvent::Stat(_, _), State::None, Mod::Deleted, _) => {
                    panic!("First state was none but last mod was deleted??");
                }
                (SyscallEvent::Stat(_, _), State::None, Mod::Modified, _) => {
                    panic!("First state was none but last mod was modified??");
                }
                (SyscallEvent::Stat(_, _), State::None, Mod::Renamed(_,_), _) => {
                    panic!("First state was none but last mod was renamed??");
                }
                (SyscallEvent::Stat(option_stat, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            if let Some(stat) = option_stat {
                                curr_set.insert(Fact::StatStructMatches(stat.clone()));
                                curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits()));
                            } else {
                                panic!("No stat struct found for successful stat syscall!");
                            }

                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            panic!("Unexpected stat failure: file already exists??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::NoDirPermission((AccessFlags::X_OK).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::InvalArg) => (),
                    }
                }
            }

            // This function will only change the first_state if it is None.
            first_state_struct.update_based_on_syscall(&full_path, event.clone());
            curr_state_struct.update_based_on_syscall(event);
        }
    }
    curr_file_preconditions
}

// REMEMBER: SIDE EFFECT FREE SYSCALLS CONTRIBUTE NOTHING TO THE POSTCONDITIONS.
// Directory Postconditions (for now just cwd), File Postconditions
pub fn generate_postconditions(
    exec_file_events: ExecFileEvents,
) -> Postconditions {
    let sys_span = span!(Level::INFO, "generate_file_postconditions");
    let _ = sys_span.enter();

    let mut curr_file_postconditions: Postconditions = HashMap::new();

    // Just be sure the map is set up ahead of time.
    for accessor in exec_file_events.events().keys() {
        curr_file_postconditions.insert(accessor.clone(), HashSet::new());
    }
    for (accessor, event_list) in exec_file_events.events() {
        let mut first_state_struct = FirstState(State::None);
        let mut last_mod_struct = LastMod(Mod::None);
        let full_path = match accessor {
            Accessor::ChildProc(_, path) => path,
            Accessor::CurrProc(path) => path, 
        };

        for event in event_list {
            let first_state = first_state_struct.state();
            let last_mod = last_mod_struct.state();

            match (event.clone(), first_state, last_mod) {
                (_, State::None, Mod::Created) => {
                    panic!("First state is none but last mod is created!!");
                }
                (_, State::None, Mod::Deleted) => {
                    panic!("First state is none but last mod is deleted!!");
                }
                (SyscallEvent::ChildExec(_), State::None, Mod::Modified) => (),
                (_, State::None, Mod::Modified) => {
                    // panic!("First state is none but last mod is modified!!");
                }
                (_, State::None, Mod::Renamed(_, _)) => {
                    panic!("First state is none but last mod is rename!!");
                }
                (SyscallEvent::Access(_, _), _, _) => (),
                (SyscallEvent::ChildExec(_), _, _) => (),
                (SyscallEvent::Create(_, _), State::DoesntExist, Mod::Created) => (),
                (SyscallEvent::Create(_, outcome), State::DoesntExist, Mod::Deleted) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.remove(&Fact::DoesntExist);
                        curr_set.insert(Fact::FinalContents);
                    }
                }

                (SyscallEvent::Create(_, _), State::DoesntExist, Mod::Modified) => (),
                (SyscallEvent::Create(_, outcome), State::DoesntExist, Mod::Renamed(_, _)) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.remove(&Fact::DoesntExist);
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (SyscallEvent::Create(_, outcome), State::DoesntExist, Mod::None) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (SyscallEvent::Create(_, _), State::Exists, Mod::Created) => (),
                (SyscallEvent::Create(_, outcome), State::Exists, Mod::Deleted) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.remove(&Fact::DoesntExist);
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (SyscallEvent::Create(_, _), State::Exists, Mod::Modified) => (),
                (SyscallEvent::Create(_, outcome), State::Exists, Mod::Renamed(_, _)) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.remove(&Fact::Exists);
                        curr_set.remove(&Fact::DoesntExist);
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (SyscallEvent::Create(_, _), State::Exists, Mod::None) => (),
                (SyscallEvent::Create(_, outcome), State::None, Mod::None) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (
                    SyscallEvent::Delete(outcome),
                    State::DoesntExist,
                    Mod::Created | Mod::Modified,
                ) => {
                    if outcome == SyscallOutcome::Success {
                        curr_file_postconditions.remove(&accessor);
                        let new_set = HashSet::from([Fact::DoesntExist]);
                        curr_file_postconditions.insert(accessor.clone(), new_set);
                    }
                }
                (SyscallEvent::Delete(outcome), State::DoesntExist, Mod::Renamed(_, new_path)) => {
                    if outcome == SyscallOutcome::Success && full_path == *new_path {
                        curr_file_postconditions.remove(&accessor);
                        let new_set = HashSet::from([Fact::DoesntExist]);
                        curr_file_postconditions.insert(accessor, new_set);
                    }
                }
                (SyscallEvent::Delete(_), State::DoesntExist, Mod::Deleted) => (),
                (SyscallEvent::Delete(_), State::DoesntExist, Mod::None) => (),
                (SyscallEvent::Delete(outcome), State::Exists, Mod::Created | Mod::Modified) => {
                    if outcome == SyscallOutcome::Success {
                        curr_file_postconditions.remove(&accessor);
                        let new_set = HashSet::from([Fact::DoesntExist]);
                        curr_file_postconditions.insert(accessor, new_set);
                    }
                }
                (SyscallEvent::Delete(outcome), State::Exists, Mod::Renamed(_, _)) => {
                    if outcome == SyscallOutcome::Success {
                        curr_file_postconditions.remove(&accessor);
                        let new_set = HashSet::from([Fact::DoesntExist]);
                        curr_file_postconditions.insert(accessor, new_set);
                    }
                }
                (SyscallEvent::Delete(_), State::Exists, Mod::Deleted) => (),
                (SyscallEvent::Delete(outcome), State::Exists, Mod::None) => {
                    if outcome == SyscallOutcome::Success {
                        curr_file_postconditions.remove(&accessor);
                        let new_set = HashSet::from([Fact::DoesntExist]);
                        curr_file_postconditions.insert(accessor, new_set);
                    }
                }
                (SyscallEvent::Delete(outcome), State::None, Mod::None) => {
                    if outcome == SyscallOutcome::Success {
                        curr_file_postconditions.remove(&accessor);
                        let new_set = HashSet::from([Fact::DoesntExist]);
                        curr_file_postconditions.insert(accessor.clone(), new_set);
                    }
                }
                (SyscallEvent::DirectoryRead(_, _, _), _, _) => (),
                (SyscallEvent::FailedExec(_), _, _) => (),
                (SyscallEvent::Open(OFlag::O_RDONLY, _, _), _, _) => (),
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, _),
                    State::DoesntExist,
                    Mod::Created | Mod::Deleted | Mod::Modified,
                ) => (),
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, outcome),
                    State::DoesntExist,
                    Mod::Renamed(_, new_path),
                ) => {
                    if outcome == SyscallOutcome::Success && full_path == *new_path {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.remove(&Fact::Exists);
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, _),
                    State::DoesntExist,
                    Mod::None,
                ) => (),
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, _),
                    State::Exists,
                    Mod::Created | Mod::Deleted | Mod::Modified,
                ) => (),
                // We shouldn't see more events after something is renamed unless it's the new file (and first state wouldn't be exists)
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, _),
                    State::Exists,
                    Mod::Renamed(_, _),
                ) => (),
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, outcome),
                    State::Exists,
                    Mod::None,
                ) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, outcome),
                    State::None,
                    Mod::None,
                ) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (SyscallEvent::Open(flag, _, _), _, _) => {
                    panic!("Unexpected oflag for open! :{:?}", flag);
                }
                (
                    SyscallEvent::Rename(old_path, new_path, outcome),
                    State::DoesntExist,
                    Mod::Created | Mod::Modified,
                ) => {
                    if outcome == SyscallOutcome::Success && old_path == full_path {
                        let new_accessor = match accessor {
                            Accessor::ChildProc(cmd, _) => Accessor::ChildProc(cmd, new_path),
                            Accessor::CurrProc(_) => Accessor::CurrProc(new_path),
                        };
                        
                        if curr_file_postconditions.contains_key(&accessor) {
                            let old_set = curr_file_postconditions.remove(&accessor).unwrap();
                            curr_file_postconditions.insert(new_accessor, old_set);
                            curr_file_postconditions
                                .insert(accessor, HashSet::from([Fact::DoesntExist]));
                        } else {
                            // We have never seen old path before.
                            curr_file_postconditions
                                .insert(accessor, HashSet::from([Fact::DoesntExist]));
                            // new path is just "exists", that's all we know!
                            curr_file_postconditions
                                .insert(new_accessor , HashSet::from([Fact::Exists]));
                        }
                    }
                }
                (
                    SyscallEvent::Rename(old_path, new_path, outcome),
                    State::DoesntExist,
                    Mod::Renamed(_, last_new_path),
                ) => {
                    let new_accessor = match accessor {
                        Accessor::ChildProc(cmd, _) => Accessor::ChildProc(cmd, new_path),
                        Accessor::CurrProc(_) => Accessor::CurrProc(new_path),
                    };

                    // This file is getting renamed. Again. For some god damn reason.
                    if outcome == SyscallOutcome::Success && old_path == *last_new_path {
                        let curr_set = curr_file_postconditions.remove(&accessor).unwrap();
                        // let _ = curr_file_postconditions.remove(&new_path);
                        curr_file_postconditions.insert(new_accessor, curr_set);
                        curr_file_postconditions
                            .insert(accessor, HashSet::from([Fact::DoesntExist]));
                    }
                }
                (SyscallEvent::Rename(_, _, _), State::DoesntExist, Mod::Deleted) => (),
                (SyscallEvent::Rename(_, _, _), State::DoesntExist, Mod::None) => (),
                (
                    SyscallEvent::Rename(old_path, new_path, outcome),
                    State::Exists,
                    Mod::Created | Mod::Modified,
                ) => {
                    let new_accessor = match accessor {
                        Accessor::ChildProc(cmd, _) => Accessor::ChildProc(cmd, new_path),
                        Accessor::CurrProc(_) => Accessor::CurrProc(new_path),
                    };

                    if outcome == SyscallOutcome::Success && old_path == full_path {
                        if curr_file_postconditions.contains_key(&accessor) {
                            let old_set = curr_file_postconditions.remove(&accessor).unwrap();
                            curr_file_postconditions.insert(new_accessor, old_set);
                            curr_file_postconditions
                                .insert(accessor, HashSet::from([Fact::DoesntExist]));
                        } else {
                            // We have never seen old path before.
                            curr_file_postconditions
                                .insert(accessor, HashSet::from([Fact::DoesntExist]));
                            // new path is just "exists", that's all we know!
                            curr_file_postconditions
                                .insert(new_accessor, HashSet::from([Fact::Exists]));
                        }
                    }
                }
                (
                    SyscallEvent::Rename(old_path, new_path, outcome),
                    State::Exists,
                    Mod::Renamed(_, _),
                ) => {
                    let new_accessor = match accessor {
                        Accessor::ChildProc(cmd, _) => Accessor::ChildProc(cmd, new_path),
                        Accessor::CurrProc(_) => Accessor::CurrProc(new_path),
                    };

                    // First state existing tells us this must be the old path
                    // but it's safer to check.
                    if outcome == SyscallOutcome::Success && full_path == old_path {
                        if curr_file_postconditions.contains_key(&accessor) {
                            let old_set = curr_file_postconditions.remove(&accessor).unwrap();
                            curr_file_postconditions.insert(new_accessor, old_set);
                            curr_file_postconditions
                                .insert(accessor, HashSet::from([Fact::DoesntExist]));
                        } else {
                            // We have never seen old path before.
                            curr_file_postconditions
                                .insert(accessor, HashSet::from([Fact::DoesntExist]));
                            // new path is just "exists", that's all we know!
                            curr_file_postconditions
                                .insert(new_accessor, HashSet::from([Fact::Exists]));
                        }
                    }
                }
                (SyscallEvent::Rename(_, _, _), State::Exists, Mod::Deleted) => (),
                (SyscallEvent::Rename(old_path, new_path, outcome), State::Exists, Mod::None) => {
                    let new_accessor = match accessor {
                        Accessor::ChildProc(cmd, _) => Accessor::ChildProc(cmd, new_path),
                        Accessor::CurrProc(_) => Accessor::CurrProc(new_path),
                    };
                    
                    if outcome == SyscallOutcome::Success && full_path == old_path {
                        if curr_file_postconditions.contains_key(&accessor) {
                            let old_set = curr_file_postconditions.remove(&accessor).unwrap();
                            curr_file_postconditions.insert(new_accessor, old_set);
                            curr_file_postconditions
                                .insert(accessor, HashSet::from([Fact::DoesntExist]));
                        } else {
                            // We have never seen old path before.
                            curr_file_postconditions
                                .insert(accessor, HashSet::from([Fact::DoesntExist]));
                            // new path is just "exists", that's all we know!
                            curr_file_postconditions
                                .insert(new_accessor, HashSet::from([Fact::Exists]));
                        }
                    }
                }

                // We haven't seen old path before.
                (SyscallEvent::Rename(old_path, new_path, outcome), State::None, Mod::None) => {
                    let new_accessor = match accessor {
                        Accessor::ChildProc(cmd, _) => Accessor::ChildProc(cmd.clone(), new_path),
                        Accessor::CurrProc(_) => Accessor::CurrProc(new_path),
                    };

                    if outcome == SyscallOutcome::Success && full_path == old_path {
                        if curr_file_postconditions.contains_key(&accessor) {
                            let old_set = curr_file_postconditions.remove(&accessor).unwrap();
                            curr_file_postconditions.insert(new_accessor, old_set);
                            curr_file_postconditions
                                .insert(accessor, HashSet::from([Fact::DoesntExist]));
                        } else {
                            // We have never seen old path before.
                            curr_file_postconditions
                                .insert(accessor.clone(), HashSet::from([Fact::DoesntExist]));
                            // new path is just "exists", that's all we know!
                            curr_file_postconditions
                                .insert(new_accessor, HashSet::from([Fact::Exists]));
                        }
                    }
                }
                (SyscallEvent::Stat(_, _), _, _) => (),
            }
            first_state_struct.update_based_on_syscall(&full_path, event.clone());
            last_mod_struct.update_based_on_syscall(event);
        }
    }
    curr_file_postconditions
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     // These tests assume you have test.txt, foo.txt, and bar.txt
//     // on your computer and you have priveleges to them.
//     // Because I am lazy right now.
//     #[test]
//     fn test_failed_access_then_create() {
//         let mut exec_file_events = ExecFileEvents::new(HashMap::new());
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Access(
//                 (AccessFlags::W_OK).bits(),
//                 SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
//             ),
//             PathBuf::from("test.txt"),
//         );
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
//             PathBuf::from("test.txt"),
//         );

//         let preconditions = generate_preconditions(exec_file_events.clone());
//         let preconditions_set = preconditions.get(&PathBuf::from("test.txt")).unwrap();
//         let mut flags = AccessFlags::empty();
//         flags.insert(AccessFlags::W_OK);
//         flags.insert(AccessFlags::X_OK);
//         let correct_preconditions =
//             HashSet::from([Fact::DoesntExist, Fact::HasDirPermission(flags.bits())]);
//         assert_eq!(preconditions_set, &correct_preconditions);

//         let postconditions = generate_postconditions(exec_file_events);
//         let postconditions_set = postconditions.get(&PathBuf::from("test.txt")).unwrap();

//         let correct_postconditions = HashSet::from([Fact::FinalContents]);
//         assert_eq!(postconditions_set, &correct_postconditions);
//     }

//     #[test]
//     fn test_stat_open_create() {
//         let mut exec_file_events = ExecFileEvents::new(HashMap::new());
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Stat(None, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
//             PathBuf::from("test.txt"),
//         );
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Open(
//                 OFlag::O_RDONLY,
//                 Some(Vec::new()), // TODO
//                 SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
//             ),
//             PathBuf::from("test.txt"),
//         );
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
//             PathBuf::from("test.txt"),
//         );
//         let preconditions = generate_preconditions(exec_file_events.clone());
//         let preconditions_set = preconditions.get(&PathBuf::from("test.txt")).unwrap();
//         let mut flags = AccessFlags::empty();
//         flags.insert(AccessFlags::W_OK);
//         flags.insert(AccessFlags::X_OK);

//         let correct_preconditions =
//             HashSet::from([Fact::DoesntExist, Fact::HasDirPermission(flags.bits())]);
//         assert_eq!(preconditions_set, &correct_preconditions);

//         let postconditions = generate_postconditions(exec_file_events);
//         let postconditions_set = postconditions.get(&PathBuf::from("test.txt")).unwrap();
//         let correct_postconditions = HashSet::from([Fact::FinalContents]);
//         assert_eq!(postconditions_set, &correct_postconditions);
//     }

//     #[test]
//     fn test_open_open_access() {
//         let mut exec_file_events = ExecFileEvents::new(HashMap::new());
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             // TODO
//             SyscallEvent::Open(OFlag::O_APPEND, Some(Vec::new()), SyscallOutcome::Success),
//             PathBuf::from("test.txt"),
//         );
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Open(OFlag::O_TRUNC, Some(Vec::new()), SyscallOutcome::Success),
//             PathBuf::from("test.txt"),
//         );
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Access((AccessFlags::R_OK).bits(), SyscallOutcome::Success),
//             PathBuf::from("test.txt"),
//         );

//         let preconditions = generate_preconditions(exec_file_events.clone());
//         let preconditions_set = preconditions.get(&PathBuf::from("test.txt")).unwrap();
//         let mut flags = AccessFlags::empty();
//         flags.insert(AccessFlags::R_OK);
//         flags.insert(AccessFlags::W_OK);

//         let correct_preconditions = HashSet::from([
//             Fact::StartingContents(Vec::new()),
//             Fact::HasPermission(flags.bits()),
//             Fact::HasDirPermission((AccessFlags::X_OK).bits()),
//         ]);
//         assert_eq!(preconditions_set, &correct_preconditions);

//         let postconditions = generate_postconditions(exec_file_events);
//         let postconditions_set = postconditions.get(&PathBuf::from("test.txt")).unwrap();
//         let correct_postconditions = HashSet::from([Fact::FinalContents]);
//         assert_eq!(postconditions_set, &correct_postconditions);
//     }

//     #[test]
//     fn test_append_delete_create() {
//         let mut exec_file_events = ExecFileEvents::new(HashMap::new());
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Open(OFlag::O_APPEND, Some(Vec::new()), SyscallOutcome::Success),
//             PathBuf::from("test.txt"),
//         );
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Delete(SyscallOutcome::Success),
//             PathBuf::from("test.txt"),
//         );
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
//             PathBuf::from("test.txt"),
//         );

//         let preconditions = generate_preconditions(exec_file_events.clone());
//         let preconditions_set = preconditions.get(&PathBuf::from("test.txt")).unwrap();
//         let correct_preconditions = HashSet::from([
//             Fact::StartingContents(Vec::new()),
//             Fact::HasDirPermission((AccessFlags::X_OK).bits()),
//             Fact::HasPermission((AccessFlags::W_OK).bits()),
//         ]);
//         assert_eq!(preconditions_set, &correct_preconditions);

//         let postconditions = generate_postconditions(exec_file_events);
//         let postconditions_set = postconditions.get(&PathBuf::from("test.txt")).unwrap();
//         let correct_postconditions = HashSet::from([Fact::FinalContents]);
//         assert_eq!(postconditions_set, &correct_postconditions);
//     }
//     // This test only works on my computer for obvious reasons.
//     #[test]
//     fn test_rename_openappend_create() {
//         let mut exec_file_events = ExecFileEvents::new(HashMap::new());
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Rename(
//                 PathBuf::from("foo.txt"),
//                 PathBuf::from("bar.txt"),
//                 SyscallOutcome::Success,
//             ),
//             PathBuf::from("foo.txt"),
//         );
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Rename(
//                 PathBuf::from("foo.txt"),
//                 PathBuf::from("bar.txt"),
//                 SyscallOutcome::Success,
//             ),
//             PathBuf::from("bar.txt"),
//         );
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
//             PathBuf::from("foo.txt"),
//         );
//         exec_file_events.add_new_file_event(
//             Pid::from_raw(0),
//             SyscallEvent::Open(OFlag::O_APPEND, Some(Vec::new()), SyscallOutcome::Success),
//             PathBuf::from("bar.txt"),
//         );

//         let preconditions = generate_preconditions(exec_file_events.clone());
//         let preconditions_set_foo = preconditions.get(&PathBuf::from("foo.txt")).unwrap();
//         let preconditions_set_bar = preconditions.get(&PathBuf::from("bar.txt")).unwrap();

//         let mut flags = AccessFlags::empty();
//         flags.insert(AccessFlags::W_OK);
//         flags.insert(AccessFlags::X_OK);

//         let correct_preconditions_foo = HashSet::from([
//             Fact::Exists,
//             Fact::StartingContents(Vec::new()),
//             Fact::HasPermission((AccessFlags::W_OK).bits()),
//             Fact::HasDirPermission(flags.bits()),
//         ]);
//         let correct_preconditions_bar = HashSet::from([Fact::DoesntExist]);

//         assert_eq!(preconditions_set_foo, &correct_preconditions_foo);
//         assert_eq!(preconditions_set_bar, &correct_preconditions_bar);

//         // let postconditions = generate_postconditions(exec_file_events);
//         // let postconditions_set = postconditions.get(&PathBuf::from("test")).unwrap();
//         // let correct_postconditions = HashSet::from([Fact::Contents)]);
//         // assert_eq!(postconditions_set, &correct_postconditions);
//     }
// }
