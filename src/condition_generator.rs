use nix::{
    fcntl::OFlag,
    sys::statfs::statfs,
    unistd::{access, AccessFlags, Pid},
    NixPath,
};
use serde::{Deserialize, Serialize};

use core::panic;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, read_dir},
    hash::Hash,
    iter::FromIterator,
    os::unix::prelude::MetadataExt,
    path::PathBuf,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

use crate::{
    cache_utils::generate_hash,
    condition_utils::{
        dir_created_by_exec, preconditions_contain_stat_fact, update_file_posts_with_renamed_dirs,
        FileType,
    },
    syscalls::{DirEvent, FileEvent, MyStatFs},
};
use crate::{
    condition_utils::{Fact, FirstState, LastMod, Mod, State},
    syscalls::Stat,
};
use crate::{
    condition_utils::{Postconditions, Preconditions},
    syscalls::{AccessMode, CheckMechanism, MyStat, OffsetMode, SyscallFailure, SyscallOutcome},
};

// For benchmarking purposes. Flag to turn off file hashing.
// Helped us realize how much time hashing was taking up!
const DONT_HASH_FILES: bool = false;

// Who done the accessin'?
// This enum helps us keep track of who actually did the resource
// access when we combine fact sets from children and parent.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Accessor {
    // String = hash of the child's command.
    // We know hashing is slow, let's do it one time,
    // and just pass the results around.
    ChildProc(String, PathBuf),
    CurrProc(PathBuf),
}

impl Accessor {
    pub fn path(&self) -> PathBuf {
        match self {
            Accessor::ChildProc(_, path) => path.clone(),
            Accessor::CurrProc(path) => path.clone(),
        }
    }

    pub fn hashed_command(&self) -> Option<String> {
        match self {
            Accessor::ChildProc(hash, _) => Some(hash.clone()),
            _ => None,
        }
    }
}

// Actual accesses to the file system performed by
// a successful execution.
// Accessor (i.e. WHO did it + WHAT resource we are talking about)
// to an ordered list of either directory events (if the resource is
// a directory) or file events
// (if the resource is a file).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecSyscallEvents {
    dir_events: HashMap<Accessor, Vec<DirEvent>>,
    file_events: HashMap<Accessor, Vec<FileEvent>>,
}

impl ExecSyscallEvents {
    pub fn new(
        dir_events: HashMap<Accessor, Vec<DirEvent>>,
        file_events: HashMap<Accessor, Vec<FileEvent>>,
    ) -> ExecSyscallEvents {
        ExecSyscallEvents {
            dir_events,
            file_events,
        }
    }

    // Add new directory access to the struct.
    pub fn add_new_dir_event(&mut self, caller_pid: Pid, dir_event: DirEvent, full_path: PathBuf) {
        let s = span!(Level::INFO, stringify!(add_new_dir_event), pid=?caller_pid);
        let _ = s.enter();

        s.in_scope(|| "in add_new_dir_event");
        // First case, we already saw this dir and now we are adding another event to it.
        if let Some(event_list) = self
            .dir_events
            .get_mut(&Accessor::CurrProc(full_path.clone()))
        {
            s.in_scope(|| "adding to existing event list");
            event_list.push(dir_event);
        } else {
            let event_list = vec![dir_event];
            s.in_scope(|| "adding new event list");
            self.dir_events
                .insert(Accessor::CurrProc(full_path), event_list);
        }
    }

    // Add new file access to the struct.
    pub fn add_new_file_event(
        &mut self,
        caller_pid: Pid,
        file_event: FileEvent,
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
        if let Some(event_list) = self
            .file_events
            .get_mut(&Accessor::CurrProc(full_path.clone()))
        {
            s.in_scope(|| "adding to existing event list");
            event_list.push(file_event);
        } else {
            let event_list = vec![file_event];
            s.in_scope(|| "adding new event list");
            self.file_events
                .insert(Accessor::CurrProc(full_path), event_list);
        }
    }

    // A parent process needs to know if and when a child process calls
    // execve successfully because we need to fold the child's events into
    // the parent's events if they access the same resource.
    pub fn add_new_fork_exec(&mut self, child_pid: Pid) {
        for (_, list) in self.dir_events.iter_mut() {
            list.push(DirEvent::ChildExec(child_pid));
        }

        for (_, list) in self.file_events.iter_mut() {
            list.push(FileEvent::ChildExec(child_pid));
        }
    }

    // Get the directory events.
    pub fn dir_events(&self) -> HashMap<Accessor, Vec<DirEvent>> {
        self.dir_events.clone()
    }

    // Get the file events.
    pub fn file_events(&self) -> HashMap<Accessor, Vec<FileEvent>> {
        self.file_events.clone()
    }
}

// This function is for checking that a given Fact holds.
// We call it to check each precondition.
fn check_fact_holds(fact: Fact, path_name: PathBuf, pid: Pid) -> bool {
    debug!("Checking fact: {:?} for path: {:?}", fact, path_name);
    if path_name.starts_with("/proc") {
        true
    } else {
        match fact {
            // Check that the cached entries match the current
            // entries for a given directory.
            Fact::DirEntriesMatch(entries) => {
                let mut curr_dir_entries = HashSet::new();

                let curr_entries = read_dir(path_name).unwrap();
                // Create a set of current directory entries and their file
                // types.
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

                let sets_are_equal = old_set == curr_dir_entries;
                let proper_subset = old_set.is_subset(&curr_dir_entries);
                // This fact is true if the old set of directory entries matches the new one
                // or it is a proper subset ( has to do with funny files like "."  and "..")
                sets_are_equal || proper_subset
            }
            Fact::DoesntExist => !path_name.exists(),
            Fact::Exists => path_name.exists(),
            // This fact shouldn't be checked as a precondition, because it is a
            // postcondition.
            Fact::FinalContents => panic!("Final contents should not be a precondition!!"),
            // TODO: Implement this.
            // Would be nice for dissertation eval. We found out quickly that copying the
            // entire input file over to the cache was slow and took up a lot of space,
            // thus I didn't bother implementing the checking mechanism for it.
            Fact::InputFileDiffsMatch => todo!(),
            // When we cached the execution, we got the hash of this input file.
            // We check this cached hash against the hash of the existing file.
            Fact::InputFileHashesMatch(old_hash) => {
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
            // Check that this process has the same permissions it had before on either
            // a passed in directory, or just the parent dir of the path we are checking.
            Fact::HasDirPermission(flags, optional_root_dir) => {
                debug!("Dir perm flags: {:?}", flags);
                let dir = if let Some(root_dir) = optional_root_dir {
                    root_dir
                } else {
                    let path = path_name.parent().unwrap();
                    PathBuf::from(path)
                };

                access(&dir, AccessFlags::from_bits(flags).unwrap()).is_ok()
            }
            // Check that this process has the same permissions on this file as it had
            // during its caching run.
            Fact::HasPermission(flags) => {
                debug!("Perm flags: {:?}", flags);
                access(&path_name, AccessFlags::from_bits(flags).unwrap()).is_ok()
            }
            // Check the cached mtime against the current mtime.
            Fact::Mtime(old_mtime) => {
                debug!("Old mtime: {:?}", old_mtime);
                let curr_metadata = fs::metadata(&path_name).unwrap();
                let curr_mtime = curr_metadata.mtime();
                debug!("New mtime: {:?}", curr_mtime);
                curr_mtime == old_mtime
            }
            // Check that this process still lacks the specified permissions it had before
            // on either a passed in directory, or just the parent dir of the path we are
            // checking.
            Fact::NoDirPermission(flags, optional_root_dir) => {
                let dir = if let Some(root_dir) = optional_root_dir {
                    root_dir
                } else {
                    let path = path_name.parent().unwrap();
                    PathBuf::from(path)
                };
                debug!("Dir no perm flags: {:?}", flags);
                access(&dir, AccessFlags::from_bits(flags).unwrap()).is_err()
            }
            // Check that this process still lacks the specified permissions on this file
            // that it also lacked during its caching run.
            Fact::NoPermission(flags) => {
                debug!("No perm flags: {:?}", flags);
                access(&path_name, AccessFlags::from_bits(flags).unwrap()).is_ok()
            }
            // Check that at least one of these Facts fails.
            // This should be only when we need to check permissions of the directory
            // and permissions of the file.
            // Example is open append failing for permissions:
            // Write access OR exec dir access is missing. Or both!
            Fact::Or(first, second) => {
                // This should be only when we need to check perms
                // of the dir and perms of the file.
                // Example is open append failing for perms:
                // write access OR exec dir access is missing
                let first_perms_hold = match *first {
                    Fact::HasDirPermission(_, _)
                    | Fact::HasPermission(_)
                    | Fact::NoDirPermission(_, _)
                    | Fact::NoPermission(_) => check_fact_holds(*first, path_name.clone(), pid),
                    e => panic!("Unexpected Fact in Fact::Or: {:?}", e),
                };
                let second_perms_hold = match *second {
                    Fact::HasDirPermission(_, _)
                    | Fact::HasPermission(_)
                    | Fact::NoDirPermission(_, _)
                    | Fact::NoPermission(_) => check_fact_holds(*second, path_name, pid),
                    e => panic!("Unexpected Fact in Fact::Or: {:?}", e),
                };
                // Technically, if both of these failed, it would be valid too.
                // They just can't both succeed.
                !(first_perms_hold && second_perms_hold)
            }
            // This is a postcondition, not a precondition. So nothing needs to checked here.
            Fact::Renamed(_, _) => true,
            // We get the current stat struct by calling stat() or lstat() if appropriate.
            // We check this against our cached stat struct.
            Fact::StatStructMatches(old_stat) => {
                let (old_stat, new_metadata) = match old_stat {
                    Stat::Stat(stat) => {
                        // let metadata = fs::metadata(&path_name).unwrap();
                        let metadata = match fs::metadata(&path_name) {
                            Ok(meta) => meta,
                            Err(e) => panic!(
                                "failed to get metadata of path: {:?}, error: {:?}",
                                path_name, e
                            ),
                        };
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
            Fact::StatFsStructMatches(old_statfs) => {
                if let Ok(statfs) = statfs(&path_name) {
                    let new_statfs = MyStatFs {
                        optimal_transfer_size: statfs.optimal_transfer_size(),
                        block_size: statfs.block_size(),
                        maximum_name_length: statfs.maximum_name_length(),
                        blocks: statfs.blocks(),
                        blocks_free: statfs.blocks_free(),
                        blocks_available: statfs.blocks_available(),
                        files: statfs.files(),
                        files_free: statfs.files_free(),
                    };
                    old_statfs == new_statfs
                } else {
                    panic!("Failed to call statfs in check_fact_holds()!")
                }
            }
        }
    }
}

// Checks file preconditions and directory preconditions for the given
// execution.
pub fn check_preconditions(conditions: Preconditions, pid: Pid) -> bool {
    let dir_preconds = conditions.dir_preconditions();
    let file_preconds = conditions.file_preconditions();

    for (path_name, fact_set) in dir_preconds {
        for fact in fact_set {
            // We short circuit on the first failing file Fact, and report it.
            if !check_fact_holds(fact.clone(), path_name.clone(), pid) {
                debug!(
                    "Dir fact that doesn't hold: {:?}, path: {:?}",
                    fact, path_name
                );
                return false;
            }
        }
    }
    for (path_name, fact_set) in file_preconds {
        for fact in fact_set {
            // We short circuit on the first failing directory Fact, and report it.
            if !check_fact_holds(fact.clone(), path_name.clone(), pid) {
                debug!(
                    "File fact that doesn't hold: {:?}, path: {:?}",
                    fact, path_name
                );
                return false;
            }
        }
    }
    true
}

// Function that takes ExecSyscallEvents and generates the file preconditions
// and file postconditions. It returns a new Preconditions struct.
pub fn generate_preconditions(events: ExecSyscallEvents) -> Preconditions {
    let dir_events = events.dir_events();
    let file_events = events.file_events();

    let dir_preconds = generate_dir_preconditions(dir_events);
    let file_preconds = generate_file_preconditions(dir_preconds.clone(), file_events);

    Preconditions::new(dir_preconds, file_preconds)
}

// Function that takes in the directory events map (Resource --> List of Events)
// and genenerates a directory preconditions map (Resource --> Set of Facts)
// It iterates through each Resource's List of Events, like a state machine.
// Once a directory is modified, there are no more preconditions to learn.
pub fn generate_dir_preconditions(
    dir_events: HashMap<Accessor, Vec<DirEvent>>,
) -> HashMap<PathBuf, HashSet<Fact>> {
    let sys_span = span!(Level::INFO, "generate_dir_preconditions");
    let _ = sys_span.enter();
    let mut curr_dir_preconditions: HashMap<PathBuf, HashSet<Fact>> = HashMap::new();

    // Set the map up with all the resources from the dir events map.
    for accessor in dir_events.keys() {
        // For preconditions, I am not concerned with who accessed it (child or
        // parent) because I only care about that for outputs and deciding whether
        // to copy or hardlink.
        let path = accessor.path();
        curr_dir_preconditions.insert(path.to_path_buf(), HashSet::new());
    }

    // Main state machine loop.
    for (accessor, event_list) in &dir_events {
        let full_path = &accessor.path();

        // 3 pieces of state help us to add / remove / update the preconditions
        // of a resource on each iteration.
        // First state = did the resource exist at the start?
        // Last mod = what was the last modification to happen to the resource?
        // (None, Renamed, Created, etc.)
        // Has been deleted = just that, has the resource been deleted at some point?
        let mut first_state_struct = FirstState(State::None);
        let mut last_mod_struct = LastMod(Mod::None);
        let mut has_been_deleted = false;

        for event in event_list {
            let first_state = first_state_struct.state();
            let last_mod = last_mod_struct.state();

            match (event.clone(), first_state, last_mod, has_been_deleted) {
                (_, _, Mod::Modified, _) => {
                    panic!("Dirs don't use last mod: modified!!");
                }
                // Used to nest events from progeny to parent process, not used
                // to generate preconditions or postconditions.
                (DirEvent::ChildExec(_), _, _, _) => (),
                // For create: if we have MODIFIED the dir in some way,
                // we aren't going to get more info out of it for the preconditions.
                (DirEvent::Create(_, _), _, _, true) => (),
                (DirEvent::Create(root_dir, outcome), State::None, last_mod, false) => {
                    if *last_mod == Mod::None {
                        let curr_set = curr_dir_preconditions.get_mut(full_path).unwrap();
                        match outcome {
                            SyscallOutcome::Success => {
                                let mut flags = AccessFlags::empty();
                                flags.insert(AccessFlags::W_OK);
                                flags.insert(AccessFlags::X_OK);
                                // We have write perm to root dir and the created dir didn't already exist.
                                curr_set
                                    .insert(Fact::HasDirPermission((flags).bits(), Some(root_dir)));
                                curr_set.insert(Fact::DoesntExist);
                            }
                            SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                                curr_set.insert(Fact::Exists);
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                // Right now just taking into account write permission to the root dir.
                                let mut flags = AccessFlags::empty();
                                flags.insert(AccessFlags::W_OK);
                                flags.insert(AccessFlags::X_OK);
                                curr_set
                                    .insert(Fact::NoDirPermission((flags).bits(), Some(root_dir)));
                            }
                            f => panic!("Unexpected failure mkdir: {:?}", f),
                        }
                    } else {
                        panic!("First state is none but last mod was: {:?}!!", last_mod);
                    }
                }
                // The last mod wsa created, so this won't succeed.
                (DirEvent::Create(_, _), State::DoesntExist, Mod::Created, false) => (),
                (DirEvent::Create(_, _), State::DoesntExist, Mod::Deleted, false) => {
                    panic!("Last mod deleted but has_been_deleted = false??");
                }
                // Old path was last renamed. It can be created. But we already know
                // existence, and we know we have dir permissions because it had
                // to be created and then renamed.
                (
                    DirEvent::Create(_, _),
                    State::DoesntExist | State::Exists,
                    Mod::Renamed(_, _),
                    false,
                ) => (),
                (DirEvent::Create(root_dir, outcome), State::DoesntExist, Mod::None, false) => {
                    // We know it doesn't exist. We might be able to create it!
                    let curr_set = curr_dir_preconditions.get_mut(full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            // We have write perm and x perm to root dir and the created dir didn't already exist.
                            curr_set.insert(Fact::HasDirPermission((flags).bits(), Some(root_dir)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission((flags).bits(), Some(root_dir)));
                        }
                        f => panic!("Unexpected failure mkdir: {:?}", f),
                    }
                }
                (DirEvent::Create(_, _), State::Exists, Mod::Created, false) => {
                    panic!("First state exists, last mod created, but not deleted??");
                }
                (DirEvent::Create(_, _), State::Exists, Mod::Deleted, false) => {
                    panic!("Last mod deleted but has_been_deleted is false!!");
                }
                (DirEvent::Create(root_dir, outcome), State::Exists, Mod::None, false) => {
                    match outcome {
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            // Need W and X perm to parent dir.
                            let curr_set = curr_dir_preconditions.get_mut(full_path).unwrap();
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission((flags).bits(), Some(root_dir)));
                        }
                        SyscallOutcome::Fail(_) => (),
                        SyscallOutcome::Success => {
                            panic!("First state exists, hasn't been deleted, but we are successfully creating??");
                        }
                    }
                }
                (DirEvent::Delete(_), _, Mod::None, true) => {
                    panic!("Last mod none, but has_been_deleted = true??");
                }
                (DirEvent::Delete(_), _, Mod::Deleted, false) => {
                    panic!("Last mod deleted but has_been_deleted = false??");
                }
                // Was created, deleted, created, now: should be able to delete it.
                // Panic if it doesn't succeed.
                (DirEvent::Delete(outcome), State::DoesntExist, Mod::Created, false) => {
                    if outcome != SyscallOutcome::Success {
                        panic!("Last mod was created, but failed to delete: {:?}", outcome);
                    } else {
                        has_been_deleted = true;
                    }
                }
                (DirEvent::Delete(outcome), State::DoesntExist, Mod::Created, true) => {
                    if outcome != SyscallOutcome::Success {
                        panic!("Last mod was created, but failed to delete: {:?}", outcome);
                    }
                }
                (DirEvent::Delete(outcome), State::DoesntExist, Mod::Deleted, true) => {
                    if outcome != SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) {
                        panic!("Last mod was deleted, unexpected outcome from trying to delete now: {:?}", outcome);
                    }
                }
                // It may have been created, then definitely renamed. This delete won't succeed.
                // It also won't tell us anything.
                (
                    DirEvent::Delete(_),
                    State::DoesntExist | State::Exists,
                    Mod::Renamed(_, _),
                    _,
                ) => (),
                // This should fail, we know it doesn't exist, we know no mods have happened.
                (DirEvent::Delete(outcome), State::DoesntExist, Mod::None, false) => {
                    match outcome {
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            // Need W and X perm to parent dir.
                            let curr_set = curr_dir_preconditions.get_mut(full_path).unwrap();
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission((flags).bits(), None));
                            has_been_deleted = true;
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => (),
                        o => panic!(
                            "Doesn't exist, no mods, unexpected outcome from rmdir: {:?}",
                            o
                        ),
                    }
                }
                // It existed at the start. Then it was deleted. Last it was created.
                // This *should* succeed.
                (DirEvent::Delete(outcome), State::Exists, Mod::Created, true) => {
                    if outcome != SyscallOutcome::Success {
                        panic!("Last mod was created, but we are failing to delete??");
                    }
                }
                (DirEvent::Delete(_), State::Exists, Mod::Created, false) => {
                    panic!("Existed at start, last mod created, but hasn't been deleted??");
                }
                (DirEvent::Delete(outcome), State::Exists, Mod::Deleted, true) => {
                    if outcome == SyscallOutcome::Success {
                        panic!("Last mod deleted, but delete succeeds??");
                    }
                }
                // We know it exists, and it has not been modified.
                (DirEvent::Delete(outcome), State::Exists, Mod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            // W + X access to the parent dir.
                            let curr_set = curr_dir_preconditions.get_mut(full_path).unwrap();
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::HasDirPermission((flags).bits(), None));
                            has_been_deleted = true;
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let curr_set = curr_dir_preconditions.get_mut(full_path).unwrap();
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission((flags).bits(), None));
                        }
                        SyscallOutcome::Fail(f) => {
                            panic!("Existed at start, no mods, failed to rmdir for strange reason: {:?}", f);
                        }
                    }
                }
                (DirEvent::Delete(outcome), State::None, last_mod, deleted_previously) => {
                    if *last_mod == Mod::None {
                        let curr_set = curr_dir_preconditions.get(full_path).unwrap().clone();
                        let curr_set_mut = curr_dir_preconditions.get_mut(full_path).unwrap();
                        match outcome {
                            SyscallOutcome::Success => {
                                if !curr_set.contains(&Fact::DoesntExist) {
                                    let mut flags = AccessFlags::empty();
                                    flags.insert(AccessFlags::W_OK);
                                    flags.insert(AccessFlags::X_OK);
                                    // We have write perm to root dir and the created dir didn't already exist.
                                    curr_set_mut
                                        .insert(Fact::HasDirPermission((flags).bits(), None));
                                    curr_set_mut.insert(Fact::Exists);
                                }
                                if !deleted_previously {
                                    has_been_deleted = true;
                                } else {
                                    panic!("Last mod was none but has been deleted is true??");
                                }
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                // Right now just taking into account write permission to the root dir.
                                let mut flags = AccessFlags::empty();
                                flags.insert(AccessFlags::W_OK);
                                flags.insert(AccessFlags::X_OK);
                                curr_set_mut.insert(Fact::NoDirPermission((flags).bits(), None));
                            }
                            f => panic!("Unexpected failure rmdir: {:?}", f),
                        }
                    } else {
                        panic!("First state is none but last mod was: {:?}!!", last_mod);
                    }
                }
                (DirEvent::Read(full_path, entries, outcome), _, _, _) => {
                    let curr_set = curr_dir_preconditions.get(&full_path).unwrap().clone();
                    let curr_set_mut = curr_dir_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set_mut.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Success => {
                            if !curr_set.contains(&Fact::DoesntExist) {
                                curr_set_mut.insert(Fact::DirEntriesMatch(entries));
                            }
                        }
                        _ => panic!("Unexpected outcome for directory read! {:?}", outcome),
                    }
                }
                (DirEvent::Rename(_, _, _), _, Mod::None, true) => {
                    panic!("Last mod none but has_been_deleted = true??");
                }
                (DirEvent::Rename(_, _, _), _, Mod::Deleted, false) => {
                    panic!("Last mod was deleted, but has_been_deleted = false??");
                }
                // Okay! Old_path didn't exist. Then it was created. That was its last mod.
                // Now it's being renamed. If rename was the first thing, we'd learn existence,
                // and W and X access to the dir. We already know the existence and we know
                // the dir perms because the last mod was created.
                (DirEvent::Rename(_, _, _), State::DoesntExist, Mod::Created, _) => (),
                // Not handling no replace for now, so no preconds for new path contributed.
                // We already know starting existence and that we can wx the dir. Nothing to learn.
                // Rename just overwrites new path if it's there, so we don't learn preconditions
                // about it.
                (DirEvent::Rename(_, _, outcome), State::DoesntExist, Mod::Deleted, true) => {
                    if outcome == SyscallOutcome::Success {
                        panic!("Last mod deleted but rename was successful??");
                    }
                }
                // It didn't exist. It was created. It was renamed. a -> b. Now they are trying to do
                // b -> c. Do we learn anything? No.
                // Not handling no replace.
                (DirEvent::Rename(_, _, _), State::DoesntExist, Mod::Renamed(_, _), _) => (),
                // It didn't exist, hasn't been created. This should not succeed.
                (DirEvent::Rename(_, _, outcome), State::DoesntExist, Mod::None, false) => {
                    if outcome == SyscallOutcome::Success {
                        panic!("Doesn't exist, no mods, but rename successful??");
                    }
                }
                // It existed, was deleted, was created again. Sure it can be renamed don't
                // see why not. We don't learn anything new though.
                (DirEvent::Rename(_, _, _), State::Exists, Mod::Created, true) => (),
                (DirEvent::Rename(_, _, _), State::Exists, Mod::Created, false) => {
                    panic!("Didn't exist at start, last mod created, but hasn't been deleted??");
                }
                // It was just deleted. Should not succeed. Gives us nothing.
                (DirEvent::Rename(_, _, outcome), State::Exists, Mod::Deleted, true) => {
                    if outcome == SyscallOutcome::Success {
                        panic!("Last mod deleted but rename was successful??");
                    }
                }
                // It existed at start. It was renamed. We aren't going to learn anything new.
                (DirEvent::Rename(_, _, _), State::Exists, Mod::Renamed(_, _), _) => (),
                // It existed at start, has not been modified. We should be able to rename it.
                // If this succeeds we know we are W+X for the parent dir.
                (DirEvent::Rename(_, new_path, outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_dir_preconditions.get_mut(full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::NoDirPermission(flags.bits(), None));
                        }
                        SyscallOutcome::Fail(f) => {
                            panic!("Existed at start, no mods, failed to rename dir for unexpected reason: {:?}", f);
                        }
                        SyscallOutcome::Success => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            curr_set.insert(Fact::HasDirPermission(flags.bits(), None));
                            curr_dir_preconditions
                                .insert(new_path, HashSet::from([Fact::DoesntExist]));
                        }
                    }
                }
                (DirEvent::Rename(_, new_path, outcome), State::None, last_mod, _) => {
                    let curr_set = curr_dir_preconditions.get(full_path).unwrap().clone();
                    let curr_set_mut = curr_dir_preconditions.get_mut(full_path).unwrap();

                    if *last_mod == Mod::None {
                        match outcome {
                            SyscallOutcome::Success => {
                                // This is the first time we are seeing this dir! Hello dir!
                                // It has been successfully renamed. So we know it existed at
                                // the start. Unless this is a rename after a rename...
                                if !curr_set.contains(&Fact::DoesntExist) {
                                    curr_set_mut.insert(Fact::Exists);
                                    let mut flags = AccessFlags::empty();
                                    flags.insert(AccessFlags::W_OK);
                                    flags.insert(AccessFlags::X_OK);
                                    curr_set_mut.insert(Fact::HasDirPermission(flags.bits(), None));
                                }
                                curr_dir_preconditions
                                    .insert(new_path, HashSet::from([Fact::DoesntExist]));
                            }
                            SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                                curr_set_mut.insert(Fact::DoesntExist);
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                // We don't have some necessary permission to the parent dir.
                                let mut flags = AccessFlags::empty();
                                flags.insert(AccessFlags::W_OK);
                                flags.insert(AccessFlags::X_OK);
                                curr_set_mut.insert(Fact::NoDirPermission(flags.bits(), None));
                            }
                            _ => (),
                        }
                    } else {
                        panic!("First state is none but last mod was: {:?}!!", last_mod);
                    }
                }
                // This directory was deleted, so the statfs will fail.
                (DirEvent::Statfs(_, _), _, _, true) => (),
                // Dir doesn't exist, this statfs will fail.
                (DirEvent::Statfs(_, _), State::DoesntExist, _, _) => (),
                (DirEvent::Statfs(option_statfs, outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_dir_preconditions.get(full_path).unwrap().clone();
                    let curr_set_mut = curr_dir_preconditions.get_mut(full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            if !curr_set.contains(&Fact::DoesntExist) {
                                if let Some(statfs) = option_statfs {
                                    curr_set_mut.insert(Fact::StatFsStructMatches(statfs));
                                    curr_set_mut.insert(Fact::HasDirPermission(
                                        (AccessFlags::X_OK).bits(),
                                        None,
                                    ));
                                } else {
                                    panic!("No statfs struct found for successful statfs syscall!");
                                }
                            }
                        }
                        // This really should succeed. We know it exists, so we must also have X permission
                        // to its parent dir.
                        SyscallOutcome::Fail(f) => {
                            panic!("Unexpected syscall failure for statfs, file existed at start, no mods: {:?}", f);
                        }
                    }
                }
                // Doesn't event make sense.
                (DirEvent::Statfs(_, _), State::Exists, Mod::Created, false) => {
                    panic!("Existed at start, last mod created, but hasn't been deleted??");
                }
                // Doesn't event make sense.
                (DirEvent::Statfs(_, _), State::Exists, Mod::Deleted, false) => {
                    panic!("Existed at start, last mod deleted, but hasn't been marked has_been_deleted??");
                }
                (DirEvent::Statfs(_, _), State::Exists, Mod::Renamed(_, _), false) => (),
                (DirEvent::Statfs(option_statfs, outcome), State::None, last_mod, false) => {
                    let curr_set = curr_dir_preconditions.get(full_path).unwrap().clone();
                    let curr_set_mut = curr_dir_preconditions.get_mut(full_path).unwrap();
                    if *last_mod == Mod::None {
                        match outcome {
                            SyscallOutcome::Success => {
                                if !curr_set.contains(&Fact::DoesntExist) {
                                    if let Some(statfs) = option_statfs {
                                        curr_set_mut.insert(Fact::StatFsStructMatches(statfs));
                                        curr_set_mut.insert(Fact::HasDirPermission(
                                            (AccessFlags::X_OK).bits(),
                                            None,
                                        ));
                                    } else {
                                        panic!(
                                            "No statfs struct found for successful statfs syscall!"
                                        );
                                    }
                                }
                            }
                            SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                                curr_set_mut.insert(Fact::DoesntExist);
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                curr_set_mut.insert(Fact::NoDirPermission(
                                    (AccessFlags::X_OK).bits(),
                                    None,
                                ));
                            }
                            SyscallOutcome::Fail(f) => {
                                panic!("Unexpected syscall failure for statfs: {:?}", f);
                            }
                        }
                    } else {
                        panic!("Starting state is none, but last mod was: {:?}", last_mod);
                    }
                }
            }
            // This function will only change the first_state if it is None.
            first_state_struct.update_based_on_dir_event(full_path, event.clone());
            last_mod_struct.update_based_on_dir_event(event.clone());
        }
    }
    curr_dir_preconditions
}

// Takes in all file events (and also dir preconditions, which are used
// to compute file preconditions) and computes all file preconditions.
pub fn generate_file_preconditions(
    dir_preconditions: HashMap<PathBuf, HashSet<Fact>>,
    file_events: HashMap<Accessor, Vec<FileEvent>>,
) -> HashMap<PathBuf, HashSet<Fact>> {
    let sys_span = span!(Level::INFO, "generate_file_preconditions");
    let _ = sys_span.enter();
    let mut curr_file_preconditions: HashMap<PathBuf, HashSet<Fact>> = HashMap::new();

    // Prep the new map by inserting all the keys into it.
    for accessor in file_events.keys() {
        // For preconditions, I am not concerned with with who accessed.
        let path = accessor.path();
        curr_file_preconditions.insert(path.to_path_buf(), HashSet::new());
    }

    // Main loop to iterate over events and generate preconditions.
    for (accessor, event_list) in &file_events {
        let full_path = accessor.path();

        // Here we can see if the parent dir of this path
        // was created by the exec.
        let parent_dir = full_path.parent().unwrap();
        let parent_dir_was_created_by_exec =
            dir_created_by_exec(PathBuf::from(parent_dir), dir_preconditions.clone());
        // Initialize our state variables so we can compute the preconditions.
        let mut first_state_struct = FirstState(State::None);
        let mut last_mod_struct = LastMod(Mod::None);
        let mut has_been_deleted = false;

        for event in event_list {
            let first_state = first_state_struct.state();
            let last_mod = last_mod_struct.state();

            match (event.clone(), first_state, last_mod, has_been_deleted) {
                (_, _, Mod::None, true) => {
                    panic!("Last mod was none but was deleted is true??");
                }
                (_, State::Exists, Mod::Created, false) => {
                    panic!("Last mod was created, but was deleted is false, and file existed at start??");
                }
                (_, _, Mod::Deleted, false) => {
                    panic!("Last mod was deleted, but was deleted is false??, path: {:?}", full_path);
                }
                (FileEvent::Access(_, _), State::DoesntExist, _, _) => {
                    // Didn't exist, was created, this access depends on a file that was created during execution,
                    // does not contribute to preconditions.
                }
                // Your access depends on a file I don't know nothing about.
                (FileEvent::Access(_, _), State::Exists, _, true) => (),
                // It existed, it hasn't been deleted, these priveleges depend on a file from
                // BEFORE the execution :O
                (FileEvent::Access(flags, outcome), State::Exists, _, false) => {
                    // It existed, it hasn't been deleted, these priveleges depend on a file from
                    // BEFORE the execution :O
                    match outcome {
                        SyscallOutcome::Success => {
                            let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
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
                (FileEvent::Access(_, _), State::None, Mod::Created, _) => {
                    panic!("No first state but last mod was created??");
                }
                (FileEvent::Access(_, _), State::None, Mod::Deleted, _) => {
                    panic!("No first state but last mod was deleted??");
                }
                (FileEvent::Access(_, _), State::None, Mod::Modified, _) => {
                    panic!("No first state but last mod was modified??");
                }
                (FileEvent::Access(_, _), State::None, Mod::Renamed(_,_), _) => {
                    panic!("No first state but last mod was renamed??");
                }
                (FileEvent::Access(flags, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get(&full_path).unwrap().clone();
                    let curr_set_mut = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            if !curr_set.contains(&Fact::DoesntExist) {
                                let flag_set = AccessFlags::from_bits(flags).unwrap();
                                if flag_set.contains(AccessFlags::F_OK) {
                                    curr_set_mut.insert(Fact::Exists);
                                } else {
                                    curr_set_mut.insert(Fact::HasPermission(flags));
                                }
                            }
                            if !parent_dir_was_created_by_exec {
                                curr_set_mut.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits(), None));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set_mut.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            if parent_dir_was_created_by_exec {
                                curr_set_mut.insert(Fact::NoPermission(flags));
                            } else {
                                // Either we don't have exec access to the dir
                                // Or we don't have these perms on this file
                                curr_set_mut.insert(Fact::Or(Box::new(Fact::NoDirPermission((AccessFlags::X_OK).bits(), None)), Box::new(Fact::NoPermission(flags))));
                            }
                        }
                        o => panic!("Unexpected access syscall failure: {:?}", o),
                    }
                }
                (FileEvent::ChildExec(_), _, _, _) => (),
                (FileEvent::Create(_, _), State::DoesntExist, Mod::Created, _) => (),
                (FileEvent::Create(_, _), State::DoesntExist, Mod::Deleted, true) => (),

                (FileEvent::Create(_, _), State::DoesntExist, Mod::Modified, true) => (),
                (FileEvent::Create(_, _), State::DoesntExist, Mod::Modified, false) => (),
                (FileEvent::Create(_, _), State::DoesntExist, Mod::Renamed(_, _), _) => (),
                (FileEvent::Create(mode, outcome), State::DoesntExist, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::DoesntExist);
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::HasDirPermission((flags).bits(), None));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            // Don't need OR because both facts are about the dir,
                            // so we can save an access call!
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::NoDirPermission((flags).bits(), None));
                            }
                        }
                        f => panic!("Unexpected create {:?} file failure, didn't exist at start no other changes: {:?}", mode, f),
                    }
                }

                (FileEvent::Create(_, _), State::Exists, Mod::Created, true) => (),
                (FileEvent::Create(_, _), State::Exists, Mod::Deleted, true) => (),
                (FileEvent::Create(_, _), State::Exists, Mod::Modified, true) => (),
                (FileEvent::Create(_, _), State::Exists, Mod::Modified, false) => (),
                (FileEvent::Create(_, _), State::Exists, Mod::Renamed(_, _), _) => (),
                (FileEvent::Create(_, _), State::Exists, Mod::None, false) => (),
                (FileEvent::Create(_, _), State::None, Mod::Created, _) => {
                    panic!("First state none but last mod created??");
                }
                (FileEvent::Create(_, _), State::None, Mod::Deleted, true) => {
                    panic!("First state none but last mod deleted??");
                }
                (FileEvent::Create(_, _), State::None, Mod::Modified, _) => {
                    panic!("First state none but last mod modified??");
                }
                (FileEvent::Create(_, _), State::None, Mod::Renamed(_, _), _) => {
                    panic!("First state none but last mod renamed??");
                }
                (FileEvent::Create(OFlag::O_CREAT, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::DoesntExist);
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::HasDirPermission((flags).bits(), None));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            // Both facts are about the dir so we can just make
                            // one access call.
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::NoDirPermission((flags).bits(), None));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            curr_set.insert(Fact::Exists);
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => (),
                        f => panic!("Unexpected create file failure, no state yet: {:?}", f),
                    }
                }
                (FileEvent::Create(OFlag::O_EXCL, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::DoesntExist);
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::HasDirPermission((flags).bits(), None));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::NoDirPermission((flags).bits(), None));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            curr_set.insert(Fact::Exists);
                        }
                        f => panic!("Unexpected create file failure, no state yet: {:?}", f),
                    }
                }
                (FileEvent::Create(f, _), _, _, _) => panic!("Unexpected create flag: {:?}", f),
                (FileEvent::Delete(_), State::DoesntExist, Mod::Created, true) => (),
                (FileEvent::Delete(outcome), State::DoesntExist, Mod::Created, false) => {
                    if outcome == SyscallOutcome::Success {
                        has_been_deleted = true;
                    }
                }
                (FileEvent::Delete(_), State::DoesntExist, Mod::Deleted, true) => (),
                (FileEvent::Delete(_), State::DoesntExist, Mod::Modified, true) => (),
                // It didn't exist, was created, was modified, we might be deleting it now.
                (FileEvent::Delete(outcome), State::DoesntExist, Mod::Modified, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, was created, last mod modified, no delete yet: {:?}", f),
                    }
                }
                // old path? didnt exist, created, renamed. now trying to delete. won't succeed it doesnt exist anymore.
                // No new path event right now
                (FileEvent::Delete(_), State::DoesntExist, Mod::Renamed(_, _), _) => (),
                (FileEvent::Delete(outcome), State::DoesntExist, Mod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, was created, last mod modified, no delete yet: {:?}", f),
                    }
                }
                (FileEvent::Delete(_), State::Exists, Mod::Created, true) => (),
                (FileEvent::Delete(_), State::Exists, Mod::Deleted, true) => (),
                (FileEvent::Delete(_), State::Exists, Mod::Modified, true) => (),
                (FileEvent::Delete(outcome), State::Exists, Mod::Modified, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, exists, last mod modified, no delete yet: {:?}", f),
                    }
                }
                (FileEvent::Delete(_), State::Exists, Mod::Renamed(_,_), true) => (),
                (FileEvent::Delete(outcome), State::Exists, Mod::Renamed(_, _), false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, exists, last mod renamed, no delete yet: {:?}", f),
                    }
                }
                (FileEvent::Delete(outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::HasDirPermission((flags).bits(), None));
                            }
                            has_been_deleted = true;
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::NoDirPermission((flags).bits(), None));
                            }
                        }
                        f => panic!("Delete failed for unexpected reason, exists, no mods: {:?}", f),
                    }
                }
                (FileEvent::Delete(_), State::None, Mod::Created, _) => {
                    panic!("First state was none but last mod was created??");
                }
                (FileEvent::Delete(_), State::None, Mod::Deleted, _) => {
                    panic!("First state was none but last mod was deleted??");
                }
                // None state can be because TRUNC
                (FileEvent::Delete(_), State::None, Mod::Modified, true) => (),
                (FileEvent::Delete(outcome), State::None, Mod::Modified, false) => {
                    if outcome == SyscallOutcome::Success {
                        has_been_deleted = true;
                    }
                }
                (FileEvent::Delete(_), State::None, Mod::Renamed(_,_), _) => {
                    panic!("First state was none but last mod was renamed??");
                }
                (FileEvent::Delete(outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get(&full_path).unwrap().clone();
                    let curr_set_mut = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            if !curr_set.contains(&Fact::DoesntExist) {
                                curr_set_mut.insert(Fact::Exists);
                            }
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set_mut.insert(Fact::HasDirPermission((flags).bits(), None));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set_mut.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set_mut.insert(Fact::NoDirPermission((flags).bits(), None));
                            }
                        }
                        f => panic!("Unexpected failure from delete event: {:?}", f),
                    }
                }
                (FileEvent::FailedExec(failure), _, _, _) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match failure {
                        SyscallFailure::FileDoesntExist => {
                            curr_set.insert(Fact::DoesntExist);
                        }
                        SyscallFailure::PermissionDenied => {
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::NoDirPermission((AccessFlags::X_OK).bits(), None));
                            }
                        }
                        _ => panic!("Unexpected failure from execve!: {:?}", failure),
                    }
                }
                (FileEvent::Open(_, _, _, _), _, Mod::Renamed(_, _), _) => (),
                (
                    FileEvent::Open(_, _, _, outcome),
                    State::DoesntExist,
                    Mod::Created,
                    true,
                ) => {
                    // It didn't exist, was created, was deleted, was created. Oof.
                    // We already know x and w access, and the contents don't depend on file at the start.
                    // fail: already exists? makes no sense. doesn't exist? makes no sense. permission denied? makes no sense.
                    if let SyscallOutcome::Fail(f) = outcome {
                        panic!(
                            "Open failed for strange reason, last mod created: {:?}",
                            f
                        );
                    }
                }

                (FileEvent::Open(_, _, _, _), State::DoesntExist, Mod::Created, false) => {
                    // Created, so not contents. not exists. we made the file in the exec so perms depend
                    // on that. and we already know x dir because we created the file at some point.
                    // So this just gives us nothing. (append, read, or trunc)
                }

                (FileEvent::Open(_, _, _, _), State::DoesntExist, Mod::Deleted, true) => {
                    // We created it. We deleted it. So we already know x dir. The perms depend on making the file during the execution.
                    // Same with contents.(append, read, or trunc)
                }
                (FileEvent::Open(_,  _, _, _), State::DoesntExist, Mod::Modified, _) => {
                    // Doesn't exist. Created, modified, maybe deleted and the whole process repeated.
                }
                (FileEvent::Open(_, _, _, _), State::DoesntExist, Mod::None, false) => {
                    // We know this doesn't exist, we know we haven't created it.
                    // This will just fail.
                }
                (FileEvent::Open(_, _, _, _), State::Exists, _, true) => {
                    // We know it existed at the start, so we have accessed it in some way.
                    // It has been deleted. Anything we do to it now is based on
                    // the file that was created during exec after the OG
                    // one was deleted. So no more preconditions contributed.
                }
                (FileEvent::Open(_, _,  _,_), State::Exists, Mod::Modified, false) => (),
                (FileEvent::Open(access_mode, Some(OffsetMode::Append), optional_check_mech, outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    if access_mode == AccessMode::Read {
                        panic!("Open for append with read access mode!!");
                    }
                    match outcome {
                        SyscallOutcome::Success => {
                            if let Some(check_mech) = optional_check_mech {
                                match check_mech {
                                    CheckMechanism::DiffFiles => {
                                        curr_set.insert(Fact::InputFileDiffsMatch);
                                    }
                                    CheckMechanism::Hash(hash) => {
                                        let hash = if DONT_HASH_FILES {
                                            Vec::new()
                                        } else {
                                            hash
                                        };
                                        curr_set.insert(Fact::InputFileHashesMatch(hash));
                                    }
                                    CheckMechanism::Mtime(mtime) => {
                                        curr_set.insert(Fact::Mtime(mtime));
                                    }
                                }
                            }

                            if access_mode == AccessMode::Both {
                                curr_set.insert(Fact::HasPermission((AccessFlags::R_OK).bits()));
                            }
                            curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits(), None));
                            curr_set.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            // Here is a case where we want to use a box.
                            // Whenever permission is denied, and this could pertain to either
                            // the dir or the file.
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            if access_mode == AccessMode::Both {
                                flags.insert(AccessFlags::R_OK);
                            }
                            curr_set.insert(Fact::Or(Box::new(Fact::NoDirPermission((AccessFlags::X_OK).bits(), None)), Box::new(Fact::NoPermission(flags.bits()))));
                        }
                        f => panic!("Unexpected open append failure, file existed, {:?}", f),
                    }
                }
                (FileEvent::Open(access_mode, None, optional_check_mech, outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            if let Some(check_mech) = optional_check_mech {
                                match check_mech {
                                    CheckMechanism::DiffFiles => {
                                        curr_set.insert(Fact::InputFileDiffsMatch);
                                    }
                                    CheckMechanism::Hash(hash) => {
                                        let hash = if DONT_HASH_FILES {
                                            Vec::new()
                                        } else {
                                            hash
                                        };
                                        curr_set.insert(Fact::InputFileHashesMatch(hash));
                                    }
                                    CheckMechanism::Mtime(mtime) => {
                                        curr_set.insert(Fact::Mtime(mtime));
                                    }
                                }
                            }
                            curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits(), None));
                            match access_mode {
                                AccessMode::Read => {curr_set.insert(Fact::HasPermission((AccessFlags::R_OK).bits()));}
                                AccessMode::Write => {curr_set.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));}
                                AccessMode::Both => {
                                    curr_set.insert(Fact::HasPermission((AccessFlags::R_OK).bits()));
                                    curr_set.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                                }
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            match access_mode {
                                AccessMode::Read => {flags.insert(AccessFlags::R_OK);}
                                AccessMode::Write => {flags.insert(AccessFlags::W_OK);}
                                AccessMode::Both => {
                                    flags.insert(AccessFlags::R_OK);
                                    flags.insert(AccessFlags::W_OK);
                                }
                            }
                            curr_set.insert(Fact::Or(Box::new(Fact::NoDirPermission((AccessFlags::X_OK).bits(), None)), Box::new(Fact::NoPermission(flags.bits()))));
                        }
                        f => panic!("Unexpected open none failure, file existed, {:?}", f),
                    }
                }
                (FileEvent::Open(access_mode, Some(OffsetMode::Trunc), _,outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match access_mode {
                        AccessMode::Read => panic!("Access mode is read with offset trunc!!"),
                        mode => {
                            match outcome {
                                SyscallOutcome::Success => {
                                    curr_set.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits(), None));
                                    curr_set.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                                    if mode == AccessMode::Both {
                                        curr_set.insert(Fact::HasPermission((AccessFlags::R_OK).bits()));
                                    }
                                }
                                SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                    let mut flags = AccessFlags::empty();
                                        flags.insert(AccessFlags::W_OK);
                                        if mode == AccessMode::Both {
                                            flags.insert(AccessFlags::R_OK);
                                        }
                                    curr_set.insert(Fact::Or(Box::new(Fact::NoDirPermission((AccessFlags::X_OK).bits(), None)), Box::new(Fact::NoPermission(flags.bits()))));
                                }
                                f => panic!("Unexpected open append failure, file existed, {:?}", f),
                            }
                        }
                    }
                }
                (FileEvent::Open(_, _,  _,_), State::None, Mod::Created, _) => {
                    panic!("First state none but last mod created??");
                }
                (FileEvent::Open(_, _,  _,_), State::None, Mod::Deleted, true) => {
                    panic!("First state none but last mod deleted??");
                }
                (FileEvent::Open(_, _, _,_), State::None, Mod::Modified, _) => {
                    panic!("First state none but last mod modified??");
                }
                (FileEvent::Open(access_mode, Some(OffsetMode::Append),  optional_check_mech, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get(&full_path).unwrap().clone();
                    let curr_set_mut = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match access_mode {
                        AccessMode::Read => panic!("Access mode is read with offset append!!"),
                        mode => {
                            match outcome {
                                SyscallOutcome::Success => {
                                    if let Some(check_mech) = optional_check_mech {
                                        match check_mech {
                                            CheckMechanism::DiffFiles => {
                                                curr_set_mut.insert(Fact::InputFileDiffsMatch);
                                            }
                                            CheckMechanism::Hash(hash) => {
                                                let hash = if DONT_HASH_FILES {
                                                    Vec::new()
                                                } else {
                                                    hash
                                                };
                                                curr_set_mut.insert(Fact::InputFileHashesMatch(hash));
                                            }
                                            CheckMechanism::Mtime(mtime) => {
                                                curr_set_mut.insert(Fact::Mtime(mtime));
                                            }
                                        }
                                    }
                                    if !parent_dir_was_created_by_exec {
                                        curr_set_mut.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits(), None));
                                    }
                                    if !curr_set.contains(&Fact::DoesntExist) {
                                        curr_set_mut.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                                        if mode == AccessMode::Both {
                                            curr_set_mut.insert(Fact::HasPermission((AccessFlags::R_OK).bits()));
                                        }
                                    }
                                }
                                SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                                    panic!("Open append, no info yet, failed because file already exists??");
                                }
                                SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                                    curr_set_mut.insert(Fact::DoesntExist);
                                }
                                SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                    let mut flags = AccessFlags::empty();
                                    flags.insert(AccessFlags::W_OK);
                                    if mode == AccessMode::Both {
                                        flags.insert(AccessFlags::R_OK);
                                    }
                                    if !parent_dir_was_created_by_exec {
                                        curr_set_mut.insert(Fact::Or(Box::new(Fact::NoDirPermission((AccessFlags::X_OK).bits(), None)), Box::new(Fact::NoPermission(flags.bits()))));
                                    }
                                }
                                SyscallOutcome::Fail(SyscallFailure::InvalArg) => (),
                            }
                        }
                    }
                }
                (FileEvent::Open(access_mode, Some(OffsetMode::Trunc), _, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get(&full_path).unwrap().clone();
                    let curr_set_mut = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match access_mode {
                        AccessMode::Read => panic!("Access mode is read with offset trunc!!"),
                        mode => {
                            match outcome {
                                SyscallOutcome::Success => {
                                    if !curr_set.contains(&Fact::DoesntExist) {
                                        let mut flags = AccessFlags::empty();
                                        flags.insert(AccessFlags::W_OK);
                                        if mode == AccessMode::Both {
                                            flags.insert(AccessFlags::R_OK);
                                        }
                                        curr_set_mut.insert(Fact::HasPermission((flags).bits()));
                                    }
                                    if !parent_dir_was_created_by_exec {
                                        curr_set_mut.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits(), None));
                                    }
                                }
                                SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                                    panic!("Open trunc, no info yet, failed because file already exists??");
                                }
                                SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                                    curr_set_mut.insert(Fact::DoesntExist);
                                }
                                SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                    let mut flags = AccessFlags::empty();
                                    flags.insert(AccessFlags::W_OK);
                                    if mode == AccessMode::Both {
                                        flags.insert(AccessFlags::R_OK);
                                    }

                                    if !parent_dir_was_created_by_exec {
                                        curr_set_mut.insert(Fact::Or(Box::new(Fact::NoDirPermission((AccessFlags::X_OK).bits(), None)), Box::new(Fact::NoPermission((flags).bits()))));
                                    }
                                }
                                SyscallOutcome::Fail(SyscallFailure::InvalArg) => (),
                            }
                        }
                    }
                }
                (FileEvent::Open(access_mode, None, optional_check_mech, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get(&full_path).unwrap().clone();
                    let curr_set_mut = curr_file_preconditions.get_mut(&full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            if let Some(check_mech) = optional_check_mech {
                                match check_mech {
                                    CheckMechanism::DiffFiles => {
                                        curr_set_mut.insert(Fact::InputFileDiffsMatch);
                                    }
                                    CheckMechanism::Hash(hash) => {
                                        let hash = if DONT_HASH_FILES {
                                            Vec::new()
                                        } else {
                                            hash
                                        };
                                        curr_set_mut.insert(Fact::InputFileHashesMatch(hash));
                                    }
                                    CheckMechanism::Mtime(mtime) => {
                                        curr_set_mut.insert(Fact::Mtime(mtime));
                                    }
                                }
                            }
                            if !curr_set.contains(&Fact::DoesntExist) {
                                match access_mode {
                                    AccessMode::Read => {curr_set_mut.insert(Fact::HasPermission((AccessFlags::R_OK).bits()));}
                                    AccessMode::Write => {curr_set_mut.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));}
                                    AccessMode::Both => {
                                        curr_set_mut.insert(Fact::HasPermission((AccessFlags::R_OK).bits()));
                                        curr_set_mut.insert(Fact::HasPermission((AccessFlags::W_OK).bits()));
                                    }
                                }
                            }
                            if !parent_dir_was_created_by_exec {
                                curr_set_mut.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits(), None));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            panic!("Open read only, no info yet, failed because file already exists??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set_mut.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            match access_mode {
                                AccessMode::Read => {curr_set_mut.insert(Fact::NoPermission((AccessFlags::R_OK).bits()));}
                                AccessMode::Write => {curr_set_mut.insert(Fact::NoPermission((AccessFlags::W_OK).bits()));}
                                AccessMode::Both => {
                                    curr_set_mut.insert(Fact::NoPermission((AccessFlags::R_OK).bits()));
                                    curr_set_mut.insert(Fact::NoPermission((AccessFlags::W_OK).bits()));
                                }
                            }
                            curr_set_mut.insert(Fact::NoDirPermission((AccessFlags::X_OK).bits(), None));
                            if !parent_dir_was_created_by_exec {
                                curr_set_mut.insert(Fact::Or(
                                    Box::new(Fact::NoPermission((AccessFlags::R_OK).bits())),
                                    Box::new(Fact::NoDirPermission((AccessFlags::X_OK).bits(), None)),
                                ));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::InvalArg) => (),
                    }
                }
                (
                    FileEvent::Rename(_, _, _),
                    State::DoesntExist,
                    Mod::Created,
                    _,
                ) => (),
                (FileEvent::Rename(_, _, _), State::DoesntExist, Mod::Deleted, true) => {
                    // Created. Deleted. Won't succeed because old path is deleted.
                    // Already exists no, doesn't exist, yes makes sense as an error.
                    // But doesn't contribute to the preconditions.
                    // Permission denied doesn't make sense either.
                }
                (FileEvent::Rename(_, _, _), State::DoesntExist, Mod::Modified, _) => {
                    // Created, deleted, created, modified. Oof.
                    // Already existe no, doesn't exist no, permissions no.
                    // Success tells us nothing new too.
                }
                (FileEvent::Rename(_, _, _), State::DoesntExist, Mod::Renamed(_,_), _) => {
                    // Created, deleted, created, renamed. Or Created, renamed.
                    // Already exists no, doesn't exist no, permissions no.
                    // Success tells us nothing for preconds.
                }
                (FileEvent::Rename(_, _, outcome), State::DoesntExist, Mod::None, false) => {
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
                        if !parent_dir_was_created_by_exec {
                            curr_set.insert(Fact::NoDirPermission((flags).bits(), None));
                        }
                    }
                }
                (FileEvent::Rename(_, _, _), State::Exists, Mod::Created, _) => {
                    // Existed. Deleted. Created! Or Existed. Created. Now renamin'.
                    // Already exists? no.
                    // Doesn't exist, no.
                    // Permissions denied, how?
                    // Success, cool.
                }
                (FileEvent::Rename(_, _, _), State::Exists, Mod::Deleted, true) => {
                    // Existed. Then was deleted.
                    // This will fail because the file doesn't exist.
                    // Success and already exist don't make sense. Same with permissions.
                    // Nothing contributes.
                }
                (FileEvent::Rename(_, _, _), State::Exists, Mod::Modified, _) => {
                    // Existed, Deleted, Created, Modified or Existed, Modified
                    // We should be able to rename this.
                    // Permissions no, doesn't exist no, already exists no.
                }
                (FileEvent::Rename(_, _, _), State::Exists, Mod::Renamed(_,_), _) => {
                    // Existed. Deleted. Created. Renamed. Or Existed, Renamed.
                    // Don't think this affects preconditions.
                    // Eventually we will handle rename flags where they don't wanna replace
                    // an existing file, and that will be a precondition.
                }
                (FileEvent::Rename(old_path, new_path, outcome), State::Exists, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    // It exists, we haven't modified it.
                    // It exists so we know that we have x access to the cwd.
                    // So if it succeeds we have to add those preconditions.
                    // oldpath preconds: exists, x w access
                    // newpath preconds: none (not handling flags)
                    if old_path == *full_path {
                        match outcome {
                            SyscallOutcome::Success => {
                                if !parent_dir_was_created_by_exec {
                                    curr_set.insert(Fact::HasDirPermission((AccessFlags::W_OK).bits(), None));
                                }
                                curr_file_preconditions.insert(new_path, HashSet::from([Fact::DoesntExist]));
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                // We may not have permission to write to the directory.
                                if !parent_dir_was_created_by_exec {
                                    curr_set.insert(Fact::NoDirPermission((AccessFlags::W_OK).bits(), None));
                                }
                            }
                            o => panic!("Unexpected failure in rename syscall event: {:?}", o),
                        }
                    }
                }
                (FileEvent::Rename(_, _, _), State::None, Mod::Created, _) => {
                    panic!("No first state but last mod was created??");
                }
                (FileEvent::Rename(_, _, _), State::None, Mod::Deleted, _) => {
                    panic!("No first state but last mod was deleted??");
                }
                (FileEvent::Rename(_, _, _), State::None, Mod::Modified, _) => {
                    panic!("No first state but last mod was modified??");
                }
                (FileEvent::Rename(_, _, _), State::None, Mod::Renamed(_,_), _) => {
                    panic!("No first state but last mod was renamed??");
                }
                (FileEvent::Rename(_, new_path, outcome), State::None, Mod::None, false) => {
                    // No first state, no mods, haven't deleted. This is the first thing we are doing to this
                    // resource probably.
                    let curr_set = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            // No need to check if old path == full path because we are not
                            // adding a rename event for new path, just old path (for now).
                            // First event is renaming and we see old path, add all the preconds.
                            curr_set.insert(Fact::Exists);
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::HasDirPermission(flags.bits(), None));
                            }
                            curr_file_preconditions.insert(new_path, HashSet::from([Fact::DoesntExist]));
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            // Old path doesn't exist cool.
                            curr_set.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let mut flags = AccessFlags::empty();
                            flags.insert(AccessFlags::W_OK);
                            flags.insert(AccessFlags::X_OK);
                            if !parent_dir_was_created_by_exec {
                                curr_set.insert(Fact::NoDirPermission(flags.bits(), None));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::InvalArg) => (),
                        o => panic!("Unexpected error for rename: {:?}", o),
                    }
                }

                (FileEvent::Stat(_, _), State::DoesntExist, Mod::Created, _) => {
                    // Didn't exist, created, deleted, created, this stat doesn't depend on
                    // a file that existed at the start. and obviously we have exec access to the dir.
                }
                (FileEvent::Stat(_, _), State::DoesntExist, Mod::Deleted, true) => {
                    // The file didn't exist. Then the file was created and deleted. Adds nothing.
                }
                (FileEvent::Stat(_, _), State::DoesntExist, Mod::Modified, _) => (),
                (FileEvent::Stat(_, _), State::DoesntExist, Mod::Renamed(_,_), _) => (),
                (FileEvent::Stat(_, outcome), State::DoesntExist, Mod::None, false) => {
                    match outcome {
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => (),
                        // Already know it exists so we don't need to add search perms
                        // on the parent dir as a precondition.
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => (),
                        _ => (),
                        // f => panic!("Unexpected failure by stat syscall, first state was doesn't exist, last mod none: {:?}", f),
                    }
                }
                // It existed at the start, but we have modified it, so this stat doesn't depend on
                // the file at the beginning of the computation.
                (FileEvent::Stat(_,_), State::Exists, Mod::Created, true) => (),
                (FileEvent::Stat(_,_), State::Exists, Mod::Deleted, true) => (),
                (FileEvent::Stat(_,_), State::Exists, Mod::Modified, true) => (),
                (FileEvent::Stat(_,_), State::Exists, Mod::Modified, false) => (),
                // Currently only going to get an event like this for old path (no event for new path means no last mod).
                // And this stat probably would fail anyway because the file was renamed.
                // Alternatively: this file has been deleted, no way the stat struct is gonna be the same.
                // (Could be either because of the _ in the has_been_deleted spot)
                (FileEvent::Stat(_,_), State::Exists, Mod::Renamed(_,_), _) => (),
                (FileEvent::Stat(option_stat, outcome), State::Exists, Mod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            let curr_set = curr_file_preconditions.get(&full_path).unwrap().clone();
                            let curr_set_mut = curr_file_preconditions.get_mut(&full_path).unwrap();

                            if !curr_set.contains(&Fact::DoesntExist) {
                                if !parent_dir_was_created_by_exec {
                                    curr_set_mut.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits(), None));
                                }
                                if let Some(stat) = option_stat {
                                    if !preconditions_contain_stat_fact(curr_set) {
                                        curr_set_mut.insert(Fact::StatStructMatches(stat.clone()));
                                    }
                                } else {
                                    panic!("No stat struct found for successful stat syscall!");
                                }
                            }
                        }
                        f => panic!("Unexpected failure of stat call, file exists: {:?}", f),
                    }
                }

                (FileEvent::Stat(_, _), State::None, Mod::Created, _) => {
                    panic!("First state was none but last mod was created??");
                }
                (FileEvent::Stat(_, _), State::None, Mod::Deleted, _) => {
                    panic!("First state was none but last mod was deleted??");
                }
                (FileEvent::Stat(_, _), State::None, Mod::Modified, _) => {
                    panic!("First state was none but last mod was modified??");
                }
                (FileEvent::Stat(_, _), State::None, Mod::Renamed(_,_), _) => {
                    panic!("First state was none but last mod was renamed??");
                }
                (FileEvent::Stat(option_stat, outcome), State::None, Mod::None, false) => {
                    let curr_set = curr_file_preconditions.get(&full_path).unwrap().clone();
                    let curr_set_mut = curr_file_preconditions.get_mut(&full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            if !curr_set.contains(&Fact::DoesntExist) {
                                if let Some(stat) = option_stat {
                                    if !preconditions_contain_stat_fact(curr_set) {
                                        curr_set_mut.insert(Fact::StatStructMatches(stat.clone()));
                                    }
                                    if !parent_dir_was_created_by_exec {
                                        curr_set_mut.insert(Fact::HasDirPermission((AccessFlags::X_OK).bits(), None));
                                    }
                                } else {
                                    panic!("No stat struct found for successful stat syscall!");
                                }
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            panic!("Unexpected stat failure: file already exists??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set_mut.insert(Fact::DoesntExist);
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            if !parent_dir_was_created_by_exec {
                                curr_set_mut.insert(Fact::NoDirPermission((AccessFlags::X_OK).bits(), None));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::InvalArg) => (),
                    }
                }
            }

            // This function will only change the first_state if it is None.
            first_state_struct.update_based_on_file_event(&full_path, event.clone());
            last_mod_struct.update_based_on_file_event(event.clone());
        }
    }
    curr_file_preconditions
}

// Function that takes ExecSyscallEvents and generates the file postconditions
// and file postconditions. It returns a new Postconditions struct.
// Note: Only syscalls that produce side effects contribute to postconditions.
pub fn generate_postconditions(events: ExecSyscallEvents) -> Postconditions {
    let dir_events = events.dir_events();
    let file_events = events.file_events();

    // We need to know which directories have been renamed...
    let (dir_postconds, renamed_dirs) = generate_dir_postconditions(dir_events);
    let file_postconds = generate_file_postconditions(file_events);

    // ...so our postconditions can reflect the correct, updated full paths!
    let updated_file_postconds: HashMap<Accessor, HashSet<Fact>> =
        update_file_posts_with_renamed_dirs(file_postconds, renamed_dirs);

    Postconditions::new(dir_postconds, updated_file_postconds)
}

// Generates the directory postconditions from the provided directory
// events.
// The only postconditions are: exists or doesn't exist for dirs.
// Returns: (HashMap<Accessor, HashSet<Fact>>, HashMap<PathBuf, PathBuf>)
// Which are: (Dir postconditions, renamed dirs)
// Note: Only system calls that produce side effects contribute to postconditions.
pub fn generate_dir_postconditions(
    dir_events: HashMap<Accessor, Vec<DirEvent>>,
) -> (HashMap<Accessor, HashSet<Fact>>, HashMap<PathBuf, PathBuf>) {
    let sys_span = span!(Level::INFO, "generate_dir_postconditions");
    let _ = sys_span.enter();

    let mut curr_dir_postconditions = HashMap::new();
    let mut renamed_dirs = HashMap::new();
    // Just be sure the map is set up ahead of time.
    for accessor in dir_events.keys() {
        curr_dir_postconditions.insert(accessor.clone(), HashSet::new());
    }

    // Main loop of state machine to produce dir postconditions.
    for (accessor, event_list) in dir_events {
        // Initialize state variables.
        let mut first_state_struct = FirstState(State::None);
        let mut last_mod_struct = LastMod(Mod::None);
        // Option cmd in accessor is used in rename.
        let full_path = accessor.path();

        for event in event_list {
            let first_state = first_state_struct.state();
            let last_mod = last_mod_struct.state();

            match (event.clone(), first_state, last_mod) {
                // "Modified" is not a possible Mod for dirs.
                (_, _, Mod::Modified) => (),
                // We don't use this event in postcondition generation.
                (DirEvent::ChildExec(_), _, _) => (),
                // Last mod created. We already know it exists.
                (DirEvent::Create(_, _), State::DoesntExist, Mod::Created) => (),
                // Last mod deleted, if this succeeds, we need to remove
                (DirEvent::Create(_, outcome), State::DoesntExist, Mod::Deleted) => {
                    if outcome == SyscallOutcome::Success {
                        curr_dir_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::Exists]));
                    }
                }
                // If full path = old path, we can create. Thus we should insert Fact::Exists
                // as old path's postconds if this succeeds.
                (DirEvent::Create(_, outcome), State::DoesntExist, Mod::Renamed(_, _)) => {
                    if outcome == SyscallOutcome::Success {
                        curr_dir_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::Exists]));
                    }
                }
                (DirEvent::Create(_, outcome), State::DoesntExist, Mod::None) => {
                    if outcome == SyscallOutcome::Success {
                        // This succeeded, we created a dir cool.
                        curr_dir_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::Exists]));
                    }
                }
                // We just created it. Can't do that again.
                (DirEvent::Create(_, _), State::Exists, Mod::Created) => (),
                // We just deleted it. Sick. We can totally create it aGAIN.
                (DirEvent::Create(_, outcome), State::Exists, Mod::Deleted) => {
                    if outcome == SyscallOutcome::Success {
                        curr_dir_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::Exists]));
                    }
                }
                // If full path is old path, then old path was renamed to new path, and
                // old path can be created again!
                (DirEvent::Create(_, outcome), State::Exists, Mod::Renamed(_, _)) => {
                    if outcome == SyscallOutcome::Success {
                        curr_dir_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::Exists]));
                    }
                }
                // It already exists. We can't make it double exist.
                (DirEvent::Create(_, _), State::Exists, Mod::None) => (),
                (DirEvent::Create(_, outcome), State::None, last_mod) => {
                    if *last_mod == Mod::None {
                        if outcome == SyscallOutcome::Success {
                            // We successfully created a directory!
                            curr_dir_postconditions
                                .insert(accessor.clone(), HashSet::from([Fact::Exists]));
                        }
                    } else {
                        panic!("First state is none but last mod is {:?}", last_mod);
                    }
                }
                (DirEvent::Delete(outcome), State::DoesntExist, Mod::Created) => {
                    // This should succeed. We should just insert a new fact
                    // with DoesntExist.
                    if outcome == SyscallOutcome::Success {
                        curr_dir_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::DoesntExist]));
                    }
                }
                // We just deleted it. What are we gonna do. Delete it again?
                (DirEvent::Delete(_), State::DoesntExist, Mod::Deleted) => (),
                // if full path is old path, then we can't delete this.
                // No info gained.
                (DirEvent::Delete(_), State::DoesntExist, Mod::Renamed(_, _)) => (),
                // It doesn't exist, and we haven't created it. So, yeah, not a
                // lot to do here.
                (DirEvent::Delete(_), State::DoesntExist, Mod::None) => (),
                // Was apparently, ugh: existed, deleted, created, now trying to
                // delete again. Like, for correctness I know this level of
                // detail is necessary but if you program like this: I. Hate. You.
                (DirEvent::Delete(outcome), State::Exists, Mod::Created) => {
                    if outcome == SyscallOutcome::Success {
                        curr_dir_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::DoesntExist]));
                    }
                }
                // We just deleted it. Can't do that again.
                (DirEvent::Delete(_), State::Exists, Mod::Deleted) => (),
                // If full path is old path, we can't delete this. No info gained.
                (DirEvent::Delete(_), State::Exists, Mod::Renamed(_, _)) => (),
                // It exists. Maybe we can even delete it.
                (DirEvent::Delete(outcome), State::Exists, Mod::None) => {
                    if outcome == SyscallOutcome::Success {
                        curr_dir_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::DoesntExist]));
                    }
                }
                (DirEvent::Delete(outcome), State::None, last_mod) => {
                    if *last_mod == Mod::None {
                        // We have never seen this before. Hello. Nice to meet you dir.
                        // I have been working on this too much lol.
                        if outcome == SyscallOutcome::Success {
                            curr_dir_postconditions
                                .insert(accessor.clone(), HashSet::from([Fact::DoesntExist]));
                        }
                    } else {
                        panic!("First state is none, but last mod was: {:?}", last_mod);
                    }
                }
                (DirEvent::Read(_, _, _), _, _) => (),
                // Last mod was creating old path. It can certainly be renamed.
                (
                    DirEvent::Rename(old_path, new_path, outcome),
                    State::DoesntExist,
                    Mod::Created,
                ) => {
                    if outcome == SyscallOutcome::Success {
                        // Remove the old set if appropriate.
                        let _ = curr_dir_postconditions.remove(&accessor);
                        curr_dir_postconditions.insert(
                            accessor.clone(),
                            HashSet::from([Fact::Renamed(old_path.clone(), new_path.clone())]),
                        );

                        renamed_dirs.insert(old_path, new_path);
                    }
                }
                // We just deleted it. We can't rename it.
                (DirEvent::Rename(_, _, _), State::DoesntExist, Mod::Deleted) => (),
                (
                    DirEvent::Rename(_old_path, _new_path, _outcome),
                    State::DoesntExist,
                    Mod::Renamed(_, _last_new_path),
                ) => {
                    panic!("Renamed dir and renaming it again!")
                }
                // It doesn't exist and hasn't been created. I am doubtful this is going to give us
                // anything. Actually, I am positive it will not give us anything.
                (DirEvent::Rename(_, _, _), State::DoesntExist, Mod::None) => (),
                // Last mod created, we can totes rename it.
                (DirEvent::Rename(old_path, new_path, outcome), State::Exists, Mod::Created) => {
                    if outcome == SyscallOutcome::Success {
                        let _ = curr_dir_postconditions.remove(&accessor);
                        curr_dir_postconditions.insert(
                            accessor.clone(),
                            HashSet::from([Fact::Renamed(old_path.clone(), new_path.clone())]),
                        );

                        renamed_dirs.insert(old_path, new_path);
                    }
                }
                // We just deleted it. We cannot rename it.
                (DirEvent::Rename(_, _, _), State::Exists, Mod::Deleted) => (),
                (
                    DirEvent::Rename(_old_path, _new_path, _outcome),
                    State::Exists,
                    Mod::Renamed(_, _last_new_path),
                ) => {
                    panic!("Renamed dir and renaming it again!")
                }
                // We know it exists. We might be able to rename it.
                (DirEvent::Rename(_old_path, _new_path, _outcome), State::Exists, Mod::None) => {
                    panic!("Renamed dir and renaming it again!")
                }
                (DirEvent::Rename(old_path, new_path, outcome), State::None, last_mod) => {
                    if *last_mod == Mod::None {
                        if outcome == SyscallOutcome::Success {
                            let _ = curr_dir_postconditions.remove(&accessor);
                            curr_dir_postconditions.insert(
                                accessor.clone(),
                                HashSet::from([Fact::Renamed(old_path.clone(), new_path.clone())]),
                            );
                            renamed_dirs.insert(old_path, new_path);
                        }
                    } else {
                        panic!("First state none but last mod was: {:?}", last_mod);
                    }
                }
                (DirEvent::Statfs(_, _), _, _) => (),
            }

            // This function will only change the first_state if it is None.
            first_state_struct.update_based_on_dir_event(&full_path, event.clone());
            last_mod_struct.update_based_on_dir_event(event.clone());
        }
    }

    (curr_dir_postconditions, renamed_dirs)
}

// Note: Only system calls that produce side effects contribute to postconditions.
// Takes in all file events and computes all file postconditions.
pub fn generate_file_postconditions(
    file_events: HashMap<Accessor, Vec<FileEvent>>,
) -> HashMap<Accessor, HashSet<Fact>> {
    let sys_span = span!(Level::INFO, "generate_file_postconditions");
    let _ = sys_span.enter();

    let mut curr_file_postconditions = HashMap::new();

    // Just be sure the map is set up ahead of time.
    for accessor in file_events.keys() {
        curr_file_postconditions.insert(accessor.clone(), HashSet::new());
    }

    // Main loop to generate postconditions.
    for (accessor, event_list) in file_events {
        let mut first_state_struct = FirstState(State::None);
        let mut last_mod_struct = LastMod(Mod::None);
        let full_path = accessor.path();
        let option_cmd = accessor.hashed_command();

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
                (FileEvent::ChildExec(_), State::None, Mod::Modified) => (),
                (_, State::None, Mod::Modified) => {
                    // panic!("First state is none but last mod is modified!!");
                }
                (_, State::None, Mod::Renamed(_, _)) => {
                    panic!("First state is none but last mod is rename!!");
                }
                (FileEvent::Access(_, _), _, _) => (),
                (FileEvent::ChildExec(_), _, _) => (),
                (FileEvent::Create(_, _), State::DoesntExist, Mod::Created) => (),
                (FileEvent::Create(_, outcome), State::DoesntExist, Mod::Deleted) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.remove(&Fact::DoesntExist);
                        curr_set.insert(Fact::FinalContents);
                    }
                }

                (FileEvent::Create(_, _), State::DoesntExist, Mod::Modified) => (),
                // This is old path because we only get an event for old path.
                (FileEvent::Create(_, outcome), State::DoesntExist, Mod::Renamed(_, _)) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.remove(&Fact::DoesntExist);
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (FileEvent::Create(_, outcome), State::DoesntExist, Mod::None) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (FileEvent::Create(_, _), State::Exists, Mod::Created) => (),
                (FileEvent::Create(_, outcome), State::Exists, Mod::Deleted) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.remove(&Fact::DoesntExist);
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (FileEvent::Create(_, _), State::Exists, Mod::Modified) => (),
                (FileEvent::Create(_, outcome), State::Exists, Mod::Renamed(_, _)) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.remove(&Fact::Exists);
                        curr_set.remove(&Fact::DoesntExist);
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (FileEvent::Create(_, _), State::Exists, Mod::None) => (),
                (FileEvent::Create(_, outcome), State::None, Mod::None) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                (FileEvent::Delete(outcome), State::DoesntExist, Mod::Created | Mod::Modified) => {
                    if outcome == SyscallOutcome::Success {
                        curr_file_postconditions.remove(&accessor);
                        let new_set = HashSet::from([Fact::DoesntExist]);
                        curr_file_postconditions.insert(accessor.clone(), new_set);
                    }
                }
                // We only have the old path event. If old path was just successfully renamed
                // it can't be deleted.
                (FileEvent::Delete(_), _, Mod::Renamed(_, _)) => (),
                (FileEvent::Delete(_), State::DoesntExist, Mod::Deleted) => (),
                (FileEvent::Delete(_), State::DoesntExist, Mod::None) => (),
                (FileEvent::Delete(outcome), State::Exists, Mod::Created | Mod::Modified) => {
                    if outcome == SyscallOutcome::Success {
                        curr_file_postconditions.remove(&accessor);
                        let new_set = HashSet::from([Fact::DoesntExist]);
                        curr_file_postconditions.insert(accessor.clone(), new_set);
                    }
                }
                (FileEvent::Delete(_), State::Exists, Mod::Deleted) => (),
                (FileEvent::Delete(outcome), State::Exists, Mod::None) => {
                    if outcome == SyscallOutcome::Success {
                        curr_file_postconditions.remove(&accessor);
                        let new_set = HashSet::from([Fact::DoesntExist]);
                        curr_file_postconditions.insert(accessor.clone(), new_set);
                    }
                }
                (FileEvent::Delete(outcome), State::None, Mod::None) => {
                    if outcome == SyscallOutcome::Success {
                        curr_file_postconditions.remove(&accessor);
                        let new_set = HashSet::from([Fact::DoesntExist]);
                        curr_file_postconditions.insert(accessor.clone(), new_set);
                    }
                }
                (FileEvent::FailedExec(_), _, _) => (),
                // Open for write or read/write: doesn't matter either way FinalContents is the fact to add.
                // And we don't care about the offset mode at all!
                // I used "last_mod" here so we can just check that it is Mod::None (as it should be if first
                // state is State::None) and panic otherwise, instead of having to do a separate match case for
                // each. Efficiency!
                (
                    FileEvent::Open(AccessMode::Both | AccessMode::Write, _, _, outcome),
                    State::None,
                    last_mod,
                ) => {
                    if *last_mod == Mod::None {
                        if outcome == SyscallOutcome::Success {
                            let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                            curr_set.insert(Fact::FinalContents);
                        }
                    } else {
                        panic!("First state is none, but last mod was: {:?}!!", last_mod);
                    }
                }

                (
                    FileEvent::Open(AccessMode::Both | AccessMode::Write, _, _, outcome),
                    State::Exists,
                    Mod::None,
                ) => {
                    if outcome == SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(&accessor).unwrap();
                        curr_set.insert(Fact::FinalContents);
                    }
                }
                // The last mod gave us FinalContents as a postcondition, so we don't need to do anything.
                (
                    FileEvent::Open(AccessMode::Both | AccessMode::Write, _, _, _),
                    State::DoesntExist | State::Exists,
                    Mod::Created | Mod::Modified,
                ) => (),
                (FileEvent::Open(_, _, _, outcome), State::Exists, Mod::Deleted) => {
                    // This should not succeed!
                    if outcome == SyscallOutcome::Success {
                        panic!("Last mod was deleted but succeeded on open??");
                    }
                }
                (
                    FileEvent::Open(_, _, _, outcome),
                    State::DoesntExist | State::Exists,
                    Mod::Renamed(_, _),
                ) => {
                    // Okay! It existed. It was last renamed. It cannot be opened.
                    if outcome == SyscallOutcome::Success {
                        panic!("Last mod was renamed but succeeded on open??");
                    }
                }
                (
                    FileEvent::Open(AccessMode::Both | AccessMode::Write, _, _, outcome),
                    State::DoesntExist,
                    Mod::None,
                ) => {
                    if outcome == SyscallOutcome::Success {
                        panic!("Successfully opened, but file didn't exist and was not created!!");
                    }
                }
                (
                    FileEvent::Open(AccessMode::Both | AccessMode::Write, _, _, outcome),
                    State::DoesntExist,
                    Mod::Deleted,
                ) => {
                    // This should not succeed!
                    if outcome == SyscallOutcome::Success {
                        panic!("Last mod was deleted but succeeded on open??");
                    }
                }
                (FileEvent::Open(AccessMode::Read, _, _, _), _, _) => (),
                // Don't have to check if full path == old path because there is only one rename event
                // right now and it is for old path.
                (
                    FileEvent::Rename(_, new_path, outcome),
                    State::DoesntExist,
                    Mod::Created | Mod::Modified,
                ) => {
                    if outcome == SyscallOutcome::Success {
                        let new_accessor = if let Some(cmd) = option_cmd.clone() {
                            Accessor::ChildProc(cmd, new_path)
                        } else {
                            Accessor::CurrProc(new_path)
                        };

                        // The postconditions get all the paths and empty sets set up before
                        // this whole state machine is started. Don't need to check for key of
                        // accessor; it is definitely there.

                        // The old set may contain nothing right now. Or it may have some postconditions.
                        // If it is empty, new accessor needs a new set with "Exists" as the fact because
                        // that's all we know about it.
                        let old_set = curr_file_postconditions.remove(&accessor).unwrap();
                        if old_set.is_empty() {
                            curr_file_postconditions
                                .insert(new_accessor, HashSet::from([Fact::Exists]));
                        } else {
                            curr_file_postconditions.insert(new_accessor, old_set);
                        }
                        curr_file_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::DoesntExist]));
                    }
                }
                // rename (old path, mid path)
                // rename (mid path, new path)
                // This is the event we will see for mid path
                // FileEvent::Rename(mid path, new path), State::None, LastMod::None
                // So we need to always "get()" the old set from the postconds just in case.
                // But, this case would only happen for old path because there is no new path event
                // as well. So this cannot succeed.
                (FileEvent::Rename(_, _, _), State::DoesntExist, Mod::Renamed(_, _)) => (),
                (FileEvent::Rename(_, _, _), State::DoesntExist, Mod::Deleted) => (),
                (FileEvent::Rename(_, _, _), State::DoesntExist, Mod::None) => (),
                (
                    FileEvent::Rename(old_path, new_path, outcome),
                    State::Exists,
                    Mod::Created | Mod::Modified,
                ) => {
                    let new_accessor = if let Some(cmd) = option_cmd.clone() {
                        Accessor::ChildProc(cmd, new_path)
                    } else {
                        Accessor::CurrProc(new_path)
                    };

                    // Only old path events so don't have to check if full path == old path.
                    if outcome == SyscallOutcome::Success {
                        let old_set = curr_file_postconditions.remove(&accessor).unwrap();
                        if old_path.is_empty() {
                            curr_file_postconditions
                                .insert(new_accessor, HashSet::from([Fact::Exists]));
                        } else {
                            curr_file_postconditions.insert(new_accessor, old_set);
                        }
                        curr_file_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::DoesntExist]));
                    }
                }
                // Old path was just renamed so this cannot succeed.
                (FileEvent::Rename(_, _, _), State::Exists, Mod::Renamed(_, _)) => (),
                (FileEvent::Rename(_, _, _), State::Exists, Mod::Deleted) => (),
                (FileEvent::Rename(_, new_path, outcome), State::Exists, Mod::None) => {
                    let new_accessor = if let Some(cmd) = option_cmd.clone() {
                        Accessor::ChildProc(cmd, new_path)
                    } else {
                        Accessor::CurrProc(new_path)
                    };

                    if outcome == SyscallOutcome::Success {
                        let old_set = curr_file_postconditions.remove(&accessor).unwrap();
                        if old_set.is_empty() {
                            curr_file_postconditions
                                .insert(new_accessor, HashSet::from([Fact::Exists]));
                        } else {
                            curr_file_postconditions.insert(new_accessor, old_set);
                        }
                        curr_file_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::DoesntExist]));
                    }
                }
                (FileEvent::Rename(_, new_path, outcome), State::None, Mod::None) => {
                    let new_accessor = if let Some(cmd) = option_cmd.clone() {
                        Accessor::ChildProc(cmd, new_path)
                    } else {
                        Accessor::CurrProc(new_path)
                    };

                    if outcome == SyscallOutcome::Success {
                        let old_set = curr_file_postconditions.remove(&accessor).unwrap();
                        if old_set.is_empty() {
                            curr_file_postconditions
                                .insert(new_accessor, HashSet::from([Fact::Exists]));
                        } else {
                            curr_file_postconditions.insert(new_accessor, old_set);
                        }
                        curr_file_postconditions
                            .insert(accessor.clone(), HashSet::from([Fact::DoesntExist]));
                    }
                }
                (FileEvent::Stat(_, _), _, _) => (),
            }
            first_state_struct.update_based_on_file_event(&full_path, event.clone());
            last_mod_struct.update_based_on_file_event(event);
        }
    }
    curr_file_postconditions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failed_access_then_create() {
        // Doesn't matter for this test, so I am just using "test".
        let path = PathBuf::from("test");
        // These are the two events we are going to add.
        // A failed Access (FileDoesntExist)
        // and a successful File create.
        let access_fail_event = FileEvent::Access(
            AccessFlags::W_OK.bits(),
            SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
        );
        let create_success_event = FileEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success);

        let mut exec_syscall_events = ExecSyscallEvents::new(HashMap::new(), HashMap::new());
        // Add these two events to the file events.
        exec_syscall_events.add_new_file_event(Pid::from_raw(0), access_fail_event, path.clone());
        exec_syscall_events.add_new_file_event(
            Pid::from_raw(0),
            create_success_event,
            path.clone(),
        );

        // Preconditions our state machine generates.
        let preconditions = generate_preconditions(exec_syscall_events.clone());
        let generated_file_preconds = preconditions.file_preconditions();
        let generated_file_preconds = generated_file_preconds.get(&path).unwrap();
        println!("Generated preconditions: {:?}", generated_file_preconds);

        let mut flags = AccessFlags::empty();
        flags.insert(AccessFlags::W_OK);
        flags.insert(AccessFlags::X_OK);
        // Correct preconds.
        let correct_preconditions = HashSet::from([
            Fact::DoesntExist,
            Fact::HasDirPermission(flags.bits(), None),
        ]);
        // Be sure the sets are equal.
        assert_eq!(generated_file_preconds, &correct_preconditions);

        // Postconditions our state machine generates.
        let postconditions = generate_postconditions(exec_syscall_events);
        let generated_file_postconditions = postconditions.file_postconditions();
        let generated_file_postconditions = generated_file_postconditions
            .get(&Accessor::CurrProc(PathBuf::from("test")))
            .unwrap();

        // The correct postconditions.
        let correct_postconditions = HashSet::from([Fact::FinalContents]);
        // Be sure the sets are equal.
        assert_eq!(generated_file_postconditions, &correct_postconditions);
    }

    #[test]
    fn test_stat_open_create() {
        let path = PathBuf::from("test");

        // Create three events to add:
        // A failed stat.
        let failed_stat_event =
            FileEvent::Stat(None, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist));
        // A failed open.
        let open_fail_event = FileEvent::Open(
            AccessMode::Read,
            None,
            None,
            SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
        );
        // And a successful create file event.
        let successful_create_event = FileEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success);
        let mut exec_syscall_events = ExecSyscallEvents::new(HashMap::new(), HashMap::new());

        // Add the events.
        exec_syscall_events.add_new_file_event(Pid::from_raw(0), failed_stat_event, path.clone());
        exec_syscall_events.add_new_file_event(Pid::from_raw(0), open_fail_event, path.clone());
        exec_syscall_events.add_new_file_event(Pid::from_raw(0), successful_create_event, path);

        // Generate the file preconditions with our state machine.
        let preconditions = generate_preconditions(exec_syscall_events.clone());
        let generated_file_preconditions = preconditions.file_preconditions();
        let generated_file_preconditions = generated_file_preconditions
            .get(&PathBuf::from("test"))
            .unwrap();

        // Create a set of the known correct preconditions.
        let mut flags = AccessFlags::empty();
        flags.insert(AccessFlags::W_OK);
        flags.insert(AccessFlags::X_OK);
        let correct_preconditions = HashSet::from([
            Fact::DoesntExist,
            Fact::HasDirPermission(flags.bits(), None),
        ]);
        // Ensure these two sets match.
        assert_eq!(generated_file_preconditions, &correct_preconditions);

        // Generate the file postconditions with our state machine.
        let postconditions = generate_postconditions(exec_syscall_events);
        let generated_file_postconditions = postconditions.file_postconditions();
        let generated_file_postconditions = generated_file_postconditions
            .get(&Accessor::CurrProc(PathBuf::from("test")))
            .unwrap();

        // Create a set of the correct postconditions.
        let correct_postconditions = HashSet::from([Fact::FinalContents]);
        // Ensure the sets are equal.
        assert_eq!(generated_file_postconditions, &correct_postconditions);
    }

    // TODO: Test for exclusive?

    #[test]
    // TODO: Rename this test and fix it. Add another event.
    fn test_open_open_access() {
        // Just a test path to use.
        let path = PathBuf::from("test");

        // Create 2 events to add.

        // A successful access call to the file.
        let successful_access_call =
            FileEvent::Access(AccessFlags::W_OK.bits(), SyscallOutcome::Success);
        // A successful truncation of a file.
        let successful_trunc_event = FileEvent::Open(
            AccessMode::Write,
            Some(OffsetMode::Trunc),
            Some(CheckMechanism::DiffFiles),
            SyscallOutcome::Success,
        );

        // Create ExecSyscallEvents and add the events.
        let mut exec_syscall_events = ExecSyscallEvents::new(HashMap::new(), HashMap::new());
        exec_syscall_events.add_new_file_event(
            Pid::from_raw(0),
            successful_access_call,
            path.clone(),
        );
        exec_syscall_events.add_new_file_event(Pid::from_raw(0), successful_trunc_event, path);

        // The preconditions generated by our state machine.
        let preconditions = generate_preconditions(exec_syscall_events.clone());
        let generated_file_preconditions = preconditions.file_preconditions();
        let generated_file_preconditions = generated_file_preconditions
            .get(&PathBuf::from("test"))
            .unwrap();

        let mut flags = AccessFlags::empty();
        flags.insert(AccessFlags::W_OK);

        // What we know the preconditions should be.
        let correct_preconditions = HashSet::from([
            Fact::Exists,
            Fact::HasPermission(flags.bits()),
            Fact::HasDirPermission((AccessFlags::X_OK).bits(), None),
        ]);
        // Ensure the two sets are equal.
        assert_eq!(generated_file_preconditions, &correct_preconditions);

        // Post conditions generated by our state machine.
        let postconditions = generate_postconditions(exec_syscall_events);
        let generated_file_postconditions = postconditions.file_postconditions();
        let generated_file_postconditions = generated_file_postconditions
            .get(&Accessor::CurrProc(PathBuf::from("test")))
            .unwrap();

        // The known correct postconditions.
        let correct_postconditions = HashSet::from([Fact::FinalContents]);

        // Ensure the two sets are equal.
        assert_eq!(generated_file_postconditions, &correct_postconditions);
    }

    #[test]
    fn test_append_delete_create() {
        // Just a test "path" to use.
        let path = PathBuf::from("test");

        // 3 events to add:
        // A successful append to the existing file.
        let successful_append_event = FileEvent::Open(
            AccessMode::Write,
            Some(OffsetMode::Append),
            Some(CheckMechanism::Mtime(0)),
            SyscallOutcome::Success,
        );
        // A successful delete of the file.
        let successful_delete_event = FileEvent::Delete(SyscallOutcome::Success);
        // A successful create. (yes, I know this is contrived)
        let successful_create_event = FileEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success);

        // Create the new ExecSyscallEvents struct and add the file events to it.
        let mut exec_syscall_events = ExecSyscallEvents::new(HashMap::new(), HashMap::new());
        exec_syscall_events.add_new_file_event(
            Pid::from_raw(0),
            successful_append_event,
            path.clone(),
        );
        exec_syscall_events.add_new_file_event(
            Pid::from_raw(0),
            successful_delete_event,
            path.clone(),
        );
        exec_syscall_events.add_new_file_event(Pid::from_raw(0), successful_create_event, path);

        // Generate preconditions with our state machine.
        let preconditions = generate_preconditions(exec_syscall_events.clone());
        let generated_file_preconditons = preconditions.file_preconditions();
        let generated_file_preconditons = generated_file_preconditons
            .get(&PathBuf::from("test"))
            .unwrap();

        // The known correct preconditions.
        let correct_preconditions = HashSet::from([
            Fact::Mtime(0),
            Fact::HasDirPermission(AccessFlags::X_OK.bits(), None),
            Fact::HasPermission((AccessFlags::W_OK).bits()),
        ]);

        // Ensure the two sets are equal.
        assert_eq!(generated_file_preconditons, &correct_preconditions);

        // Generate postconditions with our state machine.
        let postconditions = generate_postconditions(exec_syscall_events);
        let generated_file_postconditions = postconditions.file_postconditions();
        let generated_file_postconditions = generated_file_postconditions
            .get(&Accessor::CurrProc(PathBuf::from("test")))
            .unwrap();

        // Known correct postconditions.
        let correct_postconditions = HashSet::from([Fact::FinalContents]);

        // Ensure the two sets are equal.
        assert_eq!(generated_file_postconditions, &correct_postconditions);
    }

    // TODO: Fix this test
    // #[test]
    // fn test_rename_openappend_create() {
    //     // Just a test path to use.
    //     let foo = PathBuf::from("foo");
    //     let bar = PathBuf::from("bar");

    //     // 3 FileEvents to add.
    //     // A successful rename event. foo --> bar
    //     let successful_rename_event =
    //         FileEvent::Rename(foo.clone(), bar.clone(), SyscallOutcome::Success);
    //     // A successful create (foo)
    //     let successful_create_event_foo =
    //         FileEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success);
    //     // A successful append (bar)
    //     let successful_append_event_bar = FileEvent::Open(
    //         AccessMode::Write,
    //         Some(OffsetMode::Append),
    //         Some(CheckMechanism::Mtime(0)),
    //         SyscallOutcome::Success,
    //     );
    //     // Create ExecSyscallEvents and add events to it.
    //     let mut exec_syscall_events = ExecSyscallEvents::new(HashMap::new(), HashMap::new());
    //     exec_syscall_events.add_new_file_event(
    //         Pid::from_raw(0),
    //         successful_rename_event,
    //         foo.clone(),
    //     );
    //     exec_syscall_events.add_new_file_event(Pid::from_raw(0), successful_create_event_foo, foo);
    //     exec_syscall_events.add_new_file_event(Pid::from_raw(0), successful_append_event_bar, bar);

    //     let preconditions = generate_preconditions(exec_syscall_events.clone());
    //     let generated_file_preconditions = preconditions.file_preconditions();
    //     let generated_file_pres_foo = generated_file_preconditions
    //         .get(&PathBuf::from("foo"))
    //         .unwrap();
    //     let generated_file_pres_bar = generated_file_preconditions
    //         .get(&PathBuf::from("bar"))
    //         .unwrap();

    //     let mut flags = AccessFlags::empty();
    //     flags.insert(AccessFlags::W_OK);
    //     flags.insert(AccessFlags::X_OK);

    //     let correct_preconditions_foo = HashSet::from([
    //         Fact::Exists,
    //         Fact::HasDirPermission(flags.bits(), None),
    //     ]);
    //     let correct_preconditions_bar = HashSet::from([Fact::DoesntExist]);

    //     assert_eq!(generated_file_pres_foo, &correct_preconditions_foo);
    //     assert_eq!(generated_file_pres_bar, &correct_preconditions_bar);

    //     let postconditions = generate_postconditions(exec_syscall_events);
    //     let generated_file_postconditions = postconditions.file_postconditions();
    //     let generated_file_posts_foo = generated_file_postconditions.get(&Accessor::CurrProc(PathBuf::from("foo"))).unwrap();
    //     let generated_file_posts_bar = generated_file_postconditions.get(&Accessor::CurrProc(PathBuf::from("bar"))).unwrap();

    //     let correct_file_posts_foo = HashSet::from([Fact::Exists]);
    //     let correct_file_posts_bar = HashSet::from([Fact::Exists]);

    //     assert_eq!(generated_file_posts_foo, &correct_file_posts_foo);
    //     assert_eq!(generated_file_posts_bar, &correct_file_posts_bar);
    // }
}
