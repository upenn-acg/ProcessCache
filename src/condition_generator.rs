use nix::fcntl::OFlag;
use nix::unistd::{AccessFlags, Pid};

use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum LastMod {
    Created,
    Deleted,
    Modified,
    Renamed,
    None,
}
pub struct LastModStruct {
    state: LastMod,
}

impl LastModStruct {
    fn update_based_on_syscall(&mut self, syscall_event: &SyscallEvent) {
        match *syscall_event {
            SyscallEvent::Create(_, SyscallOutcome::Success) => {
                self.state = LastMod::Created;
            }
            SyscallEvent::Delete(SyscallOutcome::Success) => {
                self.state = LastMod::Deleted;
            }
            SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, SyscallOutcome::Success) => {
                self.state = LastMod::Modified;
            }
            // No change
            _ => (),
        }
    }

    fn state(&self) -> &LastMod {
        &self.state
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Fact {
    File(FileFact),
    Dir(DirFact),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum FileFact {
    Contents,
    DoesntExist,
    Exists,
    StatStructMatches,
    // HasPerms(Vec<Perm>)
    // NoPerms(Vec<Perm>)
    // Then we can have one fact holding all the perms we need to check for?
    HasPermission(AccessFlags),
    NoPermission(AccessFlags),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum DirFact {
    HasPermission(AccessFlags),
    NoPermission(AccessFlags),
}

#[derive(Eq, PartialEq)]
pub enum FirstState {
    DoesntExist,
    Exists,
    None,
}

#[derive(Eq, PartialEq)]
pub struct FirstStateStruct {
    state: FirstState,
}

impl FirstStateStruct {
    fn state(&self) -> &FirstState {
        &self.state
    }
}

impl FirstStateStruct {
    fn update_based_on_syscall(&mut self, syscall_event: &SyscallEvent) {
        if *self.state() == FirstState::None {
            match syscall_event {
                SyscallEvent::Access(_, SyscallOutcome::Success) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Access(_, SyscallOutcome::Fail(SyscallFailure::PermissionDenied)) => {
                    // If you call access(R_OK) and the file doesn't exist, you will get ENOENT,
                    // and that will be a different kind of access event.
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Access(_, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.state = FirstState::DoesntExist;
                }
                SyscallEvent::Access(_, SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!(
                        "updating first state struct, access failed because file already exists??"
                    );
                }

                SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success) => {
                    self.state = FirstState::DoesntExist;
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
                    self.state = FirstState::DoesntExist;
                }
                SyscallEvent::Create(
                    OFlag::O_EXCL,
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists),
                ) => {
                    self.state = FirstState::Exists;
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
                SyscallEvent::Delete(SyscallOutcome::Success) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Delete(SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!("Failed to delete a file because it already exists??");
                }
                SyscallEvent::Delete(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Delete(SyscallOutcome::Fail(SyscallFailure::PermissionDenied)) => (),
                SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_RDONLY, SyscallOutcome::Success) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Open(OFlag::O_TRUNC, SyscallOutcome::Success) => (),
                SyscallEvent::Open(
                    OFlag::O_APPEND | OFlag::O_RDONLY,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    self.state = FirstState::DoesntExist;
                }
                SyscallEvent::Open(
                    OFlag::O_APPEND | OFlag::O_TRUNC,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Open(OFlag::O_TRUNC, SyscallOutcome::Fail(fail)) => {
                    panic!("Failed to open trunc for strange reason: {:?}", fail)
                }
                SyscallEvent::Open(
                    OFlag::O_RDONLY,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Open(mode, SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!("Open for {:?} failed because file already exists??", mode)
                }
                SyscallEvent::Open(f, _) => panic!("Unexpected open flag: {:?}", f),
                SyscallEvent::Stat(SyscallOutcome::Success) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Stat(SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!("Failed to state because file already exists??");
                }
                SyscallEvent::Stat(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.state = FirstState::DoesntExist;
                }
                SyscallEvent::Stat(SyscallOutcome::Fail(SyscallFailure::PermissionDenied)) => (),
                SyscallEvent::Rename(_, _, SyscallOutcome::Success) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Rename(
                    _,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    self.state = FirstState::DoesntExist;
                }
                SyscallEvent::Rename(_, _, _) => (),
            }
        }
    }
}

// Actual accesses to the file system performed by
// a successful execution.
// Full path mapped to
// TODO: Handle stderr and stdout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecFileEvents {
    filename_to_events_map: HashMap<PathBuf, Vec<SyscallEvent>>,
}

impl ExecFileEvents {
    pub fn new() -> ExecFileEvents {
        ExecFileEvents {
            filename_to_events_map: HashMap::new(),
        }
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

        s.in_scope(|| "in add_new_file_event");
        // First case, we already saw this file and now we are adding another event to it.
        if let Some(event_list) = self.filename_to_events_map.get_mut(&full_path) {
            s.in_scope(|| "adding to existing event list");
            event_list.push(file_event);
        } else {
            let event_list = vec![file_event];
            s.in_scope(|| "adding new event list");
            self.filename_to_events_map.insert(full_path, event_list);
        }
    }

    pub fn file_event_list(&self) -> &HashMap<PathBuf, Vec<SyscallEvent>> {
        let s = span!(Level::INFO, stringify!(file_event_list));
        let _ = s.enter();

        &self.filename_to_events_map
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CondsMap {
    conds: HashMap<PathBuf, HashSet<Fact>>,
}
impl CondsMap {
    pub fn new() -> CondsMap {
        CondsMap {
            conds: HashMap::new(),
        }
    }
    pub fn add_preconditions(&mut self, exec_file_events: ExecFileEvents) {
        let preconds = generate_preconditions(exec_file_events);
        self.conds = preconds;
    }

    pub fn add_postconditions(&mut self, exec_file_events: ExecFileEvents) {
        let postconds = generate_postconditions(exec_file_events);
        self.conds = postconds;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Conds {
    Preconds(CondsMap),
    Postconds(CondsMap),
}
impl Conds {
    pub fn add_conditions(&mut self, exec_file_events: ExecFileEvents) {
        match self {
            Conds::Preconds(conds) => {
                conds.add_preconditions(exec_file_events);
            }
            Conds::Postconds(conds) => {
                conds.add_postconditions(exec_file_events);
            }
        }
    }
}

// Successful and failing events.
// "Open" meaning not using O_CREAT
// "Create" meaning using O_CREAT
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyscallEvent {
    Access(HashSet<AccessFlags>, SyscallOutcome), // Vec<c_int> is list of F_OK (0), R_OK, W_OK, X_OK
    Create(OFlag, SyscallOutcome), // Can fail because pathcomponentdoesntexist or failedtocreatefileexclusively, or accessdenied
    Delete(SyscallOutcome),
    Open(OFlag, SyscallOutcome), // Can fail because the file didn't exist or permission denied
    Rename(PathBuf, PathBuf, SyscallOutcome), // Old, new, outcome
    // TODO: Handle stat struct too
    Stat(SyscallOutcome), // Can fail access denied (exec/search on dir) or file didn't exist
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

// Directory Preconditions (For now, just cwd), File Preconditions
// Takes in all the events for ONE RESOURCE and generates its preconditions.
pub fn generate_preconditions(exec_file_events: ExecFileEvents) -> HashMap<PathBuf, HashSet<Fact>> {
    let sys_span = span!(Level::INFO, "generate_preconditions");
    let _ = sys_span.enter();
    let mut curr_file_preconditions: HashMap<PathBuf, HashSet<Fact>> = HashMap::new();

    for (full_path, event_list) in exec_file_events.file_event_list() {
        let mut first_state_struct = FirstStateStruct {
            state: FirstState::None,
        };
        let mut curr_state_struct = LastModStruct {
            state: LastMod::None,
        };
        let mut has_been_deleted = false;
        curr_file_preconditions.insert(full_path.clone(), HashSet::new());
        let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

        for event in event_list {
            let first_state = first_state_struct.state();
            let curr_state = curr_state_struct.state();

            match (event, first_state, curr_state, has_been_deleted) {
                (_, _, LastMod::None, true) => {
                    panic!("Last mod was none but was deleted is true??");
                }
                (_, FirstState::Exists, LastMod::Created, false) => {
                    panic!("Last mod was created, but was deleted is false, and file existed at start??");
                }
                (_, _, LastMod::Deleted, false) => {
                    panic!("Last mod was deleted, but was deleted is false??");
                }

                (SyscallEvent::Access(_, _), FirstState::DoesntExist, _, _) => {
                    // Didn't exist, was created, this access depends on a file that was created during execution,
                    // does not contribute to preconditions.
                }
                // Your access depends on a file I don't know nothing about.
                (SyscallEvent::Access(_, _), FirstState::Exists, _, true) => (),
                // It existed, it hasn't been deleted, these priveleges depend on a file from
                // BEFORE the execution :O
                (SyscallEvent::Access(flags, outcome), FirstState::Exists, _, false) => {
                    // It existed, it hasn't been deleted, these priveleges depend on a file from
                    // BEFORE the execution :O
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            if !flags.contains(&AccessFlags::F_OK) {
                                for f in flags {
                                    curr_set.insert(Fact::File(FileFact::HasPermission(*f)));
                                }
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            for f in flags {
                                curr_set.insert(Fact::File(FileFact::NoPermission(*f)));
                            }
                        }
                        o => panic!("Unexpected access syscall failure: {:?}", o),
                    }
                }
                (SyscallEvent::Access(_, _), FirstState::None, LastMod::Created, _) => {
                    panic!("No first state but last mod was created??");
                }
                (SyscallEvent::Access(_, _), FirstState::None, LastMod::Deleted, _) => {
                    panic!("No first state but last mod was deleted??");
                }
                (SyscallEvent::Access(_, _), FirstState::None, LastMod::Modified, _) => {
                    panic!("No first state but last mod was modified??");
                }
                (SyscallEvent::Access(_, _), FirstState::None, LastMod::Renamed, _) => {
                    panic!("No first state but last mod was renamed??");
                }
                (SyscallEvent::Access(flags, outcome), FirstState::None, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            if flags.contains(&AccessFlags::F_OK) {
                                curr_set.insert(Fact::File(FileFact::Exists));
                            } else {
                                for f in flags {
                                    curr_set.insert(Fact::File(FileFact::HasPermission(*f)));
                                }
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::File(FileFact::DoesntExist));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            for f in flags {
                                curr_set.insert(Fact::File(FileFact::NoPermission(*f)));
                            }
                        }
                        o => panic!("Unexpected access syscall failure: {:?}", o),
                    }
                }

                (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Created, _) => (),
                (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Deleted, true) => (),

                (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Modified, true) => (),
                (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Modified, false) => (),
                (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Renamed, true) => (),
                (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Renamed, false) => (),
                (SyscallEvent::Create(mode, outcome), FirstState::DoesntExist, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::File(FileFact::DoesntExist));
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));

                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                        }
                        f => panic!("Unexpected create {:?} file failure, didn't exist at start no other changes: {:?}", mode, f),
                    }
                }

                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Created, true) => (),
                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Deleted, true) => (),
                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Modified, true) => (),
                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Modified, false) => (),
                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Renamed, true) => (),
                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Renamed, false) => (),
                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::None, false) => (),
                (SyscallEvent::Create(_, _), FirstState::None, LastMod::Created, _) => {
                    panic!("First state none but last mod created??");
                }
                (SyscallEvent::Create(_, _), FirstState::None, LastMod::Deleted, true) => {
                    panic!("First state none but last mod deleted??");
                }
                (SyscallEvent::Create(_, _), FirstState::None, LastMod::Modified, _) => {
                    panic!("First state none but last mod modified??");
                }
                (SyscallEvent::Create(_, _), FirstState::None, LastMod::Renamed, _) => {
                    panic!("First state none but last mod renamed??");
                }
                (SyscallEvent::Create(OFlag::O_CREAT, outcome), FirstState::None, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::File(FileFact::DoesntExist));
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                        }
                        f => panic!("Unexpected create file failure, no state yet: {:?}", f),
                    }
                }
                (SyscallEvent::Create(OFlag::O_EXCL, outcome), FirstState::None, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::File(FileFact::DoesntExist));
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            curr_set.insert(Fact::File(FileFact::Exists));
                        }
                        f => panic!("Unexpected create file failure, no state yet: {:?}", f),
                    }
                }

                (SyscallEvent::Create(f, _), _, _, _) => panic!("Unexpected create flag: {:?}", f),
                (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Created, _) => (),
                (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Deleted, true) => (),
                (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Modified, true) => (),
                (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Modified, false) => (),
                (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Renamed, _) => (),
                (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::None, false) => (),
                (SyscallEvent::Delete(_), FirstState::Exists, LastMod::Created, true) => (),
                (SyscallEvent::Delete(_), FirstState::Exists, LastMod::Deleted, true) => (),
                (SyscallEvent::Delete(_), FirstState::Exists, LastMod::Modified, true) => (),
                (SyscallEvent::Delete(outcome), FirstState::Exists, LastMod::Modified, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, exists, last mod modified, no delete yet: {:?}", f),
                    }
                }
                (SyscallEvent::Delete(_), FirstState::Exists, LastMod::Renamed, true) => (),
                (SyscallEvent::Delete(outcome), FirstState::Exists, LastMod::Renamed, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, exists, last mod renamed, no delete yet: {:?}", f),
                    }
                }
                (SyscallEvent::Delete(outcome), FirstState::Exists, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                            has_been_deleted = true;
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                        }
                        f => panic!("Delete failed for unexpected reason, exists, no mods: {:?}", f),
                    }
                }
                (SyscallEvent::Delete(_), FirstState::None, LastMod::Created, _) => {
                    panic!("First state was none but last mod was created??");
                }
                (SyscallEvent::Delete(_), FirstState::None, LastMod::Deleted, _) => {
                    panic!("First state was none but last mod was deleted??");
                }
                (SyscallEvent::Delete(_), FirstState::None, LastMod::Modified, _) => {
                    panic!("First state was none but last mod was modified??");
                }
                (SyscallEvent::Delete(_), FirstState::None, LastMod::Renamed, _) => {
                    panic!("First state was none but last mod was renamed??");
                }
                (SyscallEvent::Delete(outcome), FirstState::None, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::File(FileFact::Exists));
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::File(FileFact::DoesntExist));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                        }
                        f => panic!("Unexpected failure from delete event: {:?}", f),
                    }
                }

                (
                    SyscallEvent::Open(_, outcome),
                    FirstState::DoesntExist,
                    LastMod::Created,
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


                (SyscallEvent::Open(_, _), FirstState::DoesntExist, LastMod::Created, false) => {
                    // Created, so not contents. not exists. we made the file in the exec so perms depend
                    // on that. and we already know x dir because we created the file at some point.
                    // So this just gives us nothing. (append, read, or trunc)
                }

                (SyscallEvent::Open(_, _), FirstState::DoesntExist, LastMod::Deleted, true) => {
                    // We created it. We deleted it. So we already know x dir. The perms depend on making the file during the execution.
                    // Same with contents.(append, read, or trunc)
                }
                (SyscallEvent::Open(_, _), FirstState::DoesntExist, LastMod::Modified, _) => {
                    // Doesn't exist. Created, modified, maybe deleted and the whole process repeated.
                }
                (SyscallEvent::Open(_, _), FirstState::DoesntExist, LastMod::Renamed, _) => (),
                (SyscallEvent::Open(_, outcome), FirstState::DoesntExist, LastMod::None, false) => {
                    // We know this doesn't exist, we know we haven't created it.
                    // This will just fail.
                    if *outcome != SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) {
                        panic!("Unexpected outcome open event, doesn't exist, no mods: {:?}", outcome);
                    }
                }

                (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::Created, true) => {
                    // It existed, then it was deleted, then created. This open depends on
                    // contents that are created during the execution.
                }

                // This is just going to say "file doesn't exist".
                // Or the error won't make sense or it succeeds which also makes no sense.
                (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::Deleted, true) => (),
                // Ditto - ish
                (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::Modified, true) => (),
                (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::Modified, false) => (),
                (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::Renamed, true) => (),
                (SyscallEvent::Open(OFlag::O_APPEND, outcome), FirstState::Exists, LastMod::Renamed, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            // Have the contents changed? We can check the curr_file_preconds to see if we already know
                            // we have write permission, then we know we have modified the file and don't care about the contents
                            // at the start of execution with respect to this particular open call.
                            if !curr_set.contains(&Fact::File(FileFact::HasPermission(AccessFlags::W_OK))) {
                                curr_set.insert(Fact::File(FileFact::Contents));
                            }
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            // You need w access to the dir to rename a file.
                            // I guess you could theoretically not have write perms to the file
                            // but have successfully renamed it last...
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                        }
                        f => panic!("Open append failed for strange reason, file exists and was renamed: {:?}", f),
                    }
                }
                (SyscallEvent::Open(OFlag::O_RDONLY, outcome), FirstState::Exists, LastMod::Renamed, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            if !curr_set.contains(&Fact::File(FileFact::HasPermission(AccessFlags::W_OK))) {
                                curr_set.insert(Fact::File(FileFact::Contents));
                            }
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::R_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::R_OK)));
                        }
                        f => panic!("Unexpected open read only failure, file exists and was renamed: {:?}", f),
                    }
                }
                (SyscallEvent::Open(OFlag::O_TRUNC, outcome), FirstState::Exists, LastMod::Renamed, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                        }
                        f => panic!("Unexpected open trunc failure, file exists and was renamed: {:?}", f),
                    }
                }
                (SyscallEvent::Open(OFlag::O_APPEND, outcome), FirstState::Exists, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::File(FileFact::Contents));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                        }
                        f => panic!("Unexpected open append failure, file existed, {:?}", f),
                    }
                }
                (SyscallEvent::Open(OFlag::O_RDONLY, outcome), FirstState::Exists, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::R_OK)));
                            curr_set.insert(Fact::File(FileFact::Contents));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::R_OK)));
                        }
                        f => panic!("Unexpected open append failure, file existed, {:?}", f),
                    }
                }
                (SyscallEvent::Open(OFlag::O_TRUNC, outcome), FirstState::Exists, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                        }
                        f => panic!("Unexpected open append failure, file existed, {:?}", f),
                    }
                }
                (SyscallEvent::Open(_, _), FirstState::None, LastMod::Created, _) => {
                    panic!("First state none but last mod created??");
                }
                (SyscallEvent::Open(_, _), FirstState::None, LastMod::Deleted, true) => {
                    panic!("First state none but last mod deleted??");
                }
                (SyscallEvent::Open(_, _), FirstState::None, LastMod::Modified, _) => {
                    panic!("First state none but last mod modified??");
                }
                (SyscallEvent::Open(_, _), FirstState::None, LastMod::Renamed, _) => {
                    panic!("First state none but last mod renamed??");
                }
                (SyscallEvent::Open(OFlag::O_APPEND, outcome), FirstState::None, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::Contents));
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            panic!("Open append, no info yet, failed because file already exists??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::File(FileFact::DoesntExist));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                        }
                    }
                }
                (SyscallEvent::Open(OFlag::O_RDONLY, outcome), FirstState::None, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::Contents));
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::R_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            panic!("Open read only, no info yet, failed because file already exists??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::File(FileFact::DoesntExist));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::R_OK)));
                        }
                    }
                }
                (SyscallEvent::Open(OFlag::O_TRUNC, outcome), FirstState::None, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            panic!("Open trunc, no info yet, failed because file already exists??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            panic!("Open trunc failed because file doesn't exist? So??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::R_OK)));
                        }
                    }
                }
                (SyscallEvent::Open(f, _), _, _, _) => panic!("Unexpected open flag: {:?}", f),

                (
                    SyscallEvent::Rename(_, _, _),
                    FirstState::DoesntExist,
                    LastMod::Created,
                    _,
                ) => (),
                (SyscallEvent::Rename(_, _, _), FirstState::DoesntExist, LastMod::Deleted, true) => {
                    // Created. Deleted. Won't succeed because old path is deleted.
                    // Already exists no, doesn't exist, yes makes sense as an error.
                    // But doesn't contribute to the preconditions.
                    // Permission denied doesn't make sense either.
                }
                (SyscallEvent::Rename(_, _, _), FirstState::DoesntExist, LastMod::Modified, _) => {
                    // Created, deleted, created, modified. Oof.
                    // Already existe no, doesn't exist no, permissions no.
                    // Success tells us nothing new too.
                }
                (SyscallEvent::Rename(_, _, _), FirstState::DoesntExist, LastMod::Renamed, _) => {
                    // Created, deleted, created, renamed. Or Created, renamed.
                    // Already exists no, doesn't exist no, permissions no.
                    // Success tells us nothing for preconds.
                }
                (SyscallEvent::Rename(_, _, outcome), FirstState::DoesntExist, LastMod::None, false) => {
                    // So, it doesn't exist. We can't rename it.
                    // So this can't succeed.
                    // Will fail because file doesn't exist which we already know.
                    // Fail for already exists? No.
                    // Could fail for permissions though.
                    if *outcome == SyscallOutcome::Fail(SyscallFailure::PermissionDenied) {
                        curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                        curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                }
                (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::Created, _) => {
                    // Existed. Deleted. Created! Or Existed. Created. Now renamin'.
                    // Already exists? no.
                    // Doesn't exist, no.
                    // Permissions denied, how?
                    // Success, cool.
                }
                (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::Deleted, true) => {
                    // Existed. Then was deleted.
                    // This will fail because the file doesn't exist.
                    // Success and already exist don't make sense. Same with permissions.
                    // Nothing contributes.
                }
                (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::Modified, _) => {
                    // Existed, Deleted, Created, Modified or Existed, Modified
                    // We should be able to rename this.
                    // Permissions no, doesn't exist no, already exists no.
                }
                (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::Renamed, _) => {
                    // Existed. Deleted. Created. Renamed. Or Existed, Renamed.
                    // Don't think this affects preconditions.
                    // Eventually we will handle rename flags where they don't wanna replace
                    // an existing file, and that will be a precondition.
                }
                (SyscallEvent::Rename(old_path, _, outcome), FirstState::Exists, LastMod::None, false) => {
                    // It exists, we haven't modified it.
                    // It exists so we know that we have x access to the cwd.
                    // So if it succeeds we have to add those preconditions.
                    // oldpath preconds: exists, x w access
                    // newpath preconds: none (not handling flags)
                    if old_path == full_path {
                        match outcome {
                            SyscallOutcome::Success => {
                                curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                // We may not have permission to write to the directory.
                                curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                            }
                            o => panic!("Unexpected failure in rename syscall event: {:?}", o),
                        }
                    }
                }
                (SyscallEvent::Rename(_, _, _), FirstState::None, LastMod::Created, _) => {
                    panic!("No first state but last mod was created??");
                }
                (SyscallEvent::Rename(_, _, _), FirstState::None, LastMod::Deleted, _) => {
                    panic!("No first state but last mod was deleted??");
                }
                (SyscallEvent::Rename(_, _, _), FirstState::None, LastMod::Modified, _) => {
                    panic!("No first state but last mod was modified??");
                }
                (SyscallEvent::Rename(_, _, _), FirstState::None, LastMod::Renamed, _) => {
                    panic!("No first state but last mod was renamed??");
                }
                (SyscallEvent::Rename(old_path, _, outcome), FirstState::None, LastMod::None, false) => {
                    // No first state, no mods, haven't deleted. This is the first thing we are doing to this
                    // resource probably.
                    match outcome {
                        SyscallOutcome::Success => {
                            // New path just wouldn't contribute to the preconditions.
                            if old_path == full_path {
                                // First event is renaming and we see old path, add all the preconds.
                                curr_set.insert(Fact::File(FileFact::Exists));
                                curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                                curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            // Old path doesn't exist cool.
                            curr_set.insert(Fact::File(FileFact::DoesntExist));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                        }
                        o => panic!("Unexpected error for rename: {:?}", o),
                    }
                }

                (SyscallEvent::Stat(_), FirstState::DoesntExist, LastMod::Created, _) => {
                    // Didn't exist, created, deleted, created, this stat doesn't depend on
                    // a file that existed at the start. and obviously we have exec access to the dir.
                }
                (SyscallEvent::Stat(_), FirstState::DoesntExist, LastMod::Deleted, true) => {
                    // The file didn't exist. Then the file was created and deleted. Adds nothing.
                }
                (SyscallEvent::Stat(_), FirstState::DoesntExist, LastMod::Modified, _) => (),
                (SyscallEvent::Stat(_), FirstState::DoesntExist, LastMod::Renamed, _) => (),
                (SyscallEvent::Stat(outcome), FirstState::DoesntExist, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => (),
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                        }
                        f => panic!("Unexpected failure by stat syscall, first state was doesn't exist, last mod none: {:?}", f),
                    }
                }
                // It existed at the start, but it was deleted, contributes nothing.
                (SyscallEvent::Stat(_), FirstState::Exists, LastMod::Created, true) => (),
                (SyscallEvent::Stat(_), FirstState::Exists, LastMod::Deleted, true) => (),
                (SyscallEvent::Stat(_), FirstState::Exists, LastMod::Modified, true) => (),
                (SyscallEvent::Stat(_), FirstState::Exists, LastMod::Modified, false) => {
                    // Existed at start. We have modified it. Already know x access to dir.
                    curr_set.insert(Fact::File(FileFact::StatStructMatches));
                }
                (SyscallEvent::Stat(_), FirstState::Exists, LastMod::Renamed, true) => (),
                (SyscallEvent::Stat(_), FirstState::Exists, LastMod::Renamed, false) => {
                    // Foo.txt exists.
                    // We rename it to bar.txt (preconds: foo exists, x access to dir)
                    // Bar.txt has the event [Rename(foo,bar)]
                    // Would the stat struct be the same??
                    // Should bar.txt get a "stat struct matches" fact?
                    // TODO: I feel like... maybe yes? maybe c time is affected but who cares?
                    // seems that rename works by making a new link and then removing the old one
                    curr_set.insert(Fact::File(FileFact::StatStructMatches));
                }
                (SyscallEvent::Stat(outcome), FirstState::Exists, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::StatStructMatches));
                        }
                        f => panic!("Unexpected failure of stat call, file exists: {:?}", f),
                    }
                }

                (SyscallEvent::Stat(_), FirstState::None, LastMod::Created, _) => {
                    panic!("First state was none but last mod was created??");
                }
                (SyscallEvent::Stat(_), FirstState::None, LastMod::Deleted, _) => {
                    panic!("First state was none but last mod was deleted??");
                }
                (SyscallEvent::Stat(_), FirstState::None, LastMod::Modified, _) => {
                    panic!("First state was none but last mod was modified??");
                }
                (SyscallEvent::Stat(_), FirstState::None, LastMod::Renamed, _) => {
                    panic!("First state was none but last mod was renamed??");
                }
                (SyscallEvent::Stat(outcome), FirstState::None, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            curr_set.insert(Fact::File(FileFact::StatStructMatches));
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                            panic!("Unexpected stat failure: file already exists??");
                        }
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                            curr_set.insert(Fact::File(FileFact::DoesntExist));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                        }
                    }
                }
            }

            // This function will only change the first_state if it is None.
            first_state_struct.update_based_on_syscall(event);
            curr_state_struct.update_based_on_syscall(event);
        }
    }
    curr_file_preconditions
}

// REMEMBER: SIDE EFFECT FREE SYSCALLS CONTRIBUTE NOTHING TO THE POSTCONDITIONS.
// Directory Postconditions (for now just cwd), File Postconditions
fn generate_postconditions(file_events: ExecFileEvents) -> HashMap<PathBuf, HashSet<Fact>> {
    unimplemented!();
}
//     let sys_span = span!(Level::INFO, "generate_file_postconditions");
//     let _ = sys_span.enter();

//     let mut curr_file_postconditions = HashSet::new();

//     let mut first_state_struct = FirstStateStruct {
//         state: FirstState::None,
//     };
//     let mut curr_state_struct = LastModStruct {
//         state: LastMod::None,
//     };
//     let mut has_been_deleted = false;

//     for event in file_events {
//         let first_state = first_state_struct.state();
//         let curr_state = curr_state_struct.state();

//         match (event, first_state, curr_state) {
//             (SyscallEvent::Access(_, _), _, _) => (),
//             (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Created) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Modified) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::None) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Created) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Modified) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::None) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::None, LastMod::Created) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::None, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::None, LastMod::Modified) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::None, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Create(_, _), FirstState::None, LastMod::None) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Created) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Modified) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::None) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::Exists, LastMod::Created) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::Exists, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::Exists, LastMod::Modified) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::Exists, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::Exists, LastMod::None) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::None, LastMod::Created) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::None, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::None, LastMod::Modified) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::None, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Delete(_), FirstState::None, LastMod::None) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::DoesntExist, LastMod::Created) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::DoesntExist, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::DoesntExist, LastMod::Modified) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::DoesntExist, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::DoesntExist, LastMod::None) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::Created) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::Modified) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::None) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::None, LastMod::Created) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::None, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::None, LastMod::Modified) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::None, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Open(_, _), FirstState::None, LastMod::None) => todo!(),

//             (SyscallEvent::Rename(old_path, new_path, outcome), FirstState::DoesntExist, LastMod::Created) => {
//                 match outcome {
//                     SyscallOutcome::Success => {
//                         if *old_path == file_path {

//                         }
//                     }
//                 }
//             }
//             (SyscallEvent::Rename(_, _, _), FirstState::DoesntExist, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::DoesntExist, LastMod::Modified) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::DoesntExist, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::DoesntExist, LastMod::None) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::Created) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::Modified) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::None) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::None, LastMod::Created) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::None, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::None, LastMod::Modified) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::None, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Rename(_, _, _), FirstState::None, LastMod::None) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::DoesntExist, LastMod::Created) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::DoesntExist, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::DoesntExist, LastMod::Modified) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::DoesntExist, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::DoesntExist, LastMod::None) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::Exists, LastMod::Created) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::Exists, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::Exists, LastMod::Modified) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::Exists, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::Exists, LastMod::None) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::None, LastMod::Created) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::None, LastMod::Deleted) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::None, LastMod::Modified) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::None, LastMod::Renamed) => todo!(),
//             (SyscallEvent::Stat(_), FirstState::None, LastMod::None) => todo!(),
//         }

//         first_state_struct.update_based_on_syscall(event);
//         curr_state_struct.update_based_on_syscall(event);
//     }
//     curr_file_postconditions
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_failed_access_then_create() {
//         let events = [
//             SyscallEvent::Access(
//                 HashSet::from([AccessFlags::W_OK]),
//                 SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
//             ),
//             SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
//         ];
//         let preconditions = generate_preconditions(, &events);
//         let correct_preconditions = HashSet::from([
//             Fact::File(FileFact::DoesntExist),
//             Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)),
//             Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
//         ]);
//         assert_eq!(preconditions, correct_preconditions);

//         // let postconditions = generate_postconditions(&events);
//         // let correct_postconditions = HashSet::from([Fact::File(FileFact::Contents)]);
//         // assert_eq!(postconditions, correct_postconditions);
//     }
//     #[test]
//     fn test_postconds2() {
//         let events = [
//             SyscallEvent::Access(
//                 HashSet::from([AccessFlags::W_OK]),
//                 SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
//             ),
//             SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
//         ];
//         // let postconditions = generate_postconditions(&events);
//         // let correct_postconditions = HashSet::from([Fact::File(FileFact::Contents)]);
//         // assert_eq!(postconditions, correct_postconditions);
//     }

//     // stat
//     // open open
//     #[test]
//     fn test_stat_open_create_preconds() {
//         let events = [
//             SyscallEvent::Stat(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
//             SyscallEvent::Open(
//                 OFlag::O_RDONLY,
//                 SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
//             ),
//             SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
//         ];
//         let preconditions = generate_preconditions(PathBuf::from("hi"), &events);
//         let correct_preconditions = HashSet::from([
//             Fact::File(FileFact::DoesntExist),
//             Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)),
//             Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
//         ]);
//         assert_eq!(preconditions, correct_preconditions);
//     }
//     #[test]
//     fn test_postconds3() {
//         let events = [
//             SyscallEvent::Stat(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
//             SyscallEvent::Open(
//                 OFlag::O_RDONLY,
//                 SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
//             ),
//             SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
//         ];
//         // let postconditions = generate_postconditions(&events);
//         // let correct_postconditions = HashSet::from([Fact::File(FileFact::Contents)]);
//         // assert_eq!(postconditions, correct_postconditions);
//     }

//     #[test]
//     fn test_open_open_access_stat_preconds() {
//         let events = [
//             SyscallEvent::Open(OFlag::O_APPEND, SyscallOutcome::Success),
//             SyscallEvent::Open(OFlag::O_TRUNC, SyscallOutcome::Success),
//             SyscallEvent::Access(HashSet::from([AccessFlags::R_OK]), SyscallOutcome::Success),
//             SyscallEvent::Stat(SyscallOutcome::Success),
//         ];
//         let preconditions = generate_preconditions(PathBuf::from("test"), &events);
//         let correct_preconditions = HashSet::from([
//             Fact::File(FileFact::Contents),
//             Fact::File(FileFact::HasPermission(AccessFlags::R_OK)),
//             Fact::File(FileFact::HasPermission(AccessFlags::W_OK)),
//             Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
//             Fact::File(FileFact::StatStructMatches),
//         ]);
//         assert_eq!(preconditions, correct_preconditions);
//     }

//     #[test]
//     fn test_postconds4() {
//         let events = [
//             SyscallEvent::Open(OFlag::O_APPEND, SyscallOutcome::Success),
//             SyscallEvent::Open(OFlag::O_TRUNC, SyscallOutcome::Success),
//             SyscallEvent::Access(HashSet::from([AccessFlags::R_OK]), SyscallOutcome::Success),
//             SyscallEvent::Stat(SyscallOutcome::Success),
//         ];
//         // let postconditions = generate_postconditions(&events);
//         // let correct_postconditions = HashSet::from([Fact::File(FileFact::Contents)]);
//         // assert_eq!(postconditions, correct_postconditions);
//     }

//     #[test]
//     fn test_append_delete_create() {
//         let events = [
//             SyscallEvent::Open(OFlag::O_APPEND, SyscallOutcome::Success),
//             SyscallEvent::Delete(SyscallOutcome::Success),
//             SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
//         ];
//         let preconditions = generate_preconditions(PathBuf::from("test"), &events);
//         let correct_preconditions = HashSet::from([
//             Fact::File(FileFact::Contents),
//             Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
//             Fact::File(FileFact::HasPermission(AccessFlags::W_OK)),
//         ]);
//         assert_eq!(preconditions, correct_preconditions);

//         // let postconditions = generate_postconditions(&events);
//         // let correct_postconditions = HashSet::from([Fact::File(FileFact::Contents)]);
//         // assert_eq!(postconditions, correct_postconditions);
//     }
// }
