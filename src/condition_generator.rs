use nix::fcntl::OFlag;
use nix::sys::stat::FileStat;
use nix::unistd::{AccessFlags, Pid};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    path::PathBuf,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum LastMod {
    Created,
    Deleted,
    Modified,
    Renamed(PathBuf, PathBuf),
    None,
}
pub struct LastModStruct {
    state: LastMod,
}

impl LastModStruct {
    fn update_based_on_syscall(&mut self, syscall_event: SyscallEvent) {
        match syscall_event {
            SyscallEvent::Create(_, SyscallOutcome::Success) => {
                self.state = LastMod::Created;
            }
            SyscallEvent::Delete(SyscallOutcome::Success) => {
                self.state = LastMod::Deleted;
            }
            SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, SyscallOutcome::Success) => {
                self.state = LastMod::Modified;
            }
            SyscallEvent::Rename(old_path, new_path, outcome) => {
                if outcome == SyscallOutcome::Success {
                    self.state = LastMod::Renamed(old_path.clone(), new_path);
                }
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
    Contents(Vec<u8>),
    DoesntExist,
    Exists,
    StatStructMatches(FileStat),
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
    fn update_based_on_syscall(&mut self, curr_file_path: &PathBuf, syscall_event: SyscallEvent) {
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
                SyscallEvent::Open(
                    OFlag::O_APPEND | OFlag::O_RDONLY,
                    _,
                    SyscallOutcome::Success,
                ) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Open(OFlag::O_TRUNC, _, SyscallOutcome::Success) => (),
                SyscallEvent::Open(
                    OFlag::O_APPEND | OFlag::O_RDONLY,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    self.state = FirstState::DoesntExist;
                }
                SyscallEvent::Open(
                    OFlag::O_APPEND | OFlag::O_TRUNC,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Open(OFlag::O_TRUNC, _, SyscallOutcome::Fail(fail)) => {
                    panic!("Failed to open trunc for strange reason: {:?}", fail)
                }
                SyscallEvent::Open(
                    OFlag::O_RDONLY,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => {
                    self.state = FirstState::Exists;
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
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Stat(_, SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!("Failed to state because file already exists??");
                }
                SyscallEvent::Stat(_, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.state = FirstState::DoesntExist;
                }
                SyscallEvent::Stat(_, SyscallOutcome::Fail(SyscallFailure::PermissionDenied)) => (),
                SyscallEvent::Rename(old_path, new_path, SyscallOutcome::Success) => {
                    if *curr_file_path == old_path {
                        self.state = FirstState::Exists;
                    } else if *curr_file_path == new_path {
                        self.state = FirstState::DoesntExist;
                    }
                }
                SyscallEvent::Rename(
                    old_path,
                    _,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    if *curr_file_path == old_path {
                        self.state = FirstState::DoesntExist;
                    }
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

    pub fn get_events_by_filename(&self, file_name: PathBuf) -> Vec<SyscallEvent> {
        self.filename_to_events_map.get(&file_name).unwrap().clone()
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
    Open(OFlag, Option<Vec<u8>>, SyscallOutcome), // Can fail because the file didn't exist or permission denied
    Rename(PathBuf, PathBuf, SyscallOutcome),     // Old, new, outcome
    // TODO: Handle stat struct too
    Stat(Option<FileStat>, SyscallOutcome), // Can fail access denied (exec/search on dir) or file didn't exist
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

pub fn generate_hash(path: PathBuf) -> Vec<u8> {
    // let s = span!(Level::INFO, stringify!(generate_hash), pid=?caller_pid);
    // let _ = s.enter();
    // s.in_scope(|| info!("Made it to generate_hash for path: {}", path));
    let mut file = File::open(&path).expect("Could not open file to generate hash");
    process::<Sha256, _>(&mut file)
}

// ------ Hashing stuff ------
// Process the file and generate the hash.
fn process<D: Digest + Default, R: Read>(reader: &mut R) -> Vec<u8> {
    const BUFFER_SIZE: usize = 1024;
    let mut sh = D::default();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = reader
            .read(&mut buffer)
            .expect("Could not read buffer from reader processing hash!");
        sh.update(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }
    let final_array = &sh.finalize();
    final_array.to_vec()
}
// Directory Preconditions (For now, just cwd), File Preconditions
// Takes in all the events for ONE RESOURCE and generates its preconditions.
pub fn generate_preconditions(exec_file_events: ExecFileEvents) -> HashMap<PathBuf, HashSet<Fact>> {
    let sys_span = span!(Level::INFO, "generate_preconditions");
    let _ = sys_span.enter();
    let mut curr_file_preconditions: HashMap<PathBuf, HashSet<Fact>> = HashMap::new();
    for full_path in exec_file_events.file_event_list().keys() {
        curr_file_preconditions.insert(full_path.clone(), HashSet::new());
    }

    for (full_path, event_list) in exec_file_events.file_event_list() {
        let mut first_state_struct = FirstStateStruct {
            state: FirstState::None,
        };
        let mut curr_state_struct = LastModStruct {
            state: LastMod::None,
        };
        let mut has_been_deleted = false;

        // let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

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
                            let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            if !flags.contains(&AccessFlags::F_OK) {
                                for f in flags {
                                    curr_set.insert(Fact::File(FileFact::HasPermission(*f)));
                                }
                            }
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            for f in flags {
                                let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();
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
                (SyscallEvent::Access(_, _), FirstState::None, LastMod::Renamed(_,_), _) => {
                    panic!("No first state but last mod was renamed??");
                }
                (SyscallEvent::Access(flags, outcome), FirstState::None, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();
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
                (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Renamed(_, _), _) => (),
                (SyscallEvent::Create(mode, outcome), FirstState::DoesntExist, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();
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
                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Renamed(_, _), _) => (),
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
                (SyscallEvent::Create(_, _), FirstState::None, LastMod::Renamed(_, _), _) => {
                    panic!("First state none but last mod renamed??");
                }
                (SyscallEvent::Create(OFlag::O_CREAT, outcome), FirstState::None, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();
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
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();
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
                (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Renamed(_, _), _) => {
                    // old path? didnt exist, created, renamed. now trying to delete. won't suceed it doesnt exist anymore.
                    // newpath? didn't exist, rename made it exist, now it might get deleted. does this change its preconds? nope
                    // they are still just "doesn't exist"
                }
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
                (SyscallEvent::Delete(_), FirstState::Exists, LastMod::Renamed(_,_), true) => (),
                (SyscallEvent::Delete(outcome), FirstState::Exists, LastMod::Renamed(_, _), false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            has_been_deleted = true;
                        }
                        f => panic!("Delete failed for unexpected reason, exists, last mod renamed, no delete yet: {:?}", f),
                    }
                }
                (SyscallEvent::Delete(outcome), FirstState::Exists, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

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
                (SyscallEvent::Delete(_), FirstState::None, LastMod::Renamed(_,_), _) => {
                    panic!("First state was none but last mod was renamed??");
                }
                (SyscallEvent::Delete(outcome), FirstState::None, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

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
                    SyscallEvent::Open(_,  _,outcome),
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


                (SyscallEvent::Open(_,  _,_), FirstState::DoesntExist, LastMod::Created, false) => {
                    // Created, so not contents. not exists. we made the file in the exec so perms depend
                    // on that. and we already know x dir because we created the file at some point.
                    // So this just gives us nothing. (append, read, or trunc)
                }

                (SyscallEvent::Open(_, _,_), FirstState::DoesntExist, LastMod::Deleted, true) => {
                    // We created it. We deleted it. So we already know x dir. The perms depend on making the file during the execution.
                    // Same with contents.(append, read, or trunc)
                }
                (SyscallEvent::Open(_,  _,_), FirstState::DoesntExist, LastMod::Modified, _) => {
                    // Doesn't exist. Created, modified, maybe deleted and the whole process repeated.
                }
                // TODO: fix this case, think about bar in the case of rename(foo, bar). what if we then append to bar?
                (SyscallEvent::Open(OFlag::O_APPEND, hash_option, outcome), FirstState::DoesntExist, LastMod::Renamed(old_path, new_path), false) => {
                    if full_path == new_path {
                        let old_path_preconds = curr_file_preconditions.get_mut(old_path).unwrap();

                        match outcome {
                            SyscallOutcome::Success => {
                                let hash = hash_option.clone().unwrap();
                                // This precondition needs to be added to the old path's precodns.
                                old_path_preconds.insert(Fact::File(FileFact::Contents(hash)));
                                old_path_preconds.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                // This precondition needs to be added to the old path's precodns.
                                old_path_preconds.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                            }
                            _ => (),
                        }
                    }
                }
                (SyscallEvent::Open(OFlag::O_APPEND, hash_option, outcome), FirstState::DoesntExist, LastMod::Renamed(old_path, new_path), true) => {
                    if full_path == new_path {
                        match outcome {
                            SyscallOutcome::Success => {
                                let old_path_preconds = curr_file_preconditions.get_mut(old_path).unwrap();
                                let hash = hash_option.clone().unwrap();
                                old_path_preconds.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                                old_path_preconds.insert(Fact::File(FileFact::Contents(hash)));
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                let old_path_preconds = curr_file_preconditions.get_mut(old_path).unwrap();
                                old_path_preconds.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                            }
                            _ => (),
                        }
                    }
                }

                (SyscallEvent::Open(OFlag::O_TRUNC, _, outcome), FirstState::DoesntExist, LastMod::Renamed(old_path, new_path), _) => {
                    if full_path == new_path {
                        match outcome {
                            SyscallOutcome::Success => {
                                let old_path_preconds = curr_file_preconditions.get_mut(old_path).unwrap();
                                old_path_preconds.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                            }
                            SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                                let old_path_preconds = curr_file_preconditions.get_mut(old_path).unwrap();
                                old_path_preconds.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                            }
                            _ => (),
                        }
                    }
                }
                (SyscallEvent::Open(_, _, outcome), FirstState::DoesntExist, LastMod::None, false) => {
                    // We know this doesn't exist, we know we haven't created it.
                    // This will just fail.
                    if *outcome != SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) {
                        panic!("Unexpected outcome open event, doesn't exist, no mods: {:?}", outcome);
                    }
                }

                (SyscallEvent::Open(_, _, _), FirstState::Exists, LastMod::Created, true) => {
                    // It existed, then it was deleted, then created. This open depends on
                    // contents that are created during the execution.
                }

                // This is just going to say "file doesn't exist".
                // Or the error won't make sense or it succeeds which also makes no sense.
                (SyscallEvent::Open(_, _,  _), FirstState::Exists, LastMod::Deleted, true) => (),
                // Ditto - ish
                (SyscallEvent::Open(_,  _,_), FirstState::Exists, LastMod::Modified, true) => (),
                (SyscallEvent::Open(_,  _,_), FirstState::Exists, LastMod::Modified, false) => (),
                (SyscallEvent::Open(_, _, _), FirstState::Exists, LastMod::Renamed(_, _), true) => (),
                // First state exists means this is the old path, which doesn't exist anymore, so this won't succeed and doesn't change the preconditions.
                (SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_RDONLY | OFlag::O_TRUNC, _, _), FirstState::Exists, LastMod::Renamed(_, _), false) => (),
                (SyscallEvent::Open(OFlag::O_APPEND, hash_option, outcome), FirstState::Exists, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            let hash = hash_option.clone().unwrap();
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::File(FileFact::Contents(hash)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                        }
                        f => panic!("Unexpected open append failure, file existed, {:?}", f),
                    }
                }
                (SyscallEvent::Open(OFlag::O_RDONLY, hash_option, outcome), FirstState::Exists, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            let hash = hash_option.clone().unwrap();
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::HasPermission(AccessFlags::R_OK)));
                            curr_set.insert(Fact::File(FileFact::Contents(hash)));
                        }
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            curr_set.insert(Fact::File(FileFact::NoPermission(AccessFlags::R_OK)));
                        }
                        f => panic!("Unexpected open append failure, file existed, {:?}", f),
                    }
                }
                (SyscallEvent::Open(OFlag::O_TRUNC,  _,outcome), FirstState::Exists, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

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
                (SyscallEvent::Open(_,  _,_), FirstState::None, LastMod::Created, _) => {
                    panic!("First state none but last mod created??");
                }
                (SyscallEvent::Open(_,  _,_), FirstState::None, LastMod::Deleted, true) => {
                    panic!("First state none but last mod deleted??");
                }
                (SyscallEvent::Open(_,  _,_), FirstState::None, LastMod::Modified, _) => {
                    panic!("First state none but last mod modified??");
                }
                (SyscallEvent::Open(_,  _,_), FirstState::None, LastMod::Renamed(_,_), _) => {
                    panic!("First state none but last mod renamed??");
                }
                (SyscallEvent::Open(OFlag::O_APPEND,  hash_option, outcome), FirstState::None, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();
                    match outcome {
                        SyscallOutcome::Success => {
                            let hash = hash_option.clone().unwrap();
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::Contents(hash)));
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
                (SyscallEvent::Open(OFlag::O_RDONLY,  hash_option, outcome), FirstState::None, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            let hash = hash_option.clone().unwrap();
                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            curr_set.insert(Fact::File(FileFact::Contents(hash)));
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
                (SyscallEvent::Open(OFlag::O_TRUNC,  _,outcome), FirstState::None, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

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
                (SyscallEvent::Open(f,  _,_), _, _, _) => panic!("Unexpected open flag: {:?}", f),

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
                (SyscallEvent::Rename(_, _, _), FirstState::DoesntExist, LastMod::Renamed(_,_), _) => {
                    // Created, deleted, created, renamed. Or Created, renamed.
                    // Already exists no, doesn't exist no, permissions no.
                    // Success tells us nothing for preconds.
                }
                (SyscallEvent::Rename(_, _, outcome), FirstState::DoesntExist, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

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
                (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::Renamed(_,_), _) => {
                    // Existed. Deleted. Created. Renamed. Or Existed, Renamed.
                    // Don't think this affects preconditions.
                    // Eventually we will handle rename flags where they don't wanna replace
                    // an existing file, and that will be a precondition.
                }
                (SyscallEvent::Rename(old_path, _, outcome), FirstState::Exists, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

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
                (SyscallEvent::Rename(_, _, _), FirstState::None, LastMod::Renamed(_,_), _) => {
                    panic!("No first state but last mod was renamed??");
                }
                (SyscallEvent::Rename(old_path, _, outcome), FirstState::None, LastMod::None, false) => {
                    // No first state, no mods, haven't deleted. This is the first thing we are doing to this
                    // resource probably.
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            if old_path == full_path {
                                // First event is renaming and we see old path, add all the preconds.
                                curr_set.insert(Fact::File(FileFact::Exists));
                                curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                                curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            } else {
                                // full_path = new path
                                curr_set.insert(Fact::File(FileFact::DoesntExist));
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

                (SyscallEvent::Stat(_, _), FirstState::DoesntExist, LastMod::Created, _) => {
                    // Didn't exist, created, deleted, created, this stat doesn't depend on
                    // a file that existed at the start. and obviously we have exec access to the dir.
                }
                (SyscallEvent::Stat(_, _), FirstState::DoesntExist, LastMod::Deleted, true) => {
                    // The file didn't exist. Then the file was created and deleted. Adds nothing.
                }
                (SyscallEvent::Stat(_, _), FirstState::DoesntExist, LastMod::Modified, _) => (),
                (SyscallEvent::Stat(_, _), FirstState::DoesntExist, LastMod::Renamed(_,_), _) => (),
                (SyscallEvent::Stat(_, outcome), FirstState::DoesntExist, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => (),
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                        }
                        f => panic!("Unexpected failure by stat syscall, first state was doesn't exist, last mod none: {:?}", f),
                    }
                }
                // It existed at the start, but we have modified it, so this stat doesn't depend on
                // the file at the beginning of the computation.
                (SyscallEvent::Stat(_,_), FirstState::Exists, LastMod::Created, true) => (),
                (SyscallEvent::Stat(_,_), FirstState::Exists, LastMod::Deleted, true) => (),
                (SyscallEvent::Stat(_,_), FirstState::Exists, LastMod::Modified, true) => (),
                (SyscallEvent::Stat(_,_), FirstState::Exists, LastMod::Modified, false) => (),
                // This file has been deleted, no way the stat struct is gonna be the same.
                (SyscallEvent::Stat(_,_), FirstState::Exists, LastMod::Renamed(_,_), true) => (),
                (SyscallEvent::Stat(_, _), FirstState::Exists, LastMod::Renamed(_, _), false) => {
                    // first state exists, shouldn't be true for new path. so this should not show up.
                    // for old_path does this do anything? no.
                }
                (SyscallEvent::Stat(option_stat, outcome), FirstState::Exists, LastMod::None, false) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

                            curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            if let Some(stat) = option_stat {
                                curr_set.insert(Fact::File(FileFact::StatStructMatches(*stat)));
                            } else {
                                panic!("No stat struct found for successful stat syscall!");
                            }
                        }
                        f => panic!("Unexpected failure of stat call, file exists: {:?}", f),
                    }
                }

                (SyscallEvent::Stat(_, _), FirstState::None, LastMod::Created, _) => {
                    panic!("First state was none but last mod was created??");
                }
                (SyscallEvent::Stat(_, _), FirstState::None, LastMod::Deleted, _) => {
                    panic!("First state was none but last mod was deleted??");
                }
                (SyscallEvent::Stat(_, _), FirstState::None, LastMod::Modified, _) => {
                    panic!("First state was none but last mod was modified??");
                }
                (SyscallEvent::Stat(_, _), FirstState::None, LastMod::Renamed(_,_), _) => {
                    panic!("First state was none but last mod was renamed??");
                }
                (SyscallEvent::Stat(option_stat, outcome), FirstState::None, LastMod::None, false) => {
                    let curr_set = curr_file_preconditions.get_mut(full_path).unwrap();

                    match outcome {
                        SyscallOutcome::Success => {
                            if let Some(stat) = option_stat {
                                curr_set.insert(Fact::File(FileFact::StatStructMatches(*stat)));
                                curr_set.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                            } else {
                                panic!("No stat struct found for successful stat syscall!");
                            }

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
            first_state_struct.update_based_on_syscall(full_path, event.clone());
            curr_state_struct.update_based_on_syscall(event.clone());
        }
    }
    curr_file_preconditions
}

fn no_mods_before_rename(
    old_path: PathBuf,
    new_path: PathBuf,
    file_name_list: Vec<SyscallEvent>,
) -> bool {
    let mut no_mods = true;
    for event in file_name_list {
        match event {
            SyscallEvent::Access(_, _) => (),
            SyscallEvent::Open(OFlag::O_RDONLY, _, _) => (),
            SyscallEvent::Stat(_, _) => (),
            SyscallEvent::Rename(old_path, new_path, SyscallOutcome::Success) => {
                break;
            }
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
// REMEMBER: SIDE EFFECT FREE SYSCALLS CONTRIBUTE NOTHING TO THE POSTCONDITIONS.
// Directory Postconditions (for now just cwd), File Postconditions
fn generate_postconditions(exec_file_events: ExecFileEvents) -> HashMap<PathBuf, HashSet<Fact>> {
    let sys_span = span!(Level::INFO, "generate_file_postconditions");
    let _ = sys_span.enter();

    let mut curr_file_postconditions: HashMap<PathBuf, HashSet<Fact>> = HashMap::new();

    // Just be sure the map is set up ahead of time.
    for full_path in exec_file_events.file_event_list().keys() {
        curr_file_postconditions.insert(full_path.clone(), HashSet::new());
    }
    for (full_path, event_list) in exec_file_events.file_event_list() {
        let hash = generate_hash(full_path.clone());
        let mut first_state_struct = FirstStateStruct {
            state: FirstState::None,
        };
        let mut last_mod_struct = LastModStruct {
            state: LastMod::None,
        };
        // curr_file_postconditions.insert(full_path.clone(), HashSet::new());
        for event in event_list {
            let first_state = first_state_struct.state();
            let last_mod = last_mod_struct.state();

            match (event, first_state, last_mod) {
                (_, FirstState::None, LastMod::Created) => {
                    panic!("First state is none but last mod is created!!");
                }
                (_, FirstState::None, LastMod::Deleted) => {
                    panic!("First state is none but last mod is deleted!!");
                }
                (_, FirstState::None, LastMod::Modified) => {
                    panic!("First state is none but last mod is modified!!");
                }
                (_, FirstState::None, LastMod::Renamed(_, _)) => {
                    panic!("First state is none but last mod is rename!!");
                }
                (SyscallEvent::Access(_, _), _, _) => (),
                (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Created) => (),
                (SyscallEvent::Create(_, outcome), FirstState::DoesntExist, LastMod::Deleted) => {
                    if outcome == &SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        curr_set.remove(&Fact::File(FileFact::DoesntExist));
                        curr_set.insert(Fact::File(FileFact::Contents(hash.clone())));
                    }
                }

                (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Modified) => (),
                (
                    SyscallEvent::Create(_, outcome),
                    FirstState::DoesntExist,
                    LastMod::Renamed(_, _),
                ) => {
                    if outcome == &SyscallOutcome::Success {
                        let path_clone = full_path.clone();
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        curr_set.remove(&Fact::File(FileFact::DoesntExist));
                        let hash = generate_hash(path_clone);
                        curr_set.insert(Fact::File(FileFact::Contents(hash)));
                    }
                }
                (SyscallEvent::Create(_, outcome), FirstState::DoesntExist, LastMod::None) => {
                    if outcome == &SyscallOutcome::Success {
                        let path_clone = full_path.clone();
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        let hash = generate_hash(path_clone);
                        curr_set.insert(Fact::File(FileFact::Contents(hash)));
                    }
                }
                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Created) => (),
                (SyscallEvent::Create(_, outcome), FirstState::Exists, LastMod::Deleted) => {
                    if outcome == &SyscallOutcome::Success {
                        let path_clone = full_path.clone();
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        let hash = generate_hash(path_clone);
                        curr_set.remove(&Fact::File(FileFact::DoesntExist));
                        curr_set.insert(Fact::File(FileFact::Contents(hash)));
                    }
                }
                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::Modified) => (),
                (SyscallEvent::Create(_, outcome), FirstState::Exists, LastMod::Renamed(_, _)) => {
                    if outcome == &SyscallOutcome::Success {
                        let path_clone = full_path.clone();
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        let hash = generate_hash(path_clone);
                        curr_set.remove(&Fact::File(FileFact::Exists));
                        curr_set.remove(&Fact::File(FileFact::DoesntExist));
                        curr_set.insert(Fact::File(FileFact::Contents(hash)));
                    }
                }
                (SyscallEvent::Create(_, _), FirstState::Exists, LastMod::None) => (),
                (SyscallEvent::Create(_, outcome), FirstState::None, LastMod::None) => {
                    if outcome == &SyscallOutcome::Success {
                        let path_clone = full_path.clone();
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        let hash = generate_hash(path_clone);
                        curr_set.insert(Fact::File(FileFact::Contents(hash)));
                    }
                }
                (
                    SyscallEvent::Delete(outcome),
                    FirstState::DoesntExist,
                    LastMod::Created | LastMod::Modified,
                ) => {
                    if outcome == &SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        let path_clone = full_path.clone();
                        let hash = generate_hash(path_clone);
                        curr_set.remove(&Fact::File(FileFact::Exists));
                        curr_set.remove(&Fact::File(FileFact::Contents(hash)));
                        curr_set.insert(Fact::File(FileFact::DoesntExist));
                    }
                }
                (
                    SyscallEvent::Delete(outcome),
                    FirstState::DoesntExist,
                    LastMod::Renamed(_, new_path),
                ) => {
                    if outcome == &SyscallOutcome::Success && full_path == new_path {
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        let path_clone = full_path.clone();
                        let hash = generate_hash(path_clone);
                        curr_set.remove(&Fact::File(FileFact::Exists));
                        curr_set.remove(&Fact::File(FileFact::Contents(hash)));
                        curr_set.insert(Fact::File(FileFact::DoesntExist));
                    }
                }
                (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::Deleted) => (),
                (SyscallEvent::Delete(_), FirstState::DoesntExist, LastMod::None) => (),
                (
                    SyscallEvent::Delete(outcome),
                    FirstState::Exists,
                    LastMod::Created | LastMod::Modified,
                ) => {
                    if outcome == &SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        curr_set.insert(Fact::File(FileFact::DoesntExist));
                    }
                }
                (SyscallEvent::Delete(outcome), FirstState::Exists, LastMod::Renamed(_, _)) => {
                    if outcome == &SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        curr_set.insert(Fact::File(FileFact::DoesntExist));
                    }
                }
                (SyscallEvent::Delete(_), FirstState::Exists, LastMod::Deleted) => (),
                (SyscallEvent::Delete(outcome), FirstState::Exists, LastMod::None) => {
                    if outcome == &SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        let path_clone = full_path.clone();
                        let hash = generate_hash(path_clone);
                        curr_set.remove(&Fact::File(FileFact::Exists));
                        curr_set.remove(&Fact::File(FileFact::Contents(hash)));
                        curr_set.insert(Fact::File(FileFact::DoesntExist));
                    }
                }
                (SyscallEvent::Delete(outcome), FirstState::None, LastMod::None) => {
                    if outcome == &SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        curr_set.insert(Fact::File(FileFact::DoesntExist));
                    }
                }
                (SyscallEvent::Open(OFlag::O_RDONLY, _, _), _, _) => (),
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, _),
                    FirstState::DoesntExist,
                    LastMod::Created | LastMod::Deleted | LastMod::Modified,
                ) => (),
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, outcome),
                    FirstState::DoesntExist,
                    LastMod::Renamed(_, new_path),
                ) => {
                    if outcome == &SyscallOutcome::Success && full_path == new_path {
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        let path_clone = full_path.clone();
                        let hash = generate_hash(path_clone);
                        curr_set.remove(&Fact::File(FileFact::Exists));
                        curr_set.insert(Fact::File(FileFact::Contents(hash)));
                    }
                }
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, _),
                    FirstState::DoesntExist,
                    LastMod::None,
                ) => (),
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, _),
                    FirstState::Exists,
                    LastMod::Created | LastMod::Deleted | LastMod::Modified,
                ) => (),
                // We shouldn't see more events after something is renamed unless it's the new file (and first state wouldn't be exists)
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, _),
                    FirstState::Exists,
                    LastMod::Renamed(_, _),
                ) => (),
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, outcome),
                    FirstState::Exists,
                    LastMod::None,
                ) => {
                    if outcome == &SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        let path_clone = full_path.clone();
                        let hash = generate_hash(path_clone);
                        curr_set.insert(Fact::File(FileFact::Contents(hash)));
                    }
                }
                // TODO: this isn't right lol
                (
                    SyscallEvent::Open(OFlag::O_APPEND | OFlag::O_TRUNC, _, outcome),
                    FirstState::None,
                    LastMod::None,
                ) => {
                    if outcome == &SyscallOutcome::Success {
                        let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                        let path_clone = full_path.clone();
                        let hash = generate_hash(path_clone);
                        curr_set.insert(Fact::File(FileFact::Contents(hash)));
                    }
                }
                (SyscallEvent::Open(flag, _, _), _, _) => {
                    panic!("Unexpected oflag for open! :{:?}", flag);
                }
                (
                    SyscallEvent::Rename(old_path, new_path, outcome),
                    FirstState::DoesntExist,
                    LastMod::Created | LastMod::Modified,
                ) => {
                    if outcome == &SyscallOutcome::Success && full_path == old_path {
                        // Get the oldpath's postconds.
                        // Look up new_path's postconds and set them to oldpath's
                        // set oldpaths postconds to doesnt exist.
                        let curr_set = curr_file_postconditions.get(full_path).unwrap();
                        let curr_set_clone = curr_set.clone();
                        let new_path_post_set = curr_file_postconditions.get_mut(new_path).unwrap();
                        for post_cond in curr_set_clone.iter() {
                            new_path_post_set.insert(post_cond.clone());
                        }
                        curr_file_postconditions.insert(
                            full_path.clone(),
                            HashSet::from([Fact::File(FileFact::DoesntExist)]),
                        );
                    }
                }
                (
                    SyscallEvent::Rename(old_path, new_path, outcome),
                    FirstState::DoesntExist,
                    LastMod::Renamed(_, last_new_path),
                ) => {
                    // This file is getting renamed. Again. For some god damn reason.
                    if outcome == &SyscallOutcome::Success && old_path == last_new_path {
                        let curr_set = curr_file_postconditions.get(old_path).unwrap();
                        let curr_set_clone = curr_set.clone();
                        let new_path_post_set = curr_file_postconditions.get_mut(new_path).unwrap();
                        for post_cond in curr_set_clone.iter() {
                            new_path_post_set.insert(post_cond.clone());
                        }
                        curr_file_postconditions.insert(
                            old_path.clone(),
                            HashSet::from([Fact::File(FileFact::DoesntExist)]),
                        );
                        // It is the new path! We update its postconditions when we see this event in the
                        // old path's list.
                    }
                }
                (SyscallEvent::Rename(_, _, _), FirstState::DoesntExist, LastMod::Deleted) => (),
                (SyscallEvent::Rename(_, _, _), FirstState::DoesntExist, LastMod::None) => (),
                (
                    SyscallEvent::Rename(old_path, new_path, outcome),
                    FirstState::Exists,
                    LastMod::Created | LastMod::Modified,
                ) => {
                    if outcome == &SyscallOutcome::Success && full_path == old_path {
                        // Get the oldpath's postconds.
                        // Look up new_path's postconds and set them to oldpath's
                        // set oldpaths postconds to doesnt exist.
                        let curr_set = curr_file_postconditions.get(full_path).unwrap();
                        let curr_set_clone = curr_set.clone();
                        let new_path_post_set = curr_file_postconditions.get_mut(new_path).unwrap();
                        for post_cond in curr_set_clone.iter() {
                            new_path_post_set.insert(post_cond.clone());
                        }
                        curr_file_postconditions.insert(
                            full_path.clone(),
                            HashSet::from([Fact::File(FileFact::DoesntExist)]),
                        );
                    }
                }
                (
                    SyscallEvent::Rename(old_path, new_path, outcome),
                    FirstState::Exists,
                    LastMod::Renamed(_, _),
                ) => {
                    // First state existing tells us this must be the old path
                    // but it's safer to check.
                    if outcome == &SyscallOutcome::Success && full_path == old_path {
                        // Get the oldpath's postconds.
                        // Look up new_path's postconds and set them to oldpath's
                        // set oldpaths postconds to doesnt exist.
                        let curr_set = curr_file_postconditions.get(full_path).unwrap();
                        let curr_set_clone = curr_set.clone();
                        let new_path_post_set = curr_file_postconditions.get_mut(new_path).unwrap();
                        for post_cond in curr_set_clone.iter() {
                            new_path_post_set.insert(post_cond.clone());
                        }
                        curr_file_postconditions.insert(
                            full_path.clone(),
                            HashSet::from([Fact::File(FileFact::DoesntExist)]),
                        );
                    }
                }
                (SyscallEvent::Rename(_, _, _), FirstState::Exists, LastMod::Deleted) => (),
                (
                    SyscallEvent::Rename(old_path, new_path, outcome),
                    FirstState::Exists,
                    LastMod::None,
                ) => {
                    match outcome {
                        SyscallOutcome::Success => {
                            if full_path == old_path {
                                // Get the oldpath's postconds.
                                // Look up new_path's postconds and set them to oldpath's
                                // set oldpaths postconds to doesnt exist.
                                let curr_set = curr_file_postconditions.get(full_path).unwrap();
                                let curr_set_clone = curr_set.clone();
                                let new_path_post_set =
                                    curr_file_postconditions.get_mut(new_path).unwrap();
                                for post_cond in curr_set_clone.iter() {
                                    new_path_post_set.insert(post_cond.clone());
                                }

                                curr_file_postconditions.insert(
                                    full_path.clone(),
                                    HashSet::from([Fact::File(FileFact::DoesntExist)]),
                                );
                            }
                        }
                        // These don't even make sense.
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                            let curr_set = curr_file_postconditions.get_mut(full_path).unwrap();
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                            curr_set.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                        }
                        _ => (),
                    }
                }

                // We haven't seen old path before.
                (
                    SyscallEvent::Rename(old_path, new_path, outcome),
                    FirstState::None,
                    LastMod::None,
                ) => {
                    if outcome == &SyscallOutcome::Success && full_path == old_path {
                        curr_file_postconditions.insert(
                            new_path.clone(),
                            HashSet::from([Fact::File(FileFact::Exists)]),
                        );
                        curr_file_postconditions.insert(
                            full_path.clone(),
                            HashSet::from([Fact::File(FileFact::DoesntExist)]),
                        );
                    }
                }
                (SyscallEvent::Stat(_, _), _, _) => (),
            }
            first_state_struct.update_based_on_syscall(&full_path, event.clone());
            last_mod_struct.update_based_on_syscall(event.clone());
        }
    }
    curr_file_postconditions
}

#[cfg(test)]
mod tests {
    use std::mem;

    use super::*;

    #[test]
    fn test_failed_access_then_create() {
        let mut exec_file_events = ExecFileEvents::new();
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Access(
                HashSet::from([AccessFlags::W_OK]),
                SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
            ),
            PathBuf::from("test"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
            PathBuf::from("test"),
        );

        let preconditions = generate_preconditions(exec_file_events.clone());
        let preconditions_set = preconditions.get(&PathBuf::from("test")).unwrap();
        let correct_preconditions = HashSet::from([
            Fact::File(FileFact::DoesntExist),
            Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)),
            Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
        ]);
        assert_eq!(preconditions_set, &correct_preconditions);

        let postconditions = generate_postconditions(exec_file_events);
        let postconditions_set = postconditions.get(&PathBuf::from("test")).unwrap();

        let correct_postconditions = HashSet::from([Fact::File(FileFact::Contents(Vec::new()))]);
        assert_eq!(postconditions_set, &correct_postconditions);
    }

    #[test]
    fn test_stat_open_create() {
        let mut exec_file_events = ExecFileEvents::new();
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Stat(None, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
            PathBuf::from("test"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Open(
                OFlag::O_RDONLY,
                Some(Vec::new()), // TODO
                SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
            ),
            PathBuf::from("test"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
            PathBuf::from("test"),
        );
        let preconditions = generate_preconditions(exec_file_events.clone());
        let preconditions_set = preconditions.get(&PathBuf::from("test")).unwrap();
        let correct_preconditions = HashSet::from([
            Fact::File(FileFact::DoesntExist),
            Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)),
            Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
        ]);
        assert_eq!(preconditions_set, &correct_preconditions);

        let postconditions = generate_postconditions(exec_file_events);
        let postconditions_set = postconditions.get(&PathBuf::from("test")).unwrap();
        let correct_postconditions = HashSet::from([Fact::File(FileFact::Contents(Vec::new()))]);
        assert_eq!(postconditions_set, &correct_postconditions);
    }

    #[test]
    fn test_open_open_access_stat() {
        let mut exec_file_events = ExecFileEvents::new();
        let stat: libc::stat = unsafe { mem::zeroed() };
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            // TODO
            SyscallEvent::Open(OFlag::O_APPEND, Some(Vec::new()), SyscallOutcome::Success),
            PathBuf::from("test"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Open(OFlag::O_TRUNC, Some(Vec::new()), SyscallOutcome::Success),
            PathBuf::from("test"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Access(HashSet::from([AccessFlags::R_OK]), SyscallOutcome::Success),
            PathBuf::from("test"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Stat(Some(stat), SyscallOutcome::Success),
            PathBuf::from("test"),
        );

        let preconditions = generate_preconditions(exec_file_events.clone());
        let preconditions_set = preconditions.get(&PathBuf::from("test")).unwrap();
        let correct_preconditions = HashSet::from([
            Fact::File(FileFact::Contents(Vec::new())),
            Fact::File(FileFact::HasPermission(AccessFlags::R_OK)),
            Fact::File(FileFact::HasPermission(AccessFlags::W_OK)),
            Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
            Fact::File(FileFact::StatStructMatches(stat)),
        ]);
        assert_eq!(preconditions_set, &correct_preconditions);

        let postconditions = generate_postconditions(exec_file_events);
        let postconditions_set = postconditions.get(&PathBuf::from("test")).unwrap();
        let correct_postconditions = HashSet::from([Fact::File(FileFact::Contents(Vec::new()))]);
        assert_eq!(postconditions_set, &correct_postconditions);
    }

    #[test]
    fn test_append_delete_create() {
        let mut exec_file_events = ExecFileEvents::new();
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Open(OFlag::O_APPEND, Some(Vec::new()), SyscallOutcome::Success),
            PathBuf::from("test"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Delete(SyscallOutcome::Success),
            PathBuf::from("test"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
            PathBuf::from("test"),
        );

        let preconditions = generate_preconditions(exec_file_events.clone());
        let preconditions_set = preconditions.get(&PathBuf::from("test")).unwrap();
        let correct_preconditions = HashSet::from([
            Fact::File(FileFact::Contents(Vec::new())),
            Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
            Fact::File(FileFact::HasPermission(AccessFlags::W_OK)),
        ]);
        assert_eq!(preconditions_set, &correct_preconditions);

        let postconditions = generate_postconditions(exec_file_events);
        let postconditions_set = postconditions.get(&PathBuf::from("test")).unwrap();
        let correct_postconditions = HashSet::from([Fact::File(FileFact::Contents(Vec::new()))]);
        assert_eq!(postconditions_set, &correct_postconditions);
    }

    #[test]
    fn test_rename_openappend_create() {
        let mut exec_file_events = ExecFileEvents::new();
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Rename(
                PathBuf::from("foo"),
                PathBuf::from("bar"),
                SyscallOutcome::Success,
            ),
            PathBuf::from("foo"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Rename(
                PathBuf::from("foo"),
                PathBuf::from("bar"),
                SyscallOutcome::Success,
            ),
            PathBuf::from("bar"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success),
            PathBuf::from("foo"),
        );
        exec_file_events.add_new_file_event(
            Pid::from_raw(0),
            SyscallEvent::Open(OFlag::O_APPEND, Some(Vec::new()), SyscallOutcome::Success),
            PathBuf::from("bar"),
        );

        let preconditions = generate_preconditions(exec_file_events.clone());
        let preconditions_set_foo = preconditions.get(&PathBuf::from("foo")).unwrap();
        let preconditions_set_bar = preconditions.get(&PathBuf::from("bar")).unwrap();
        let correct_preconditions_foo = HashSet::from([
            Fact::File(FileFact::Exists),
            Fact::File(FileFact::Contents(Vec::new())),
            Fact::File(FileFact::HasPermission(AccessFlags::W_OK)),
            Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
            Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)),
        ]);
        let correct_preconditions_bar = HashSet::from([Fact::File(FileFact::DoesntExist)]);

        assert_eq!(preconditions_set_foo, &correct_preconditions_foo);
        assert_eq!(preconditions_set_bar, &correct_preconditions_bar);

        // let postconditions = generate_postconditions(exec_file_events);
        // let postconditions_set = postconditions.get(&PathBuf::from("test")).unwrap();
        // let correct_postconditions = HashSet::from([Fact::File(FileFact::Contents)]);
        // assert_eq!(postconditions_set, &correct_postconditions);
    }
}
