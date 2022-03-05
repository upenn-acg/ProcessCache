use nix::unistd::{AccessFlags, Pid};

use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CreateMode {
    Create,
    Excl,
}
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum LastMod {
    Created,
    Modified,
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
            SyscallEvent::Open(Mode::Append | Mode::Trunc, SyscallOutcome::Success) => {
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

                SyscallEvent::Create(CreateMode::Create, SyscallOutcome::Success) => {
                    self.state = FirstState::DoesntExist;
                }
                // Failed to create a file. Doesn't mean we know anything about whether it exists.
                SyscallEvent::Create(
                    CreateMode::Create,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => (),
                SyscallEvent::Create(CreateMode::Create, SyscallOutcome::Fail(failure)) => {
                    panic!("Failed to create for strange reason: {:?}", failure);
                }
                SyscallEvent::Create(CreateMode::Excl, SyscallOutcome::Success) => {
                    self.state = FirstState::DoesntExist;
                }
                SyscallEvent::Create(
                    CreateMode::Excl,
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists),
                ) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Create(
                    CreateMode::Excl,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    panic!("Failed to create a file excl because file doesn't exist??");
                }
                SyscallEvent::Create(
                    CreateMode::Excl,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => (),
                SyscallEvent::Open(Mode::Append | Mode::ReadOnly, SyscallOutcome::Success) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Open(Mode::Trunc, SyscallOutcome::Success) => (),
                SyscallEvent::Open(
                    Mode::Append | Mode::ReadOnly,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                ) => {
                    self.state = FirstState::DoesntExist;
                }
                SyscallEvent::Open(
                    Mode::Append | Mode::Trunc,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Open(Mode::Trunc, SyscallOutcome::Fail(fail)) => {
                    panic!("Failed to open trunc for strange reason: {:?}", fail)
                }
                SyscallEvent::Open(
                    Mode::ReadOnly,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                ) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Open(mode, SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!("Open for {:?} failed because file already exists??", mode)
                }

                SyscallEvent::Stat(SyscallOutcome::Success) => {
                    self.state = FirstState::Exists;
                }
                SyscallEvent::Stat(SyscallOutcome::Fail(SyscallFailure::AlreadyExists)) => {
                    panic!("Failed to state because file already exists??");
                }
                SyscallEvent::Stat(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
                    self.state = FirstState::DoesntExist
                }
                SyscallEvent::Stat(SyscallOutcome::Fail(SyscallFailure::PermissionDenied)) => (),
            }
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Mode {
    Append,
    ReadOnly,
    Trunc,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
    WriteOnly,
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
            event_list.push(file_event);
        } else {
            let event_list = vec![file_event];
            s.in_scope(|| "adding event");
            self.filename_to_events_map.insert(full_path, event_list);
        }
    }

    pub fn file_event_list(&self) -> &HashMap<PathBuf, Vec<SyscallEvent>> {
        let s = span!(Level::INFO, stringify!(file_event_list));
        let _ = s.enter();

        &self.filename_to_events_map
    }
}

// Successful and failing events.
// "Open" meaning not using O_CREAT
// "Create" meaning using O_CREAT
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyscallEvent {
    // None =
    Access(HashSet<AccessFlags>, SyscallOutcome), // Vec<c_int> is list of F_OK (0), R_OK, W_OK, X_OK
    Create(CreateMode, SyscallOutcome), // Can fail because pathcomponentdoesntexist or failedtocreatefileexclusively, or accessdenied
    Open(Mode, SyscallOutcome), // Can fail because the file didn't exist or permission denied
    // TODO: Handle stat struct too
    Stat(SyscallOutcome), // Can fail access denied (exec/search on dir) or file didn't exist
}

impl SyscallEvent {
    // Returns true if the syscall event DOES NOT CAUSE SIDE EFFECTS
    // The phrase "side effects" is confusing me at this point haha.
    fn is_side_effect_free(&self) -> bool {
        match self {
            SyscallEvent::Access(_, _) => true,
            SyscallEvent::Create(_, _) => false,
            SyscallEvent::Open(Mode::ReadOnly, _) => true,
            SyscallEvent::Open(Mode::Append | Mode::Trunc, outcome) => match outcome {
                SyscallOutcome::Success => false,
                SyscallOutcome::Fail(failure) => match failure {
                    SyscallFailure::AlreadyExists => {
                        panic!("is_side_effect_free(): open for writing failed by already exists??")
                    }
                    SyscallFailure::FileDoesntExist => true,
                    SyscallFailure::PermissionDenied => true,
                },
            },
            SyscallEvent::Stat(_) => true,
        }
    }
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
    Success,
    Fail(SyscallFailure),
}

// Directory Preconditions (For now, just cwd), File Preconditions
// Takes in all the events for ONE RESOURCE and generates its preconditions.
fn generate_file_preconditions(file_events: &[SyscallEvent]) -> HashSet<Fact> {
    let sys_span = span!(Level::INFO, "generate_file_preconditions");
    let _ = sys_span.enter();
    let mut curr_file_preconditions = HashSet::new();

    let mut first_state_struct = FirstStateStruct {
        state: FirstState::None,
    };
    let mut curr_state_struct = LastModStruct {
        state: LastMod::None,
    };

    for event in file_events {
        let first_state = first_state_struct.state();
        let curr_state = curr_state_struct.state();

        match (event, first_state, curr_state) {
            // Starting out it didn't exist.
            // It was created during the execution.
            // So any permission it has on this file has nothing to do with the precondition, regardless of its outcome.
            // This goes for DoesntExist Modified and DoesntExist Created because Modified and DoesntExist means it was created
            // then later modified. So it's kind of the same case.
            (SyscallEvent::Access(_, _), FirstState::DoesntExist, LastMod::Created | LastMod::Modified) => (),
            (SyscallEvent::Access(_, SyscallOutcome::Fail(SyscallFailure::AlreadyExists)), _, _) => {
                panic!("Access failed because file already exists??");
            }
            (SyscallEvent::Access(_, outcome), FirstState::DoesntExist, LastMod::None) => {
                match outcome {
                    // How did we succeed? It doesn't exist, it hasn't been created...
                    SyscallOutcome::Success => {
                        panic!("Succeeded on access called on file that doesn't exist??");
                    }
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        // This is the only one that makes sense.
                        // File doesn't exist, haven't seen any modifications to it either.
                        // So an access would fail 
                        curr_file_preconditions.insert(Fact::File(FileFact::DoesntExist));
                    }
                    SyscallOutcome::Fail(f) => {
                        panic!("Access syscall failed for strange reason, first state: doesnt exist, no mods: {:?}", f);
                    }
                }
            }
            // If it existed at the beginning, and then created is its last mod, it had to be deleted.
            // So this access is based on something that happened during the exec.
            (SyscallEvent::Access(_, _), FirstState::Exists, LastMod::Created) => (),
            // Existed at the beginning, then was modified. So this access does depend on the initial state of the resource.
            (SyscallEvent::Access(flags, outcome), FirstState::Exists, LastMod::Modified) => {
                match outcome {
                    SyscallOutcome::Success => {
                        if flags.contains(&AccessFlags::F_OK) {
                            curr_file_preconditions.insert(Fact::File(FileFact::Exists));
                        } else {
                            for f in flags {
                                curr_file_preconditions.insert(Fact::File(FileFact::HasPermission(*f)));
                            }
                        }
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        for f in flags {
                            curr_file_preconditions.insert(Fact::File(FileFact::NoPermission(*f)));
                        }
                    }
                    SyscallOutcome::Fail(f) => {
                        panic!("Access failed for strange reason: {:?}", f);
                    }
                }
            }

            (SyscallEvent::Access(flags, outcome), FirstState::Exists, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Success => {
                        if flags.contains(&AccessFlags::F_OK) {
                            curr_file_preconditions.insert(Fact::File(FileFact::Exists));
                        } else {
                            for f in flags {
                                curr_file_preconditions.insert(Fact::File(FileFact::HasPermission(*f)));
                            }
                        }
                    }
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                        panic!("Access failed because file already exists??");
                    }
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::DoesntExist));
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        for f in flags {
                            curr_file_preconditions.insert(Fact::File(FileFact::NoPermission(*f)));
                        }
                    }
                }
            }
            // No first state, but last mod was created or modified? what?
            (SyscallEvent::Access(_, _), FirstState::None, LastMod::Created | LastMod::Modified) => {
                panic!("Unexpected access failure, no first state but last mod created or modified??");
            }

            (SyscallEvent::Access(flags, outcome), FirstState::None, LastMod::None) => {
                // Nothing has modified this file yet.
                match outcome {
                    SyscallOutcome::Success => {
                        if flags.contains(&AccessFlags::F_OK) {
                            curr_file_preconditions.insert(Fact::File(FileFact::Exists));
                        } else {
                            for f in flags {
                                curr_file_preconditions.insert(Fact::File(FileFact::HasPermission(*f)));
                            }
                        }
                    }
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                        panic!("Access failed because file already exists??")
                    }
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::DoesntExist));
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        for f in flags {
                            curr_file_preconditions.insert(Fact::File(FileFact::NoPermission(*f)));
                        }
                    }
                }
            }
            // File didn't exist. Then it was created.
            // IF you try to O_CREAT again, it should be an open syscall event.
            // IF you try to O_CREAT again with O_EXCL, it should error with AlreadyExists.
            // BUT regardless, because the file was created during the exec, this event contributes nothing.
            (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Created) => (),
            // Didn't exist, was created and modified, another create event doesn't change preconditions.
            (SyscallEvent::Create(_, _), FirstState::DoesntExist, LastMod::Modified) => (),
            (SyscallEvent::Create(CreateMode::Create, outcome), FirstState::DoesntExist, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(f) => {
                        panic!("Failed to created file for strange reason: {:?}", f);
                    }
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::File(FileFact::DoesntExist));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                    }
                }
            }
            (SyscallEvent::Create(CreateMode::Excl, outcome), FirstState::DoesntExist, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(f) => {
                        panic!("Failed to create excl file for strange reason: {:?}", f);
                    }
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::File(FileFact::DoesntExist));
                    }
                }
            }
            (SyscallEvent::Create(CreateMode::Create, _), FirstState::Exists, LastMod::Created) => {
                panic!("First state exists, last mod created, creating again (not excl) should be open event??");
            }
            (SyscallEvent::Create(CreateMode::Excl, outcome), FirstState::Exists, LastMod::Created) => {
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => (),
                    o => panic!("Strange outcome trying to create excl file that already exists??: {:?}", o),
                }
            }
            (SyscallEvent::Create(CreateMode::Create, _), FirstState::Exists, LastMod::Modified) => {
                panic!("First state exists, last mod modified, creating again (not excl) should be open event??");
            }
            (SyscallEvent::Create(CreateMode::Excl, outcome), FirstState::Exists, LastMod::Modified) => {
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => (),
                    o => panic!("Strange outcome trying to create excl file that already exists??: {:?}", o),
                }
            }
            (SyscallEvent::Create(CreateMode::Create, outcome), FirstState::Exists, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    o => panic!("Create file event, first state: exists, last mod: none, unexpected outcome: {:?}", o),
                }
            }
            (SyscallEvent::Create(CreateMode::Excl, outcome), FirstState::Exists, LastMod::None) => {
                match outcome {
                    // We already know the file existed at the beginning because first state has been updated.
                    // So we don't have to readd it here as a fact, not that it matters because this is a set.
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => (),
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    o => panic!("Create file excl event, first state: exists, last mod: none, unexpected outcome: {:?}", o),
                }
            }
            (SyscallEvent::Create(CreateMode::Create, outcome), FirstState::None, LastMod::Created) => {
                match outcome {
                    SyscallOutcome::Fail(f) => panic!("Failed to create file for strange reason: {:?}", f),
                    SyscallOutcome::Success => panic!("Last mod was created but we successfully created again??"),
                }
            }
            (SyscallEvent::Create(CreateMode::Excl, outcome), FirstState::None, LastMod::Created) => {
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => (),
                    SyscallOutcome::Fail(f) => panic!("Failed to create excl file for strange reason: {:?}", f),
                    SyscallOutcome::Success => panic!("Last mod was created but we successfully create excl again??"),
                }
            }
            (SyscallEvent::Create(CreateMode::Create, outcome), FirstState::None, LastMod::Modified) => {
                match outcome {
                    SyscallOutcome::Fail(f) => panic!("Failed to create file for strange reason: {:?}", f),
                    SyscallOutcome::Success => panic!("Successfully created file but last mod was modified??"),
                }
            }
            (SyscallEvent::Create(CreateMode::Excl, outcome), FirstState::None, LastMod::Modified) => {
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => (),
                    SyscallOutcome::Fail(f) => panic!("Failed to excl create file for strange reason: {:?}", f),
                    SyscallOutcome::Success => panic!("Successfully created excl file but last mod was modified??"),
                }
            }
            (SyscallEvent::Create(CreateMode::Create, outcome), FirstState::None, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(f) => panic!("Failed to create file for strange reason: {:?}", f),
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::File(FileFact::DoesntExist));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                    }
                }
            }
            (SyscallEvent::Create(CreateMode::Excl, outcome), FirstState::None, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(f) => panic!("Create excl no first state no last mod failed for strange reason: {:?}", f),
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::File(FileFact::DoesntExist));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                    }
                }
            }
            // Ok, so the file didn't exist. We created it. Which is dependent on the exec. So all of these cases
            // CONTRIBUTE NOTHING.
            (SyscallEvent::Open(_, _), FirstState::DoesntExist, _) => (),
            // Appending to a file successfully tells us we have
            // write access to file, x access to dir, file contents, it exists
            // all of these we already know based on last mod and first state.
            // ----------------------------------------------------------------
            // Reading from the file:
            // - exists
            // - contents
            // - read access
            // - x access to dir
            // only new one we get here is the read access to file
            // and even that doesn't matter bc: it existed, we must have deleted, then created, so that permission is
            // based on something in the execution.
            // ----------------------------------------------------------------
            // Again, it existed, so we had to delete it and then create it again.
            // Trunc would tell us...
            // - write access to file, x access to dir (already known)
            // - failures: doesn't exist, already exist make no sense, so does the permission one.
            (SyscallEvent::Open(_, _), FirstState::Exists, LastMod::Created) => (),

            // Open appending, it already existed at the start, we modified this,
            // we add nothing to the preconditions that we don't already know.s=
            (SyscallEvent::Open(Mode::Append | Mode::Trunc, _), FirstState::Exists, LastMod::Modified) => (),
            (SyscallEvent::Open(Mode::ReadOnly, outcome), FirstState::Exists, LastMod::Modified) => {
                // - read access to file (had to exist already)
                // - existence (known)
                // - contents (dependent on the exec)
                match outcome {
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::File(FileFact::HasPermission(AccessFlags::R_OK)));
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::NoPermission(AccessFlags::R_OK)));
                    }
                    SyscallOutcome::Fail(f) => panic!("Open read only failed for strange reason: {:?}", f),
                }
            }
            (SyscallEvent::Open(Mode::Append, outcome), FirstState::Exists, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::File(FileFact::Contents));
                        curr_file_preconditions.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        // If you can't write to the file either you don't have write permission to it,
                        // or you don't have exec access to the dir its in.
                        curr_file_preconditions.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(f) => {
                        panic!("Open append failed for strange reason, first state exists with no mods, {:?}", f);
                    }
                }
            }
            (SyscallEvent::Open(Mode::ReadOnly, outcome), FirstState::Exists, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::File(FileFact::Contents));
                        curr_file_preconditions.insert(Fact::File(FileFact::HasPermission(AccessFlags::R_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::NoPermission(AccessFlags::R_OK)));
                    }
                    SyscallOutcome::Fail(f) => panic!("Unexpected open readonly failure, first state exists, no mods: {:?}", f),
                }
            }
            (SyscallEvent::Open(Mode::Trunc, outcome), FirstState::Exists, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Success => {
                        // We know it exists. Now we have successfully truncated it.
                        // We can:
                        // - x the dir
                        // - w the file
                        // - we dont care about contents
                        curr_file_preconditions.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(f) => panic!("Unexpected open trunc failure, first state exists, no mods: {:?}", f),
                }
            }

            // No first state means it didn't exist, and we created it, so all this stuff
            // depends on stuff that happens in the execution.
            (SyscallEvent::Open(_, _), FirstState::None, LastMod::Created) => (),
            // Regardless of mode of opening, we had to create the file, so anything
            // about this file we know has come out of the execution happening,
            // except that we have exec access to the dir, but we already know that
            // from creating and modifying the file.
            (SyscallEvent::Open(_, _), FirstState::None, LastMod::Modified) => (),
            (SyscallEvent::Open(Mode::Append, outcome), FirstState::None, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::File(FileFact::Contents));
                        curr_file_preconditions.insert(Fact::File(FileFact::Exists));
                        curr_file_preconditions.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => panic!("Unexpected open append failure, file already exists??"),
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::DoesntExist));
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::NoPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                }
            }
            (SyscallEvent::Open(Mode::ReadOnly, outcome), FirstState::None, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::File(FileFact::Contents));
                        curr_file_preconditions.insert(Fact::File(FileFact::Exists));
                        curr_file_preconditions.insert(Fact::File(FileFact::HasPermission(AccessFlags::R_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => panic!("Unexpected open readonly failure, no first state or mods, already exists??"),
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::DoesntExist));
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::NoPermission(AccessFlags::R_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                }
            }
            (SyscallEvent::Open(Mode::Trunc, outcome), FirstState::None, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::File(FileFact::HasPermission(AccessFlags::W_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::NoPermission(AccessFlags::R_OK)));
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(f) => panic!("Unexected open trunc failure, first first state or mods: {:?}", f),
                }
            }
            (SyscallEvent::Stat(outcome), FirstState::DoesntExist, LastMod::Created | LastMod::Modified) => {
                match outcome {
                    // This shouldn't happen. Even permissions, we have to have exec access on our cwd to have
                    // made this file, which we know we did.
                    SyscallOutcome::Fail(f) => panic!("Unexpected failure of stat syscall!: {:?}", f),
                    // We should already have the exec access on the cwd noted because the last mod was created.
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::File(FileFact::StatStructMatches));
                    },
                }
            }
            (SyscallEvent::Stat(outcome), FirstState::DoesntExist, LastMod::None) => {
                // It didn't exist at the start, we haven't modified (created) it.
                // This should fail for the file not existing, otherwise makes no sense.
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => (),
                    o => panic!("Unexpected outcome from stat syscall, first state: doesn't exist, last mod: none. {:?}", o),
                }
            }
            (SyscallEvent::Stat(outcome), FirstState::Exists, LastMod::Created) => {
                // File existed at the start. We created it though, so it must have been deleted at some point.
                // And we created it again. So the stat struct probably won't match like it would have at
                // the beginning of the execution, thus it is not added to the preconditions.
                match outcome {
                    SyscallOutcome::Fail(f) => panic!("Unexpected failure of stat syscall!: {:?}", f),
                    SyscallOutcome::Success => (),
                }
            }
            (SyscallEvent::Stat(outcome), FirstState::Exists, LastMod::Modified) => {
                // It existed at the start, and we have modified it.
                // All that matters to stat here is:
                // 1) whether it existed at the start (yes)
                // 2) whether they had exec access of the cwd (we shall see). to modify they only need write permission. they might not have exec access
                // though.
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(f) => panic!("Unexpected failure of stat syscall: {:?}", f),
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                    }
                }
            }
            (SyscallEvent::Stat(outcome), FirstState::Exists, LastMod::None) => {
                match outcome {
                    // It existed at the start. We haven't modified it.
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(f) => panic!("Unexpected failure of stat syscall!: {:?}", f),
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                        curr_file_preconditions.insert(Fact::File(FileFact::StatStructMatches));
                    }
                }
            }
            (SyscallEvent::Stat(outcome), FirstState::None, LastMod::Created) => {
                match outcome {
                    // File didn't exist at beginning of exec. It was created though, so we do have
                    // exec access.
                    SyscallOutcome::Fail(f) => panic!("Unexpected failure of stat syscall!: {:?}", f),
                    SyscallOutcome::Success => (),
                }
            }
            (SyscallEvent::Stat(outcome), FirstState::None, LastMod::Modified) => {
                match outcome {
                    // File didn't existed at beginning of exec. It was created and modified though,
                    // so we know we have exec access to the cwd already.
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Fail(f) => panic!("Unexpected failure of stat syscall!: {:?}", f),
                    SyscallOutcome::Success => (),
                }
            }
            (SyscallEvent::Stat(outcome), FirstState::None, LastMod::None) => {
                match outcome {
                    SyscallOutcome::Fail(SyscallFailure::AlreadyExists) => {
                        panic!("Unexpected failure of stat syscall: already exists!");
                    }
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist) => {
                        curr_file_preconditions.insert(Fact::File(FileFact::DoesntExist));
                    }
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied) => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::NoPermission(AccessFlags::X_OK)));
                    }
                    SyscallOutcome::Success => {
                        curr_file_preconditions.insert(Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)));
                        curr_file_preconditions.insert(Fact::File(FileFact::Exists));
                        curr_file_preconditions.insert(Fact::File(FileFact::StatStructMatches));
                    }
                }
            }
        }

        // This function will only change the first_state if it is None.
        first_state_struct.update_based_on_syscall(event);
        curr_state_struct.update_based_on_syscall(event);
    }
    curr_file_preconditions
}

// REMEMBER: SIDE EFFECT FREE SYSCALLS CONTRIBUTE NOTHING TO THE POSTCONDITIONS.
// Directory Postconditions (for now just cwd), File Postconditions
fn generate_postconditions(file_events: &[SyscallEvent]) -> HashSet<Fact> {
    let sys_span = span!(Level::INFO, "generate_file_postconditions");
    let _ = sys_span.enter();
    let mut curr_file_postconditions = HashSet::new();

    let mut first_state_struct = FirstStateStruct {
        state: FirstState::None,
    };
    let mut curr_state_struct = LastModStruct {
        state: LastMod::None,
    };

    for event in file_events {
        let first_state = first_state_struct.state();
        let curr_state = curr_state_struct.state();

        match (event, first_state, curr_state) {
            (SyscallEvent::Access(_, _), _, _) => (),

            (
                SyscallEvent::Create(CreateMode::Create, outcome),
                FirstState::DoesntExist,
                LastMod::Created | LastMod::Modified,
            ) => {
                if *outcome == SyscallOutcome::Success {
                    panic!("Successfully created but last mod was created or modified??");
                }
            }
            (
                SyscallEvent::Create(CreateMode::Excl, outcome),
                FirstState::DoesntExist,
                LastMod::Created | LastMod::Modified,
            ) => {
                if *outcome == SyscallOutcome::Success {
                    panic!("Successfully created excl but last mod was created or modified??");
                }
            }
            (
                SyscallEvent::Create(CreateMode::Create | CreateMode::Excl, _),
                FirstState::DoesntExist,
                LastMod::None,
            ) => {
                curr_file_postconditions.insert(Fact::File(FileFact::Contents));
            }
            (
                SyscallEvent::Create(_, outcome),
                FirstState::Exists,
                LastMod::Created | LastMod::Modified,
            ) => {
                if *outcome == SyscallOutcome::Success {
                    panic!("Successfully created but last mod was created or modified??");
                }
            }
            (
                SyscallEvent::Create(CreateMode::Create, outcome),
                FirstState::Exists,
                LastMod::None,
            ) => {
                if *outcome == SyscallOutcome::Success {
                    panic!("Successfully created file but it already exists??");
                }
            }
            (
                SyscallEvent::Create(CreateMode::Excl, outcome),
                FirstState::Exists,
                LastMod::None,
            ) => {
                if *outcome == SyscallOutcome::Success {
                    panic!("Successfully created excl file but it already exists??");
                }
            }
            (
                SyscallEvent::Create(_, outcome),
                FirstState::None,
                LastMod::Created | LastMod::Modified,
            ) => {
                if *outcome == SyscallOutcome::Success {
                    panic!("No first state but last mod was created or modified??");
                }
            }
            (SyscallEvent::Create(_, outcome), FirstState::None, LastMod::None) => {
                if *outcome == SyscallOutcome::Success {
                    curr_file_postconditions.insert(Fact::File(FileFact::Contents));
                }
            }
            (SyscallEvent::Open(Mode::ReadOnly, _), _, _) => (),
            (
                SyscallEvent::Open(Mode::Append | Mode::Trunc, outcome),
                FirstState::DoesntExist,
                LastMod::Created | LastMod::Modified,
            ) => {
                // We created the file and are now modifying it.
                // - exists (already known)
                // - wr access to file (known)
                // - x access to dir (known)
                // - contents (known)
                match outcome {
                    SyscallOutcome::Fail(f) => panic!("Unexpected open append or trunc failure, first state doesn't exist, last mod created: {:?}", f),
                    SyscallOutcome::Success => (),
                }
            }
            (
                SyscallEvent::Open(Mode::Append | Mode::Trunc, _),
                FirstState::DoesntExist,
                LastMod::None,
            ) => (),
            // If you create a file and don't give yourself write access... I don't even know man.
            (
                SyscallEvent::Open(_, _),
                FirstState::Exists,
                LastMod::Created | LastMod::Modified,
            ) => (),
            (
                SyscallEvent::Open(Mode::Append | Mode::Trunc, outcome),
                FirstState::Exists,
                LastMod::None,
            ) => {
                if *outcome == SyscallOutcome::Success {
                    curr_file_postconditions.insert(Fact::File(FileFact::Contents));
                }
            }
            // Created or modified but no first state??
            (SyscallEvent::Open(_, _), FirstState::None, LastMod::Created | LastMod::Modified) => {
                panic!("Open event, no first state but last state was created or modified??");
            }
            (
                SyscallEvent::Open(Mode::Append | Mode::Trunc, outcome),
                FirstState::None,
                LastMod::None,
            ) => {
                if *outcome == SyscallOutcome::Success {
                    curr_file_postconditions.insert(Fact::File(FileFact::Contents));
                }
            }
            (SyscallEvent::Stat(_), _, _) => (),
        }

        // This function will only change the first_state if it is None.
        first_state_struct.update_based_on_syscall(event);
        curr_state_struct.update_based_on_syscall(event);
    }
    curr_file_postconditions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preconds1() {
        let events = [SyscallEvent::Access(
            HashSet::from([AccessFlags::R_OK]),
            SyscallOutcome::Success,
        )];
        let preconditions = generate_file_preconditions(&events);
        let correct_preconditions =
            HashSet::from([Fact::File(FileFact::HasPermission(AccessFlags::R_OK))]);
        assert_eq!(preconditions, correct_preconditions);
    }
    #[test]
    fn test_postconds1() {
        let events = [SyscallEvent::Access(
            HashSet::from([AccessFlags::R_OK]),
            SyscallOutcome::Success,
        )];
        let postconditions = generate_postconditions(&events);
        let correct_postconditions = HashSet::new();
        assert_eq!(postconditions, correct_postconditions);
    }

    #[test]
    fn test_preconds2() {
        let events = [
            SyscallEvent::Access(
                HashSet::from([AccessFlags::W_OK]),
                SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
            ),
            SyscallEvent::Create(CreateMode::Create, SyscallOutcome::Success),
        ];
        let preconditions = generate_file_preconditions(&events);
        let correct_preconditions = HashSet::from([
            Fact::File(FileFact::DoesntExist),
            Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)),
            Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
        ]);
        assert_eq!(preconditions, correct_preconditions);
    }

    // stat
    // open open
    fn test_preconds3() {
        let events = [
            SyscallEvent::Stat(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
            SyscallEvent::Open(
                Mode::ReadOnly,
                SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
            ),
            SyscallEvent::Create(CreateMode::Create, SyscallOutcome::Success),
        ];
        let preconditions = generate_file_preconditions(&events);
        let correct_preconditions = HashSet::from([
            Fact::File(FileFact::DoesntExist),
            Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)),
            Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
        ]);
        assert_eq!(preconditions, correct_preconditions);
    }
    fn test_postconds3() {
        let events = [
            SyscallEvent::Stat(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
            SyscallEvent::Open(
                Mode::ReadOnly,
                SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
            ),
            SyscallEvent::Create(CreateMode::Create, SyscallOutcome::Success),
        ];
        let postconditions = generate_postconditions(&events);
        let correct_postconditions = HashSet::from([
            Fact::File(FileFact::DoesntExist),
            Fact::Dir(DirFact::HasPermission(AccessFlags::W_OK)),
            Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
        ]);
        assert_eq!(postconditions, correct_postconditions);
    }

    fn test_preconds4() {
        let events = [
            SyscallEvent::Open(Mode::Append, SyscallOutcome::Success),
            SyscallEvent::Open(Mode::Trunc, SyscallOutcome::Success),
            SyscallEvent::Access(HashSet::from([AccessFlags::R_OK]), SyscallOutcome::Success),
            SyscallEvent::Stat(SyscallOutcome::Success),
        ];
        let preconditions = generate_file_preconditions(&events);
        let correct_preconditions = HashSet::from([
            Fact::File(FileFact::Exists),
            Fact::File(FileFact::Contents),
            Fact::File(FileFact::HasPermission(AccessFlags::R_OK)),
            Fact::File(FileFact::HasPermission(AccessFlags::W_OK)),
            Fact::Dir(DirFact::HasPermission(AccessFlags::X_OK)),
        ]);
        assert_eq!(preconditions, correct_preconditions);
    }
}
