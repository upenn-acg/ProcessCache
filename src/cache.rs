use libc::{c_int, stat, F_OK, R_OK, W_OK, X_OK};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
// use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    path::PathBuf,
    rc::Rc,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

// impl Serialize for i32 {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         serializer.serialize_i32(*self)
//     }
// }

#[derive(Clone, Debug, PartialEq)]
pub struct Proc(pub Pid);

impl Default for Proc {
    fn default() -> Proc {
        Proc(Pid::from_raw(0))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
    WriteOnly,
}

// The i32 is the return value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyscallOutcome {
    Success(i32),
    Fail(SyscallFailure),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyscallFailure {
    AlreadyExists,
    FileDoesntExist,
    PermissionDenied(Permission),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Permission {
    Exec, // Pointless?
    Read,
    Search,  // Exec for dirs?
    Unknown, // If you call access with multiple options, idk what permission you don't have. and it's YOUR fault for programming like an asshole.
    Write,
}

// Append and trunc imply WR_ONLY
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Mode {
    Append,
    ReadOnly,
    Trunc,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CreateMode {
    Create,
    Excl,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatStruct {
    Struct(stat),
    None,
}
// Successful and failing events.
// "Open" meaning not using O_CREAT
// "Create" meaning using O_CREAT
// Current syscalls covered: creat, open, openat, access, stat, fstat
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyscallEvent {
    Access(Vec<c_int>, SyscallOutcome), // Vec<c_int> is list of F_OK (0), R_OK, W_OK, X_OK
    Create(CreateMode, SyscallOutcome), // Can fail because pathcomponentdoesntexist or failedtocreatefileexclusively, or accessdenied
    Open(Mode, SyscallOutcome), // Can fail because the file didn't exist or permission denied
    // TODO: Handle stat struct too
    Stat(SyscallOutcome), // Can fail access denied (exec/search on dir) or file didn't exist
}

impl SyscallEvent {
    // Returns true if the syscall event DOES NOT CAUSE SIDE EFFECTS
    // The phrase "side effects" is confusing me at this point haha.
    fn is_innocuous(&self) -> bool {
        match self {
            SyscallEvent::Access(_, _) => true,
            SyscallEvent::Create(_, _) => false,
            SyscallEvent::Open(Mode::ReadOnly, _) => true,
            SyscallEvent::Open(Mode::Append | Mode::Trunc, outcome) => match outcome {
                SyscallOutcome::Success(_) => false,
                SyscallOutcome::Fail(failure) => match failure {
                    SyscallFailure::AlreadyExists => {
                        panic!("is_innocuous(): open for writing failed by already exists??")
                    }
                    SyscallFailure::FileDoesntExist => true,
                    SyscallFailure::PermissionDenied(Permission::Write) => true,
                    SyscallFailure::PermissionDenied(perm) => panic!(
                        "is_innocuous(): open for writing failed for weird permission: {:?}",
                        perm
                    ),
                },
            },
            SyscallEvent::Stat(_) => true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Fact {
    FileContents,
    FileDidntExist,
    FileExisted,
    StatStructMatches,
    HasPermission(Vec<Permission>),
    NoPermission(Vec<Permission>),
}

fn generate_conditions(file_events: Vec<SyscallEvent>) {
    // First and easiest case for finding precondition:
    // All events are innocuous!

    if file_events.iter().all(|event| event.is_innocuous()) {
        let mut preconditions = HashSet::new();
        let mut postconditions = HashSet::new();
        for event in file_events {
            let (before_facts, after_facts) = generate_facts(event);
            for fact in before_facts {
                preconditions.insert(fact);
            }
            for fact in after_facts {
                postconditions.insert(fact);
            }
        }
    } else {
        todo!();
    }
}
// Given a SyscallEvent, return the "Before" facts and "After" facts.
// If "After" facts is empty, you know the syscall event was SIDE EFFECT FREE.
fn generate_facts(syscall_event: SyscallEvent) -> (Vec<Fact>, Vec<Fact>) {
    match syscall_event {
        // In order to call access successfully, the user has to have the access mode(s) they specified, or just file existence in the
        // case of F_OK.
        SyscallEvent::Access(mode_list, SyscallOutcome::Success(ret_val)) => {
            if ret_val != 0 {
                panic!("Return value from access said success but was not 0!");
            } else {
                let mut before = Vec::new();
                let mut has_permissions: Vec<Permission> = Vec::new();

                if mode_list.len() == 1 {
                    let first = mode_list.get(0).unwrap();
                    // F_OK == 0
                    if *first == 0 {
                        before.push(Fact::FileExisted);
                    }
                } else {
                    for mode in mode_list {
                        match mode {
                            R_OK => has_permissions.push(Permission::Read),
                            W_OK => has_permissions.push(Permission::Write),
                            X_OK => has_permissions.push(Permission::Exec),
                            _ => panic!("Mode not recognized for access syscall event!: {}", mode),
                        }
                    }
                    before.push(Fact::FileExisted);
                    before.push(Fact::HasPermission(has_permissions));
                }

                (before, vec![])
            }
        }

        // If you get back EACCES from an access() call, you had to not have access to something.
        // Or the file didn't exist. Here are the cases:
        // Access(more than one) -> Ceheck R_OK, W_OK, and X_OK
        SyscallEvent::Access(
            mode_list,
            SyscallOutcome::Fail(SyscallFailure::PermissionDenied(_)),
        ) => {
            let mut before = Vec::new();
            let mut not_these_perms: Vec<Permission> = Vec::new();

            for mode in mode_list {
                match mode {
                    F_OK => {
                        panic!("Syscall event is permission denied in access, why do we get F_OK?")
                    }
                    R_OK => not_these_perms.push(Permission::Read),
                    W_OK => not_these_perms.push(Permission::Write),
                    X_OK => not_these_perms.push(Permission::Exec),
                    _ => panic!("Mode value not recognized! {}", mode),
                }
            }

            before.push(Fact::NoPermission(not_these_perms));
            (before, vec![])
        }

        // This is: access(F_OK) == failure.
        // So the only "before" fact is "file didn't exist"
        SyscallEvent::Access(_, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)) => {
            (vec![Fact::FileDidntExist], vec![])
        }

        // Shouldn't be possible
        SyscallEvent::Access(_, SyscallOutcome::Fail(e)) => {
            panic!("Unrecognized syscall failure for access syscall: {:?}", e);
        }

        // These events represent successfully creating the file, with or without the EXCL flag.
        // But either way, we know the file didn't exist to start, so their "before" facts are the same.
        SyscallEvent::Create(_, SyscallOutcome::Success(_)) => {
            let before = vec![
                Fact::FileDidntExist,
                Fact::HasPermission(vec![Permission::Write]),
            ];
            let after = vec![Fact::FileExisted, Fact::FileContents];
            (before, after)
        }

        SyscallEvent::Create(CreateMode::Create, SyscallOutcome::Fail(failure)) => match failure {
            SyscallFailure::AlreadyExists => {
                panic!("Create event, NOT EXCL, failed on already exists??")
            }
            SyscallFailure::FileDoesntExist => {
                panic!("Create event, NOT EXCL, failed on file doesn't exist??")
            }
            SyscallFailure::PermissionDenied(Permission::Write) => {
                (vec![Fact::NoPermission(vec![Permission::Write])], vec![])
            }
            SyscallFailure::PermissionDenied(perm) => panic!(
                "Create event, NOT EXCL, failed for strange permission: {:?}",
                perm
            ),
        },

        SyscallEvent::Create(CreateMode::Excl, SyscallOutcome::Fail(failure)) => match failure {
            SyscallFailure::AlreadyExists => (vec![Fact::FileExisted], vec![]),
            SyscallFailure::FileDoesntExist => {
                panic!("Create event, EXCL, failed on file doesn't exist??")
            }
            SyscallFailure::PermissionDenied(Permission::Write) => {
                (vec![Fact::NoPermission(vec![Permission::Write])], vec![])
            }
            SyscallFailure::PermissionDenied(perm) => panic!(
                "Create event, EXCL, failed for strange permission: {:?}",
                perm
            ),
        },

        // To successfully open a file, user must have permissions for the open mode, and the file had to already exist.
        // ReadOnly causes no side effects (therefore has an empty "after" facts list)
        SyscallEvent::Open(mode, SyscallOutcome::Success(_)) => match mode {
            Mode::Append => (
                vec![
                    Fact::FileContents,
                    Fact::FileExisted,
                    Fact::HasPermission(vec![Permission::Write]),
                ],
                vec![Fact::FileContents, Fact::FileExisted],
            ),
            Mode::ReadOnly => (
                vec![
                    Fact::FileContents,
                    Fact::FileExisted,
                    Fact::HasPermission(vec![Permission::Read]),
                ],
                vec![],
            ),
            Mode::Trunc => (
                vec![
                    Fact::FileExisted,
                    Fact::HasPermission(vec![Permission::Write]),
                ],
                vec![Fact::FileContents, Fact::FileExisted],
            ),
        },

        SyscallEvent::Open(Mode::Append, SyscallOutcome::Fail(failure)) => match failure {
            SyscallFailure::AlreadyExists => {
                panic!("Failed to open for appending but failed because file already exists??")
            }
            SyscallFailure::FileDoesntExist => (vec![Fact::FileDidntExist], vec![]),
            SyscallFailure::PermissionDenied(Permission::Write) => {
                (vec![Fact::NoPermission(vec![Permission::Write])], vec![])
            }
            SyscallFailure::PermissionDenied(perm) => panic!(
                "Open for append but permission denied was not writing: {:?}",
                perm
            ),
        },

        SyscallEvent::Open(Mode::ReadOnly, SyscallOutcome::Fail(failure)) => match failure {
            SyscallFailure::FileDoesntExist => (vec![Fact::FileDidntExist], vec![]),
            SyscallFailure::PermissionDenied(Permission::Read) => {
                (vec![Fact::NoPermission(vec![Permission::Read])], vec![])
            }
            SyscallFailure::PermissionDenied(perm) => panic!(
                "Open for read only but failed on weird permission: {:?}",
                perm
            ),
            SyscallFailure::AlreadyExists => {
                panic!("Open for read only but failed on file already exists??")
            }
        },

        SyscallEvent::Open(Mode::Trunc, SyscallOutcome::Fail(failure)) => match failure {
            SyscallFailure::FileDoesntExist => (vec![Fact::FileDidntExist], vec![]),
            SyscallFailure::PermissionDenied(Permission::Write) => {
                (vec![Fact::NoPermission(vec![Permission::Write])], vec![])
            }
            SyscallFailure::PermissionDenied(perm) => panic!(
                "Open for write/trunc but failed on weird permission: {:?}",
                perm
            ),
            SyscallFailure::AlreadyExists => {
                panic!("Open for truncate but failed on file already exists??")
            }
        },

        // To successfully stat a file, the file has to have existed already, and the user must have search access on the dir.
        // Because this is a "side effect FREE" syscall event, the facts that had to be true before and after
        // TODO: properly handle stat struct and checking
        SyscallEvent::Stat(SyscallOutcome::Success(ret_val)) => {
            if ret_val != 0 {
                panic!("Return value from stat said success but was not 0!");
            } else {
                let before = vec![
                    Fact::FileExisted,
                    Fact::HasPermission(vec![Permission::Write]),
                    Fact::StatStructMatches,
                ];
                (before, vec![])
            }
        }

        SyscallEvent::Stat(SyscallOutcome::Fail(failure)) => match failure {
            SyscallFailure::FileDoesntExist => (vec![Fact::FileDidntExist], vec![]),
            SyscallFailure::AlreadyExists => panic!("Stat failed because file already exists??"),
            SyscallFailure::PermissionDenied(Permission::Search) => {
                (vec![Fact::NoPermission(vec![Permission::Search])], vec![])
            }
            SyscallFailure::PermissionDenied(perm) => panic!(
                "Stat failed for strange permission (not search): {:?}",
                perm
            ),
        },
    }
}

// #[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
// struct FileInfo {
//     events: Vec<SyscallEvent>,
//     final_hash: Option<Vec<u8>>,
//     starting_hash: Option<Vec<u8>>,
// }

// impl FileInfo {
//     fn new() -> FileInfo {
//         FileInfo {
//             events: Vec::new(),
//             final_hash: None,
//             starting_hash: None,
//         }
//     }

//     fn add_event(&mut self, file_event: SyscallEvent) {
//         self.events.push(file_event);
//     }

//     fn add_starting_hash(&mut self, hash: Vec<u8>) {
//         if self.starting_hash.is_none() {
//             self.starting_hash = Some(hash);
//         }
//     }

//     fn add_final_hash(&mut self, hash: Vec<u8>) {
//         if self.final_hash.is_none() {
//             self.final_hash = Some(hash);
//         }
//     }
// }

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

    fn file_event_list(&self) -> &HashMap<PathBuf, Vec<SyscallEvent>> {
        let s = span!(Level::INFO, stringify!(file_event_list));
        let _ = s.enter();

        &self.filename_to_events_map
    }

    // At the end of a successful execution, we get the hash of each output
    // file.
    // pub fn add_output_file_hashes(&mut self, caller_pid: Pid) -> anyhow::Result<()> {
    //     // let s = span!(Level::INFO, stringify!(add_output_file_hashes), pid=?caller_pid);
    //     // let _ = s.enter();

    //     // for output in self.output_files.iter_mut() {
    //     //     if let FileAccess::Success(full_path, hash, _) = output {
    //     //         let path = full_path.clone().into_os_string().into_string().unwrap();
    //     //         s.in_scope(|| info!("gonna generate an output hash"));
    //     //         let hash_value = generate_hash(caller_pid, path);
    //     //         *hash = Some(hash_value);
    //     //     }
    //     // }
    //     // Ok(())
    //     unimplemented!();
    // }

    // fn add_starting_hash(&mut self, full_path: PathBuf, hash: Vec<u8>) {
    //     if let Some(file_info) = self.filename_to_events_map.get_mut(&full_path) {
    //         file_info.add_starting_hash(hash);
    //     } else {
    //         panic!("Should not be adding starting hash when full path entry is not present!");
    //     }
    // }

    // fn add_final_hash(&mut self, full_path: PathBuf, hash: Vec<u8>) {
    //     if let Some(file_info) = self.filename_to_events_map.get_mut(&full_path) {
    //         file_info.add_final_hash(hash);
    //     } else {
    //         panic!("Should not be adding final hash when full path entry is not present!");
    //     }
    // }

    // Only want to copy output files that had successful
    // accesses to the cache.
    // pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
    // for output in self.output_files.iter() {
    //     if let FileAccess::Success(full_path, _, _) = output {
    //         let file_name = full_path
    //             .file_name()
    //             .expect("Can't get file name in copy_outputs_to_cache()!");

    //         let cache_dir = PathBuf::from("./IOTracker/cache");
    //         let cache_path = cache_dir.join(file_name);

    //         if cache_path.exists() {
    //             panic!("Trying to copy a file to the cache that is already present in the cache, at least with the same filename! : {:?}", cache_path);
    //         } else {
    //             fs::copy(full_path, cache_path)?;
    //         }
    //     }
    // }
    // Ok(())
    //     unimplemented!();
    // }
}

// Info about the execution that we want to keep around
// even if the execution fails (so we know it should fail
// if we see it again, it would be some kinda error if
// we expect it to fail and it succeeds).
#[derive(Clone, Debug, PartialEq)]
pub struct ExecMetadata {
    args: Vec<String>,
    // The cwd can change during the execution, this is fine.
    // I am tracking absolute paths anyways.
    // This DOES need to match at the beginning of the execution though.
    starting_cwd: PathBuf,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    executable: String,
    // We don't know the exit code until it exits.
    // So while an execution is running this is None.
    exit_code: Option<i32>,
    // I need the caller pid so I know which execution struct
    // to add info to. But, I don't want this serialized with
    // the rest of the metadata (obviously pids change from run
    // to run).
    // #[serde(skip)]
    caller_pid: Proc,
}

impl ExecMetadata {
    pub fn new() -> ExecMetadata {
        ExecMetadata {
            args: Vec::new(),
            starting_cwd: PathBuf::new(),
            env_vars: Vec::new(),
            executable: String::new(),
            exit_code: None,
            caller_pid: Proc::default(),
        }
    }

    fn add_exit_code(&mut self, code: i32) {
        self.exit_code = Some(code);
    }

    fn add_identifiers(
        &mut self,
        args: Vec<String>,
        caller_pid: Pid,
        env_vars: Vec<String>,
        executable: String,
        starting_cwd: PathBuf,
    ) {
        self.args = args;
        self.starting_cwd = starting_cwd;
        self.env_vars = env_vars;
        self.executable = executable;

        let pid = Proc(caller_pid);
        self.caller_pid = pid;
    }

    // fn args(&self) -> Vec<String> {
    //     self.args.clone()
    // }

    fn caller_pid(&self) -> Pid {
        let Proc(actual_pid) = self.caller_pid;
        actual_pid
    }

    // fn env_vars(&self) -> Vec<String> {
    //     self.env_vars.clone()
    // }

    // fn execution_name(&self) -> String {
    //     self.executable.clone()
    // }

    fn starting_cwd(&self) -> PathBuf {
        self.starting_cwd.clone()
    }
}

pub type ChildExecutions = Vec<RcExecution>;
#[derive(Clone, Debug, PartialEq)]
pub enum Execution {
    Failed(ExecMetadata),
    // Before we find out if the root execution's "execve" call succeeds,
    // its kinda just pending. I want to know which one the root is
    // and doing it in the enum seems easiest.
    PendingRoot,
    Successful(ChildExecutions, ExecFileEvents, ExecMetadata),
}

impl Execution {
    pub fn add_child_execution(&mut self, child_execution: RcExecution) {
        match self {
            Execution::Failed(_) => {
                panic!("Trying to add a child process to a failed execution!")
            }
            Execution::PendingRoot => {
                panic!("Trying to add a child process to a pending execution!")
            }
            Execution::Successful(child_execs, _, _) => {
                child_execs.push(child_execution);
            }
        }
    }

    pub fn add_exit_code(&mut self, exit_code: i32, pid: Pid) {
        match self {
            Execution::Failed(meta) | Execution::Successful(_, _, meta) => {
                // Only want the exit code if this is the process
                // that actually exec'd the process.
                let exec_pid = meta.caller_pid();
                if exec_pid == pid {
                    meta.add_exit_code(exit_code);
                }
            }
            _ => {
                panic!("Trying to add exit code to pending execution!")
            }
        }
    }

    pub fn add_identifiers(
        &mut self,
        args: Vec<String>,
        caller_pid: Pid,
        env_vars: Vec<String>,
        executable: String,
        starting_cwd: PathBuf,
    ) {
        match self {
            Execution::Failed(metadata) | Execution::Successful(_, _, metadata) => {
                metadata.add_identifiers(args, caller_pid, env_vars, executable, starting_cwd)
            }
            _ => panic!("Should not be adding identifiers to pending exec!"),
        }
    }

    pub fn add_new_file_event(
        &mut self,
        caller_pid: Pid,
        // OBVIOUSLY, will handle any syscall event eventually.
        file_access: SyscallEvent,
        full_path: PathBuf,
    ) {
        match self {
            Execution::Successful(_, accesses, _) => {
                accesses.add_new_file_event(caller_pid, file_access, full_path);
            }
            Execution::PendingRoot => {
                panic!("Should not be adding file event to pending execution!")
            }
            _ => panic!("Should not be adding file event to failed execution!"),
        }
    }

    fn exec_file_event_map(&self) -> &HashMap<PathBuf, Vec<SyscallEvent>> {
        match self {
            Execution::Successful(_, accesses, _) => accesses.file_event_list(),
            Execution::Failed(_) => panic!("No file events for failed execution!"),
            Execution::PendingRoot => panic!("No file events for pending root!"),
        }
    }
    // pub fn add_output_file_hashes(&mut self, caller_pid: Pid) -> anyhow::Result<()> {
    //     match self {
    //         Execution::Successful(_, accesses, _) => accesses.add_output_file_hashes(caller_pid),
    //         // Should this be some fancy kinda error? Meh?
    //         Execution::Failed(_) => {
    //             panic!("Should not be adding output file hashes to failed execution!")
    //         }
    //         Execution::PendingRoot => {
    //             panic!("Should not be adding output file hashes to pending root execution!")
    //         }
    //     }
    // }

    // fn add_final_hash(&mut self, full_path: PathBuf, hash: Vec<u8>) {
    //     match self {
    //         Execution::Successful(_, accesses, _) => accesses.add_final_hash(full_path, hash),
    //         Execution::Failed(_) => {
    //             panic!("Should not be adding final hash to failed execution!")
    //         }
    //         Execution::PendingRoot => {
    //             panic!("Should not be adding final hash to pending root execution!")
    //         }
    //     }
    // }

    // fn add_starting_hash(&mut self, full_path: PathBuf, hash: Vec<u8>) {
    //     match self {
    //         Execution::Successful(_, accesses, _) => accesses.add_starting_hash(full_path, hash),
    //         Execution::Failed(_) => {
    //             panic!("Should not be adding starting hash to failed execution!")
    //         }
    //         Execution::PendingRoot => {
    //             panic!("Should not be adding starting hash to pending root execution!")
    //         }
    //     }
    // }

    // fn args(&self) -> Vec<String> {
    //     match self {
    //         Execution::Successful(_, _, metadata) | Execution::Failed(metadata) => metadata.args(),
    //         _ => panic!("Should not be getting args from pending execution!"),
    //     }
    // }

    fn caller_pid(&self) -> Pid {
        match self {
            Execution::Successful(_, _, meta) | Execution::Failed(meta) => meta.caller_pid(),
            _ => panic!("Trying to get caller pid of pending root execution!"),
        }
    }

    fn child_executions(&self) -> Vec<RcExecution> {
        match self {
            Execution::Successful(children, _, _) => children.clone(),
            Execution::Failed(_) => {
                panic!("Should not be getting child execs from failed execution!")
            }
            Execution::PendingRoot => {
                panic!("Should not be trying to get child execs from pending root execution!")
            }
        }
    }

    // pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
    //     match self {
    //         Execution::Successful(_, accesses, _) => accesses.copy_outputs_to_cache(),
    //         // Should this be some fancy kinda error? Meh?
    //         _ => Ok(()),
    //     }
    // }

    // fn env_vars(&self) -> Vec<String> {
    //     match self {
    //         Execution::Successful(_, _, metadata) | Execution::Failed(metadata) => {
    //             metadata.env_vars()
    //         }
    //         _ => panic!("Should not be getting execution name from pending execution!"),
    //     }
    // }

    // fn execution_name(&self) -> String {
    //     match self {
    //         Execution::Successful(_, _, metadata) | Execution::Failed(metadata) => {
    //             metadata.execution_name()
    //         }
    //         _ => panic!("Should not be getting execution name from pending execution!"),
    //     }
    // }

    fn is_pending_root(&self) -> bool {
        matches!(self, Execution::PendingRoot)
    }

    // pub fn is_successful(&self) -> bool {
    //     matches!(self, Execution::Successful(_, _, _))
    // }

    fn starting_cwd(&self) -> PathBuf {
        match self {
            Execution::Successful(_, _, metadata) | Execution::Failed(metadata) => {
                metadata.starting_cwd()
            }
            _ => panic!("Should not be getting starting cwd from pending execution!"),
        }
    }
}

// Rc stands for reference counted.
// This is the wrapper around the Execution
// enum.
#[derive(Clone, Debug, PartialEq)]
pub struct RcExecution {
    execution: Rc<RefCell<Execution>>,
}

impl RcExecution {
    pub fn new(execution: Execution) -> RcExecution {
        RcExecution {
            execution: Rc::new(RefCell::new(execution)),
        }
    }

    pub fn add_child_execution(&self, child_execution: RcExecution) {
        self.execution
            .borrow_mut()
            .add_child_execution(child_execution);
    }

    pub fn add_exit_code(&self, code: i32, exec_pid: Pid) {
        self.execution.borrow_mut().add_exit_code(code, exec_pid);
    }

    pub fn add_new_file_event(
        &self,
        caller_pid: Pid,
        file_event: SyscallEvent,
        full_path: PathBuf,
    ) {
        self.execution
            .borrow_mut()
            .add_new_file_event(caller_pid, file_event, full_path);
    }

    // pub fn add_output_file_hashes(&self, caller_pid: Pid) -> anyhow::Result<()> {
    //     self.execution
    //         .borrow_mut()
    //         .add_output_file_hashes(caller_pid)
    // }

    // pub fn add_starting_hash(&self, full_path: PathBuf, hash: Vec<u8>) {
    //     self.execution
    //         .borrow_mut()
    //         .add_starting_hash(full_path, hash)
    // }

    // pub fn add_final_hash(&self, full_path: PathBuf, hash: Vec<u8>) {
    //     self.execution.borrow_mut().add_final_hash(full_path, hash)
    // }

    // fn args(&self) -> Vec<String> {
    //     self.execution.borrow().args()
    // }

    pub fn caller_pid(&self) -> Pid {
        self.execution.borrow().caller_pid()
    }

    // pub fn child_executions(&self) -> Vec<RcExecution> {
    //     self.execution.borrow().child_executions()
    // }

    // pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
    //     self.execution.borrow().copy_outputs_to_cache()
    // }

    // fn env_vars(&self) -> Vec<String> {
    //     self.execution.borrow().env_vars()
    // }

    // pub fn execution_name(&self) -> String {
    //     self.execution.borrow().execution_name()
    // }

    fn exec_file_event_map(&self) -> HashMap<PathBuf, Vec<SyscallEvent>> {
        self.execution.borrow().exec_file_event_map().clone()
    }

    pub fn is_pending_root(&self) -> bool {
        self.execution.borrow().is_pending_root()
    }

    // pub fn is_successful(&self) -> bool {
    //     self.execution.borrow().is_successful()
    // }

    // Print all file event lists for the execution.
    // TODO: This doesn't print the child exec stuff.
    // Need to make a function to get the child execs as well.
    // For now, one layer deep is ok.
    pub fn print_pathbuf_to_file_event_lists(&self) {
        println!("First execution.");
        let exec_file_event_map = self.exec_file_event_map();
        for (full_path, event_list) in exec_file_event_map {
            println!("Resource path: {:?}", full_path);
            println!("Event list: {:?}", event_list);
            println!();
        }

        println!();
        println!();

        for child in self.execution.borrow().child_executions() {
            println!("Child execution: {}", child.caller_pid());
            let child_exec_file_event_map = child.exec_file_event_map();
            for (full_path, event_list) in child_exec_file_event_map {
                println!("Resource path: {:?}", full_path);
                println!("Event list: {:?}", event_list);
                println!();
            }
        }
    }

    pub fn starting_cwd(&self) -> PathBuf {
        self.execution.borrow().starting_cwd()
    }

    pub fn update_root(&self, new_root_exec: Execution) {
        if self.execution.borrow().is_pending_root() {
            *self.execution.borrow_mut() = new_root_exec;
        } else {
            panic!("Trying to update an execution which is NOT the pending root execution!");
        }
    }
}

// When we deserialize the cache, this is what
// we will get.
// #[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
// pub struct GlobalExecutions {
//     pub executions: Vec<RcExecution>,
// }

// impl GlobalExecutions {
//     pub fn new() -> GlobalExecutions {
//         GlobalExecutions {
//             executions: Vec::new(),
//         }
//     }

//     pub fn add_new_execution(&mut self, new_execution: RcExecution) {
//         self.executions.push(new_execution);
//     }
// }

// Return the cached execution if there exists a cached success.
// Else return None.
// pub fn get_cached_root_execution(caller_pid: Pid, new_execution: Execution) -> Option<RcExecution> {
//     let s = span!(Level::INFO, stringify!(get_cached_root_execution), pid=?caller_pid);
//     let _ = s.enter();
//     let cache_path = PathBuf::from("./IOTracker/cache/cache");
//     if !cache_path.exists() {
//         s.in_scope(|| info!("No cached exec bc cache doesn't exist"));
//         None
//     } else if !new_execution.is_successful() {
//         s.in_scope(|| info!("No cached exec bc exec failed"));
//         None
//     } else {
//         let global_execs = deserialize_execs_from_cache();
//         // Have to find the root exec in the list of global execs
//         // in the cache.
//         for cached_root_exec in global_execs.executions.iter() {
//             // We check that the metadata matches
//             // That the inputs and outputs match (all the way down the tree of child execs)
//             // And that success or failure matches
//             if exec_metadata_matches(cached_root_exec, caller_pid, &new_execution)
//                 && execution_matches(cached_root_exec, caller_pid)
//             {
//                 // TODO: don't short circuit
//                 return Some(cached_root_exec.clone());
//             }
//         }
//         None
//     }
// }

// fn execution_matches(cached_root: &RcExecution, caller_pid: Pid) -> bool {
// unimplemented!();
// let s = span!(Level::INFO, stringify!(execution_matches), pid=?caller_pid);
// let _ = s.enter();
// s.in_scope(|| info!("Checking inputs and outputs of children"));

// if !inputs_match(cached_root.clone(), caller_pid)
//     || !outputs_match(caller_pid, cached_root.clone())
// {
//     false
// } else {
//     s.in_scope(|| {
//         info!(
//             "Number of cached children: {}",
//             cached_root.child_executions().len()
//         )
//     });

//     cached_root
//         .child_executions()
//         .iter()
//         .all(|child| execution_matches(child, caller_pid))
// }
// }

// It's a lot of logic to do all the metadata checking.
// Right now if an execution has child executions, all child
// executions must be skippable as well so we just skip the whole
// dang thing. This means we don't have to check the metadata of
// the child executions or their child executions.
// fn exec_metadata_matches(cached_exec: &RcExecution, caller_pid: Pid, new_exec: &Execution) -> bool {
//     let s = span!(Level::INFO, stringify!(exec_metadata_matches), pid=?caller_pid);
//     let _ = s.enter();
//     s.in_scope(|| info!("Checking inputs and outputs of children"));
//     let new_executable = new_exec.execution_name();
//     let new_starting_cwd = new_exec.starting_cwd();
//     let new_args = new_exec.args();
//     let new_env_vars = new_exec.env_vars();
//     // Check if any execution struct existing in the cache matches this
//     // We should skip it if:
//     // - it WAS in the cache before (loop)
//     // - it was successful
//     // - execution name matches
//     // - arguments match
//     // - starting cwd matches
//     // - env vars match
//     // If it is failed exec but we have it cached, we also want to return that.
//     let executable_matches = cached_exec.execution_name() == new_executable;
//     s.in_scope(|| info!("Executable names match: {}", executable_matches));
//     let success_failure_match = cached_exec.is_successful() == new_exec.is_successful();
//     s.in_scope(|| info!("Success/Failure match: {}", success_failure_match));
//     let args_match = new_args == cached_exec.args();
//     s.in_scope(|| info!("Args match: {}", args_match));
//     let cwd_matches = new_starting_cwd == cached_exec.starting_cwd();
//     s.in_scope(|| info!("Cwd matches: {}", cwd_matches));
//     let env_vars_match = new_env_vars == cached_exec.env_vars();
//     s.in_scope(|| info!("Env vars match: {}", env_vars_match));

//     executable_matches && success_failure_match && args_match && cwd_matches && env_vars_match
// }

// TODO: Is this function relevant anymore?
// The inputs in the cached execution match the
// new execution's inputs, the hashes match,
// and they are in the correct absolute path locations.
// fn inputs_match(cached_exec: RcExecution, caller_pid: Pid) -> bool {
// unimplemented!();
// let s = span!(Level::INFO, stringify!(inputs_match), pid=?caller_pid);
// let _ = s.enter();
// s.in_scope(|| info!("Checking inputs and outputs of children"));
// let cached_inputs = cached_exec.inputs();
// // First, they must share the same inputs.
// // So get the keys of each and check that they are equal?
// for input in cached_inputs.into_iter() {
//     if let FileAccess::Success(full_path, Some(old_hash), _) = input {
//         // Only check these things if it's a true file.
//         // If the hash is None, we can just move on.
//         if !full_path.exists() {
//             s.in_scope(|| {
//                 info!(
//                     "Inputs don't match because path doesn't exist: {:?}",
//                     full_path
//                 )
//             });
//             return false;
//         } else {
//             // Hash the file that is there right now.
//             let full_path = full_path.clone().into_os_string().into_string().unwrap();
//             let new_hash = generate_hash(caller_pid, full_path.clone());

//             // Compare the new hash to the old hash.
//             if !new_hash.iter().eq(old_hash.iter()) {
//                 s.in_scope(|| {
//                     info!(
//                         "Inputs don't match new hash and old hash don't match: {:?}",
//                         full_path
//                     )
//                 });
//                 return false;
//             }
//         }
//     }
// }
// true
// }

// TODO: Does this function even make sense anymore?
// Check that output files are either:
// - Exist, in the right place, and the hash matches the hash we have in the cache.
// - OR, the file doesn't exist, which is great, because we have it in our cache
// and we can just copy it over.
// fn outputs_match(caller_pid: Pid, curr_execution: RcExecution) -> bool {
// unimplemented!();
// let s = span!(Level::INFO, stringify!(outputs_match), pid=?caller_pid);
// let _ = s.enter();
// s.in_scope(|| info!("Checking inputs and outputs of children"));
// let cached_outputs = curr_execution.outputs();

// for output in cached_outputs.into_iter() {
//     if let FileAccess::Success(full_path, hash, _) = output {
//         // If the output file does indeed exist and is in the correct spot
//         // already, check if the hash matches the old one.
//         // Then we won't have to copy this file over from the cache.
//         if full_path.exists() {
//             if let Some(old_hash) = hash {
//                 let full_path = full_path.clone().into_os_string().into_string().unwrap();
//                 let new_hash = generate_hash(caller_pid, full_path.clone());

//                 // Compare the new hash to the old hash.
//                 if !new_hash.iter().eq(old_hash.iter()) {
//                     s.in_scope(|| {
//                         info!(
//                             "Output hashes don't match. Old :{:?}, New :{:?}",
//                             new_hash, old_hash
//                         )
//                     });
//                     return false;
//                 }
//             }
//         }
//         // If it doesn't exist, fantastic
//         // MOVE ON it doesn't exist.
//         // "I'm sorry for your loss. Move on."
//     }
// }
// true
// }

// TODO: make this work with the other stuff
// Take in the root execution.
// Copy its outputs to the appropriate places.
// pub fn serve_outputs_from_cache(
//     caller_pid: Pid,
//     root_execution: &RcExecution,
// ) -> anyhow::Result<()> {
//     unimplemented!();
// let s = span!(Level::INFO, stringify!(serve_outputs_from_cache), pid=?caller_pid);
// let _ = s.enter();
// s.in_scope(|| info!("Serving outputs from cache."));

// for output in root_execution.outputs() {
//     if let FileAccess::Success(full_path, _, _) = output {
//         s.in_scope(|| {
//             info!(
//                 "Cached successful output file access going to serve: {:?}",
//                 full_path
//             )
//         });
//         let file_name = full_path.file_name().unwrap();

//         let cache_dir = PathBuf::from("./research/IOTracker/cache");
//         let cached_output_path = cache_dir.join(file_name);

//         if !full_path.exists() {
//             fs::copy(cached_output_path, full_path)?;
//         } else {
//             s.in_scope(|| {
//                 info!(
//                     "Not copying from cache, file is already there: {:?}",
//                     full_path
//                 )
//             });
//         }
//     }
// }

// root_execution
//     .child_executions()
//     .iter()
//     .all(|child| serve_outputs_from_cache(caller_pid, child).is_ok());
// Ok(())
// }

// ------ Hashing stuff ------
// Process the file and generate the hash.
// fn process<D: Digest + Default, R: Read>(reader: &mut R) -> Vec<u8> {
//     const BUFFER_SIZE: usize = 1024;
//     let mut sh = D::default();
//     let mut buffer = [0u8; BUFFER_SIZE];
//     loop {
//         let n = reader
//             .read(&mut buffer)
//             .expect("Could not read buffer from reader processing hash!");
//         sh.update(&buffer[..n]);
//         if n == 0 || n < BUFFER_SIZE {
//             break;
//         }
//     }

//     let final_array = &sh.finalize();
//     final_array.to_vec()
// }

// Wrapper for generating the hash.
// Opens the file and calls process() to get the hash.
// pub fn generate_hash(caller_pid: Pid, path: String) -> Vec<u8> {
//     let s = span!(Level::INFO, stringify!(generate_hash), pid=?caller_pid);
//     let _ = s.enter();
//     s.in_scope(|| info!("Made it to generate_hash for path: {}", path));
//     let mut file = fs::File::open(&path).expect("Could not open file to generate hash");
//     process::<Sha256, _>(&mut file)
// }

// Serialize the execs and write them to the cache.
// pub fn serialize_execs_to_cache(root_execution: RcExecution) -> anyhow::Result<()> {
//     const CACHE_LOCATION: &str = "./IOTracker/cache/cache";

//     let cache_path = PathBuf::from(CACHE_LOCATION);
//     let cache_copy_path = PathBuf::from(CACHE_LOCATION.to_owned() + "_copy");

//     if Path::new(CACHE_LOCATION).exists() {
//         // If the cache file exists:
//         // - make a copy of cache/cache at cache/cache_copy (just in case)
//         fs::copy(&cache_path, &cache_copy_path)?;
//         // - deserialize existing structure from cache/cache
//         let mut existing_global_execs = deserialize_execs_from_cache();
//         // - add the new root_execution to the vector
//         existing_global_execs.add_new_execution(root_execution);
//         // - serialize again
//         let serialized_execs = rmp_serde::to_vec(&existing_global_execs).unwrap();
//         // - remove old cache/cache file
//         fs::remove_file(&cache_path)?;
//         // - make a new cache/cache file and write the updated serialized execs to it
//         fs::write(cache_path, serialized_execs)?;
//         // - delete cache/cache_copy
//         fs::remove_file(cache_copy_path)?;
//     } else {
//         // If the cache file doesn't exist:
//         // - make a new GlobalExecutions
//         let mut global_execs = GlobalExecutions::new();
//         // - put root_execution in it
//         global_execs.add_new_execution(root_execution);
//         // - serialize GlobalExecutions
//         let serialized_execs = rmp_serde::to_vec(&global_execs).unwrap();
//         // - and write the serialized_execs to the cache/cache file we are making
//         //   right here because that's what the write() function here does, creates
//         //   if it doesn't exist, and then writes.
//         fs::write(CACHE_LOCATION, serialized_execs)
//             .with_context(|| context!("Cannot write to cache location: \"{}\".", CACHE_LOCATION))?;
//     }
//     Ok(())
//     // let serialized_execs = rmp_serde::to_vec(&root_exection).unwrap();
// }

// pub fn deserialize_execs_from_cache() -> GlobalExecutions {
//     let exec_struct_bytes = fs::read("./research/IOTracker/cache/cache").expect("failed");
//     if exec_struct_bytes.is_empty() {
//         GlobalExecutions::new()
//     } else {
//         rmp_serde::from_read_ref(&exec_struct_bytes).unwrap()
//     }
// }
