use crate::condition_generator::{ExecFileEvents, SyscallEvent};
use nix::{unistd::Pid, NixPath};
// use sha2::{Digest, Sha256};
use std::{cell::RefCell, path::PathBuf, rc::Rc};
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

// use anyhow::{bail, Context, Result};
#[derive(Clone)]
pub struct Command(pub String, pub Vec<String>);

impl Command {
    pub fn new(exe: String, args: Vec<String>) -> Self {
        Command(exe, args)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Proc(pub Pid);

impl Default for Proc {
    fn default() -> Proc {
        Proc(Pid::from_raw(0))
    }
}

pub type ChildExecutions = Vec<RcExecution>;

#[derive(Clone, Debug, PartialEq)]
pub struct Execution {
    caller_pid: Proc,
    child_execs: ChildExecutions,
    exit_code: Option<i32>,
    failed_execs: Vec<ExecMetadata>,
    file_events: ExecFileEvents,
    starting_cwd: PathBuf,
    successful_exec: ExecMetadata,
}

impl Execution {
    pub fn new() -> Execution {
        Execution {
            caller_pid: Proc::default(),
            child_execs: Vec::new(),
            exit_code: None,
            failed_execs: Vec::new(),
            file_events: ExecFileEvents::new(),
            starting_cwd: PathBuf::new(),
            successful_exec: ExecMetadata::new(),
        }
    }

    pub fn add_child_execution(&mut self, child_execution: RcExecution) {
        self.child_execs.push(child_execution);
    }

    pub fn add_failed_exec(&mut self, exec_metadata: ExecMetadata) {
        self.failed_execs.push(exec_metadata);
    }

    pub fn update_successful_exec(&mut self, exec_metadata: ExecMetadata) {
        self.successful_exec = exec_metadata;
    }

    pub fn add_exit_code(&mut self, code: i32) {
        self.exit_code = Some(code);
    }

    // You can have max 1 successful execve.
    // [Success] or [Fail,...,Fail,Success]
    // Can only add file event to the successful one
    // Successful one should be last.
    fn add_new_file_event(
        &mut self,
        caller_pid: Pid,
        // OBVIOUSLY, will handle any syscall event eventually.
        file_access: SyscallEvent,
        full_path: PathBuf,
    ) {
        self.file_events
            .add_new_file_event(caller_pid, file_access, full_path);
    }

    fn is_empty_root_exec(&self) -> bool {
        self.successful_exec.is_empty_root_exec()
    }

    fn pid(&self) -> Pid {
        let Proc(pid) = self.caller_pid;
        pid
    }

    fn print_basic_exec_info(&self) {
        println!("Successful executable:");
        self.successful_exec.print_basic_exec_info();

        println!("Failed executables:");
        for failed_exec in self.failed_execs.clone() {
            failed_exec.print_basic_exec_info();
        }

        println!("Now starting children:");
        for child in self.child_execs.clone() {
            child.print_basic_exec_info()
        }
    }

    fn starting_cwd(&self) -> PathBuf {
        self.starting_cwd.clone()
    }
}

// Info about the execution that we want to keep around
// even if the execution fails (so we know it should fail
// if we see it again, it would be some kinda error if
// we expect it to fail and it succeeds).
#[derive(Clone, Debug, PartialEq)]
pub struct ExecMetadata {
    args: Vec<String>,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    executable: PathBuf,
    starting_cwd: PathBuf,
}

impl ExecMetadata {
    pub fn new() -> ExecMetadata {
        ExecMetadata {
            args: Vec::new(),
            env_vars: Vec::new(),
            executable: PathBuf::new(),
            starting_cwd: PathBuf::new(),
        }
    }

    pub fn add_identifiers(
        &mut self,
        args: Vec<String>,
        env_vars: Vec<String>,
        executable: PathBuf,
        starting_cwd: PathBuf,
    ) {
        self.args = args;
        self.env_vars = env_vars;
        self.executable = executable;
        self.starting_cwd = starting_cwd;
    }

    fn is_empty_root_exec(&self) -> bool {
        self.executable.is_empty()
    }

    fn print_basic_exec_info(&self) {
        println!(
            "Executable: {:?}, args: {:?}, starting_cwd: {:?}",
            self.executable, self.args, self.starting_cwd
        );
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

    pub fn add_exit_code(&self, code: i32) {
        self.execution.borrow_mut().add_exit_code(code);
    }

    pub fn add_failed_exec(&self, failed_exec: ExecMetadata) {
        self.execution.borrow_mut().add_failed_exec(failed_exec);
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

    pub fn is_empty_root_exec(&self) -> bool {
        self.execution.borrow().is_empty_root_exec()
    }

    pub fn pid(&self) -> Pid {
        self.execution.borrow().pid()
    }

    pub fn print_basic_exec_info(&self) {
        self.execution.borrow().print_basic_exec_info()
    }

    // pub fn exit_code(&self) -> Option<i32> {
    //     self.execution.borrow().exit_code()
    // }

    pub fn starting_cwd(&self) -> PathBuf {
        self.execution.borrow().starting_cwd()
    }

    pub fn update_successful_exec(&self, new_exec_metadata: ExecMetadata) {
        self.execution
            .borrow_mut()
            .update_successful_exec(new_exec_metadata);
    }
}

// #[derive(Hash)]
// pub struct ExecUniqId {
//     exec_full_path: PathBuf,
//     args: Vec<String>,
// }

// pub fn hash_exec_uniqid(hash_struct: ExecUniqId) -> u64 {
//     let mut s = DefaultHasher::new();
//     hash_struct.hash(&mut s);
//     s.finish()
// }

// #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
// pub struct GlobalExecutions {
//     global_execs: HashMap<u64, CachedExecution>,
// }

// impl GlobalExecutions {
//     fn new() -> GlobalExecutions {
//         GlobalExecutions {
//             global_execs: HashMap::new(),
//         }
//     }

//     fn add_new_execution(&mut self, hash: u64, exec: CachedExecution) {
//         println!("Hash for exec is: {}", hash);
//         // TODO: max file name size??
//         // TODO: check if it's there
//         self.global_execs.insert(hash, exec);
//     }

//     fn lookup(&self, exec: ExecCall) -> Option<CachedExecution> {
//         let exec_id_str = ExecUniqId {
//             exec_full_path: exec.executable(),
//             args: exec.args(),
//         };
//         let hash_id = hash_exec_uniqid(exec_id_str);
//         self.global_execs.get(&hash_id).cloned()
//     }
// }

// pub fn deserialize_execs_from_cache() -> GlobalExecutions {
//     // if Path::new("./cache/cache").exists() {
//     //     File::create("./cache/cache").unwrap();
//     //     GlobalExecutions::new()
//     // } else {
//     //     let exec_struct_bytes =
//     //     fs::read("./cache/cache").expect("failed to deserialize execs from cache");
//     //     rmp_serde::from_read_ref(&exec_struct_bytes).unwrap()
//     // }

//     let cache_path = Path::new("./cache/cache");
//     let cache_bytes = fs::read(cache_path).unwrap();
//     if cache_bytes.is_empty() {
//         GlobalExecutions::new()
//     } else {
//         rmp_serde::from_read_ref(&cache_bytes).unwrap()
//     }
// }

// pub fn lookup_exec_in_cache(exec: ExecCall) -> Option<CachedExecution> {
//     let global_execs = deserialize_execs_from_cache();
//     global_execs.lookup(exec)
// }
// // Serialize the execs and write them to the cache.
// // Also copy the output files over.
// pub fn serialize_execs_to_cache(
//     exec_path: PathBuf,
//     args_list: Vec<String>,
//     root_execution: CachedExecution,
// ) {
//     // TODO: probably shouldn't be copying the output files before checking
//     // the cache.
//     // TODO: Get existing execs out and add to that.
//     const CACHE_LOCATION: &str = "./cache/cache";
//     let cache_path = PathBuf::from(CACHE_LOCATION);
//     let exec_id_str = ExecUniqId {
//         exec_full_path: exec_path,
//         args: args_list,
//     };
//     let hash = hash_exec_uniqid(exec_id_str);
//     println!("Hash for exec is: {}", hash);

//     let mut global_execs = deserialize_execs_from_cache();
//     global_execs.add_new_execution(hash, root_execution.clone());

//     let serialized_exec = rmp_serde::to_vec(&global_execs).unwrap();
//     if cache_path.exists() {
//         fs::remove_file(&cache_path).unwrap();
//     }
//     fs::write(cache_path, serialized_exec).unwrap();
//     root_execution.copy_output_files_to_cache(hash);
// }

// pub fn generate_cachable_exec(root_execution: RcExecution) -> CachedExecution {
//     let mut exec_list = Vec::new();
//     for exec_call in root_execution.exec_calls() {
//         match exec_call {
//             ExecCall::Failed(meta) => {
//                 exec_list.push(CachedExecCall::Failed(meta));
//             }
//             ExecCall::Successful(file_events, meta) => {
//                 let mut preconditions = CondsMap::new();
//                 let mut postconditions = CondsMap::new();
//                 preconditions.add_preconditions(file_events.clone());
//                 postconditions.add_postconditions(file_events);
//                 exec_list.push(CachedExecCall::Successful(
//                     meta,
//                     preconditions,
//                     postconditions,
//                 ));
//             }
//         }
//     }

//     let mut children = Vec::new();
//     // TODO: actually recurse lmao
//     for child in root_execution.child_executions() {
//         let cachable_child = generate_cachable_exec(child);
//         children.push(cachable_child);
//     }

//     // if let Some(code) = root_execution.exit_code() {
//     println!("execution: {:?}", root_execution);
//     // TODO: weird shit with exit code = none for root process
//     // let exit_code = if let Some(code) = root_execution.exit_code() {
//     //     code
//     // } else {
//     //     0
//     // };
//     CachedExecution::new(
//         children,
//         exec_list,
//         root_execution.exit_code().unwrap(),
//         root_execution.starting_cwd(),
//     )
// }
