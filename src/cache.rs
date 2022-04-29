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
// pub type Postconditions = HashMap<PathBuf, HashSet<Fact>>;
#[derive(Clone, Debug, PartialEq)]
pub struct Execution {
    child_execs: ChildExecutions,
    failed_execs: Vec<ExecMetadata>,
    file_events: ExecFileEvents,
    successful_exec: ExecMetadata,
}

impl Execution {
    pub fn new(command: Command, pid: Pid) -> Execution {
        let metadata = ExecMetadata {
            args: command.1,
            // TODO: make sure this is right
            starting_cwd: PathBuf::new(),
            env_vars: Vec::new(),
            executable: command.0,
            exit_code: None,
            caller_pid: Proc(pid),
        };
        Execution {
            child_execs: ChildExecutions::new(),
            failed_execs: Vec::new(),
            file_events: ExecFileEvents::new(),
            successful_exec: metadata,
        }
    }

    fn add_child_execution(&mut self, child_execution: RcExecution) {
        self.child_execs.push(child_execution);
    }

    pub fn add_exit_code(&mut self, exit_code: i32, pid: Pid) {
        // match self {
        //     Execution::Failed(meta) | Execution::Successful(_, _, meta) => {
        //         // Only want the exit code if this is the process
        //         // that actually exec'd the process.
        //         let exec_pid = meta.caller_pid();
        //         if exec_pid == pid {
        //             meta.add_exit_code(exit_code);
        //         }
        //     }
        //     _ => {
        //         panic!("Trying to add exit code to pending execution!")
        //     }
        // }
    }

    pub fn add_new_file_event(
        &mut self,
        caller_pid: Pid,
        file_access: SyscallEvent,
        full_path: PathBuf,
    ) {
        match self {
            ExecCall::Successful(file_events, _) => {
                file_events.add_new_file_event(caller_pid, file_access, full_path)
            }
            _ => panic!("Trying to add file event to failed execve!"),
        }
    }

    fn args(&self) -> Vec<String> {
        match self {
            ExecCall::Successful(_, meta) | ExecCall::Failed(meta) => meta.args(),
        }
    }

    fn executable(&self) -> PathBuf {
        match self {
            ExecCall::Successful(_, meta) | ExecCall::Failed(meta) => meta.executable(),
        }
    }

    fn file_event_list(&self) -> &ExecFileEvents {
        match self {
            ExecCall::Successful(file_events, _) => file_events,
            _ => panic!("Trying to get file event list for failed execve!!"),
        }
    }

    fn is_successful(&self) -> bool {
        matches!(self, ExecCall::Successful(_, _))
    }

    fn metadata(&self) -> &ExecMetadata {
        match self {
            ExecCall::Failed(meta) => meta,
            ExecCall::Successful(_, meta) => meta,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExecCallList {
    exec_calls: Vec<ExecCall>,
}

impl ExecCallList {
    fn new() -> ExecCallList {
        ExecCallList {
            exec_calls: Vec::new(),
        }
    }

    fn add_new_exec_call(&mut self, exec: ExecCall) {
        self.exec_calls.push(exec);
    }

    // Add file event to the latest exec (if it is successful)
    fn add_new_file_event(
        &mut self,
        caller_pid: Pid,
        file_event: SyscallEvent,
        full_path: PathBuf,
    ) {
        let length = self.exec_calls.len();
        let last_exec = self.exec_calls.as_mut_slice().get_mut(length - 1).unwrap();
        last_exec.add_new_file_event(caller_pid, file_event, full_path);
    }

    fn exec_calls(&self) -> Vec<ExecCall> {
        self.exec_calls.clone()
    }

    fn exec_file_event_map(&self) -> &ExecFileEvents {
        let last_exec = self.exec_calls.last().unwrap();
        last_exec.file_event_list()
    }

    fn get_first_exec_and_args(&self) -> (PathBuf, Vec<String>) {
        let first = self.exec_calls.first().unwrap();
        (first.executable(), first.args())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Execution {
    caller_pid: Proc,
    child_execs: ChildExecutions,
    exec_calls: ExecCallList,
    exit_code: Option<i32>,
    starting_cwd: PathBuf,
}

impl Execution {
    pub fn new(proc: Pid) -> Execution {
        Execution {
            caller_pid: Proc(proc),
            child_execs: Vec::new(),
            exec_calls: ExecCallList::new(),
            exit_code: None,
            starting_cwd: PathBuf::new(),
        }
    }

    pub fn add_child_execution(&mut self, child_execution: RcExecution) {
        self.child_execs.push(child_execution);
    }

    pub fn add_new_exec_call(&mut self, exec_call: ExecCall) {
        self.exec_calls.add_new_exec_call(exec_call);
    }

    pub fn add_exit_code(&mut self, code: i32) {
        self.exit_code = Some(code);
    }

    // You can have max 1 successful execve.
    // [Success] or [Fail,...,Fail,Success]
    // Can only add file event to the successful one
    // Successful one should be last.
    pub fn add_new_file_event(
        &mut self,
        caller_pid: Pid,
        // OBVIOUSLY, will handle any syscall event eventually.
        file_access: SyscallEvent,
        full_path: PathBuf,
    ) {
        self.exec_calls
            .add_new_file_event(caller_pid, file_access, full_path);
    }

    fn add_starting_cwd(&mut self, cwd: PathBuf) {
        if self.starting_cwd().is_empty() {
            self.starting_cwd = cwd;
        }
    }

    fn caller_pid(&self) -> Pid {
        let proc = &self.caller_pid;
        let Proc(pid) = proc;
        *pid
    }

    fn child_executions(&self) -> ChildExecutions {
        self.child_execs.clone()
    }

    // fn copy_outputs_to_cache(&self) {
    //     self.exec_calls.copy_outputs_to_cache();
    //     for child in self.child_execs.iter() {
    //         child.copy_outputs_to_cache();
    //     }
    // }

    fn execs(&self) -> Vec<ExecCall> {
        self.exec_calls.exec_calls()
    }

    fn exec_file_event_map(&self) -> &ExecFileEvents {
        self.exec_calls.exec_file_event_map()
    }

    fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    // fn generate_pre_and_post_conditions(&mut self) {
    //     self.exec_calls.generate_pre_and_post_conditions();
    //     for child in self.child_execs.iter_mut() {
    //         child.generate_pre_and_post_conditions();
    //     }
    // }

    fn get_child_exec_by_pid(&self, pid: Pid) -> RcExecution {
        let child_execs = self.child_executions();
        for child in child_execs {
            if pid == child.caller_pid() {
                return child;
            }
        }
        panic!("Child pid not found in child execs!");
    }

    fn get_exec_path_and_args(&self) -> (PathBuf, Vec<String>) {
        self.exec_calls.get_first_exec_and_args()
    }

    fn starting_cwd(&self) -> PathBuf {
        self.starting_cwd.clone()
    }
}

// Info about the execution that we want to keep around
// even if the execution fails (so we know it should fail
// if we see it again, it would be some kinda error if
// we expect it to fail and it succeeds).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExecMetadata {
    args: Vec<String>,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    executable: PathBuf,
}

impl ExecMetadata {
    pub fn new() -> ExecMetadata {
        ExecMetadata {
            args: Vec::new(),
            env_vars: Vec::new(),
            executable: PathBuf::new(),
        }
    }

    pub fn add_identifiers(
        &mut self,
        args: Vec<String>,
        env_vars: Vec<String>,
        executable: PathBuf,
    ) {
        self.args = args;
        self.env_vars = env_vars;
        self.executable = executable;
    }

    pub fn args(&self) -> Vec<String> {
        self.args.clone()
    }

    pub fn executable(&self) -> PathBuf {
        self.executable.clone()
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
        println!("In add_exit_code()!!");
        self.execution.borrow_mut().add_exit_code(code);
    }

    pub fn add_new_exec_call(&self, new_exec_call: ExecCall) {
        self.execution.borrow_mut().add_new_exec_call(new_exec_call)
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

    pub fn add_starting_cwd(&self, cwd: PathBuf) {
        self.execution.borrow_mut().add_starting_cwd(cwd);
    }

    pub fn child_executions(&self) -> ChildExecutions {
        self.execution.borrow().child_executions()
    }

    // pub fn copy_outputs_to_cache(&self) {
    //     self.execution.borrow().copy_outputs_to_cache()
    // }

    pub fn exec_calls(&self) -> Vec<ExecCall> {
        self.execution.borrow().execs()
    }

    pub fn exec_file_event_map(&self) -> ExecFileEvents {
        self.execution.borrow().exec_file_event_map().clone()
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.execution.borrow().exit_code()
    }

    // pub fn generate_pre_and_post_conditions(&self) {
    //     self.execution
    //         .borrow_mut()
    //         .generate_pre_and_post_conditions()
    // }

    // This should only be called when the curr_exec of the child is
    // still the parent's. So we know we can just check the parent's
    // child execs for it.
    pub fn get_child_exec_by_pid(&self, pid: Pid) -> RcExecution {
        self.execution.borrow().get_child_exec_by_pid(pid)
    }

    pub fn get_exec_path_and_args(&self) -> (PathBuf, Vec<String>) {
        self.execution.borrow().get_exec_path_and_args()
    }
    pub fn no_successful_exec_yet(&self) -> bool {
        let execs = self.execution.borrow().execs();
        for exec in execs {
            if exec.is_successful() {
                return false;
            }
        }
        true
    }

    pub fn caller_pid(&self) -> Pid {
        self.execution.borrow().caller_pid()
    }

    pub fn print_event_lists(&self) {
        println!("Printing executions of first execution:");
        let exec_calls = self.exec_calls();
        for exec in exec_calls {
            let successful = exec.is_successful();
            let executable = exec.executable();
            println!("Executable: {:?}, Success: {}", executable, successful);
            if let ExecCall::Successful(file_events, _) = exec {
                println!("File events: {:?}", file_events);
            }
        }

        for child in self.child_executions() {
            println!("Child!");
            let exec_calls = child.exec_calls();
            for exec in exec_calls {
                let successful = exec.is_successful();
                let executable = exec.executable();
                println!("Executable: {:?}, Success: {}", executable, successful);
                println!();
            }
        }
    }
    // Print all file event lists for the execution.
    // TODO: This doesn't print the child exec stuff.
    // Need to make a function to get the child execs as well.
    // For now, one layer deep is ok.
    // pub fn print_execs(&self) {
    //     let exec_calls = self.exec_calls();
    //     for exec in exec_calls {
    //         if let ExecCall::Successful(_, _, preconds, postconds) = exec {
    //             println!("PRECONDITIONS: {:?}", preconds);
    //             println!("POSTCONDITIONS: {:?}", postconds)
    //         }
    //     }

    //     for child in self.child_executions() {
    //         let exec_calls = child.exec_calls();
    //         for exec in exec_calls {
    //             if let ExecCall::Successful(_, _, preconds, postconds) = exec {
    //                 println!("PRECONDITIONS: {:?}", preconds);
    //                 println!("POSTCONDITIONS: {:?}", postconds)
    //             }
    //         }
    //     }
    // }

    pub fn starting_cwd(&self) -> PathBuf {
        self.execution.borrow().starting_cwd()
    }
}

pub type CachedChildren = Vec<CachedExecution>;
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
enum CachedExecCall {
    Failed(ExecMetadata),
    // Preconditions, postconditions
    Successful(ExecMetadata, CondsMap, CondsMap),
}

impl CachedExecCall {
    fn copy_output_files_to_cache(&self, hash: u64) {
        if let CachedExecCall::Successful(_, _, postconds) = self {
            postconds.copy_outputs_to_cache(hash)
        }
    }

    fn is_successful(&self) -> bool {
        matches!(self, CachedExecCall::Successful(_, _, _))
    }

    fn matches_exec(&self, exec: ExecCall) -> bool {
        self.metadata() == exec.metadata() && (exec.is_successful() && self.is_successful())
            || (!exec.is_successful() && !self.is_successful())
    }

    fn metadata(&self) -> &ExecMetadata {
        match self {
            CachedExecCall::Failed(meta) => meta,
            CachedExecCall::Successful(meta, _, _) => meta,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CachedExecution {
    child_execs: CachedChildren,
    exec_calls: Vec<CachedExecCall>,
    exit_code: i32,
    starting_cwd: PathBuf,
}

impl CachedExecution {
    fn new(
        children: CachedChildren,
        execs: Vec<CachedExecCall>,
        exit: i32,
        cwd: PathBuf,
    ) -> CachedExecution {
        CachedExecution {
            child_execs: children,
            exec_calls: execs,
            exit_code: exit,
            starting_cwd: cwd,
        }
    }

    fn copy_output_files_to_cache(&self, hash: u64) {
        let len = self.exec_calls.len();
        let last_exec = self.exec_calls.as_slice().get(len - 1).unwrap();
        last_exec.copy_output_files_to_cache(hash);

        for child in self.child_execs.clone() {
            child.copy_output_files_to_cache(hash);
        }
    }

    pub fn print_pre_and_postconditions(&self) {
        for call in self.exec_calls.clone() {
            if let CachedExecCall::Successful(_, pres, posts) = call {
                println!("Preconditions: {:?}", pres);
                println!("Postconditions: {:?}", posts);
            }
        }

        for child in self.child_execs.clone() {
            child.print_pre_and_postconditions();
        }
    }
}

#[derive(Hash)]
pub struct ExecUniqId {
    exec_full_path: PathBuf,
    args: Vec<String>,
}

pub fn hash_exec_uniqid(hash_struct: ExecUniqId) -> u64 {
    let mut s = DefaultHasher::new();
    hash_struct.hash(&mut s);
    s.finish()
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GlobalExecutions {
    global_execs: HashMap<u64, CachedExecution>,
}

impl GlobalExecutions {
    fn new() -> GlobalExecutions {
        GlobalExecutions {
            global_execs: HashMap::new(),
        }
    }

    fn add_new_execution(&mut self, hash: u64, exec: CachedExecution) {
        println!("Hash for exec is: {}", hash);
        // TODO: max file name size??
        // TODO: check if it's there
        self.global_execs.insert(hash, exec);
    }

    fn lookup(&self, exec: ExecCall) -> Option<CachedExecution> {
        let exec_id_str = ExecUniqId {
            exec_full_path: exec.executable(),
            args: exec.args(),
        };
        let hash_id = hash_exec_uniqid(exec_id_str);
        self.global_execs.get(&hash_id).cloned()
    }
}

pub fn deserialize_execs_from_cache() -> GlobalExecutions {
    // if Path::new("./cache/cache").exists() {
    //     File::create("./cache/cache").unwrap();
    //     GlobalExecutions::new()
    // } else {
    //     let exec_struct_bytes =
    //     fs::read("./cache/cache").expect("failed to deserialize execs from cache");
    //     rmp_serde::from_read_ref(&exec_struct_bytes).unwrap()
    // }

    let cache_path = Path::new("./cache/cache");
    let cache_bytes = fs::read(cache_path).unwrap();
    if cache_bytes.is_empty() {
        GlobalExecutions::new()
    } else {
        rmp_serde::from_read_ref(&cache_bytes).unwrap()
    }
}

pub fn lookup_exec_in_cache(exec: ExecCall) -> Option<CachedExecution> {
    let global_execs = deserialize_execs_from_cache();
    global_execs.lookup(exec)
}
// Serialize the execs and write them to the cache.
// Also copy the output files over.
pub fn serialize_execs_to_cache(
    exec_path: PathBuf,
    args_list: Vec<String>,
    root_execution: CachedExecution,
) {
    // TODO: probably shouldn't be copying the output files before checking
    // the cache.
    // TODO: Get existing execs out and add to that.
    const CACHE_LOCATION: &str = "./cache/cache";
    let cache_path = PathBuf::from(CACHE_LOCATION);
    let exec_id_str = ExecUniqId {
        exec_full_path: exec_path,
        args: args_list,
    };
    let hash = hash_exec_uniqid(exec_id_str);
    println!("Hash for exec is: {}", hash);

    let mut global_execs = deserialize_execs_from_cache();
    global_execs.add_new_execution(hash, root_execution.clone());

    let serialized_exec = rmp_serde::to_vec(&global_execs).unwrap();
    if cache_path.exists() {
        fs::remove_file(&cache_path).unwrap();
    }
    fs::write(cache_path, serialized_exec).unwrap();
    root_execution.copy_output_files_to_cache(hash);
}

pub fn generate_cachable_exec(root_execution: RcExecution) -> CachedExecution {
    let mut exec_list = Vec::new();
    for exec_call in root_execution.exec_calls() {
        match exec_call {
            ExecCall::Failed(meta) => {
                exec_list.push(CachedExecCall::Failed(meta));
            }
            ExecCall::Successful(file_events, meta) => {
                let mut preconditions = CondsMap::new();
                let mut postconditions = CondsMap::new();
                preconditions.add_preconditions(file_events.clone());
                postconditions.add_postconditions(file_events);
                exec_list.push(CachedExecCall::Successful(
                    meta,
                    preconditions,
                    postconditions,
                ));
            }
        }
    }

    let mut children = Vec::new();
    // TODO: actually recurse lmao
    for child in root_execution.child_executions() {
        let cachable_child = generate_cachable_exec(child);
        children.push(cachable_child);
    }

    // if let Some(code) = root_execution.exit_code() {
    println!("execution: {:?}", root_execution);
    // TODO: weird shit with exit code = none for root process
    // let exit_code = if let Some(code) = root_execution.exit_code() {
    //     code
    // } else {
    //     0
    // };
    CachedExecution::new(
        children,
        exec_list,
        root_execution.exit_code().unwrap(),
        root_execution.starting_cwd(),
    )
}
