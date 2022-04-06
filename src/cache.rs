use crate::condition_generator::{CondsMap, ExecFileEvents, SyscallEvent};
use nix::{unistd::Pid, NixPath};
use serde::Serialize;
// use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs::{self, create_dir},
    path::PathBuf,
    rc::Rc,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

#[derive(Clone, Debug, PartialEq)]
pub struct Proc(pub Pid);

impl Default for Proc {
    fn default() -> Proc {
        Proc(Pid::from_raw(0))
    }
}

pub type ChildExecutions = Vec<RcExecution>;
// pub type Postconditions = HashMap<PathBuf, HashSet<Fact>>;
#[derive(Clone, Debug, PartialEq)]
pub enum ExecCall {
    Failed(ExecMetadata),
    // Before we find out if the root execution's "execve" call succeeds,
    // its kinda just pending. I want to know which one the root is
    // and doing it in the enum seems easiest.
    Successful(ExecFileEvents, ExecMetadata),
}

impl ExecCall {
    pub fn add_identifiers(
        &mut self,
        args: Vec<String>,
        env_vars: Vec<String>,
        executable: String,
    ) {
        match self {
            ExecCall::Failed(metadata) | ExecCall::Successful(_, metadata) => {
                metadata.add_identifiers(args, env_vars, executable);
            }
        }
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

    fn executable(&self) -> String {
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

    fn starting_cwd(&self) -> PathBuf {
        self.starting_cwd.clone()
    }
}

// Info about the execution that we want to keep around
// even if the execution fails (so we know it should fail
// if we see it again, it would be some kinda error if
// we expect it to fail and it succeeds).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExecMetadata {
    args: Vec<String>,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    executable: String,
}

impl ExecMetadata {
    pub fn new() -> ExecMetadata {
        ExecMetadata {
            args: Vec::new(),
            env_vars: Vec::new(),
            executable: String::new(),
        }
    }

    pub fn add_identifiers(
        &mut self,
        args: Vec<String>,
        env_vars: Vec<String>,
        executable: String,
    ) {
        self.args = args;
        self.env_vars = env_vars;
        self.executable = executable;
    }

    pub fn executable(&self) -> String {
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
            println!("Executable: {}, Success: {}", executable, successful);
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
                println!("Executable: {}, Success: {}", executable, successful);
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
#[derive(Clone, Debug, PartialEq, Serialize)]
enum CachedExecCall {
    Failed(ExecMetadata),
    // Preconditions, postconditions
    Successful(ExecMetadata, CondsMap, CondsMap),
}

impl CachedExecCall {
    fn copy_output_files_to_cache(&self) {
        if let CachedExecCall::Successful(_, _, postconds) = self {
            postconds.copy_outputs_to_cache()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
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

    fn copy_output_files_to_cache(&self) {
        let len = self.exec_calls.len();
        let last_exec = self.exec_calls.as_slice().get(len - 1).unwrap();
        last_exec.copy_output_files_to_cache();

        for child in self.child_execs.clone() {
            child.copy_output_files_to_cache();
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
struct GlobalExecutions {
    global_execs: Vec<CachedExecution>,
}

// Wrapper for generating the hash.
// Opens the file and calls process() to get the hash.

// Serialize the execs and write them to the cache.
// Also copy the output files over.
pub fn serialize_execs_to_cache(root_execution: CachedExecution) {
    // TODO: probably shouldn't be copying the output files before checking
    // the cache.
    // TODO: Get existing execs out and add to that.
    const CACHE_LOCATION: &str = "./cache/cache";
    let cache_path = PathBuf::from(CACHE_LOCATION);

    let serialized_exec = rmp_serde::to_vec(&root_execution).unwrap();

    fs::write(cache_path, serialized_exec).unwrap();
    root_execution.copy_output_files_to_cache();
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
// pub fn deserialize_execs_from_cache() -> GlobalExecutions {
//     let exec_struct_bytes = fs::read("./research/IOTracker/cache/cache").expect("failed");
//     if exec_struct_bytes.is_empty() {
//         GlobalExecutions::new()
//     } else {
//         rmp_serde::from_read_ref(&exec_struct_bytes).unwrap()
//     }
// }
