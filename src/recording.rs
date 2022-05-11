use crate::{
    cache::{CachedExecution, ExecCacheMap, RcCachedExec},
    cache_utils::Command,
    condition_generator::{generate_postconditions, generate_preconditions, ExecFileEvents},
    syscalls::SyscallEvent,
};
use nix::{unistd::Pid, NixPath};
use std::{cell::RefCell, hash::Hash, path::PathBuf, rc::Rc};

pub type ChildExecutions = Vec<RcExecution>;

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

    fn args(&self) -> Vec<String> {
        self.args.clone()
    }

    fn executable(&self) -> PathBuf {
        self.executable.clone()
    }

    fn env_vars(&self) -> Vec<String> {
        self.env_vars.clone()
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

    fn starting_cwd(&self) -> PathBuf {
        self.starting_cwd.clone()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Execution {
    caller_pid: Proc,
    child_execs: ChildExecutions,
    exit_code: Option<i32>,
    file_events: ExecFileEvents,
    successful_exec: ExecMetadata,
}

impl Execution {
    pub fn new() -> Execution {
        Execution {
            caller_pid: Proc::default(),
            child_execs: Vec::new(),
            exit_code: None,
            file_events: ExecFileEvents::new(),
            successful_exec: ExecMetadata::new(),
        }
    }

    pub fn add_child_execution(&mut self, child_execution: RcExecution) {
        self.child_execs.push(child_execution);
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

    fn args(&self) -> Vec<String> {
        self.successful_exec.args()
    }

    fn env_vars(&self) -> Vec<String> {
        self.successful_exec.env_vars()
    }

    fn executable(&self) -> PathBuf {
        self.successful_exec.executable()
    }

    fn add_to_cachable_map(&self, exec_cache_map: &mut ExecCacheMap) {
        let curr_file_events = self.file_events.clone();
        let preconditions = generate_preconditions(curr_file_events.clone());
        let postconditions = generate_postconditions(curr_file_events);
        let command_key = Command(
            self.executable().into_os_string().into_string().unwrap(),
            self.args(),
        );
        let mut cached_exec = CachedExecution::new(
            Vec::new(),
            command_key.clone(),
            self.env_vars(),
            preconditions,
            postconditions,
            self.starting_cwd(),
        );

        for child in self.child_execs.iter() {
            let child_file_events = child.file_events();
            let preconditions = generate_preconditions(child_file_events.clone());
            let postconditions = generate_postconditions(child_file_events);
            let child_command = Command(
                child.executable().into_os_string().into_string().unwrap(),
                child.args(),
            );

            let cached_child = CachedExecution::new(
                Vec::new(),
                child_command,
                child.env_vars(),
                preconditions,
                postconditions,
                child.starting_cwd(),
            );
            let child_rc = RcCachedExec::new(cached_child);
            cached_exec.add_child(child_rc.clone());
            child.add_to_cachable_map(exec_cache_map);
        }
        let rc_cached_exec = RcCachedExec::new(cached_exec);
        exec_cache_map.insert(command_key, rc_cached_exec);
    }

    fn file_events(&self) -> ExecFileEvents {
        self.file_events.clone()
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

        // println!("Failed executables:");
        // for failed_exec in self.failed_execs.clone() {
        //     failed_exec.print_basic_exec_info();
        // }

        println!("Now starting children:");
        for child in self.child_execs.clone() {
            child.print_basic_exec_info()
        }
    }

    fn print_file_events(&self) {
        println!("Successful executable:");
        println!();
        self.file_events.print_file_events();

        println!("Now starting children:");
        println!();
        for child in self.child_execs.clone() {
            child.print_file_events();
        }
    }

    fn print_pre_and_postconditions(&self) {
        println!("Successful executable:");
        println!();
        let events = self.file_events.clone();
        let preconditions = generate_preconditions(events.clone());
        // check_preconditions(preconditions.clone());
        let postconditions = generate_postconditions(events);
        println!("Preconditions:");
        for (path, fact) in preconditions {
            println!("Path: {:?}, Fact: {:?}", path, fact);
        }
        println!();
        println!("Postconditions:");
        for (path, fact) in postconditions {
            println!("Path: {:?}, Fact: {:?}", path, fact);
        }
        println!();

        println!("Now starting children:");
        println!();
        for child in self.child_execs.clone() {
            child.print_pre_and_postconditions();
        }
    }

    pub fn starting_cwd(&self) -> PathBuf {
        self.successful_exec.starting_cwd()
    }

    pub fn update_successful_exec(&mut self, exec_metadata: ExecMetadata) {
        self.successful_exec = exec_metadata;
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Proc(pub Pid);

impl Default for Proc {
    fn default() -> Proc {
        Proc(Pid::from_raw(0))
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

    pub fn add_to_cachable_map(&self, exec_cache_map: &mut ExecCacheMap) {
        self.execution.borrow().add_to_cachable_map(exec_cache_map)
    }

    pub fn args(&self) -> Vec<String> {
        self.execution.borrow().args()
    }

    pub fn env_vars(&self) -> Vec<String> {
        self.execution.borrow().env_vars()
    }

    pub fn executable(&self) -> PathBuf {
        self.execution.borrow().executable()
    }
    pub fn file_events(&self) -> ExecFileEvents {
        self.execution.borrow().file_events()
    }

    // pub fn generate_cachable_exec(&self) -> CachedExecution {
    //     self.execution.borrow().generate_cachable_exec()
    // }

    pub fn is_empty_root_exec(&self) -> bool {
        self.execution.borrow().is_empty_root_exec()
    }

    pub fn pid(&self) -> Pid {
        self.execution.borrow().pid()
    }

    pub fn print_basic_exec_info(&self) {
        self.execution.borrow().print_basic_exec_info()
    }

    pub fn print_file_events(&self) {
        self.execution.borrow().print_file_events()
    }

    pub fn print_pre_and_postconditions(&self) {
        self.execution.borrow().print_pre_and_postconditions()
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
