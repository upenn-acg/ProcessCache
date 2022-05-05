use crate::condition_generator::{
    check_preconditions, generate_postconditions, generate_preconditions, Conditions,
    ExecFileEvents, SyscallEvent,
};
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

    // Generate the map of execs, where each child, and child of child,
    // and so on, has its own entry which has ref counts to its subtree
    // of computation.
    // Pro: constant time lookup.
    // Pro: Don't have multiple copies all over the place.
    // To start:
    // fn generate_cachable_map(&self) -> HashMap<Command, Rc<CachedExecution>> {
    //     let curr_file_events = self.file_events;
    //     let preconditions = generate_preconditions(curr_file_events);
    //     let postconditions = generate_postconditions(curr_file_events);

    //     CachedExecution {
    //         preconditions: Conditions::Pre(preconditions),
    //         postconditions: Conditions::Post(postconditions),
    //     }
    // }

    fn file_events(&self) -> ExecFileEvents {
        self.file_events.clone()
    }

    // fn generate_cachable_exec(&self) -> Rc<CachedExecution> {
    //     let curr_file_events = self.file_events.clone();
    //     let preconditions = generate_preconditions(curr_file_events.clone());
    //     let postconditions = generate_postconditions(curr_file_events);

    //     let mut cachable_child_execs = Vec::new();
    //     let children = self.child_execs.clone();
    //     for child in children {
    //         let cachable_child = child.generate_cachable_exec();
    //         cachable_child_execs.push(cachable_child.clone());
    //     }

    //     let new_cachable_exec = CachedExecution {
    //         child_execs: cachable_child_execs,
    //         failed_execs: self.failed_execs.clone(),
    //         preconditions: Conditions(preconditions),
    //         postconditions: Conditions(postconditions),
    //         successful_exec: self.successful_exec.clone(),
    //     };

    //     Rc::new(new_cachable_exec)
    // }

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

    fn starting_cwd(&self) -> PathBuf {
        self.starting_cwd.clone()
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

    pub fn file_events(&self) -> ExecFileEvents {
        self.execution.borrow().file_events()
    }

    // pub fn generate_cachable_exec(&self) -> Rc<CachedExecution> {
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

// TODO: exit code
// TODO: failed execs part of Conditions::Pre() and part of Facts (Fact::FailedExec)?
// TODO: don't need all of exec metadata
pub struct CachedExecution {
    child_execs: Vec<Rc<CachedExecution>>,
    env_vars: Vec<String>,
    failed_execs: Vec<ExecMetadata>,
    preconditions: Conditions,
    postconditions: Conditions,
    starting_cwd: PathBuf,
}

impl CachedExecution {}
