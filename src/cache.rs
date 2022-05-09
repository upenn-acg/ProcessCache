use crate::condition_generator::{
    check_preconditions, generate_postconditions, generate_preconditions, Command, ExecFileEvents,
    Fact, SyscallEvent,
};
use nix::{unistd::Pid, NixPath};
use serde::{Deserialize, Serialize};
// use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fs::{self, File},
    hash::{Hash, Hasher},
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

// use anyhow::{bail, Context, Result};

pub type ChildExecutions = Vec<RcExecution>;
pub type ExecCacheMap = HashMap<Command, RcCachedExec>;
// The executable path and args
// are the key to the map.
// Having them be a part of this struct would
// be redundant.
// TODO: exit code
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CachedExecution {
    child_execs: Vec<RcCachedExec>,
    env_vars: Vec<String>,
    preconditions: HashMap<PathBuf, HashSet<Fact>>,
    postconditions: HashMap<PathBuf, HashSet<Fact>>,
    starting_cwd: PathBuf,
}

impl CachedExecution {
    fn add_child(&mut self, child: RcCachedExec) {
        self.child_execs.push(child)
    }

    fn check_all_preconditions(&self) -> bool {
        let my_preconds = self.preconditions.clone();

        if !check_preconditions(my_preconds) {
            return false;
        }

        let children = self.child_execs.clone();
        for child in children {
            if !child.check_all_preconditions() {
                return false;
            }
        }
        true
    }

    fn print_me(&self) {
        println!("NEW CACHED EXEC:");
        println!("Preconds: {:?}", self.preconditions);
        for child in self.child_execs.clone() {
            child.print_me()
        }
    }

    fn postconditions(&self) -> HashMap<PathBuf, HashSet<Fact>> {
        self.postconditions.clone()
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

        let mut cached_exec = CachedExecution {
            child_execs: Vec::new(),
            env_vars: self.env_vars(),
            preconditions,
            postconditions,
            starting_cwd: self.starting_cwd(),
        };
        // let rc_cached_exec = RcCachedExec::new(cached_exec);
        let command_key = Command(
            self.executable().into_os_string().into_string().unwrap(),
            self.args(),
        );
        // exec_cache_map.insert(command_key, rc_cached_exec.clone());

        for child in self.child_execs.iter() {
            let child_file_events = child.file_events();
            let preconditions = generate_preconditions(child_file_events.clone());
            let postconditions = generate_postconditions(child_file_events);
            let cached_child = CachedExecution {
                child_execs: Vec::new(),
                env_vars: child.env_vars(),
                preconditions,
                postconditions,
                starting_cwd: child.starting_cwd(),
            };
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RcCachedExec {
    cached_exec: Rc<CachedExecution>,
}

impl RcCachedExec {
    fn new(cached_exec: CachedExecution) -> RcCachedExec {
        RcCachedExec {
            cached_exec: Rc::new(cached_exec),
        }
    }

    pub fn check_all_preconditions(&self) -> bool {
        self.cached_exec.check_all_preconditions()
    }

    pub fn print_me(&self) {
        self.cached_exec.print_me()
    }

    pub fn postconditions(&self) -> HashMap<PathBuf, HashSet<Fact>> {
        self.cached_exec.postconditions()
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

    pub fn env_vars(&self) -> Vec<String> {
        self.execution.borrow().env_vars()
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

// I *THINK* I can just iterate through the keys and do this for each and
fn copy_output_files_to_cache(exec_cache_map: ExecCacheMap) {
    for (command, rc_cached_exec) in exec_cache_map {
        const CACHE_LOCATION: &str = "/home/kelly/research/IOTracker/cache";
        let cache_dir = PathBuf::from(CACHE_LOCATION);
        // We will put the files at /cache/hash(command)/
        let mut hasher = DefaultHasher::new();
        command.hash(&mut hasher);

        let curr_command_subdir = hasher.finish();
        let cache_subdir = cache_dir.join(curr_command_subdir.to_string());
        fs::create_dir(cache_subdir.clone()).unwrap();
        debug!("cache subdir: {:?}", cache_subdir);
        let postconditions = rc_cached_exec.postconditions();
        for (full_path, facts) in postconditions {
            for fact in facts {
                if fact == Fact::FinalContents {
                    let file_name = full_path.file_name().unwrap();
                    debug!("file name: {:?}", file_name);
                    let cache_file_path = cache_subdir.join(file_name);
                    debug!("cache_file_path: {:?}", cache_file_path);
                    debug!("full_path: {:?}", full_path);
                    fs::copy(full_path.clone(), cache_file_path).unwrap();
                }
            }
        }
    }
}

// TODO: insert into an EXISTING cache
pub fn insert_execs_into_cache(exec_map: ExecCacheMap) {
    const CACHE_LOCATION: &str = "./IOTracker/cache/cache";
    let cache_path = PathBuf::from(CACHE_LOCATION);
    // Make the cache file if it doesn't exist.
    let mut existing_cache = if !cache_path.exists() {
        File::create(cache_path).unwrap();
        HashMap::new()
    } else if let Some(existing_cache) = retrieve_existing_cache() {
        existing_cache
    } else {
        HashMap::new()
    };

    for (command, cached_exec) in exec_map.clone() {
        if let std::collections::hash_map::Entry::Vacant(e) = existing_cache.entry(command.clone())
        {
            e.insert(cached_exec);
        } else {
            panic!("Cache already has command: {:?}", command);
        }
    }
    let serialized_exec_map = rmp_serde::to_vec(&existing_cache).unwrap();

    // This will replace the contents
    fs::write(CACHE_LOCATION, serialized_exec_map).unwrap();

    copy_output_files_to_cache(exec_map);
}

pub fn retrieve_existing_cache() -> Option<ExecCacheMap> {
    const CACHE_LOCATION: &str = "./IOTracker/cache/cache";
    let cache_path = PathBuf::from(CACHE_LOCATION);
    if cache_path.exists() {
        let exec_struct_bytes =
            fs::read("./IOTracker/cache/cache").expect("failed to deserialize execs from cache");
        Some(rmp_serde::from_read_ref(&exec_struct_bytes).unwrap())
    } else {
        None
    }
}
