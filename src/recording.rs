use crate::{
    cache::{CachedExecution, ExecCacheMap, RcCachedExec},
    cache_utils::{hash_command, Command},
    condition_generator::{generate_postconditions, generate_preconditions, ExecFileEvents},
    condition_utils::Fact,
    syscalls::SyscallEvent,
};
use nix::{unistd::Pid, NixPath};
use std::{cell::RefCell, fs, hash::Hash, path::PathBuf, rc::Rc};
use tracing::debug;

pub type ChildExecutions = Vec<RcExecution>;

// Info about the execution that we want to keep around
// even if the execution fails (so we know it should fail
// if we see it again, it would be some kinda error if
// we expect it to fail and it succeeds).
#[derive(Clone, Debug, PartialEq)]
pub struct ExecMetadata {
    args: Vec<String>,
    caller_pid: Proc,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    executable: PathBuf,
    starting_cwd: PathBuf,
}

impl ExecMetadata {
    pub fn new(caller_pid: Proc) -> ExecMetadata {
        ExecMetadata {
            args: Vec::new(),
            caller_pid,
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

    fn caller_pid(&self) -> Pid {
        let Proc(pid) = self.caller_pid;
        pid
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
    child_execs: ChildExecutions,
    exit_code: Option<i32>,
    file_events: ExecFileEvents,
    successful_exec: ExecMetadata,
}

impl Execution {
    pub fn new(calling_pid: Proc) -> Execution {
        Execution {
            child_execs: Vec::new(),
            exit_code: None,
            file_events: ExecFileEvents::new(),
            successful_exec: ExecMetadata::new(calling_pid),
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

    // change from add_to_cachable_map(&mut execachemap)
    // to update_curr_cache_map(&mut existing_cache_map_)
    // recurse through the Execution and children and children of children...
    // yada yada yada
    // updating existing cache structure by
    // 1) checking if Execution's command exists in the map
    // 2) it does? great. add to  command -> [first exec, second, etc...]
    //
    // 3) no? add to the overall map
    // 4) is a child? add to parent
    fn update_curr_cache_map(&self, existing_cache_map: &mut ExecCacheMap) {
        const CACHE_LOCATION: &str = "./cache";
        let cache_dir = PathBuf::from(CACHE_LOCATION);
        let curr_file_events = self.file_events.clone();
        let preconditions = generate_preconditions(curr_file_events.clone());
        let postconditions = generate_postconditions(curr_file_events);

        let command_key = Command(
            self.executable().into_os_string().into_string().unwrap(),
            self.args(),
        );

        let index = if let Some(exec_list) = existing_cache_map.get(&command_key) {
            exec_list.len()
        } else {
            0
        };
        let mut cached_exec = CachedExecution::new(
            Vec::new(),
            command_key.clone(),
            self.env_vars(),
            index as u32,
            preconditions,
            postconditions.clone(),
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

            let index = if let Some(exec_list) = existing_cache_map.get(&child_command) {
                exec_list.len()
            } else {
                0
            };
            let cached_child = CachedExecution::new(
                Vec::new(),
                child_command,
                child.env_vars(),
                index as u32,
                preconditions,
                postconditions.clone(),
                child.starting_cwd(),
            );
            let child_rc = RcCachedExec::new(cached_child);
            cached_exec.add_child(child_rc.clone());
            child.update_curr_cache_map(existing_cache_map);
        }

        let rc_cached_exec = RcCachedExec::new(cached_exec);
        // let exec_list = existing_cache_map.get_mut(&command_key).unwrap();
        existing_cache_map
            .entry(command_key.clone())
            .or_insert_with(|| vec![rc_cached_exec]);
        // exec_list.push(rc_cached_exec);

        // Now copy the output files to the appropriate places.
        let hashed_command = hash_command(command_key);
        let cache_subdir_hashed_command = cache_dir.join(hashed_command.to_string());

        let stdout_file_name = format!("stdout_{:?}", self.successful_exec.caller_pid().as_raw());
        let curr_stdout_file_path = cache_subdir_hashed_command.join(stdout_file_name.clone());
        let cache_subdir_hash_and_idx = cache_subdir_hashed_command.join(index.to_string());
        if !cache_subdir_hash_and_idx.exists() {
            fs::create_dir(cache_subdir_hash_and_idx.clone()).unwrap();
        }
        let new_stdout_file_path = cache_subdir_hash_and_idx.join(stdout_file_name);
        debug!("NEW STD OUT FILE PATH: {:?}", new_stdout_file_path);
        debug!("OLD STD OUT FILE PATH: {:?}", curr_stdout_file_path);
        fs::copy(curr_stdout_file_path.clone(), new_stdout_file_path).unwrap();
        fs::remove_file(curr_stdout_file_path).unwrap();
        for (full_path, facts) in postconditions {
            for fact in facts {
                if fact == Fact::FinalContents {
                    let file_name = full_path.file_name().unwrap();
                    let cache_file_path = cache_subdir_hash_and_idx.join(file_name);
                    // TODO: not a real solution to the mothur problem
                    debug!("FULL PATH: {:?}", full_path);
                    debug!("CACHE PATH: {:?}", cache_file_path);
                    if full_path.extension().unwrap() != "temp" {
                        fs::copy(full_path.clone(), cache_file_path).unwrap();
                    }
                }
            }
        }
    }

    // fn add_to_cachable_map(&self, exec_cache_map: &mut ExecCacheMap) {
    //     let curr_file_events = self.file_events.clone();
    //     let preconditions = generate_preconditions(curr_file_events.clone());
    //     let postconditions = generate_postconditions(curr_file_events);
    //     let command_key = Command(
    //         self.executable().into_os_string().into_string().unwrap(),
    //         self.args(),
    //     );
    //     let mut cached_exec = CachedExecution::new(
    //         Vec::new(),
    //         command_key.clone(),
    //         self.env_vars(),
    //         preconditions,
    //         postconditions,
    //         self.starting_cwd(),
    //     );

    //     for child in self.child_execs.iter() {
    //         let child_file_events = child.file_events();
    //         let preconditions = generate_preconditions(child_file_events.clone());
    //         let postconditions = generate_postconditions(child_file_events);
    //         let child_command = Command(
    //             child.executable().into_os_string().into_string().unwrap(),
    //             child.args(),
    //         );

    //         let cached_child = CachedExecution::new(
    //             Vec::new(),
    //             child_command,
    //             child.env_vars(),
    //             preconditions,
    //             postconditions,
    //             child.starting_cwd(),
    //         );
    //         let child_rc = RcCachedExec::new(cached_child);
    //         cached_exec.add_child(child_rc.clone());
    //         child.add_to_cachable_map(exec_cache_map);
    //     }
    //     let rc_cached_exec = RcCachedExec::new(cached_exec);
    //     exec_cache_map.insert(command_key, rc_cached_exec);
    // }

    fn file_events(&self) -> ExecFileEvents {
        self.file_events.clone()
    }

    fn is_empty_root_exec(&self) -> bool {
        self.successful_exec.is_empty_root_exec()
    }

    fn pid(&self) -> Pid {
        self.successful_exec.caller_pid()
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
pub struct RcExecution(Rc<RefCell<Execution>>);

impl RcExecution {
    pub fn new(execution: Execution) -> RcExecution {
        RcExecution(Rc::new(RefCell::new(execution)))
    }

    pub fn add_child_execution(&self, child_execution: RcExecution) {
        self.0.borrow_mut().add_child_execution(child_execution);
    }

    pub fn add_exit_code(&self, code: i32) {
        self.0.borrow_mut().add_exit_code(code);
    }

    pub fn add_new_file_event(
        &self,
        caller_pid: Pid,
        file_event: SyscallEvent,
        full_path: PathBuf,
    ) {
        self.0
            .borrow_mut()
            .add_new_file_event(caller_pid, file_event, full_path);
    }

    // pub fn add_to_cachable_map(&self, exec_cache_map: &mut ExecCacheMap) {
    //     self.0.borrow().add_to_cachable_map(exec_cache_map)
    // }

    pub fn args(&self) -> Vec<String> {
        self.0.borrow().args()
    }

    pub fn env_vars(&self) -> Vec<String> {
        self.0.borrow().env_vars()
    }

    pub fn executable(&self) -> PathBuf {
        self.0.borrow().executable()
    }
    pub fn file_events(&self) -> ExecFileEvents {
        self.0.borrow().file_events()
    }

    pub fn is_empty_root_exec(&self) -> bool {
        self.0.borrow().is_empty_root_exec()
    }

    pub fn pid(&self) -> Pid {
        self.0.borrow().pid()
    }

    pub fn print_basic_exec_info(&self) {
        self.0.borrow().print_basic_exec_info()
    }

    pub fn print_file_events(&self) {
        self.0.borrow().print_file_events()
    }

    pub fn print_pre_and_postconditions(&self) {
        self.0.borrow().print_pre_and_postconditions()
    }

    // pub fn exit_code(&self) -> Option<i32> {
    //     self.execution.borrow().exit_code()
    // }

    pub fn starting_cwd(&self) -> PathBuf {
        self.0.borrow().starting_cwd()
    }

    pub fn update_curr_cache_map(&self, existing_cache_map: &mut ExecCacheMap) {
        self.0.borrow().update_curr_cache_map(existing_cache_map)
    }

    pub fn update_successful_exec(&self, new_exec_metadata: ExecMetadata) {
        self.0
            .borrow_mut()
            .update_successful_exec(new_exec_metadata);
    }
}
