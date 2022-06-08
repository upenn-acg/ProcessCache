use crate::{
    cache::{CacheMap, CachedExecution, RcCachedExec},
    cache_utils::{hash_command, CachedExecMetadata, Command},
    condition_generator::{generate_postconditions, generate_preconditions, ExecFileEvents},
    condition_utils::Fact,
    syscalls::SyscallEvent,
};
use nix::unistd::Pid;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fs::{self, File},
    hash::Hash,
    io::{self, Read, Write},
    path::PathBuf,
    rc::Rc,
};

pub type ChildExecutions = Vec<RcExecution>;

// Info about the execution that we want to keep around
// even if the execution fails (so we know it should fail
// if we see it again, it would be some kinda error if
// we expect it to fail and it succeeds).
#[derive(Clone, Debug, PartialEq)]
pub struct ExecMetadata {
    caller_pid: Proc,
    command: Command,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    starting_cwd: PathBuf,
}

impl ExecMetadata {
    pub fn new(caller_pid: Proc) -> ExecMetadata {
        ExecMetadata {
            caller_pid,
            command: Command(String::new(), Vec::new()),
            env_vars: Vec::new(),
            starting_cwd: PathBuf::new(),
        }
    }

    pub fn add_identifiers(
        &mut self,
        args: Vec<String>,
        env_vars: Vec<String>,
        executable: String,
        starting_cwd: PathBuf,
    ) {
        self.command.1 = args;
        self.env_vars = env_vars;
        self.command.0 = executable;
        self.starting_cwd = starting_cwd;
    }

    fn args(&self) -> Vec<String> {
        self.command.1.clone()
    }

    fn caller_pid(&self) -> Pid {
        let Proc(pid) = self.caller_pid;
        pid
    }

    fn command(&self) -> Command {
        self.command.clone()
    }

    fn executable(&self) -> String {
        self.command.0.clone()
    }

    fn env_vars(&self) -> Vec<String> {
        self.env_vars.clone()
    }

    fn is_empty_root_exec(&self) -> bool {
        self.command.0.is_empty()
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
            file_events: ExecFileEvents::new(HashMap::new()),
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

    fn executable(&self) -> String {
        self.successful_exec.executable()
    }

    fn generate_cached_exec(&self, cache_map: &mut CacheMap) -> CachedExecution {
        let command_key = Command(self.executable(), self.args());
        let file_events = self.file_events.clone();
        let children = self.child_execs.clone();

        let cached_meta = CachedExecMetadata::new(
            self.successful_exec.caller_pid().as_raw(),
            self.successful_exec.command(),
            self.env_vars(),
            self.starting_cwd(),
        );

        let mut new_cached_exec =
            CachedExecution::new(cached_meta, Vec::new(), HashMap::new(), HashMap::new());

        for child in children.clone() {
            let child_cached_exec = child.generate_cached_exec(cache_map);
            let child_command = Command(child.executable(), child.args());
            // TODO
            if let Some(entry) = cache_map.get(&child_command) {
                new_cached_exec.add_child(entry.clone());
            } else {
                new_cached_exec.add_child(RcCachedExec::new(child_cached_exec));
            }
        }

        if children.is_empty() {
            let preconds = generate_preconditions(file_events.clone());
            let postconds = generate_postconditions(file_events);
            // We can copy the output files over now.
            copy_output_files_to_cache(command_key.clone(), postconds.clone());
            new_cached_exec.add_preconditions(preconds);
            new_cached_exec.add_postconditions(postconds);
        }

        let new_rc_cached_exec = RcCachedExec::new(new_cached_exec.clone());
        cache_map.insert(command_key, new_rc_cached_exec);
        // let e = cache_map.entry(command_key).or_insert(Vec::new());
        // e.push(new_rc_cached_exec);
        new_cached_exec
    }

    fn populate_cache_map(&self, cache_map: &mut CacheMap) {
        let _ = self.generate_cached_exec(cache_map);
    }

    fn print_stdout(&self) {
        let command_hashed = hash_command(self.successful_exec.command());
        let stdout_filename = format!("stdout_{:?}", self.successful_exec.caller_pid().as_raw());
        let cache_dir = PathBuf::from("./cache").join(format!("{:?}", command_hashed));
        let stdout_file_path = cache_dir.join(stdout_filename);

        let mut f = File::open(stdout_file_path).unwrap();
        let mut buf = Vec::new();
        let bytes = f.read_to_end(&mut buf).unwrap();
        if bytes != 0 {
            io::stdout().write_all(&buf).unwrap();
        }

        for child in self.child_execs.iter() {
            child.print_stdout();
        }
    }

    // fn generate_event_list_and_cached_exec(
    //     &self,
    //     root_command: Command,
    //     cache_map: &mut HashMap<Command, Vec<RcCachedExec>>,
    // ) -> (CachedExecution, ExecFileEvents) {
    //     let command_key = Command(
    //         self.executable().into_os_string().into_string().unwrap(),
    //         self.args(),
    //     );
    //     let file_events = self.file_events.clone();

    //     let preconditions = generate_preconditions(file_events.clone());
    //     let index = if let Some(exec_list) = cache_map.get(&command_key) {
    //         exec_list.len()
    //     } else {
    //         0
    //     };

    //     let mut new_cached_exec = CachedExecution::new(
    //         Vec::new(),
    //         command_key.clone(),
    //         root_command.clone(),
    //         self.env_vars(),
    //         index as u32,
    //         preconditions,
    //         HashMap::new(),
    //         self.starting_cwd(),
    //     );

    //     let children = self.child_execs.clone();
    //     let file_events = self.file_events.clone();
    //     let mut new_events = if children.is_empty() {
    //         file_events
    //     } else {
    //         let mut new_events = HashMap::new();
    //         for child in children {
    //             // logic to append map
    //             let (child_exec, child_events) =
    //                 child.generate_event_list_and_cached_exec(root_command.clone(), cache_map);
    //             new_events = append_file_events(file_events.clone(), child_events);
    //             new_cached_exec.add_child(RcCachedExec::new(child_exec));
    //         }
    //         ExecFileEvents::new(new_events)
    //     };

    //     let postconditions = generate_postconditions(new_events.clone());
    //     new_cached_exec.add_postconditions(postconditions);
    //     let new_rc_cached_exec = RcCachedExec::new(new_cached_exec.clone());
    //     let e = cache_map.entry(command_key).or_insert(Vec::new());
    //     e.push(new_rc_cached_exec);
    //     (new_cached_exec, new_events)
    // }

    // pub fn populate_cache_map(&self, cache_map: &mut CacheMap) {
    //     let root_command = Command(
    //         self.executable().into_os_string().into_string().unwrap(),
    //         self.args(),
    //     );
    //     let (cached_exec, _) = self.generate_event_list_and_cached_exec(root_command, cache_map);
    //     let command_key = cached_exec.command();
    //     let index = cached_exec.index_in_exec_list();
    //     let posts = cached_exec.postconditions();
    //     copy_output_files_to_cache(command_key, index, posts);
    // }

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
    // fn update_curr_cache_map(&self, existing_cache_map: &mut CacheMap) {
    //     const CACHE_LOCATION: &str = "./cache";
    //     let cache_dir = PathBuf::from(CACHE_LOCATION);
    //     let curr_file_events = self.file_events.clone();
    //     let preconditions = generate_preconditions(curr_file_events.clone());
    //     let postconditions = generate_postconditions(curr_file_events);

    //     let command_key = Command(
    //         self.executable().into_os_string().into_string().unwrap(),
    //         self.args(),
    //     );

    //     let index = if let Some(exec_list) = existing_cache_map.get(&command_key) {
    //         exec_list.len()
    //     } else {
    //         0
    //     };
    //     let mut cached_exec = CachedExecution::new(
    //         Vec::new(),
    //         command_key.clone(),
    //         self.env_vars(),
    //         index as u32,
    //         preconditions,
    //         postconditions.clone(),
    //         self.starting_cwd(),
    //     );

    //     debug!(
    //         "number of children as we create cache map: {:?}",
    //         self.child_execs.iter().len()
    //     );
    //     for child in self.child_execs.iter() {
    //         let child_file_events = child.file_events();
    //         let preconditions = generate_preconditions(child_file_events.clone());
    //         let postconditions = generate_postconditions(child_file_events);
    //         let child_command = Command(
    //             child.executable().into_os_string().into_string().unwrap(),
    //             child.args(),
    //         );

    //         let index = if let Some(exec_list) = existing_cache_map.get(&child_command) {
    //             exec_list.len()
    //         } else {
    //             0
    //         };
    //         let cached_child = CachedExecution::new(
    //             Vec::new(),
    //             child_command,
    //             child.env_vars(),
    //             index as u32,
    //             preconditions,
    //             postconditions.clone(),
    //             child.starting_cwd(),
    //         );
    //         let child_rc = RcCachedExec::new(cached_child);
    //         cached_exec.add_child(child_rc.clone());
    //         child.update_curr_cache_map(existing_cache_map);
    //         // TODO: am I adding the child of the child to the child's structure? I feel like no.
    //     }

    //     let rc_cached_exec = RcCachedExec::new(cached_exec);
    //     // let exec_list = existing_cache_map.get_mut(&command_key).unwrap();
    //     existing_cache_map
    //         .entry(command_key.clone())
    //         .or_insert_with(|| vec![rc_cached_exec]);
    //     // exec_list.push(rc_cached_exec);

    //     // Now copy the output files to the appropriate places.
    //     let hashed_command = hash_command(command_key);
    //     let cache_subdir_hashed_command = cache_dir.join(hashed_command.to_string());

    //     let stdout_file_name = format!("stdout_{:?}", self.successful_exec.caller_pid().as_raw());
    //     let curr_stdout_file_path = cache_subdir_hashed_command.join(stdout_file_name.clone());
    //     let cache_subdir_hash_and_idx = cache_subdir_hashed_command.join(index.to_string());
    //     if !cache_subdir_hash_and_idx.exists() {
    //         fs::create_dir(cache_subdir_hash_and_idx.clone()).unwrap();
    //     }

    //     let new_stdout_file_path = cache_subdir_hash_and_idx.join(stdout_file_name);
    //     debug!("NEW STD OUT FILE PATH: {:?}", new_stdout_file_path);
    //     debug!("OLD STD OUT FILE PATH: {:?}", curr_stdout_file_path);
    //     fs::copy(curr_stdout_file_path.clone(), new_stdout_file_path).unwrap();
    //     let mut f = File::open(curr_stdout_file_path.clone()).unwrap();
    //     let mut buf = Vec::new();
    //     let bytes = f.read_to_end(&mut buf).unwrap();
    //     if bytes != 0 {
    //         io::stdout().write_all(&buf).unwrap();
    //     }
    //     fs::remove_file(curr_stdout_file_path).unwrap();

    //     for (full_path, facts) in postconditions {
    //         for fact in facts {
    //             if fact == Fact::FinalContents || fact == Fact::Exists {
    //                 let file_name = full_path.file_name().unwrap();
    //                 let cache_file_path = cache_subdir_hash_and_idx.join(file_name);
    //                 // TODO: not a real solution to the mothur problem
    //                 debug!("FULL PATH: {:?}", full_path);
    //                 debug!("CACHE PATH: {:?}", cache_file_path);
    //                 if let Some(ext) = full_path.extension() {
    //                     if ext != "temp" {
    //                         fs::copy(full_path.clone(), cache_file_path).unwrap();
    //                     }
    //                 } else {
    //                     fs::copy(full_path.clone(), cache_file_path).unwrap();
    //                 }
    //             }
    //         }
    //     }
    // }

    // fn add_to_cachable_map(&self, exec_cache_map: &mut CacheMap) {
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

    // fn file_events(&self) -> ExecFileEvents {
    //     self.file_events.clone()
    // }

    fn is_empty_root_exec(&self) -> bool {
        self.successful_exec.is_empty_root_exec()
    }

    fn pid(&self) -> Pid {
        self.successful_exec.caller_pid()
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

    // pub fn add_to_cachable_map(&self, exec_cache_map: &mut CacheMap) {
    //     self.0.borrow().add_to_cachable_map(exec_cache_map)
    // }

    pub fn args(&self) -> Vec<String> {
        self.0.borrow().args()
    }

    // pub fn env_vars(&self) -> Vec<String> {
    //     self.0.borrow().env_vars()
    // }

    pub fn executable(&self) -> String {
        self.0.borrow().executable()
    }

    // pub fn file_events(&self) -> ExecFileEvents {
    //     self.0.borrow().file_events()
    // }

    pub fn generate_cached_exec(&self, cache_map: &mut CacheMap) -> CachedExecution {
        self.0.borrow().generate_cached_exec(cache_map)
    }

    // pub fn generate_event_list_and_cached_exec(
    //     &self,
    //     root_command: Command,
    //     cache_map: &mut HashMap<Command, Vec<RcCachedExec>>,
    // ) -> (CachedExecution, ExecFileEvents) {
    //     self.0
    //         .borrow()
    //         .generate_event_list_and_cached_exec(root_command, cache_map)
    // }

    pub fn is_empty_root_exec(&self) -> bool {
        self.0.borrow().is_empty_root_exec()
    }

    pub fn pid(&self) -> Pid {
        self.0.borrow().pid()
    }

    pub fn populate_cache_map(&self, cache_map: &mut HashMap<Command, RcCachedExec>) {
        self.0.borrow().populate_cache_map(cache_map)
    }

    pub fn print_stdout(&self) {
        self.0.borrow().print_stdout()
    }

    // pub fn exit_code(&self) -> Option<i32> {
    //     self.execution.borrow().exit_code()
    // }

    pub fn starting_cwd(&self) -> PathBuf {
        self.0.borrow().starting_cwd()
    }

    pub fn update_successful_exec(&self, new_exec_metadata: ExecMetadata) {
        self.0
            .borrow_mut()
            .update_successful_exec(new_exec_metadata);
    }
}

// fn append_file_events(
//     parent_events: ExecFileEvents,
//     child_events: ExecFileEvents,
// ) -> HashMap<PathBuf, Vec<SyscallEvent>> {
//     let mut new_appended_events = parent_events.events();
//     let curr_child_map = child_events.events();

//     for (path_name, mut child_list) in curr_child_map {
//         if let Some(parent_list) = new_appended_events.get(&path_name) {
//             let mut parent_list_clone = parent_list.clone();
//             parent_list_clone.append(&mut child_list);
//             new_appended_events.insert(path_name, parent_list_clone);
//         } else {
//             new_appended_events.insert(path_name, child_list);
//         }
//     }

//     new_appended_events
// }

fn copy_output_files_to_cache(command: Command, postconditions: HashMap<PathBuf, HashSet<Fact>>) {
    // Now copy the output files to the appropriate places.
    const CACHE_LOCATION: &str = "./cache";
    let cache_dir = PathBuf::from(CACHE_LOCATION);

    let hashed_command = hash_command(command);
    let cache_subdir_hashed_command = cache_dir.join(hashed_command.to_string());
    if !cache_subdir_hashed_command.exists() {
        fs::create_dir(cache_subdir_hashed_command.clone()).unwrap();
    }

    for (path, fact_set) in postconditions {
        for fact in fact_set {
            if fact == Fact::Exists || fact == Fact::FinalContents {
                let cache_path = cache_subdir_hashed_command.join(path.file_name().unwrap());
                fs::copy(path.clone(), cache_path).unwrap();
            }
        }
    }

    // let stdout_file_name = format!("stdout_{:?}", pid);
    // let curr_stdout_file_path = cache_subdir_hashed_command.join(stdout_file_name.clone());

    // let new_stdout_file_path = cache_subdir_hash_and_idx.join(stdout_file_name);
    // debug!("NEW STD OUT FILE PATH: {:?}", new_stdout_file_path);
    // debug!("OLD STD OUT FILE PATH: {:?}", curr_stdout_file_path);
    // fs::copy(curr_stdout_file_path.clone(), new_stdout_file_path).unwrap();
    // let mut f = File::open(curr_stdout_file_path.clone()).unwrap();
    // let mut buf = Vec::new();
    // let bytes = f.read_to_end(&mut buf).unwrap();
    // if bytes != 0 {
    //     io::stdout().write_all(&buf).unwrap();
    // }
    // fs::remove_file(curr_stdout_file_path).unwrap();
}
