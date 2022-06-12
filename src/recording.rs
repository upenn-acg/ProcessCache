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
    fs,
    hash::Hash,
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
        self.child_execs.push(child_execution.clone());
        self.file_events.add_new_fork_exec(child_execution.pid());
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

    fn children(&self) -> Vec<RcExecution> {
        self.child_execs.clone()
    }

    fn env_vars(&self) -> Vec<String> {
        self.successful_exec.env_vars()
    }

    fn executable(&self) -> String {
        self.successful_exec.executable()
    }

    // fn generate_cached_exec(&self, cache_map: &mut CacheMap) -> CachedExecution {
    //     let command_key = Command(self.executable(), self.args());
    //     let pid = self.successful_exec.caller_pid();
    //     let file_events = self.file_events.clone();
    //     let children = self.child_execs.clone();

    //     let cached_meta = CachedExecMetadata::new(
    //         self.successful_exec.caller_pid().as_raw(),
    //         self.successful_exec.command(),
    //         self.env_vars(),
    //         self.starting_cwd(),
    //     );

    //     let mut new_cached_exec =
    //         CachedExecution::new(cached_meta, Vec::new(), HashMap::new(), HashMap::new());

    //     for child in children.clone() {
    //         let child_cached_exec = child.generate_cached_exec(cache_map);
    //         let child_command = Command(child.executable(), child.args());
    //         // TODO
    //         if let Some(entry) = cache_map.get(&child_command) {
    //             new_cached_exec.add_child(entry.clone());
    //         } else {
    //             new_cached_exec.add_child(RcCachedExec::new(child_cached_exec));
    //         }
    //     }

    //     if children.is_empty() {
    //         let preconds = generate_preconditions(file_events.clone());
    //         let postconds = generate_postconditions(file_events);
    //         let starting_cwd = self.starting_cwd();
    //         // We can copy the output files over now.
    //         copy_output_files_to_cache(command_key.clone(), pid, postconds.clone(), starting_cwd);
    //         new_cached_exec.add_preconditions(preconds);
    //         new_cached_exec.add_postconditions(postconds);
    //     }

    //     let new_rc_cached_exec = RcCachedExec::new(new_cached_exec.clone());
    //     cache_map.insert(command_key, new_rc_cached_exec);
    //     // let e = cache_map.entry(command_key).or_insert(Vec::new());
    //     // e.push(new_rc_cached_exec);
    //     new_cached_exec
    // }

    // fn populate_cache_map(&self, cache_map: &mut CacheMap) {
    //     let _ = self.generate_cached_exec(cache_map);
    // }

    fn generate_event_list_and_cached_exec(
        &self,
        cache_map: &mut HashMap<Command, RcCachedExec>,
    ) -> (CachedExecution, ExecFileEvents) {
        let command_key = Command(self.executable(), self.args());
        let file_events = self.file_events.clone();

        let preconditions = generate_preconditions(file_events);
        let command = Command(self.executable(), self.args());
        let cached_metadata = CachedExecMetadata::new(
            self.pid().as_raw(),
            command,
            self.env_vars(),
            self.starting_cwd(),
        );
        let mut new_cached_exec =
            CachedExecution::new(cached_metadata, Vec::new(), preconditions, HashMap::new());

        let children = self.child_execs.clone();
        let file_events = self.file_events.clone();
        let new_events = if children.is_empty() {
            println!("No new events: {:?}", file_events);
            file_events
        } else {
            let mut new_events = HashMap::new();
            for child in children {
                // logic to append map
                let (child_exec, child_events) =
                    child.generate_event_list_and_cached_exec(cache_map);
                // TODO: Here I need to go through the parent's file events, find the child's ForkExec(childpid) event,
                // and replace it with the child's file events.
                new_events = append_file_events(file_events.clone(), child_events, child.pid());
                println!("New events: {:?}", new_events);
                new_cached_exec.add_child(RcCachedExec::new(child_exec));
            }
            ExecFileEvents::new(new_events)
        };

        let postconditions = generate_postconditions(new_events.clone());
        new_cached_exec.add_postconditions(postconditions);
        let new_rc_cached_exec = RcCachedExec::new(new_cached_exec.clone());
        // let e = cache_map.entry(command_key).or_insert(Vec::new());
        // e.push(new_rc_cached_exec);
        cache_map.insert(command_key, new_rc_cached_exec);
        (new_cached_exec, new_events)
    }

    pub fn populate_cache_map(&self, cache_map: &mut CacheMap) {
        // let root_command = Command(
        //     self.executable(),
        //     self.args(),
        // );
        let (_, _) = self.generate_event_list_and_cached_exec(cache_map);
        // let command_key = cached_exec.command();
        // TODO: INDEX
        // let index = cached_exec.index_in_exec_list();
        // let posts = cached_exec.postconditions();

        // TODO:
        // copy_output_files_to_cache(command_key, index, posts);
    }

    fn file_events(&self) -> ExecFileEvents {
        self.file_events.clone()
    }

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

    pub fn children(&self) -> Vec<RcExecution> {
        self.0.borrow().children()
    }

    // pub fn env_vars(&self) -> Vec<String> {
    //     self.0.borrow().env_vars()
    // }

    pub fn executable(&self) -> String {
        self.0.borrow().executable()
    }

    pub fn file_events(&self) -> ExecFileEvents {
        self.0.borrow().file_events()
    }

    // pub fn generate_cached_exec(&self, cache_map: &mut CacheMap) -> CachedExecution {
    //     self.0.borrow().generate_cached_exec(cache_map)
    // }

    pub fn generate_event_list_and_cached_exec(
        &self,
        cache_map: &mut HashMap<Command, RcCachedExec>,
    ) -> (CachedExecution, ExecFileEvents) {
        self.0
            .borrow()
            .generate_event_list_and_cached_exec(cache_map)
    }

    pub fn is_empty_root_exec(&self) -> bool {
        self.0.borrow().is_empty_root_exec()
    }

    pub fn pid(&self) -> Pid {
        self.0.borrow().pid()
    }

    pub fn populate_cache_map(&self, cache_map: &mut HashMap<Command, RcCachedExec>) {
        self.0.borrow().populate_cache_map(cache_map)
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

fn append_file_events(
    parent_events: ExecFileEvents,
    child_events: ExecFileEvents,
    child_pid: Pid,
) -> HashMap<PathBuf, Vec<SyscallEvent>> {
    // let mut new_appended_events = parent_events.events();
    // let curr_child_map = child_events.events();
    // let mut child_event_map = child_events.events();
    // for (path_name, mut child_list) in curr_child_map {
    //     if let Some(parent_list) = new_appended_events.get(&path_name) {
    //         let mut parent_list_clone = parent_list.clone();
    //         parent_list_clone.append(&mut child_list);
    //         new_appended_events.insert(path_name, parent_list_clone);
    //     } else {
    //         new_appended_events.insert(path_name, child_list);
    //     }
    // }

    let child_event_map = child_events.events();
    let curr_parent_events = parent_events.events();
    let mut new_parent_events = curr_parent_events.clone();
    for (path_name, file_event_list) in curr_parent_events {
        let child_exec_index = file_event_list
            .iter()
            .position(|x| x == &SyscallEvent::ChildExec(child_pid))
            .unwrap();
        if let Some(childs_file_event_list) = child_event_map.get(&path_name) {
            // [e1, e2, CHILD_EXEC, e3, e4]
            // child_list = [c1, c2, c3]
            let mut childs_events = childs_file_event_list.clone();
            let before_events = &file_event_list[..child_exec_index];
            let after_events = &file_event_list[(child_exec_index + 1)..];
            let mut new_events = before_events.to_vec();
            new_events.append(&mut childs_events);
            new_events.append(&mut after_events.to_vec());
            new_parent_events.insert(path_name, new_events);
        } else {
            // If the child has not touched this file, just remove the ChildExec event.
            let mut file_events = file_event_list.clone();
            let _ = file_events.remove(child_exec_index);
            new_parent_events.insert(path_name, file_events);
        }
    }

    new_parent_events
}

fn copy_output_files_to_cache(
    command: Command,
    pid: Pid,
    postconditions: HashMap<PathBuf, HashSet<Fact>>,
    starting_cwd: PathBuf,
) {
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

    let stdout_file_name = format!("stdout_{:?}", pid.as_raw());
    let stdout_file_path = starting_cwd.join(stdout_file_name.clone());
    println!("CURR STD OUT FILE PATH: {:?}", stdout_file_path);
    let cache_stdout_file_path = cache_subdir_hashed_command.join(stdout_file_name);
    println!("CACHE FILE PATH: {:?}", cache_stdout_file_path);

    // let new_stdout_file_path = cache_subdir_hash_and_idx.join(stdout_file_name);
    // debug!("NEW STD OUT FILE PATH: {:?}", new_stdout_file_path);
    // debug!("OLD STD OUT FILE PATH: {:?}", curr_stdout_file_path);
    fs::copy(stdout_file_path.clone(), cache_stdout_file_path).unwrap();
    // let mut f = File::open(curr_stdout_file_path.clone()).unwrap();
    // let mut buf = Vec::new();
    // let bytes = f.read_to_end(&mut buf).unwrap();
    // if bytes != 0 {
    //     io::stdout().write_all(&buf).unwrap();
    // }
    fs::remove_file(stdout_file_path).unwrap();
}
