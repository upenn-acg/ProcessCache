use crate::{
    cache::{CacheMap, CachedExecution, RcCachedExec},
    cache_utils::{hash_command, CachedExecMetadata, Command},
    condition_generator::{generate_preconditions, Accessor, ExecFileEvents},
    condition_utils::{Fact, Postconditions},
    syscalls::SyscallEvent,
};
use nix::unistd::Pid;
use std::{
    cell::RefCell,
    collections::HashMap,
    fs::{self, File},
    hash::Hash,
    io::{self, Read, Write},
    path::PathBuf,
    rc::Rc,
};

pub type ChildExecutions = Vec<RcExecution>;

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum LinkType {
    Copy,
    Hardlink,
}

// Info about the execution that we want to keep around
// even if the execution fails (so we know it should fail
// if we see it again, it would be some kinda error if
// we expect it to fail and it succeeds).
#[derive(Clone, Debug, PartialEq)]
pub struct ExecMetadata {
    caller_pid: Proc,
    command: Command,
    cwd: PathBuf,
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
            cwd: PathBuf::new(),
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
        // These are the same to start.
        self.cwd = starting_cwd.clone();
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

    fn cwd(&self) -> PathBuf {
        self.cwd.clone()
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

    fn update_cwd(&mut self, new_cwd: PathBuf) {
        self.cwd = new_cwd;
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Execution {
    child_execs: ChildExecutions,
    exit_code: Option<i32>,
    file_events: ExecFileEvents,
    is_ignored: bool,
    is_root: bool,
    postconditions: Option<Postconditions>,
    // stdout_duped_fd: Option<i32>,
    stdout_fd_map: HashMap<Pid, i32>,
    successful_exec: ExecMetadata,
}

impl Execution {
    pub fn new(calling_pid: Proc) -> Execution {
        Execution {
            child_execs: Vec::new(),
            exit_code: None,
            file_events: ExecFileEvents::new(HashMap::new()),
            is_ignored: false,
            is_root: false,
            postconditions: None,
            stdout_fd_map: HashMap::new(),
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

    fn command(&self) -> Command {
        self.successful_exec.command()
    }

    fn cwd(&self) -> PathBuf {
        self.successful_exec.cwd()
    }

    fn env_vars(&self) -> Vec<String> {
        self.successful_exec.env_vars()
    }

    fn executable(&self) -> String {
        self.successful_exec.executable()
    }

    fn generate_cached_exec(&self, cache_map: &mut HashMap<Command, RcCachedExec>) {
        let command_key = Command(self.executable(), self.args());

        // let preconditions = generate_preconditions(file_events);
        let cached_metadata = CachedExecMetadata::new(
            self.pid().as_raw(),
            command_key.clone(),
            self.env_vars(),
            self.starting_cwd(),
        );
        let mut new_cached_exec = CachedExecution::new(
            cached_metadata,
            self.is_ignored,
            None,
            self.postconditions(),
        );

        let children = self.child_execs.clone();
        let file_events = self.file_events.clone();

        for child in children {
            child.generate_cached_exec(cache_map);
            // new_cached_exec.add_child(RcCachedExec::new(child_exec));
        }

        if !self.is_ignored {
            let preconditions = generate_preconditions(file_events);
            new_cached_exec.add_preconditions(preconditions);
        }

        let new_rc_cached_exec = RcCachedExec::new(new_cached_exec.clone());
        cache_map.insert(command_key, new_rc_cached_exec);
    }

    fn get_stdout_duped_fd(&self, pid: Pid) -> Option<i32> {
        match self.stdout_fd_map.get(&pid) {
            Some(fd) => Some(*fd),
            _ => None,
        }
    }

    fn file_events(&self) -> ExecFileEvents {
        self.file_events.clone()
    }

    fn is_empty_root_exec(&self) -> bool {
        self.successful_exec.is_empty_root_exec() && self.is_root
    }

    fn is_ignored(&self) -> bool {
        self.is_ignored
    }

    fn is_root(&self) -> bool {
        self.is_root
    }

    fn pid(&self) -> Pid {
        self.successful_exec.caller_pid()
    }

    pub fn populate_cache_map(&self, cache_map: &mut CacheMap) {
        let _ = self.generate_cached_exec(cache_map);
    }

    fn postconditions(&self) -> Option<Postconditions> {
        self.postconditions.clone()
    }

    pub fn starting_cwd(&self) -> PathBuf {
        self.successful_exec.starting_cwd()
    }

    fn set_to_ignored(&mut self, exec_metadata: ExecMetadata) {
        self.is_ignored = true;
        self.exit_code = None;
        self.postconditions = None;
        self.successful_exec = exec_metadata;
    }

    fn remove_stdout_duped_fd(&mut self, pid: Pid) {
        if self.stdout_fd_map.remove(&pid).is_none() {
            panic!(
                "Tried to remove stdout fd from map but it doesn't exist, pid: {:?}",
                pid
            );
        }
    }

    fn set_to_root(&mut self) {
        self.is_root = true;
    }

    fn update_cwd(&mut self, new_cwd: PathBuf) {
        self.successful_exec.update_cwd(new_cwd.clone());
        let children = self.child_execs.clone();
        for child in children {
            child.update_cwd(new_cwd.clone());
        }
    }

    fn update_file_events(&mut self, file_events: ExecFileEvents) {
        self.file_events = file_events;
    }

    fn update_postconditions(&mut self, postconditions: Postconditions) {
        self.postconditions = Some(postconditions);
    }

    fn add_stdout_duped_fd(&mut self, duped_fd: i32, pid: Pid) {
        if !self.stdout_fd_map.contains_key(&pid) {
            self.stdout_fd_map.insert(pid, duped_fd);
        } else {
            panic!(
                "Trying to add stdout duped fd but this has already been done for this pid (in this exec struct)!!"
            );
        }
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

    pub fn add_stdout_duped_fd(&self, duped_fd: i32, pid: Pid) {
        self.0.borrow_mut().add_stdout_duped_fd(duped_fd, pid);
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

    pub fn command(&self) -> Command {
        self.0.borrow().command()
    }

    pub fn cwd(&self) -> PathBuf {
        self.0.borrow().cwd()
    }

    pub fn executable(&self) -> String {
        self.0.borrow().executable()
    }

    pub fn file_events(&self) -> ExecFileEvents {
        self.0.borrow().file_events()
    }

    // pub fn generate_cached_exec(&self, cache_map: &mut CacheMap) -> CachedExecution {
    //     self.0.borrow().generate_cached_exec(cache_map)
    // }

    pub fn generate_cached_exec(&self, cache_map: &mut HashMap<Command, RcCachedExec>) {
        self.0.borrow().generate_cached_exec(cache_map)
    }

    pub fn get_stdout_duped_fd(&self, pid: Pid) -> Option<i32> {
        self.0.borrow().get_stdout_duped_fd(pid)
    }
    // Tells us that the Execution struct has not been filled
    // in (this is the root proc and it has not execve'd yet).
    pub fn is_empty_root_exec(&self) -> bool {
        self.0.borrow().is_empty_root_exec()
    }

    pub fn is_ignored(&self) -> bool {
        self.0.borrow().is_ignored()
    }

    // Just tells us whether this is the root process.
    pub fn is_root(&self) -> bool {
        self.0.borrow().is_root()
    }

    pub fn pid(&self) -> Pid {
        self.0.borrow().pid()
    }

    pub fn populate_cache_map(&self, cache_map: &mut HashMap<Command, RcCachedExec>) {
        self.0.borrow().populate_cache_map(cache_map)
    }

    pub fn remove_stdout_duped_fd(&self, pid: Pid) {
        self.0.borrow_mut().remove_stdout_duped_fd(pid)
    }

    pub fn set_to_ignored(&self, new_exec_metadata: ExecMetadata) {
        self.0.borrow_mut().set_to_ignored(new_exec_metadata)
    }

    pub fn set_to_root(&self) {
        self.0.borrow_mut().set_to_root()
    }

    pub fn starting_cwd(&self) -> PathBuf {
        self.0.borrow().starting_cwd()
    }

    pub fn update_cwd(&self, new_cwd: PathBuf) {
        self.0.borrow_mut().update_cwd(new_cwd);
    }

    pub fn update_file_events(&mut self, file_events: ExecFileEvents) {
        self.0.borrow_mut().update_file_events(file_events)
    }

    pub fn update_postconditions(&self, postconditions: Postconditions) {
        self.0.borrow_mut().update_postconditions(postconditions)
    }

    pub fn update_successful_exec(&self, new_exec_metadata: ExecMetadata) {
        self.0
            .borrow_mut()
            .update_successful_exec(new_exec_metadata);
    }
}

pub fn append_file_events(
    parent_events: &mut HashMap<Accessor, Vec<SyscallEvent>>,
    child_command: Command,
    child_events: ExecFileEvents,
    child_pid: Pid,
) {
    let child_events = child_events.events();
    let hashed_child_command = hash_command(child_command);

    // For each child resource and its event list...
    for (child_accessor, child_file_event_list) in child_events {
        // Check parent_events.get(&Accessor::CurrProc(path)) -> we need to check if the
        // PARENT touched this resource...
        let path = child_accessor.path().to_owned();
        if let Some(parents_event_list) = parent_events.get(&Accessor::CurrProc(path.to_path_buf()))
        {
            // If the parent HAS touched this resource, we need to
            // - get the parent's event list
            // - remove the ChildExec event from the parent's list
            // - replace it with the child's list of events
            if let Some(child_exec_index) = parents_event_list
                .iter()
                .position(|x| x == &SyscallEvent::ChildExec(child_pid))
            {
                let mut childs_events = child_file_event_list.clone();
                let before_events = &parents_event_list[..child_exec_index];
                let after_events = &parents_event_list[(child_exec_index + 1)..];
                let mut new_events = before_events.to_vec();
                new_events.append(&mut childs_events);
                new_events.append(&mut after_events.to_vec());
                // After we have correctly incorporated the child's events into
                // the parent's event list, we need to update the parent's events
                // to contain the new events with the parent as the Accessor.
                parent_events.insert(Accessor::CurrProc(path.to_path_buf()), new_events);
            }
        } else {
            // If the parent has never touched this file we must copy the child's
            // events to the parent's map (with the CHILD as the Accessor).
            // child_accessor is this for the child: CurrProc(Path)
            // For the parent it needs to be: ChildProc(HashedCommand, Path).
            let accessor = match child_accessor {
                Accessor::ChildProc(hash_of_grandchild, path) => {
                    Accessor::ChildProc(hash_of_grandchild, path)
                }
                // The child done it.
                Accessor::CurrProc(path) => {
                    Accessor::ChildProc(hashed_child_command.to_string(), path.to_owned())
                }
            };
            parent_events.insert(accessor, child_file_event_list);
        }
    }
}

pub fn copy_output_files_to_cache(
    curr_execution: &RcExecution,
    // command: Command,
    // pid: Pid,
    postconditions: Postconditions,
    // starting_cwd: PathBuf,
) {
    // Now copy the output files to the appropriate places.
    const CACHE_LOCATION: &str = "./cache";
    let cache_dir = PathBuf::from(CACHE_LOCATION);

    let command = Command(curr_execution.executable(), curr_execution.args());
    let hashed_command = hash_command(command);
    let cache_subdir_hashed_command = cache_dir.join(hashed_command.to_string());
    if !cache_subdir_hashed_command.exists() {
        fs::create_dir(cache_subdir_hashed_command.clone()).unwrap();
    }

    for (accessor, fact_set) in postconditions {
        let option_hashed_command = accessor.hashed_command();
        let path = accessor.path();

        // For regular files the parent accessed: copy the file from its OG path to the parent's
        // cache subdir.
        // For child's files: copy from cache/childs_cache/file -->  cache/parents_cache/childs_cache/file
        let (source_path, destination_path, is_child) =
            if let Some(hashed_cmd) = option_hashed_command {
                let childs_subdir_in_parents_cache =
                    cache_subdir_hashed_command.join(hashed_cmd.clone());
                if !childs_subdir_in_parents_cache.exists() {
                    fs::create_dir(childs_subdir_in_parents_cache.clone()).unwrap();
                }
                let childs_cache_path = cache_dir.join(hashed_cmd);
                let childs_cache_path = childs_cache_path.join(path.file_name().unwrap());
                (
                    childs_cache_path,
                    childs_subdir_in_parents_cache.join(path.file_name().unwrap()),
                    true,
                )
            } else {
                (
                    path.clone(),
                    cache_subdir_hashed_command.join(path.file_name().unwrap()),
                    false,
                )
            };

        for fact in fact_set {
            if (fact == Fact::Exists || fact == Fact::FinalContents) && path.clone().exists() {
                if is_child {
                    // If it's a child's file, then we need to hardlink from the
                    // child's cache to the parent's.
                    fs::hard_link(source_path.clone(), destination_path.clone()).unwrap();
                } else {
                    // Otherwise, we are doing a regular ol' copy to the
                    fs::copy(source_path.clone(), destination_path.clone()).unwrap();
                }
            }
        }
    }

    let stdout_file_name = format!("stdout_{:?}", curr_execution.pid().as_raw());
    let stdout_file_path = curr_execution.starting_cwd().join(stdout_file_name.clone());
    let cache_stdout_file_path = cache_subdir_hashed_command.join(stdout_file_name);

    // let new_stdout_file_path = cache_subdir_hash_and_idx.join(stdout_file_name);
    // println!("Copy from: {:?}", stdout_file_path.clone());
    // println!("Copy to: {:?}", cache_stdout_file_path.clone());
    if stdout_file_path.exists() {
        fs::copy(stdout_file_path.clone(), cache_stdout_file_path).unwrap();
        let mut f = File::open(stdout_file_path.clone()).unwrap();
        let mut buf = Vec::new();
        let bytes = f.read_to_end(&mut buf).unwrap();
        if bytes != 0 {
            io::stdout().write_all(&buf).unwrap();
        }
        fs::remove_file(stdout_file_path).unwrap();
    }

    let children = curr_execution.children();
    for child in children {
        let child_command = Command(child.executable(), child.args());
        let hashed_command = hash_command(child_command);
        let child_subdir = cache_dir.join(hashed_command.to_string());
        if !child_subdir.exists() {
            fs::create_dir(child_subdir.clone()).unwrap();
        }
        let childs_cached_stdout_file = format!("stdout_{:?}", child.pid().as_raw());
        let childs_cached_stdout_path = child_subdir.join(childs_cached_stdout_file.clone());

        let parents_spot_for_childs_stdout =
            cache_subdir_hashed_command.join(childs_cached_stdout_file);

        // We want to hardlink instead of actually copying if it's a child's output file.
        if childs_cached_stdout_path.exists() {
            // fs::copy(childs_cached_stdout_path, parents_spot_for_childs_stdout).unwrap();
            fs::hard_link(childs_cached_stdout_path, parents_spot_for_childs_stdout).unwrap();
        }
    }
}

pub fn generate_list_of_files_to_copy_to_cache(
    curr_execution: &RcExecution,
    postconditions: Postconditions,
) -> Vec<(LinkType, PathBuf, PathBuf)> {
    let mut list_of_files: Vec<(LinkType, PathBuf, PathBuf)> = Vec::new();

    const CACHE_LOCATION: &str = "./cache";
    let cache_dir = PathBuf::from(CACHE_LOCATION);

    let command = Command(curr_execution.executable(), curr_execution.args());
    let hashed_command = hash_command(command);
    let cache_subdir_hashed_command = cache_dir.join(hashed_command.to_string());
    if !cache_subdir_hashed_command.exists() {
        fs::create_dir(cache_subdir_hashed_command.clone()).unwrap();
    }

    // All the current proc's output files.
    for (accessor, fact_set) in postconditions {
        let option_hashed_command = accessor.hashed_command();
        let path = accessor.path();

        // Don't have to do any of this if the fact set is empty.
        if !fact_set.is_empty() {
            let file_name = path.file_name().unwrap();

            let (source_path, dest_path, link_type) =
                if let Some(hashed_child_command) = option_hashed_command {
                    let childs_subdir_in_parents_cache =
                        cache_subdir_hashed_command.join(hashed_child_command.clone());
                    if !childs_subdir_in_parents_cache.exists() {
                        fs::create_dir(childs_subdir_in_parents_cache.clone()).unwrap();
                    }
                    let parents_location_for_child = childs_subdir_in_parents_cache.join(file_name);
                    let childs_cache_subdir = cache_dir.join(hashed_child_command);
                    let childs_cache_location = childs_cache_subdir.join(file_name);
                    (
                        childs_cache_location,
                        parents_location_for_child,
                        LinkType::Hardlink,
                    )
                } else {
                    let cache_location = cache_subdir_hashed_command.join(file_name);
                    (path.clone(), cache_location, LinkType::Copy)
                };

            for fact in fact_set {
                // We don't want to copy if it's a directory...
                if (fact == Fact::Exists || fact == Fact::FinalContents) && path.exists() {
                    if path.is_dir() {
                        // We want to create the dir in the cache if it's a dir.
                        fs::create_dir(dest_path.clone()).unwrap();
                    } else {
                        list_of_files.push((
                            link_type.clone(),
                            source_path.clone(),
                            dest_path.clone(),
                        ));
                    }
                }
            }
        }
    }

    // The current proc's stdout file.
    let stdout_file_name = format!("stdout_{:?}", curr_execution.pid().as_raw());
    let stdout_file_path = curr_execution.starting_cwd().join(stdout_file_name.clone());
    let cache_stdout_file_path = cache_subdir_hashed_command.join(stdout_file_name);

    if stdout_file_path.exists() {
        // fs::copy(stdout_file_path.clone(), cache_stdout_file_path).unwrap();
        list_of_files.push((
            LinkType::Copy,
            stdout_file_path.clone(),
            cache_stdout_file_path,
        ));
        let mut f = File::open(stdout_file_path).unwrap();
        let mut buf = Vec::new();
        // Write the bytes to stdout.
        let bytes = f.read_to_end(&mut buf).unwrap();
        if bytes != 0 {
            io::stdout().write_all(&buf).unwrap();
        }
        // We don't want to remove the file before the thread even has the chance to copy it to the cache...
        // fs::remove_file(stdout_file_path).unwrap();
    }

    // Children's stdout files.
    let children = curr_execution.children();
    for child in children {
        let child_command = Command(child.executable(), child.args());
        let hashed_child_command = hash_command(child_command);
        let child_subdir = cache_dir.join(hashed_child_command.to_string());

        if !child_subdir.exists() {
            fs::create_dir(child_subdir.clone()).unwrap();
        }
        let childs_cached_stdout_file = format!("stdout_{:?}", child.pid().as_raw());
        let childs_cached_stdout_path = child_subdir.join(childs_cached_stdout_file.clone());

        let parents_spot_for_childs_stdout =
            cache_subdir_hashed_command.join(childs_cached_stdout_file);
        if childs_cached_stdout_path.exists() {
            // fs::copy(childs_cached_stdout_path, parents_spot_for_childs_stdout).unwrap();
            list_of_files.push((
                LinkType::Hardlink,
                childs_cached_stdout_path,
                parents_spot_for_childs_stdout,
            ))
        }
    }

    list_of_files
}
