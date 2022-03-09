use crate::condition_generator::{ExecFileEvents, SyscallEvent};
use nix::unistd::Pid;
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

#[derive(Clone, Debug, PartialEq)]
pub struct Proc(pub Pid);

impl Default for Proc {
    fn default() -> Proc {
        Proc(Pid::from_raw(0))
    }
}

pub type ChildExecutions = Vec<RcExecution>;
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

    fn caller_pid(&self) -> Pid {
        let proc = &self.caller_pid;
        let Proc(pid) = proc;
        *pid
    }

    fn child_executions(&self) -> ChildExecutions {
        self.child_execs.clone()
    }

    fn execs(&self) -> ExecCallList {
        self.exec_calls.clone()
    }

    fn exec_file_event_map(&self) -> &ExecFileEvents {
        self.exec_calls.exec_file_event_map()
    }

    fn starting_cwd(&self) -> PathBuf {
        self.starting_cwd.clone()
    }
}

// impl FileInfo {
//     fn new() -> FileInfo {
//         FileInfo {
//             events: Vec::new(),
//             final_hash: None,
//             starting_hash: None,
//         }
//     }

//     fn add_event(&mut self, file_event: SyscallEvent) {
//         self.events.push(file_event);
//     }

//     fn add_starting_hash(&mut self, hash: Vec<u8>) {
//         if self.starting_hash.is_none() {
//             self.starting_hash = Some(hash);
//         }
//     }

//     fn add_final_hash(&mut self, hash: Vec<u8>) {
//         if self.final_hash.is_none() {
//             self.final_hash = Some(hash);
//         }
//     }
// }

// At the end of a successful execution, we get the hash of each output
// file.
// pub fn add_output_file_hashes(&mut self, caller_pid: Pid) -> anyhow::Result<()> {
//     // let s = span!(Level::INFO, stringify!(add_output_file_hashes), pid=?caller_pid);
//     // let _ = s.enter();

//     // for output in self.output_files.iter_mut() {
//     //     if let FileAccess::Success(full_path, hash, _) = output {
//     //         let path = full_path.clone().into_os_string().into_string().unwrap();
//     //         s.in_scope(|| info!("gonna generate an output hash"));
//     //         let hash_value = generate_hash(caller_pid, path);
//     //         *hash = Some(hash_value);
//     //     }
//     // }
//     // Ok(())
//     unimplemented!();
// }

// fn add_starting_hash(&mut self, full_path: PathBuf, hash: Vec<u8>) {
//     if let Some(file_info) = self.filename_to_events_map.get_mut(&full_path) {
//         file_info.add_starting_hash(hash);
//     } else {
//         panic!("Should not be adding starting hash when full path entry is not present!");
//     }
// }

// fn add_final_hash(&mut self, full_path: PathBuf, hash: Vec<u8>) {
//     if let Some(file_info) = self.filename_to_events_map.get_mut(&full_path) {
//         file_info.add_final_hash(hash);
//     } else {
//         panic!("Should not be adding final hash when full path entry is not present!");
//     }
// }

// Only want to copy output files that had successful
// accesses to the cache.
// pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
// for output in self.output_files.iter() {
//     if let FileAccess::Success(full_path, _, _) = output {
//         let file_name = full_path
//             .file_name()
//             .expect("Can't get file name in copy_outputs_to_cache()!");

//         let cache_dir = PathBuf::from("./IOTracker/cache");
//         let cache_path = cache_dir.join(file_name);

//         if cache_path.exists() {
//             panic!("Trying to copy a file to the cache that is already present in the cache, at least with the same filename! : {:?}", cache_path);
//         } else {
//             fs::copy(full_path, cache_path)?;
//         }
//     }
// }
// Ok(())
//     unimplemented!();
// }

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

    fn add_identifiers(&mut self, args: Vec<String>, env_vars: Vec<String>, executable: String) {
        self.args = args;
        self.env_vars = env_vars;
        self.executable = executable;
    }
}

// pub fn add_output_file_hashes(&mut self, caller_pid: Pid) -> anyhow::Result<()> {
//     match self {
//         Execution::Successful(_, accesses, _) => accesses.add_output_file_hashes(caller_pid),
//         // Should this be some fancy kinda error? Meh?
//         Execution::Failed(_) => {
//             panic!("Should not be adding output file hashes to failed execution!")
//         }
//         Execution::PendingRoot => {
//             panic!("Should not be adding output file hashes to pending root execution!")
//         }
//     }
// }

// fn add_final_hash(&mut self, full_path: PathBuf, hash: Vec<u8>) {
//     match self {
//         Execution::Successful(_, accesses, _) => accesses.add_final_hash(full_path, hash),
//         Execution::Failed(_) => {
//             panic!("Should not be adding final hash to failed execution!")
//         }
//         Execution::PendingRoot => {
//             panic!("Should not be adding final hash to pending root execution!")
//         }
//     }
// }

// fn add_starting_hash(&mut self, full_path: PathBuf, hash: Vec<u8>) {
//     match self {
//         Execution::Successful(_, accesses, _) => accesses.add_starting_hash(full_path, hash),
//         Execution::Failed(_) => {
//             panic!("Should not be adding starting hash to failed execution!")
//         }
//         Execution::PendingRoot => {
//             panic!("Should not be adding starting hash to pending root execution!")
//         }
//     }
// }

// fn args(&self) -> Vec<String> {
//     match self {
//         Execution::Successful(_, _, metadata) | Execution::Failed(metadata) => metadata.args(),
//         _ => panic!("Should not be getting args from pending execution!"),
//     }
// }

// pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
//     match self {
//         Execution::Successful(_, accesses, _) => accesses.copy_outputs_to_cache(),
//         // Should this be some fancy kinda error? Meh?
//         _ => Ok(()),
//     }
// }

// fn env_vars(&self) -> Vec<String> {
//     match self {
//         Execution::Successful(_, _, metadata) | Execution::Failed(metadata) => {
//             metadata.env_vars()
//         }
//         _ => panic!("Should not be getting execution name from pending execution!"),
//     }
// }

// fn execution_name(&self) -> String {
//     match self {
//         Execution::Successful(_, _, metadata) | Execution::Failed(metadata) => {
//             metadata.execution_name()
//         }
//         _ => panic!("Should not be getting execution name from pending execution!"),
//     }
// }

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

    pub fn exec_file_event_map(&self) -> ExecFileEvents {
        self.execution.borrow().exec_file_event_map().clone()
    }

    pub fn no_successful_exec_yet(&self) -> bool {
        let execs = self.execution.borrow().execs();
        for exec in execs.exec_calls {
            if exec.is_successful() {
                return false;
            }
        }
        true
    }
    // pub fn add_output_file_hashes(&self, caller_pid: Pid) -> anyhow::Result<()> {
    //     self.execution
    //         .borrow_mut()
    //         .add_output_file_hashes(caller_pid)
    // }

    // pub fn add_starting_hash(&self, full_path: PathBuf, hash: Vec<u8>) {
    //     self.execution
    //         .borrow_mut()
    //         .add_starting_hash(full_path, hash)
    // }

    // pub fn add_final_hash(&self, full_path: PathBuf, hash: Vec<u8>) {
    //     self.execution.borrow_mut().add_final_hash(full_path, hash)
    // }

    // fn args(&self) -> Vec<String> {
    //     self.execution.borrow().args()
    // }

    pub fn caller_pid(&self) -> Pid {
        self.execution.borrow().caller_pid()
    }

    // pub fn child_executions(&self) -> Vec<RcExecution> {
    //     self.execution.borrow().child_executions()
    // }

    // pub fn copy_outputs_to_cache(&self) -> anyhow::Result<()> {
    //     self.execution.borrow().copy_outputs_to_cache()
    // }

    // fn env_vars(&self) -> Vec<String> {
    //     self.execution.borrow().env_vars()
    // }

    // pub fn execution_name(&self) -> String {
    //     self.execution.borrow().execution_name()
    // }

    // fn exec_file_event_map(&self) -> HashMap<PathBuf, Vec<SyscallEvent>> {
    //     self.execution.borrow().exec_file_event_map().clone()
    // }

    // Print all file event lists for the execution.
    // TODO: This doesn't print the child exec stuff.
    // Need to make a function to get the child execs as well.
    // For now, one layer deep is ok.
    pub fn print_pathbuf_to_file_event_lists(&self) {
        println!("First execution.");
        let exec_file_event_map = self.exec_file_event_map();
        let event_map = exec_file_event_map.file_event_list();
        for (full_path, event_list) in event_map {
            println!("Resource path: {:?}", full_path);
            println!("Event list: {:?}", event_list);
            println!();

            // let preconditions = generate_preconditions(&event_list);
            // println!("Preconditions: {:?}", preconditions);
            // println!();

            // let postconditions = generate_postconditions(&event_list);
            // println!("Postconditions: {:?}", postconditions);
            // println!();
        }

        println!();
        println!();

        for child in self.execution.borrow().child_executions() {
            println!("Child execution: {}", child.caller_pid());
            let child_exec_file_event_map = child.exec_file_event_map();
            let event_map = child_exec_file_event_map.file_event_list();
            for (full_path, event_list) in event_map {
                println!("Resource path: {:?}", full_path);
                println!("Event list: {:?}", event_list);

                // let preconditions = generate_preconditions(&event_list);
                // println!("Preconditions: {:?}", preconditions);
                // println!();
            }
        }
    }

    pub fn starting_cwd(&self) -> PathBuf {
        self.execution.borrow().starting_cwd()
    }
}

// When we deserialize the cache, this is what
// we will get.
// #[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
// pub struct GlobalExecutions {
//     pub executions: Vec<RcExecution>,
// }

// impl GlobalExecutions {
//     pub fn new() -> GlobalExecutions {
//         GlobalExecutions {
//             executions: Vec::new(),
//         }
//     }

//     pub fn add_new_execution(&mut self, new_execution: RcExecution) {
//         self.executions.push(new_execution);
//     }
// }

// Return the cached execution if there exists a cached success.
// Else return None.
// pub fn get_cached_root_execution(caller_pid: Pid, new_execution: Execution) -> Option<RcExecution> {
//     let s = span!(Level::INFO, stringify!(get_cached_root_execution), pid=?caller_pid);
//     let _ = s.enter();
//     let cache_path = PathBuf::from("./IOTracker/cache/cache");
//     if !cache_path.exists() {
//         s.in_scope(|| info!("No cached exec bc cache doesn't exist"));
//         None
//     } else if !new_execution.is_successful() {
//         s.in_scope(|| info!("No cached exec bc exec failed"));
//         None
//     } else {
//         let global_execs = deserialize_execs_from_cache();
//         // Have to find the root exec in the list of global execs
//         // in the cache.
//         for cached_root_exec in global_execs.executions.iter() {
//             // We check that the metadata matches
//             // That the inputs and outputs match (all the way down the tree of child execs)
//             // And that success or failure matches
//             if exec_metadata_matches(cached_root_exec, caller_pid, &new_execution)
//                 && execution_matches(cached_root_exec, caller_pid)
//             {
//                 // TODO: don't short circuit
//                 return Some(cached_root_exec.clone());
//             }
//         }
//         None
//     }
// }

// fn execution_matches(cached_root: &RcExecution, caller_pid: Pid) -> bool {
// unimplemented!();
// let s = span!(Level::INFO, stringify!(execution_matches), pid=?caller_pid);
// let _ = s.enter();
// s.in_scope(|| info!("Checking inputs and outputs of children"));

// if !inputs_match(cached_root.clone(), caller_pid)
//     || !outputs_match(caller_pid, cached_root.clone())
// {
//     false
// } else {
//     s.in_scope(|| {
//         info!(
//             "Number of cached children: {}",
//             cached_root.child_executions().len()
//         )
//     });

//     cached_root
//         .child_executions()
//         .iter()
//         .all(|child| execution_matches(child, caller_pid))
// }
// }

// It's a lot of logic to do all the metadata checking.
// Right now if an execution has child executions, all child
// executions must be skippable as well so we just skip the whole
// dang thing. This means we don't have to check the metadata of
// the child executions or their child executions.
// fn exec_metadata_matches(cached_exec: &RcExecution, caller_pid: Pid, new_exec: &Execution) -> bool {
//     let s = span!(Level::INFO, stringify!(exec_metadata_matches), pid=?caller_pid);
//     let _ = s.enter();
//     s.in_scope(|| info!("Checking inputs and outputs of children"));
//     let new_executable = new_exec.execution_name();
//     let new_starting_cwd = new_exec.starting_cwd();
//     let new_args = new_exec.args();
//     let new_env_vars = new_exec.env_vars();
//     // Check if any execution struct existing in the cache matches this
//     // We should skip it if:
//     // - it WAS in the cache before (loop)
//     // - it was successful
//     // - execution name matches
//     // - arguments match
//     // - starting cwd matches
//     // - env vars match
//     // If it is failed exec but we have it cached, we also want to return that.
//     let executable_matches = cached_exec.execution_name() == new_executable;
//     s.in_scope(|| info!("Executable names match: {}", executable_matches));
//     let success_failure_match = cached_exec.is_successful() == new_exec.is_successful();
//     s.in_scope(|| info!("Success/Failure match: {}", success_failure_match));
//     let args_match = new_args == cached_exec.args();
//     s.in_scope(|| info!("Args match: {}", args_match));
//     let cwd_matches = new_starting_cwd == cached_exec.starting_cwd();
//     s.in_scope(|| info!("Cwd matches: {}", cwd_matches));
//     let env_vars_match = new_env_vars == cached_exec.env_vars();
//     s.in_scope(|| info!("Env vars match: {}", env_vars_match));

//     executable_matches && success_failure_match && args_match && cwd_matches && env_vars_match
// }

// TODO: Is this function relevant anymore?
// The inputs in the cached execution match the
// new execution's inputs, the hashes match,
// and they are in the correct absolute path locations.
// fn inputs_match(cached_exec: RcExecution, caller_pid: Pid) -> bool {
// unimplemented!();
// let s = span!(Level::INFO, stringify!(inputs_match), pid=?caller_pid);
// let _ = s.enter();
// s.in_scope(|| info!("Checking inputs and outputs of children"));
// let cached_inputs = cached_exec.inputs();
// // First, they must share the same inputs.
// // So get the keys of each and check that they are equal?
// for input in cached_inputs.into_iter() {
//     if let FileAccess::Success(full_path, Some(old_hash), _) = input {
//         // Only check these things if it's a true file.
//         // If the hash is None, we can just move on.
//         if !full_path.exists() {
//             s.in_scope(|| {
//                 info!(
//                     "Inputs don't match because path doesn't exist: {:?}",
//                     full_path
//                 )
//             });
//             return false;
//         } else {
//             // Hash the file that is there right now.
//             let full_path = full_path.clone().into_os_string().into_string().unwrap();
//             let new_hash = generate_hash(caller_pid, full_path.clone());

//             // Compare the new hash to the old hash.
//             if !new_hash.iter().eq(old_hash.iter()) {
//                 s.in_scope(|| {
//                     info!(
//                         "Inputs don't match new hash and old hash don't match: {:?}",
//                         full_path
//                     )
//                 });
//                 return false;
//             }
//         }
//     }
// }
// true
// }

// TODO: Does this function even make sense anymore?
// Check that output files are either:
// - Exist, in the right place, and the hash matches the hash we have in the cache.
// - OR, the file doesn't exist, which is great, because we have it in our cache
// and we can just copy it over.
// fn outputs_match(caller_pid: Pid, curr_execution: RcExecution) -> bool {
// unimplemented!();
// let s = span!(Level::INFO, stringify!(outputs_match), pid=?caller_pid);
// let _ = s.enter();
// s.in_scope(|| info!("Checking inputs and outputs of children"));
// let cached_outputs = curr_execution.outputs();

// for output in cached_outputs.into_iter() {
//     if let FileAccess::Success(full_path, hash, _) = output {
//         // If the output file does indeed exist and is in the correct spot
//         // already, check if the hash matches the old one.
//         // Then we won't have to copy this file over from the cache.
//         if full_path.exists() {
//             if let Some(old_hash) = hash {
//                 let full_path = full_path.clone().into_os_string().into_string().unwrap();
//                 let new_hash = generate_hash(caller_pid, full_path.clone());

//                 // Compare the new hash to the old hash.
//                 if !new_hash.iter().eq(old_hash.iter()) {
//                     s.in_scope(|| {
//                         info!(
//                             "Output hashes don't match. Old :{:?}, New :{:?}",
//                             new_hash, old_hash
//                         )
//                     });
//                     return false;
//                 }
//             }
//         }
//         // If it doesn't exist, fantastic
//         // MOVE ON it doesn't exist.
//         // "I'm sorry for your loss. Move on."
//     }
// }
// true
// }

// TODO: make this work with the other stuff
// Take in the root execution.
// Copy its outputs to the appropriate places.
// pub fn serve_outputs_from_cache(
//     caller_pid: Pid,
//     root_execution: &RcExecution,
// ) -> anyhow::Result<()> {
//     unimplemented!();
// let s = span!(Level::INFO, stringify!(serve_outputs_from_cache), pid=?caller_pid);
// let _ = s.enter();
// s.in_scope(|| info!("Serving outputs from cache."));

// for output in root_execution.outputs() {
//     if let FileAccess::Success(full_path, _, _) = output {
//         s.in_scope(|| {
//             info!(
//                 "Cached successful output file access going to serve: {:?}",
//                 full_path
//             )
//         });
//         let file_name = full_path.file_name().unwrap();

//         let cache_dir = PathBuf::from("./research/IOTracker/cache");
//         let cached_output_path = cache_dir.join(file_name);

//         if !full_path.exists() {
//             fs::copy(cached_output_path, full_path)?;
//         } else {
//             s.in_scope(|| {
//                 info!(
//                     "Not copying from cache, file is already there: {:?}",
//                     full_path
//                 )
//             });
//         }
//     }
// }

// root_execution
//     .child_executions()
//     .iter()
//     .all(|child| serve_outputs_from_cache(caller_pid, child).is_ok());
// Ok(())
// }

// ------ Hashing stuff ------
// Process the file and generate the hash.
// fn process<D: Digest + Default, R: Read>(reader: &mut R) -> Vec<u8> {
//     const BUFFER_SIZE: usize = 1024;
//     let mut sh = D::default();
//     let mut buffer = [0u8; BUFFER_SIZE];
//     loop {
//         let n = reader
//             .read(&mut buffer)
//             .expect("Could not read buffer from reader processing hash!");
//         sh.update(&buffer[..n]);
//         if n == 0 || n < BUFFER_SIZE {
//             break;
//         }
//     }

//     let final_array = &sh.finalize();
//     final_array.to_vec()
// }

// Wrapper for generating the hash.
// Opens the file and calls process() to get the hash.
// pub fn generate_hash(caller_pid: Pid, path: String) -> Vec<u8> {
//     let s = span!(Level::INFO, stringify!(generate_hash), pid=?caller_pid);
//     let _ = s.enter();
//     s.in_scope(|| info!("Made it to generate_hash for path: {}", path));
//     let mut file = fs::File::open(&path).expect("Could not open file to generate hash");
//     process::<Sha256, _>(&mut file)
// }

// Serialize the execs and write them to the cache.
// pub fn serialize_execs_to_cache(root_execution: RcExecution) -> anyhow::Result<()> {
//     const CACHE_LOCATION: &str = "./IOTracker/cache/cache";

//     let cache_path = PathBuf::from(CACHE_LOCATION);
//     let cache_copy_path = PathBuf::from(CACHE_LOCATION.to_owned() + "_copy");

//     if Path::new(CACHE_LOCATION).exists() {
//         // If the cache file exists:
//         // - make a copy of cache/cache at cache/cache_copy (just in case)
//         fs::copy(&cache_path, &cache_copy_path)?;
//         // - deserialize existing structure from cache/cache
//         let mut existing_global_execs = deserialize_execs_from_cache();
//         // - add the new root_execution to the vector
//         existing_global_execs.add_new_execution(root_execution);
//         // - serialize again
//         let serialized_execs = rmp_serde::to_vec(&existing_global_execs).unwrap();
//         // - remove old cache/cache file
//         fs::remove_file(&cache_path)?;
//         // - make a new cache/cache file and write the updated serialized execs to it
//         fs::write(cache_path, serialized_execs)?;
//         // - delete cache/cache_copy
//         fs::remove_file(cache_copy_path)?;
//     } else {
//         // If the cache file doesn't exist:
//         // - make a new GlobalExecutions
//         let mut global_execs = GlobalExecutions::new();
//         // - put root_execution in it
//         global_execs.add_new_execution(root_execution);
//         // - serialize GlobalExecutions
//         let serialized_execs = rmp_serde::to_vec(&global_execs).unwrap();
//         // - and write the serialized_execs to the cache/cache file we are making
//         //   right here because that's what the write() function here does, creates
//         //   if it doesn't exist, and then writes.
//         fs::write(CACHE_LOCATION, serialized_execs)
//             .with_context(|| context!("Cannot write to cache location: \"{}\".", CACHE_LOCATION))?;
//     }
//     Ok(())
//     // let serialized_execs = rmp_serde::to_vec(&root_exection).unwrap();
// }

// pub fn deserialize_execs_from_cache() -> GlobalExecutions {
//     let exec_struct_bytes = fs::read("./research/IOTracker/cache/cache").expect("failed");
//     if exec_struct_bytes.is_empty() {
//         GlobalExecutions::new()
//     } else {
//         rmp_serde::from_read_ref(&exec_struct_bytes).unwrap()
//     }
// }
