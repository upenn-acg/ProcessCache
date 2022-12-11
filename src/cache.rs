use crate::{
    cache_utils::{
        apply_file_transition_function, create_dirs, delete_dirs, hash_command,
        number_of_child_cache_subdirs, rename_dirs, CachedExecMetadata, ExecCommand,
    },
    condition_generator::{check_preconditions, Accessor},
    condition_utils::{Fact, Postconditions, Preconditions},
    execution_utils::get_umask,
};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
// use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, read_dir, remove_dir_all, File},
    io::{self, Read, Write},
    path::PathBuf,
    rc::Rc,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

// TODO:
// pub type CacheMap = HashMap<Command, Vec<RcCachedExec>>;
pub type CacheMap = HashMap<ExecCommand, RcCachedExec>;

// The executable path and args
// are the key to the map.
// Having them be a part of this struct would
// be redundant.
// TODO: exit code
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CachedExecution {
    cached_metadata: CachedExecMetadata,
    is_ignored: bool,
    preconditions: Option<Preconditions>,
    postconditions: Option<Postconditions>,
}

impl CachedExecution {
    pub fn new(
        cached_metadata: CachedExecMetadata,
        is_ignored: bool,
        preconditions: Option<Preconditions>,
        postconditions: Option<Postconditions>,
    ) -> CachedExecution {
        CachedExecution {
            cached_metadata,
            is_ignored,
            preconditions,
            postconditions,
        }
    }

    pub fn add_preconditions(&mut self, pres: Preconditions) {
        self.preconditions = Some(pres);
    }

    fn apply_all_dir_transitions(&self) {
        if !self.is_ignored {
            let posts = self.postconditions();
            // There are postconditions.
            if let Some(postconditions) = posts {
                let dir_postconditions = postconditions.dir_postconditions();
                // First create necessary dirs. And rename appropriately.
                create_dirs(dir_postconditions.clone());

                // TODO: I don't know if it is appropriate for me to rename the dirs next, but whatever.
                rename_dirs(dir_postconditions.clone());

                // TODO: Deleting dirs should prob happen at the end of all transitions.
                // But I want this to go zoom zoom.
                // Delete appropriate dirs.
                delete_dirs(dir_postconditions);
            }
        }
    }

    fn apply_all_transitions(&self) {
        if !self.is_ignored {
            let postconditions = self.postconditions();

            let cache_subdir = PathBuf::from("./cache/");
            let comm_hash = hash_command(self.command());
            let cache_subdir = cache_subdir.join(comm_hash.to_string());
            debug!("cache_subdir: {:?}", cache_subdir);
            let dir = read_dir(cache_subdir.clone()).unwrap();

            // Parent has all the stdouts of the whole tree below it.
            // Get vec of all files that contain "stdout" in their file name
            let mut vec_of_stdout_files = Vec::new();
            for file in dir {
                let file = file.unwrap();
                let path = file.path();
                let file_name = file.file_name();
                let file_name = file_name.into_string().unwrap();
                if file_name.contains("stdout") {
                    vec_of_stdout_files.push(path);
                }
            }

            // sort this vec
            vec_of_stdout_files.sort();
            // print in this order
            for stdout_file_path in vec_of_stdout_files {
                let mut f = File::open(stdout_file_path).unwrap();
                let mut buf = Vec::new();
                let bytes = f.read_to_end(&mut buf).unwrap();
                if bytes != 0 {
                    io::stdout().write_all(&buf).unwrap();
                }
            }

            // If an execution has no postconditions, it may just not have output files.
            // That's not a reason to panic.
            if let Some(posts) = postconditions {
                debug!("There are postconditions");
                let file_postconditions = posts.file_postconditions();
                let dir_postconditions = posts.dir_postconditions();
                debug!("Dir posts: {:?}", dir_postconditions);
                // First create necessary dirs. And rename appropriately.
                create_dirs(dir_postconditions.clone());

                // TODO: I don't know if it is appropriate for me to rename the dirs next, but whatever.
                rename_dirs(dir_postconditions.clone());

                // Put files in the right places.
                for (accessor, fact_set) in file_postconditions {
                    apply_file_transition_function(accessor, cache_subdir.clone(), fact_set);
                }

                // Delete appropriate dirs.
                delete_dirs(dir_postconditions);
            }
        } else {
            panic!("Should not be trying to apply all transitions for ignored cached execution!!")
        }
    }

    // TODO: this needs to work with the "ignored" stuff.
    fn check_all_preconditions(&self, pid: Pid) -> bool {
        if !self.is_ignored {
            // Create the exec's cache subdir path.
            // let command = self.command();
            // let hashed_command = hash_command(command);
            // let cache_dir = PathBuf::from("./cache");
            // let root_exec_cache_subdir = cache_dir.join(hashed_command.to_string());
            // if root_exec_cache_subdir.exists() {
            //     if self.cached_metadata.child_exec_count()
            //         != number_of_child_cache_subdirs(self.command())
            //     {
            //         debug!("Precondition that failed: diff number of child cache subdirs");
            //         return false;
            //     }
            // } else {
            //     // If it doesn't exist we certainly can't serve from it ;)
            //     return false;
            // }
            let my_preconds = self.preconditions.clone();
            // TODO: actaully handle checking env vars x)
            let vars = std::env::vars();
            let mut vec_vars = Vec::new();
            for (first, second) in vars {
                vec_vars.push(format!("{}={}", first, second));
            }

            let curr_cwd = std::env::current_dir().unwrap();
            if self.cached_metadata.starting_cwd() != curr_cwd {
                debug!("starting cwd doesn't match");
                debug!("old cwd: {:?}", self.cached_metadata.starting_cwd());
                debug!("new cwd: {:?}", curr_cwd);
                // panic!("cwd");
                return false;
            }

            let current_umask = get_umask(&pid);
            if self.cached_metadata.starting_umask() != current_umask {
                debug!("umask mismatch");
                debug!("cached umask: 0{:o}", self.cached_metadata.starting_umask());
                debug!("current umask: 0{:o}", current_umask);
                return false;
            }

            // Preconditions are recursively created now
            // so we only have to check the root.

            if let Some(preconds) = my_preconds {
                check_preconditions(preconds, Pid::from_raw(self.cached_metadata.caller_pid()))
            } else {
                panic!("Trying to check preconditions for non-ignored cache entry but there are none!!")
            }
        } else {
            false
        }
    }

    fn check_all_preconditions_regardless(&self) {
        if !self.is_ignored {
            debug!("CHECKING ALL PRECONDS REGARDLESS!!");
            let my_preconds = self.preconditions.clone();
            let vars = std::env::vars();
            let mut vec_vars = Vec::new();
            for (first, second) in vars {
                vec_vars.push(format!("{}={}", first, second));
            }

            let curr_cwd = std::env::current_dir().unwrap();
            if self.cached_metadata.starting_cwd() != curr_cwd {
                debug!("starting cwd doesn't match");
                debug!("old cwd: {:?}", self.cached_metadata.starting_cwd());
                debug!("new cwd: {:?}", curr_cwd);
            }

            if let Some(preconds) = my_preconds {
                if !self.is_ignored {
                    check_preconditions(preconds, Pid::from_raw(self.cached_metadata.caller_pid()));
                } else {
                    panic!("Trying to check preconditions of ignored cached execution!!")
                }
            }
        }
    }

    pub fn child_exec_count(&self) -> u32 {
        self.cached_metadata.child_exec_count()
    }

    pub fn command(&self) -> ExecCommand {
        self.cached_metadata.command()
    }

    // Get a list of stdout files to serve from the cache.
    pub fn list_stdout_files(&self) -> Vec<PathBuf> {
        let cache_subdir = PathBuf::from("./cache/");
        let comm_hash = hash_command(self.command());
        let cache_subdir = cache_subdir.join(comm_hash.to_string());
        debug!("cache_subdir: {:?}", cache_subdir);
        let dir = read_dir(cache_subdir.clone()).unwrap();

        // Parent has all the stdouts of the whole tree below it.
        // Get vec of all files that contain "stdout" in their file name
        let mut vec_of_stdout_files = Vec::new();
        for file in dir {
            let file = file.unwrap();
            let path = file.path();
            let file_name = file.file_name();
            let file_name = file_name.into_string().unwrap();
            if file_name.contains("stdout") {
                vec_of_stdout_files.push(path);
            }
        }

        // sort this vec
        vec_of_stdout_files.sort();
        vec_of_stdout_files
    }

    pub fn postconditions(&self) -> Option<Postconditions> {
        self.postconditions.clone()
    }

    // (Precondition Count, Postcondition Count)
    fn total_pre_and_post_count(&self) -> (u64, u64) {
        let mut total_preconditions = 0;
        let pres = self.preconditions.clone().unwrap();

        let file_pres = pres.file_preconditions();
        let dir_pres = pres.dir_preconditions();

        // Count file preconditions.
        for (_, fact_set) in file_pres {
            let set_size = fact_set.len();
            total_preconditions += set_size as u64;
        }

        // Count dir preconditions.
        for (_, fact_set) in dir_pres {
            let set_size = fact_set.len();
            total_preconditions += set_size as u64;
        }

        let mut total_postconditions = 0;
        let posts = self.postconditions.clone().unwrap();

        let file_posts = posts.file_postconditions();
        let dir_posts = posts.dir_postconditions();

        for (_, fact_set) in file_posts {
            let set_size = fact_set.len();
            total_postconditions += set_size as u64;
        }

        for (_, fact_set) in dir_posts {
            let set_size = fact_set.len();
            total_postconditions += set_size as u64;
        }

        (total_preconditions, total_postconditions)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RcCachedExec(Rc<CachedExecution>);

impl RcCachedExec {
    pub fn new(cached_exec: CachedExecution) -> RcCachedExec {
        RcCachedExec(Rc::new(cached_exec))
    }

    pub fn command(&self) -> ExecCommand {
        self.0.command()
    }

    pub fn apply_all_dir_transitions(&self) {
        self.0.apply_all_dir_transitions()
    }

    pub fn apply_all_transitions(&self) {
        self.0.apply_all_transitions()
    }

    // pub fn caller_pid(&self) -> SessionId {
    //     self.0.caller_pid()
    // }

    pub fn check_all_preconditions(&self, pid: Pid) -> bool {
        self.0.check_all_preconditions(pid)
    }

    pub fn check_all_preconditions_regardless(&self) {
        self.0.check_all_preconditions_regardless()
    }

    pub fn child_exec_count(&self) -> u32 {
        self.0.child_exec_count()
    }

    pub fn list_stdout_files(&self) -> Vec<PathBuf> {
        self.0.list_stdout_files()
    }

    pub fn postconditions(&self) -> Option<Postconditions> {
        self.0.postconditions()
    }

    pub fn total_pre_and_post_count(&self) -> (u64, u64) {
        self.0.total_pre_and_post_count()
    }
}

// TODO: insert into an EXISTING cache
pub fn serialize_execs_to_cache(exec_map: CacheMap) {
    let serialized_exec_map = rmp_serde::to_vec(&exec_map).unwrap();
    const CACHE_LOCATION: &str = "./cache/cache";

    // This will replace the contents
    fs::write(CACHE_LOCATION, serialized_exec_map).unwrap();
}

pub fn retrieve_existing_cache() -> Option<CacheMap> {
    const CACHE_LOCATION: &str = "./cache/cache";
    let cache_path = PathBuf::from(CACHE_LOCATION);
    if cache_path.exists() {
        let exec_struct_bytes =
            fs::read("./cache/cache").expect("failed to deserialize execs from cache");
        Some(rmp_serde::from_read_ref(&exec_struct_bytes).unwrap())
    } else {
        None
    }
}

pub fn remove_entries_from_existing_cache(percent_to_remove: i32) {
    // There are 31 gcc jobs that lead to an object file.
    // exec: "/usr/bin/gcc", arg count: 11.
    let child_exec_count = 31;
    let num_to_remove_from_cache = match percent_to_remove {
        5 => {
            let five_percent: f64 = (child_exec_count as f64) * (5.0 / 100.0);
            five_percent as u64
        }
        50 => child_exec_count / 2,
        90 => {
            let ninety_percent: f64 = (child_exec_count as f64) * (90.0 / 100.0);
            ninety_percent as u64
        }
        e => panic!("Unrecognized skip option: {:?}", e),
    };

    if let Some(mut existing_cache) = retrieve_existing_cache() {
        let mut curr_count = 0;
        let mut list_to_remove: Vec<ExecCommand> = Vec::new();
        let mut vec_of_dirs_to_remove: Vec<u64> = Vec::new();

        // Get a list of gcc job keys to remove from the cache.
        for key in existing_cache.clone().keys() {
            if curr_count < num_to_remove_from_cache {
                let exec = key.exec();
                let arg_count = key.clone().args().len();
                if exec == "/usr/bin/gcc" && arg_count == 11 {
                    list_to_remove.push(key.clone());
                    curr_count += 1;
                }
            } else {
                break;
            }
        }

        // Remove from the cache, also remove appropriate child exec
        // from the cache. Add both hashes to a list of dirs to remove
        // from /cache.
        for exec_command in list_to_remove {
            // Generate the hash and add to the vec of dirs to remove from /cache.
            let hashed_existing_gcc_entry = hash_command(exec_command.clone());
            vec_of_dirs_to_remove.push(hashed_existing_gcc_entry);
            let existing_gcc_entry = existing_cache.remove(&exec_command);

            if let Some(gcc_entry) = existing_gcc_entry {
                // TODO: If this doesn't work right, we may need to remove all the child execs?
                let postconditions = gcc_entry.postconditions();
                if let Some(posts) = postconditions {
                    let file_posts = posts.file_postconditions();
                    for (accessor, fact_set) in file_posts {
                        let child_hashed_command = accessor.hashed_command();
                        if let Some(ch_command) = child_hashed_command {
                            if fact_set.contains(&Fact::FinalContents) {
                                // The key in the cache map that matches this hash is what we want to remove.
                                for key in existing_cache.clone().keys() {
                                    let hashed_command = hash_command(key.clone());
                                    if hashed_command.to_string() == ch_command {
                                        // Remove the appropriate child exec from the cache.
                                        existing_cache.remove(key);
                                        // Add this hash to the vec of dirs to remove from  /cache.
                                        vec_of_dirs_to_remove.push(hashed_command);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    panic!("The gcc entry doesn't have postconditions??");
                }
            } else {
                panic!("Could not find gcc execution in existing cache!!");
            }
        }

        // Actually remove the /cache subdirs.
        for hash in vec_of_dirs_to_remove {
            let cache_path =
                PathBuf::from("/home/kship/kship/bioinformatics-workflows/bwa/bin/cache");
            let dir_path = cache_path.join(hash.to_string());
            if let Err(e) = remove_dir_all(dir_path.clone()) {
                panic!("Failed to remove dir: {:?} because {:?}", dir_path, e);
            }
        }

        // Serialize the cache map back to disk.
        serialize_execs_to_cache(existing_cache);
    } else {
        panic!("Cannot remove entries from nonexistent cache!!");
    }
}
