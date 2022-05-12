use crate::{
    cache_utils::{hash_command, Command},
    condition_generator::check_preconditions,
    condition_utils::Fact,
};
use serde::{Deserialize, Serialize};
// use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    path::PathBuf,
    rc::Rc,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

pub type ExecCacheMap = HashMap<Command, RcCachedExec>;
// The executable path and args
// are the key to the map.
// Having them be a part of this struct would
// be redundant.
// TODO: exit code
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CachedExecution {
    child_execs: Vec<RcCachedExec>,
    command: Command,
    env_vars: Vec<String>,
    preconditions: HashMap<PathBuf, HashSet<Fact>>,
    postconditions: HashMap<PathBuf, HashSet<Fact>>,
    starting_cwd: PathBuf,
}

impl CachedExecution {
    pub fn new(
        child_execs: Vec<RcCachedExec>,
        command: Command,
        env_vars: Vec<String>,
        preconditions: HashMap<PathBuf, HashSet<Fact>>,
        postconditions: HashMap<PathBuf, HashSet<Fact>>,
        starting_cwd: PathBuf,
    ) -> CachedExecution {
        CachedExecution {
            child_execs,
            command,
            env_vars,
            preconditions,
            postconditions,
            starting_cwd,
        }
    }

    pub fn add_child(&mut self, child: RcCachedExec) {
        self.child_execs.push(child)
    }

    fn apply_all_transitions(&self) {
        let postconditions = self.postconditions();
        let cache_dir = PathBuf::from("./IOTracker/cache/");
        let command = self.command();
        let curr_command_subdir = hash_command(command);
        let cache_subdir = cache_dir.join(curr_command_subdir.to_string());

        for (file, fact_set) in postconditions {
            apply_transition_function(cache_subdir.clone(), fact_set, file);
        }

        let children = self.child_execs.clone();
        for child in children {
            child.apply_all_transitions()
        }
    }

    fn check_all_preconditions(&self) -> bool {
        let my_preconds = self.preconditions.clone();
        let vars = std::env::vars();
        let mut vec_vars = Vec::new();
        for (first, second) in vars {
            vec_vars.push(format!("{}={}", first, second));
        }

        let curr_cwd = std::env::current_dir().unwrap();
        if self.starting_cwd != curr_cwd {
            debug!("starting cwd doesn't match");
            debug!("old cwd: {:?}", self.starting_cwd);
            debug!("new cwd: {:?}", curr_cwd);
            // panic!("cwd");
            return false;
        }
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

    fn check_all_preconditions_regardless(&self) {
        let my_preconds = self.preconditions.clone();
        // let vars = std::env::vars();
        // let mut vec_vars = Vec::new();
        // for (first, second) in vars {
        //     vec_vars.push(format!("{}={}", first, second));
        // }

        let curr_cwd = std::env::current_dir().unwrap();
        if self.starting_cwd != curr_cwd {
            debug!("starting cwd doesn't match");
            debug!("old cwd: {:?}", self.starting_cwd);
            debug!("new cwd: {:?}", curr_cwd);
        }

        check_preconditions(my_preconds);

        let children = self.child_execs.clone();
        for child in children {
            child.check_all_preconditions_regardless();
        }
    }

    fn command(&self) -> Command {
        self.command.clone()
    }

    fn postconditions(&self) -> HashMap<PathBuf, HashSet<Fact>> {
        self.postconditions.clone()
    }

    fn print_me(&self) {
        println!("NEW CACHED EXEC:");
        println!("Preconds: {:?}", self.preconditions);
        for child in self.child_execs.clone() {
            child.print_me()
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RcCachedExec {
    cached_exec: Rc<CachedExecution>,
}

impl RcCachedExec {
    pub fn new(cached_exec: CachedExecution) -> RcCachedExec {
        RcCachedExec {
            cached_exec: Rc::new(cached_exec),
        }
    }

    pub fn check_all_preconditions(&self) -> bool {
        self.cached_exec.check_all_preconditions()
    }

    pub fn check_all_preconditions_regardless(&self) {
        self.cached_exec.check_all_preconditions_regardless()
    }

    pub fn apply_all_transitions(&self) {
        self.cached_exec.apply_all_transitions()
    }

    pub fn print_me(&self) {
        self.cached_exec.print_me()
    }

    pub fn postconditions(&self) -> HashMap<PathBuf, HashSet<Fact>> {
        self.cached_exec.postconditions()
    }
}

fn apply_transition_function(cache_subdir: PathBuf, fact_set: HashSet<Fact>, file: PathBuf) {
    for fact in fact_set {
        match fact {
            Fact::DoesntExist => {
                if file.exists() {
                    fs::remove_file(file.clone()).unwrap();
                }
            }
            Fact::FinalContents => {
                let file_name = file.file_name().unwrap();
                let cache_file_location = cache_subdir.join(file_name);
                fs::copy(cache_file_location, file.clone()).unwrap();
            }
            _ => (),
        }
    }
}
// I *THINK* I can just iterate through the keys and do this for each and
fn copy_output_files_to_cache(exec_cache_map: ExecCacheMap) {
    for (command, rc_cached_exec) in exec_cache_map {
        const CACHE_LOCATION: &str = "/home/kelly/research/IOTracker/cache";
        let cache_dir = PathBuf::from(CACHE_LOCATION);
        // We will put the files at /cache/hash(command)/

        let curr_command_subdir = hash_command(command);
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
    const CACHE_LOCATION: &str = "/home/kelly/research/IOTracker/cache/cache";
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
    const CACHE_LOCATION: &str = "/home/kelly/research/IOTracker/cache/cache";
    let cache_path = PathBuf::from(CACHE_LOCATION);
    if cache_path.exists() {
        let exec_struct_bytes = fs::read("/home/kelly/research/IOTracker/cache/cache")
            .expect("failed to deserialize execs from cache");
        Some(rmp_serde::from_read_ref(&exec_struct_bytes).unwrap())
    } else {
        None
    }
}
