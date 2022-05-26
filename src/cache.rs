use crate::{
    cache_utils::{hash_command, Command},
    condition_generator::check_preconditions,
    condition_utils::Fact,
};
use serde::{Deserialize, Serialize};
// use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
    rc::Rc,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

pub type ExecCacheMap = HashMap<Command, Vec<RcCachedExec>>;
// The executable path and args
// are the key to the map.
// Having them be a part of this struct would
// be redundant.
// TODO: exit code
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CachedExecution {
    child_execs: Vec<RcCachedExec>,
    command: Command,
    env_vars: Vec<String>,
    index_in_exec_list: u32,
    preconditions: HashMap<PathBuf, HashSet<Fact>>,
    postconditions: HashMap<PathBuf, HashSet<Fact>>,
    starting_cwd: PathBuf,
}

impl CachedExecution {
    pub fn new(
        child_execs: Vec<RcCachedExec>,
        command: Command,
        env_vars: Vec<String>,
        index_in_exec_list: u32,
        preconditions: HashMap<PathBuf, HashSet<Fact>>,
        postconditions: HashMap<PathBuf, HashSet<Fact>>,
        starting_cwd: PathBuf,
    ) -> CachedExecution {
        CachedExecution {
            child_execs,
            command,
            env_vars,
            index_in_exec_list,
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
        let cache_subdir = PathBuf::from("./cache/");
        let command = self.command();
        let index = self.index_in_exec_list();
        let comm_hash = hash_command(command);
        let cache_subdir = cache_subdir.join(comm_hash.to_string());
        let cache_subdir = cache_subdir.join(index.to_string());

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
        debug!("CHECKING ALL PRECONDS REGARDLESS!!");
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

    fn index_in_exec_list(&self) -> u32 {
        self.index_in_exec_list
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

    fn update_index(&mut self, new_index: u32) {
        self.index_in_exec_list = new_index;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RcCachedExec(Rc<CachedExecution>);

impl RcCachedExec {
    pub fn new(cached_exec: CachedExecution) -> RcCachedExec {
        RcCachedExec(Rc::new(cached_exec))
    }

    pub fn apply_all_transitions(&self) {
        self.0.apply_all_transitions()
    }

    pub fn check_all_preconditions(&self) -> bool {
        self.0.check_all_preconditions()
    }

    pub fn check_all_preconditions_regardless(&self) {
        self.0.check_all_preconditions_regardless()
    }

    pub fn index_in_exec_list(&self) -> u32 {
        self.0.index_in_exec_list()
    }

    pub fn print_me(&self) {
        self.0.print_me()
    }

    pub fn postconditions(&self) -> HashMap<PathBuf, HashSet<Fact>> {
        self.0.postconditions()
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
                debug!("cache file location: {:?}", cache_file_location);
                debug!("og file path: {:?}", file);
                fs::copy(cache_file_location, file.clone()).unwrap();
            }
            _ => (),
        }
    }
}

// TODO: insert into an EXISTING cache
pub fn serialize_execs_to_cache(exec_map: ExecCacheMap) {
    let serialized_exec_map = rmp_serde::to_vec(&exec_map).unwrap();
    const CACHE_LOCATION: &str = "./cache/cache";

    // This will replace the contents
    fs::write(CACHE_LOCATION, serialized_exec_map).unwrap();
    // copy_output_files_to_cache(exec_map);
}

pub fn retrieve_existing_cache() -> Option<ExecCacheMap> {
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
