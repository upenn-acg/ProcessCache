use crate::{
    cache_utils::{hash_command, CachedExecMetadata, Command},
    condition_generator::{check_preconditions, Accessor},
    condition_utils::{Fact, Postconditions, Preconditions},
};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
// use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, read_dir, File},
    io::{self, Read, Write},
    path::PathBuf,
    rc::Rc,
};
#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

// TODO:
// pub type CacheMap = HashMap<Command, Vec<RcCachedExec>>;
pub type CacheMap = HashMap<Command, RcCachedExec>;

// The executable path and args
// are the key to the map.
// Having them be a part of this struct would
// be redundant.
// TODO: exit code
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CachedExecution {
    cached_metadata: CachedExecMetadata,
    child_execs: Vec<RcCachedExec>,
    preconditions: Preconditions,
    postconditions: Postconditions,
}

impl CachedExecution {
    pub fn new(
        cached_metadata: CachedExecMetadata,
        child_execs: Vec<RcCachedExec>,
        preconditions: Preconditions,
        postconditions: Postconditions,
    ) -> CachedExecution {
        CachedExecution {
            cached_metadata,
            child_execs,
            preconditions,
            postconditions,
        }
    }

    pub fn add_child(&mut self, child: RcCachedExec) {
        self.child_execs.push(child)
    }

    pub fn add_preconditions(&mut self, pres: Preconditions) {
        self.preconditions = pres;
    }

    fn apply_all_transitions(&self) {
        let postconditions = self.postconditions();

        let cache_subdir = PathBuf::from("./cache/");
        let comm_hash = hash_command(self.command());
        let cache_subdir = cache_subdir.join(comm_hash.to_string());
        debug!("cache_subdir: {:?}", cache_subdir);
        let dir = read_dir(cache_subdir.clone()).unwrap();

        // get vec of all files that contain "stdout" in their file name
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

        for (accessor, fact_set) in postconditions {
            apply_transition_function(accessor, cache_subdir.clone(), fact_set);
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
        if self.cached_metadata.starting_cwd() != curr_cwd {
            debug!("starting cwd doesn't match");
            debug!("old cwd: {:?}", self.cached_metadata.starting_cwd());
            debug!("new cwd: {:?}", curr_cwd);
            // panic!("cwd");
            return false;
        }

        // Preconditions are recursively created now
        // so we only have to check the root.
        // if !check_preconditions(
        //     my_preconds,
        //     Pid::from_raw(self.cached_metadata.caller_pid()),
        // ) {
        //     return false;
        // }

        // let children = self.child_execs.clone();
        // for child in children {
        //     if !child.check_all_preconditions() {
        //         return false;
        //     }
        // }
        // true

        check_preconditions(
            my_preconds,
            Pid::from_raw(self.cached_metadata.caller_pid()),
        )
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
        if self.cached_metadata.starting_cwd() != curr_cwd {
            debug!("starting cwd doesn't match");
            debug!("old cwd: {:?}", self.cached_metadata.starting_cwd());
            debug!("new cwd: {:?}", curr_cwd);
        }

        check_preconditions(
            my_preconds,
            Pid::from_raw(self.cached_metadata.caller_pid()),
        );

        let children = self.child_execs.clone();
        for child in children {
            child.check_all_preconditions_regardless();
        }
    }

    pub fn command(&self) -> Command {
        self.cached_metadata.command()
    }

    pub fn postconditions(&self) -> Postconditions {
        self.postconditions.clone()
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

    // pub fn caller_pid(&self) -> SessionId {
    //     self.0.caller_pid()
    // }

    pub fn check_all_preconditions(&self) -> bool {
        self.0.check_all_preconditions()
    }

    pub fn check_all_preconditions_regardless(&self) {
        self.0.check_all_preconditions_regardless()
    }
}

fn apply_transition_function(
    accessor_and_file: Accessor,
    parents_cache_subdir: PathBuf,
    fact_set: HashSet<Fact>,
) {
    for fact in fact_set {
        debug!("Applying transition for fact");
        match fact {
            Fact::DoesntExist => {
                let file = match &accessor_and_file {
                    Accessor::ChildProc(_, path) => path,
                    Accessor::CurrProc(path) => path,
                };

                if file.exists() {
                    fs::remove_file(file.clone()).unwrap();
                }
            }
            Fact::FinalContents | Fact::Exists => {
                // Okay we want to copy the file from the cache to the correct
                // output location.
                match &accessor_and_file {
                    Accessor::ChildProc(hashed_child_cmd, file) => {
                        // Who done it? Child.
                        // Ex: Child writes to foo. cache/child/foo
                        // Parent will have this in its cache: cache/parent/child/foo
                        let file_name = file.file_name().unwrap();
                        let childs_subdir_in_parents_cache =
                            parents_cache_subdir.join(hashed_child_cmd);
                        let childs_cache_file_location =
                            childs_subdir_in_parents_cache.join(file_name);

                        debug!(
                            "child's subdir in parent's cache: {:?}",
                            childs_subdir_in_parents_cache
                        );
                        debug!("cache file location: {:?}", childs_cache_file_location);
                        debug!("og file path: {:?}", file);

                        if childs_cache_file_location.exists() {
                            fs::copy(childs_cache_file_location, file.clone()).unwrap();
                        }
                    }
                    Accessor::CurrProc(file) => {
                        // Simple case when curr proc was the writer of the file.
                        let file_name = file.file_name().unwrap();
                        let cache_file_location = parents_cache_subdir.join(file_name);
                        debug!("cache file location: {:?}", cache_file_location);
                        debug!("og file path: {:?}", file);
                        if cache_file_location.exists() {
                            fs::copy(cache_file_location, file.clone()).unwrap();
                        }
                    }
                }
            }
            _ => (),
        }
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
