use crate::{
    cache_utils::{hash_command, CachedExecMetadata, Command},
    condition_generator::{check_preconditions, Accessor},
    condition_utils::{Fact, Postconditions, Preconditions},
    execution_utils::get_umask,
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
                let file_postconditions = posts.file_postconditions();
                let dir_postconditions = posts.dir_postconditions();

                create_dirs(dir_postconditions);

                for (accessor, fact_set) in file_postconditions {
                    apply_file_transition_function(accessor, cache_subdir.clone(), fact_set);
                }

                remove_dirs(dir_postconditions);
            }
        } else {
            panic!("Should not be trying to apply all transitions for ignored cached execution!!")
        }
    }

    // TODO: this needs to work with the "ignored" stuff.
    fn check_all_preconditions(&self, pid: Pid) -> bool {
        if !self.is_ignored {
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

    pub fn command(&self) -> Command {
        self.cached_metadata.command()
    }

    pub fn postconditions(&self) -> Option<Postconditions> {
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

    pub fn check_all_preconditions(&self, pid: Pid) -> bool {
        self.0.check_all_preconditions(pid)
    }

    pub fn check_all_preconditions_regardless(&self) {
        self.0.check_all_preconditions_regardless()
    }
}

// So for directories. I think this is basically just creating and deleting.
// Thoughts: Deleting dirs. So, you delete a dir once there are no files in it. I see
// two cases here.
// 1) This is an empty dir. We delete it. Doesn't really matter when, just so long
// as we delete them LONGEST path to SHORTEST. Think: rm /hello/hi then rm /hello
// 2) This dir has stuff in it. A bunch of files must be deleted in it first. Then it
// is NECESSARY for us to delete the files first (apply file transition function first)
// before deleting the dirs.
// -----------------------------------------------------------------------------------
// Thoughts: rename. Rename is weird. It is not obvious the order to things.
// If we rename a directory, and the execution is accessing files in that directory,
// we need to know to update the paths.
// We also need to ... I guess make sure we rename the dir before applying the
// transition function for files.
// write /foo/file.txt
// rename /foo /bar
// vs.
// rename /foo /bar
// write /bar/file.txt
// fn apply_dir_transition_function(accessor_and_file: Accessor, fact_set: HashSet<Fact>) {
//     todo!();
// }

fn create_dirs(dir_postconditions: HashMap<Accessor, HashSet<Fact>>) {
    // We need to create dirs in order: shortest path to longest path.
    // Make a vector of paths to create. Then sort it by # of chars.
    // Then create the dir, if it does not exist already.

    let mut vec_of_paths: Vec<PathBuf> = Vec::new();

    for (accessor, fact_set) in dir_postconditions {
        let path = accessor.path();
    }
}

fn delete_dirs(accessor_and_file: Accessor, fact_set: HashSet<Fact>) {}

fn apply_file_transition_function(
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
