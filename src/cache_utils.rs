use crossbeam::channel::Receiver;
use nix::pty::SessionId;
use tracing::debug;

use std::{
    collections::{hash_map::DefaultHasher, HashMap, HashSet},
    fs::{self, create_dir, metadata, read_dir, remove_dir, rename, File},
    hash::{Hash, Hasher},
    io::{self, Read, Write},
    os::linux::fs::MetadataExt,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{condition_generator::Accessor, condition_utils::Fact, syscalls::CheckMechanism};

// Struct housing the metadata associated with a unique execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CachedExecMetadata {
    caller_pid: SessionId,
    child_exec_count: u32,
    command: ExecCommand,
    env_vars: Vec<String>,
    executable_check: CheckMechanism,
    starting_cwd: PathBuf,
    starting_umask: u32,
}

impl CachedExecMetadata {
    pub fn new(
        caller_pid: SessionId,
        child_exec_count: u32,
        command: ExecCommand,
        env_vars: Vec<String>,
        executable_check: CheckMechanism,
        starting_cwd: PathBuf,
        starting_umask: u32,
    ) -> CachedExecMetadata {
        CachedExecMetadata {
            caller_pid,
            child_exec_count,
            command,
            env_vars,
            executable_check,
            starting_cwd,
            starting_umask,
        }
    }

    pub fn caller_pid(&self) -> SessionId {
        self.caller_pid
    }

    pub fn command(&self) -> ExecCommand {
        self.command.clone()
    }

    pub fn executable_check_passes(&self) -> bool {
        let check_mech = self.executable_check.clone();
        match check_mech {
            CheckMechanism::DiffFiles => panic!(
                "Diffing files not handled as a CheckMechanism, can't use it check executable!!"
            ),
            CheckMechanism::Mtime(cached_mtime) => {
                // Get current mtime of the executable.
                let executable_path = self.command.0.clone();
                let curr_metadata = metadata(executable_path).unwrap();
                let curr_mtime = curr_metadata.st_mtime();
                curr_mtime == cached_mtime
            }
            CheckMechanism::Hash(option_old_hash) => {
                let executable_path = self.command.0.clone();
                if let Some(old_hash) = option_old_hash {
                    if !old_hash.is_empty() {
                        let new_hash = generate_hash(executable_path.into());
                        // if old_hash != new_hash {
                        //     panic!(
                        //         "Exec hashes don't match. Old: {:?}, New: {:?}",
                        //         old_hash, new_hash
                        //     );
                        // }
                        old_hash == new_hash
                    } else {
                        true
                    }
                } else {
                    // panic!("Cannot check fact for Hash(None)!!");
                    true
                }
            }
        }
    }

    pub fn env_vars(&self) -> Vec<String> {
        self.env_vars.clone()
    }

    pub fn starting_cwd(&self) -> PathBuf {
        self.starting_cwd.clone()
    }

    pub fn starting_umask(&self) -> u32 {
        self.starting_umask
    }
}

// In the cache map, executions are identified by their executable
// and arguments, to make lookup fast and increase the chances of
// getting a hit.
// Because we can have collisions (example: 2 programs with same executable and command line
// args, but difference env vars), we map ExecCommand --> Vec<CachedExecution>
// so we can figure out which cached exec this is.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ExecCommand(pub String, pub Vec<String>);

impl ExecCommand {
    pub fn new(exe: String, args: Vec<String>) -> Self {
        ExecCommand(exe, args)
    }

    pub fn exec(&self) -> String {
        self.0.clone()
    }

    pub fn args(&self) -> Vec<String> {
        self.1.clone()
    }
}

// Counts the number child subdirs a parent exec has in its cache subdir.
#[allow(dead_code)]
pub fn number_of_child_cache_subdirs(root_exec_command: ExecCommand) -> u32 {
    // Create the root exec's cache subdir path.
    let hashed_root_exec_command = hash_command(root_exec_command);
    let cache_dir = PathBuf::from("./cache");
    let root_exec_cache_subdir = cache_dir.join(hashed_root_exec_command.to_string());

    let curr_entries = read_dir(root_exec_cache_subdir).unwrap();
    let mut count = 0;
    for entry in curr_entries {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            count += 1;
        }
    }
    count
}

// Function for creating directories if the postconditions call for it.
pub fn create_dirs(dir_postconditions: HashMap<Accessor, HashSet<Fact>>) {
    // We need to create dirs in order: shortest path to longest path.
    // Make a vector of paths to create. Then sort it by # of chars.
    // Then create the dir, if it does not exist already.

    let mut vec_of_paths: Vec<(PathBuf, HashSet<Fact>)> = Vec::new();

    for (accessor, fact_set) in dir_postconditions {
        let path = accessor.path();
        vec_of_paths.push((path, fact_set));
    }

    vec_of_paths.sort_by_key(|a| a.0.to_str().unwrap().chars().count());
    for (path, fact_set) in vec_of_paths {
        if !path.exists() {
            for fact in fact_set {
                if fact == Fact::Exists {
                    debug!("Fact is exists for dir!");
                    create_dir(path.clone()).unwrap();
                }
            }
        }
    }
}

// Function for deleting directories if the postconditions call for it.
pub fn delete_dirs(dir_postconditions: HashMap<Accessor, HashSet<Fact>>) {
    // We need to delete dirs in order: longest path to shortest.
    // Same drill as above, but flip a and b in sort_by() basically.
    let mut vec_of_paths: Vec<(PathBuf, HashSet<Fact>)> = Vec::new();

    for (accessor, fact_set) in dir_postconditions {
        let path = accessor.path();
        vec_of_paths.push((path, fact_set));
    }

    vec_of_paths.sort_by_key(|a| a.0.to_str().unwrap().chars().count());
    let v: Vec<(PathBuf, HashSet<Fact>)> = vec_of_paths.into_iter().rev().collect();

    for (path, fact_set) in v {
        if path.exists() {
            for fact in fact_set {
                if fact == Fact::DoesntExist {
                    remove_dir(path).unwrap();
                    break;
                }
            }
        }
    }
}

// Function for renaming directories if the postconditions call for it.
pub fn rename_dirs(dir_postconditions: HashMap<Accessor, HashSet<Fact>>) {
    let mut vec_of_paths: Vec<(PathBuf, HashSet<Fact>)> = Vec::new();

    for (accessor, fact_set) in dir_postconditions {
        let path = accessor.path();
        vec_of_paths.push((path, fact_set));
    }

    vec_of_paths.sort_by_key(|a| a.0.to_str().unwrap().chars().count());
    for (_, fact_set) in vec_of_paths {
        for fact in fact_set {
            if let Fact::Renamed(old_dir_path, new_dir_path) = fact {
                debug!("Fact is renamed for dir!");
                if !old_dir_path.exists() {
                    create_dir(old_dir_path.clone()).unwrap();
                }
                rename(old_dir_path, new_dir_path).unwrap();
                break;
            }
        }
    }
}

// Generate the hash of a file's contents.
// Used when we use file hashing as our input
// checking mechanism.
pub fn generate_hash(path: PathBuf) -> Vec<u8> {
    if !path.is_dir() {
        let file = File::open(&path);
        if let Ok(mut f) = file {
            process::<Sha256, _>(&mut f)
        } else {
            // panic!("Cannot open file for hashing: {:?}", path);
            Vec::new()
        }
    } else {
        Vec::new()
    }
}

// Generate the hash of the ExecCommand struct.
// Used for cache subdir naming.
pub fn hash_command(command: ExecCommand) -> u64 {
    let mut hasher = DefaultHasher::new();
    command.hash(&mut hasher);

    hasher.finish()
}

// ------ Hashing stuff ------
// Process the file and generate the hash.
fn process<D: Digest + Default, R: Read>(reader: &mut R) -> Vec<u8> {
    const BUFFER_SIZE: usize = 1024;
    let mut sh = D::default();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = reader
            .read(&mut buffer)
            .expect("Could not read buffer from reader processing hash!");
        sh.update(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }
    let final_array = &sh.finalize();
    final_array.to_vec()
}

// This is the function that background threads that serve outputs from the cache call.
// The tuple received is this:
// (Accessor, Parent Cache Subdir, Fact Set)
// Who accessed it? So we know if this is a child's file or the parent's and thus where
// in the cache to look for the file (parent/file1 vs parent/child/file1).
// The parent's cache subdirectory, and the fact set associated with the output file in question.
pub fn background_thread_serving_outputs(recv_end: Receiver<(Accessor, PathBuf, HashSet<Fact>)>) {
    while let Ok((accessor, parent_cache_subdir, fact_set)) = recv_end.recv() {
        apply_file_transition_function(accessor, parent_cache_subdir, fact_set);
    }
}

// This is the function that background threads that serve stdout call.
// The PathBuf returned is the full path to the stdout file in the cache we
// want printed.
pub fn background_thread_serving_stdout(recv_end: Receiver<PathBuf>) {
    while let Ok(stdout_file) = recv_end.recv() {
        // It's a stdout file just print it.
        let mut f = File::open(stdout_file).unwrap();
        let mut buf = Vec::new();
        let bytes = f.read_to_end(&mut buf).unwrap();
        if bytes != 0 {
            io::stdout().write_all(&buf).unwrap();
        }
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

// Function for applying transition for a single output file.
pub fn apply_file_transition_function(
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
            Fact::FinalContents => {
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
                        match file.file_name() {
                            Some(file_name) => {
                                let cache_file_location = parents_cache_subdir.join(file_name);
                                debug!("cache file location: {:?}", cache_file_location);
                                debug!("og file path: {:?}", file);
                                if cache_file_location.exists() {
                                    fs::copy(cache_file_location, file.clone()).unwrap();
                                }
                            }
                            None => {
                                panic!("can't get file name for: {:?}", file);
                            }
                        }
                    }
                }
            }
            _ => (),
        }
    }
}
