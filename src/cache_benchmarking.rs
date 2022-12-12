use std::{fs::remove_dir_all, path::PathBuf};

use crate::{
    cache::{retrieve_existing_cache, serialize_execs_to_cache},
    cache_utils::{hash_command, ExecCommand},
    condition_utils::Fact,
};

pub fn remove_buildbwa_entries_from_existing_cache(percent_to_remove: i32) {
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

pub fn remove_buildraxml_entries_from_existing_cache(percent_to_remove: i32) {
    // There are 31 gcc jobs that lead to an object file.
    // exec: "/usr/bin/gcc", arg count: 10
    let child_exec_count = 24;
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
                if exec == "/usr/bin/gcc" && arg_count == 10 {
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
            let cache_path = PathBuf::from("/home/kship/kship/standard-RAxML/cache");
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
pub fn remove_bioinfo_entries_from_existing_cache(percent_to_remove: i32) {
    let child_exec_count = 905;
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

    // ROOT: ExecCommand("/home/kship/kship/bioinformatics-workflows/all_hmmer_jobs", ["./target/release/all_hmmer_jobs"])
    if let Some(mut existing_cache) = retrieve_existing_cache() {
        let mut curr_count = 0;
        let mut list_to_remove: Vec<ExecCommand> = Vec::new();
        let mut vec_of_dirs_to_remove: Vec<u64> = Vec::new();

        // Get a list of gcc job keys to remove from the cache.
        for key in existing_cache.keys() {
            if curr_count < num_to_remove_from_cache {
                let exec = key.exec();
                let arg_count = key.clone().args().len();
                //ExecCommand("/home/kship/kship/bioinformatics-workflows/hmmbuild",
                // ["./hmmer/bin/hmmbuild", "--cpu", "0", "./hmmer/out/100.aln", "./hmmer/in/100/100.fa"]), HASHED COMMAND: 15141315317065790283
                // if exec == "/home/kship/kship/bioinformatics-workflows/hmmbuild" && arg_count > 3 {
                if exec == "/home/kship/kship/bioinformatics-workflows/clustalw2" && arg_count > 2 {
                    list_to_remove.push(key.clone());
                    curr_count += 1;
                }
            } else {
                break;
            }
        }

        // Remove from the cache, and add hash to a list of dirs to remove
        // from /cache.
        for exec_command in list_to_remove {
            // TODO
            let existing_hmmer_job = hash_command(exec_command.clone());
            vec_of_dirs_to_remove.push(existing_hmmer_job);
            existing_cache.remove(&exec_command);
        }

        // Actually remove the /cache subdirs.
        for hash in vec_of_dirs_to_remove {
            let cache_path = PathBuf::from("/home/kship/kship/bioinformatics-workflows/cache");
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
