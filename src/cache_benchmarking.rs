use std::{fs::remove_dir_all, path::PathBuf};

use crate::{
    cache::{retrieve_existing_cache, serialize_execs_to_cache},
    cache_utils::{hash_command, ExecCommand},
    condition_utils::Fact,
};

// This function serves to remove bwa build entries from the
// cache for benchmarking purposes. It does the following:
// 1) Depending on percent_to_remove, calculates how many jobs to remove from the cache.
// 2) Get the existing cache, then construct a list of child exec keys to remove from the cache.
// 3) Remove those keys from the cache, and serialize the updated cache map to disk.
// 4) Remove the cache subdirs associated with the keys removed from the cache.
// Note: We don't need to remove the child subdirectories within the parent's cache subdirectory
// because the files are hardlinked, and when we delete the child's cache subdir (ex: /cache/child),
// the link is broken in the child's subdir within the parent's cache subdir
// (ex: /cache/parent/child/foo.txt)
#[allow(dead_code)]
pub fn remove_buildbwa_entries_from_existing_cache(percent_to_remove: i32) {
    // There are 31 gcc jobs that lead to an object file.
    // Child execs are of this form: "/usr/bin/gcc", arg count: 11.
    let child_exec_count = 31;
    // Calculate the total number of child execs to remove.
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

// This function serves to remove raxml build entries from the
// cache for benchmarking purposes. It does the following:
// 1) Depending on percent_to_remove, calculates how many jobs to remove from the cache.
// 2) Get the existing cache, then construct a list of child exec keys to remove from the cache.
// 3) Remove those keys from the cache, and serialize the updated cache map to disk.
// 4) Remove the cache subdirs associated with the keys removed from the cache.
#[allow(dead_code)]
pub fn remove_buildraxml_entries_from_existing_cache(percent_to_remove: i32) {
    // There are 31 gcc jobs that lead to an object file.
    // Child execs are of the form: "/usr/bin/gcc", arg count: 10
    let child_exec_count = 24;
    // Calculate the number of child execs to remove.
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

// This function serves to remove minigraph build entries from the
// cache for benchmarking purposes. It does the following:
// 1) Depending on percent_to_remove, calculates how many jobs to remove from the cache.
// 2) Get the existing cache, then construct a list of child exec keys to remove from the cache.
// 3) Remove those keys from the cache, and serialize the updated cache map to disk.
// 4) Remove the cache subdirs associated with the keys removed from the cache.
#[allow(dead_code)]
pub fn remove_buildminigraph_entries_from_existing_cache(percent_to_remove: i32) {
    // There are 31 gcc jobs that lead to an object file.
    // exec: "/usr/bin/gcc", arg count: 11.
    let child_exec_count = 28;
    // Calculate the number of child execs to remove.
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
            let cache_path = PathBuf::from("/home/kship/kship/minigraph/cache");
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

// This function serves to remove bioinformatics workflow entries from the
// cache for benchmarking purposes. It does the following:
// 1) Depending on percent_to_remove, calculates how many jobs to remove from the cache.
// 2) Get the existing cache, then construct a list of child exec keys to remove from the cache.
// 3) Remove those keys from the cache, and serialize the updated cache map to disk.
// 4) Remove the cache subdirs associated with the keys removed from the cache.
pub fn remove_bioinfo_entries_from_existing_cache(percent_to_remove: u8) {
    // let child_exec_count = 905; // raxml?
    // let child_exec_count = 606; // pix2pix
    // Calculate number of child jobs to remove from the cache.
    // Most common number of jobs is 905 but can be changed obviously.
    // let num_to_remove_from_cache = match percent_to_remove {
    //     5 => {
    //         let five_percent: f64 = (child_exec_count as f64) * (5.0 / 100.0);
    //         five_percent as u64
    //     }
    //     50 => child_exec_count / 2,
    //     90 => {
    //         let ninety_percent: f64 = (child_exec_count as f64) * (90.0 / 100.0);
    //         ninety_percent as u64
    //     }
    //     e => panic!("Unrecognized skip option: {:?}", e),
    // };

    // The root execution's ExecCommand struct for hmmer: ExecCommand("/home/kship/kship/bioinformatics-workflows/all_hmmer_jobs", ["./target/release/all_hmmer_jobs"])
    if let Some(mut existing_cache) = retrieve_existing_cache() {
        let mut curr_count = 0;
        let mut list_to_remove: Vec<ExecCommand> = Vec::new();
        let mut vec_of_dirs_to_remove: Vec<u64> = Vec::new();

        // we will only remove exec units whose executable has one of these suffixes
        let executable_suffixes = ["raxml", "montage"];

        let total_cache_keys = existing_cache.keys()
            .filter(|k| executable_suffixes.iter().any(|pat| k.exec().ends_with(pat)))
            .count();
        let num_to_remove_from_cache = (total_cache_keys as f64 * (percent_to_remove as f64 / 100.0)) as u64;

        // Get a list of job keys to remove from the cache.
        for key in existing_cache.keys() {
            if curr_count < num_to_remove_from_cache {
                // let exec = key.exec();
                // let arg_count = key.clone().args().len();
                //ExecCommand("/home/kship/kship/bioinformatics-workflows/hmmbuild",
                // ["./hmmer/bin/hmmbuild", "--cpu", "0", "./hmmer/out/100.aln", "./hmmer/in/100/100.fa"]), HASHED COMMAND: 15141315317065790283
                // if exec == "/home/kship/kship/bioinformatics-workflows/hmmbuild" && arg_count > 3 {
                //if exec == "/home/kship/kship/bioinformatics-workflows/raxml/bin/raxml"
                //    && arg_count > 2
                if executable_suffixes.iter().any(|pat| key.exec().ends_with(pat)) {
                    list_to_remove.push(key.clone());
                    curr_count += 1;
                }
            } else {
                break;
            }
        }
        let num_execs_removed = list_to_remove.len();

        // Remove from the cache, and add hash to a list of dirs to remove
        // from /cache.
        for exec_command in list_to_remove {
            let existing_hmmer_job = hash_command(exec_command.clone());
            vec_of_dirs_to_remove.push(existing_hmmer_job);
            existing_cache.remove(&exec_command);
        }

        // Actually remove the /cache subdirs.
        let cache_path = PathBuf::from("/home/devietti/bioinformatics-workflows/cache");
        for hash in vec_of_dirs_to_remove {
            // let cache_path = PathBuf::from("/home/kship/kship/bioinformatics-workflows/cache");
            let dir_path = cache_path.join(hash.to_string());
            if let Err(e) = remove_dir_all(dir_path.clone()) {
                panic!("Failed to remove dir: {:?} because {:?}", dir_path, e);
            }
        }

        // Serialize the cache map back to disk.
        serialize_execs_to_cache(existing_cache);
        println!("Removed {} entries ({}%) from the cache at {:?}", num_execs_removed, percent_to_remove, cache_path);
    } else {
        panic!("Cannot remove entries from nonexistent cache!!");
    }
}
