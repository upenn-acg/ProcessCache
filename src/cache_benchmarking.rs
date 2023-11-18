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
        10 => {
            let ten_percent: f64 = (child_exec_count as f64) * (10.0 / 100.0);
            ten_percent as u64
        }
        25 => {
            let twenty_five_percent: f64 = (child_exec_count as f64) * (25.0 / 100.0);
            twenty_five_percent as u64
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
                PathBuf::from("/home/kship/kship/bioinformatics-workflows/bwa/bwa-0.7.10/cache");
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
        10 => {
            let ten_percent: f64 = (child_exec_count as f64) * (10.0 / 100.0);
            ten_percent as u64
        }
        25 => {
            let twenty_five_percent: f64 = (child_exec_count as f64) * (25.0 / 100.0);
            twenty_five_percent as u64
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
            let cache_path =
                PathBuf::from("/home/kship/kship/bioinformatics-workflows/standard-RAxML/cache");
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
    // let child_exec_count = 28;
    let child_exec_count = 87;
    // Calculate the number of child execs to remove.
    let num_to_remove_from_cache = match percent_to_remove {
        5 => {
            let five_percent: f64 = (child_exec_count as f64) * (5.0 / 100.0);
            five_percent as u64
        }
        10 => {
            let ten_percent: f64 = (child_exec_count as f64) * (10.0 / 100.0);
            ten_percent as u64
        }
        25 => {
            let twenty_five_percent: f64 = (child_exec_count as f64) * (25.0 / 100.0);
            twenty_five_percent as u64
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
                PathBuf::from("/home/kship/kship/bioinformatics-workflows/minigraph/cache");
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
pub fn remove_bioinfo_entries_from_existing_cache(percent_to_remove: i32) {
    let child_exec_count = 905;
    // Calculate number of child jobs to remove from the cache.
    // Most common number of jobs is 905 but can be changed obviously.
    let num_to_remove_from_cache = match percent_to_remove {
        5 => {
            let five_percent: f64 = (child_exec_count as f64) * (5.0 / 100.0);
            five_percent as u64
        }
        10 => {
            let ten_percent: f64 = (child_exec_count as f64) * (10.0 / 100.0);
            ten_percent as u64
        }
        25 => {
            let twenty_five_percent: f64 = (child_exec_count as f64) * (25.0 / 100.0);
            twenty_five_percent as u64
        }
        50 => child_exec_count / 2,
        90 => {
            let ninety_percent: f64 = (child_exec_count as f64) * (90.0 / 100.0);
            ninety_percent as u64
        }
        e => panic!("Unrecognized skip option: {:?}", e),
    };

    // The root execution's ExecCommand struct for hmmer: ExecCommand("/home/kship/kship/bioinformatics-workflows/all_hmmer_jobs", ["./target/release/all_hmmer_jobs"])
    if let Some(mut existing_cache) = retrieve_existing_cache() {
        let mut curr_count = 0;
        let mut list_to_remove: Vec<ExecCommand> = Vec::new();
        let mut vec_of_dirs_to_remove: Vec<u64> = Vec::new();

        // Get a list of job keys to remove from the cache.
        for key in existing_cache.keys() {
            println!("Key: {:?}", key);
            if curr_count < num_to_remove_from_cache {
                let exec = key.exec();
                let arg_count = key.clone().args().len();
                // Key: ExecCommand("/home/kship/kship/bioinformatics-workflows/hmmer/bin/hmmbuild", ["./hmmer/bin/hmmbuild", "--cpu", "0", "./hmmer/out/523.aln", "./hmmer/in/523/523.fa"])
                // Hmmer:
                // if exec == "/home/kship/kship/bioinformatics-workflows/hmmer/bin/hmmbuild"
                //     && arg_count > 3
                // Clustal:
                // if exec == "/home/kship/kship/bioinformatics-workflows/clustal/bin/clustalw2"
                //     && arg_count > 2
                // {
                // Raxml:
                if exec == "/home/kship/kship/bioinformatics-workflows/raxml/bin/raxml"
                    && arg_count > 2
                {
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
            let existing_job = hash_command(exec_command.clone());
            vec_of_dirs_to_remove.push(existing_job);
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

// PASH STUFF !
// --------------------------------------------------------------------------

// This IS NOT GENERAL.
// This is for 1_1.sh of the pash benchmarks lol.
// Returns a list of removed ExecCommands.
// So we know which cache subdirs to delete
pub fn remove_entries_from_existing_cache_struct(percent_to_remove: i32) -> Vec<ExecCommand> {
    if let Some(mut existing_cache) = retrieve_existing_cache() {
        // TODO: Handle for bioinfo / other pash
        let child_exec_count = 1060;
        let num_to_remove_from_cache = match percent_to_remove {
            5 => {
                let five_percent: f64 = (child_exec_count as f64) * (5.0 / 100.0);
                five_percent as u64
            }
            10 => {
                let ten_percent: f64 = (child_exec_count as f64) * (10.0 / 100.0);
                ten_percent as u64
            }
            25 => {
                let twenty_five_percent: f64 = (child_exec_count as f64) * (25.0 / 100.0);
                twenty_five_percent as u64
            }
            50 => child_exec_count / 2,
            90 => {
                let ninety_percent: f64 = (child_exec_count as f64) * (90.0 / 100.0);
                ninety_percent as u64
            }
            e => panic!("Unrecognized skip option: {:?}", e),
        };

        // Remove /usr/bin/ls
        // Remove /usr/bin/head
        // Remove five percent of ExecCommand("/usr/bin/bash", ["/usr/bin/bash", where there are MORE THAN 2 ARGS.
        // (These are the output file generating ones).
        // So first we go through the existing the cache and add these keys to a list.
        let mut list_to_remove: Vec<ExecCommand> = Vec::new();
        // let ls_command = ExecCommand(String::from("/usr/bin/ls"), vec![String::from("ls"), String::from("input/pg/")]);
        // let head_command = ExecCommand(String::from("/usr/bin/head"), vec![String::from("head"), String::from("-n"), String::from("1060")]);
        // list_to_remove.push(ls_command);
        // list_to_remove.push(head_command);
        let mut curr_count = 0;

        for (key, _) in existing_cache.clone() {
            if curr_count < num_to_remove_from_cache {
                let exec = key.exec();
                let args = key.args();
                if exec == "/usr/bin/bash" && args.len() > 2 {
                    list_to_remove.push(key);
                    curr_count += 1;
                }
            } else {
                break;
            }
        }

        // println!("Keys to remove:");
        // for key in list_to_remove.clone() {
        //     println!("{:?}", key);
        // }
        // Then we actually remove them.
        for key in list_to_remove.clone() {
            existing_cache.remove(&key);
        }
        // Remove ls and head.
        let ls_command = ExecCommand(
            String::from("/usr/bin/ls"),
            vec![String::from("ls"), String::from("input/pg/")],
        );
        let head_command = ExecCommand(
            String::from("/usr/bin/head"),
            vec![
                String::from("head"),
                String::from("-n"),
                String::from("1060"),
            ],
        );
        existing_cache.remove(&ls_command);
        existing_cache.remove(&head_command);

        // Then we serialize the cache back to disk.
        serialize_execs_to_cache(existing_cache);

        list_to_remove
    } else {
        panic!("Can't remove entries from a nonexistent cache!!");
    }
}

// Takes in a list of ExecCommands that were removed from the existing cache.
// We will hash 'em and turn 'em into paths to cache subdirs we will then
// remove.
// Get EVERYTHING ready to skip SOME jobs.
pub fn remove_pash_dirs(exec_command_list: Vec<ExecCommand>) {
    let cache_path = PathBuf::from("/home/kship/kship/bioinformatics-workflows/pash_nlp/cache");

    // TODO: Remove /usr/bin/ls
    // TODO: Remove /usr/bin/head
    let ls_command = ExecCommand(
        String::from("/usr/bin/ls"),
        vec![String::from("ls"), String::from("input/pg/")],
    );
    let head_command = ExecCommand(
        String::from("/usr/bin/head"),
        vec![
            String::from("head"),
            String::from("-n"),
            String::from("1060"),
        ],
    );
    let hashed_ls_command = hash_command(ls_command);
    let hashed_head_command = hash_command(head_command);

    println!("Trying to remove ls");
    let ls_cache_subdir_path = cache_path.join(hashed_ls_command.to_string());
    if let Err(e) = remove_dir_all(ls_cache_subdir_path.clone()) {
        panic!(
            "Failed to remove dir: {:?} because {:?}",
            ls_cache_subdir_path, e
        );
    }

    println!("Trying to remove head");
    let head_cache_subdir_path = cache_path.join(hashed_head_command.to_string());
    if let Err(e) = remove_dir_all(head_cache_subdir_path.clone()) {
        panic!(
            "Failed to remove dir: {:?} because {:?}",
            head_cache_subdir_path, e
        );
    }

    for exec_command in exec_command_list {
        // Remove the exec's cache subdir.
        let hashed_command = hash_command(exec_command.clone());
        // println!("Command I'm trying to remove dir for {:?}", exec_command);
        let cache_subdir_path = cache_path.join(hashed_command.to_string());
        if let Err(e) = remove_dir_all(cache_subdir_path.clone()) {
            panic!(
                "Failed to remove dir: {:?} because {:?}",
                cache_subdir_path, e
            );
        }
        // remove_dir_all(cache_subdir_path).unwrap();

        // Remove it from the root exec's subdir as well.
        // let root_executable = String::from("/usr/bin/bash");
        // let root_args = vec![String::from("/usr/bin/bash"), String::from("bash_c_1_1.sh")];
        // let root_exec_command = ExecCommand(root_executable, root_args);
        // let hashed_root_command = hash_command(root_exec_command);
        // 2_1
        // let hashed_root_command: u64 = 1863920304175310196;
        // 2_2
        // let hashed_root_command: u64 = 7312860072276720428;
        // 3_1
        // let hashed_root_command: u64 = 16722961511146699481;
        // 3_2
        let hashed_root_command: u64 = 16885473537218455101;
        let root_exec_cache_path = cache_path.join(hashed_root_command.to_string());
        let childs_subdir_in_root = root_exec_cache_path.join(hashed_command.to_string());
        println!(
            "Child exec whose dir I'ma try to remove: {:?}",
            exec_command
        );
        if let Err(e) = remove_dir_all(childs_subdir_in_root.clone()) {
            panic!(
                "Failed to remove dir: {:?} because {:?}",
                childs_subdir_in_root, e
            );
        } else {
            println!("Successfully removed dir: {:?}", childs_subdir_in_root);
        }
        // remove_dir_all(childs_subdir_in_root).unwrap();
    }
}
