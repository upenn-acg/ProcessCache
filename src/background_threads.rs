use std::{collections::HashMap, path::PathBuf};

use crossbeam::channel::Receiver;

use crate::cache_utils::generate_hash;

// Our background threads use this function to wait for (source, dest) file path pairs
// to be sent to them, so that they may copy the output files to the cache.
pub fn background_thread_read_only_hashing(
    recv_end: Receiver<PathBuf>,
) -> HashMap<PathBuf, Vec<u8>> {
    let mut computed_hashes = HashMap::new();

    while let Ok(full_path) = recv_end.recv() {
        // If this hash is not in the map, compute it,
        // and put it in the map.
        computed_hashes
            .entry(full_path.clone())
            .or_insert_with(|| generate_hash(full_path));
    }

    // Return the computed hashes at thread exit.
    computed_hashes
}
