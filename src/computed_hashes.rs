use std::{cell::RefCell, collections::HashMap, path::PathBuf, rc::Rc};

use crate::cache_utils::generate_hash;

// Full Path --> Hash
pub struct ComputedHashes(HashMap<PathBuf, Vec<u8>>);

impl ComputedHashes {
    fn get_computed_hash(&mut self, full_path: PathBuf) -> Vec<u8> {
        // if let Some(existing_hash) = self.0.get_mut(&full_path) {
        //     existing_hash
        // } else {
        //     // We don't yet have an entry. Compute the hash.
        //     let hash = generate_hash(full_path);
        //     self.0.insert(full_path, hash.clone());
        //     &hash
        // }

        let entry = self
            .0
            .entry(full_path.clone())
            .or_insert_with(|| generate_hash(&full_path));

        entry.to_vec()
    }
}
#[derive(Clone)]
pub struct RcComputedHashes(Rc<RefCell<ComputedHashes>>);

impl RcComputedHashes {
    pub fn new() -> RcComputedHashes {
        RcComputedHashes(Rc::new(RefCell::new(ComputedHashes(HashMap::new()))))
    }

    pub fn get_computed_hash(&self, full_path: PathBuf) -> Vec<u8> {
        self.0.borrow_mut().get_computed_hash(full_path)
    }
}
