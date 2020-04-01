use crate::program::Shared;
use std::marker::PhantomData;

#[derive(Clone)]
pub enum BlockingEnd {}
#[derive(Clone)]
pub enum BlockedEnd {}

/// Handle that a blocking system call can query to see if its partner system call
/// is blocking.
#[derive(Clone)]
pub struct BlockingHandle<T> {
    /// Shared vector of all live syscalls across all threads. API enforces that any given
    /// instance of this struct only accesses it's live_syscalls element at index!
    /// true represents a blocked system call, false represents unblocked.
    live_syscalls: Shared<Vec<bool>>,
    /// Only element BlockingHandle should be accessing.
    index: usize,
    phantom: PhantomData<T>,
}

impl<T> BlockingHandle<T> {
    pub fn new(handle: Shared<Vec<bool>>, index: usize) -> BlockingHandle<T> {
        BlockingHandle {
            live_syscalls: handle,
            index,
            phantom: PhantomData,
        }
    }

    pub fn get_index(&self) -> usize {
        self.index
    }
}

impl BlockingHandle<BlockedEnd> {
    /// Only BlockedEnd handles may check if they're still blocked.
    pub fn is_blocked(&self) -> bool {
        *self
            .live_syscalls
            .borrow_mut()
            .get(self.index)
            .expect("Expected entry to be here.")
    }
}

impl BlockingHandle<BlockingEnd> {
    /// Only BlockingEnd handles may convey when they're done blocking.
    /// Next time the BlockedEnd pair call `.is_blocked()` it will be false.
    pub fn unblock_blocked_end(&self) {
        *self
            .live_syscalls
            .borrow_mut()
            .get_mut(self.index)
            .expect("Expected entry to be here.") = false;
    }
}
