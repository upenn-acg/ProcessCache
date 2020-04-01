use crate::blocking_event::{BlockedEnd, BlockingEnd, BlockingHandle};
use tracer::regs::{empty_regs, Regs, Unmodified};
use tracing::{debug, event, info, span, trace, Level};

/// Allows us to use and store different types of system calls using
/// a dynamic trait object.
pub type BoxedSyscall = Box<dyn Syscall>;

/// Interface for describing system calls.
/// Allow us to implement per system call expected values.
pub trait Syscall {
    fn name(&self) -> &str;
    fn syscall_number(&self) -> u32;
    /// Default values system call should contain on prehook event.
    /// Should at least have system call number set.
    fn get_prehook_regs(&self) -> Regs<Unmodified>;
    /// Default values system call should contain on posthook event.
    /// Should at least have some meaningful return value set.
    fn get_posthook_regs(&self) -> Regs<Unmodified>;
}

pub struct ReadSyscall {}

impl Syscall for ReadSyscall {
    fn name(&self) -> &str {
        "read"
    }
    fn syscall_number(&self) -> u32 {
        0
    }

    fn get_prehook_regs(&self) -> Regs<Unmodified> {
        let mut regs = Regs::new(empty_regs()).make_modified();

        regs.write_syscall_number(libc::SYS_read as u64);
        regs.make_unmodified()
    }

    fn get_posthook_regs(&self) -> Regs<Unmodified> {
        let mut regs = Regs::new(empty_regs()).make_modified();

        regs.write_syscall_number(libc::SYS_read as u64);
        regs.write_retval(1000 /*arbitrary bytes*/);
        regs.make_unmodified()
    }
}

pub struct WriteSyscall {}

impl Syscall for WriteSyscall {
    fn name(&self) -> &str {
        "write"
    }
    fn syscall_number(&self) -> u32 {
        1
    }

    fn get_prehook_regs(&self) -> Regs<Unmodified> {
        let mut regs = Regs::new(empty_regs()).make_modified();

        regs.write_syscall_number(libc::SYS_write as u64);
        regs.make_unmodified()
    }

    fn get_posthook_regs(&self) -> Regs<Unmodified> {
        let mut regs = Regs::new(empty_regs()).make_modified();

        regs.write_syscall_number(libc::SYS_write as u64);
        regs.write_retval(1000 /*arbitrary bytes*/);
        regs.make_unmodified()
    }
}

pub struct BlockingSyscall {
    handle: BlockingHandle<BlockingEnd>,
    pub syscall: BoxedSyscall,
}

impl BlockingSyscall {
    /// Notify BlockedSyscall that it may now continue.
    pub fn unblock_blocked_end(&self) {
        debug!("BlockingSyscall::consume()");
        self.handle.unblock_blocked_end();
    }

    /// Get unique index representing handle. Useful for uniquely identifying a unique
    /// pair of system calls.
    pub fn get_handle_index(&self) -> usize {
        self.handle.get_index()
    }

    pub fn new(handle: BlockingHandle<BlockingEnd>, syscall: BoxedSyscall) -> BlockingSyscall {
        BlockingSyscall { handle, syscall }
    }
}

pub struct BlockedSyscall {
    handle: BlockingHandle<BlockedEnd>,
    pub syscall: BoxedSyscall,
}

impl BlockedSyscall {
    /// Get unique index representing handle. Useful for uniquely identifying a unique
    /// pair of system calls.
    pub fn get_handle_index(&self) -> usize {
        self.handle.get_index()
    }

    pub fn is_blocked(&self) -> bool {
        self.handle.is_blocked()
    }

    pub fn new(handle: BlockingHandle<BlockedEnd>, syscall: BoxedSyscall) -> BlockedSyscall {
        BlockedSyscall { handle, syscall }
    }

    pub fn clone_handle(&self) -> BlockingHandle<BlockedEnd> {
        self.handle.clone()
    }
}
