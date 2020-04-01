//! Testing infrastructure to test mocked streams of events.

use nix::unistd::Pid;
use single_threaded_runtime::Reactor;
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use tracer::regs::{Regs, Unmodified};
use tracer::TraceEvent;

use std::cmp::Ordering;
use std::rc::Rc;

use tracing::{debug, event, info, span, trace, Level};

use crate::blocking_event::BlockingHandle;
use crate::system_call::{BlockedSyscall, BlockingSyscall, Syscall};

use crate::events::{
    Events, Ready, {ForkData, MockedAsyncEvent, MockedTraceEvent},
};
use crate::process::Process;

/// New type pattern to allows us to implement ordering for Pids.
///
/// Required for determininistic set iterations via BTreeSet.
#[derive(Hash, Eq, PartialEq, Debug)]
struct OrdPid(Pid);

impl Ord for OrdPid {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_raw().cmp(&other.0.as_raw())
    }
}

impl PartialOrd for OrdPid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.0.as_raw().cmp(&other.0.as_raw()))
    }
}

/// Data shared across multiple different types. This data lives as long as the last
/// reference there is to it. I chose this approach over a global as we want it to
/// be thread safe when running tests.
pub type Shared<T> = Rc<RefCell<T>>;

/// Runtime representation of a program.
///
/// Program owns the live processes, and blocking system calls, and all other state.
///
/// This program holds all the state necessary to be both the tracer and the reactor.
/// The tracer and reactor need all this data so it is easier to implement those traits
/// for this single struct than try to separate into different structs which share a
/// bunch of data. The executor API makes an implicit assumption about a shared global
/// state: the OS! So we have to mock this shared global state here via Rc and RefCells.
/// Notice we wrap our shared fields in `Shared<_>` "at the leaves" as multiple tasks will
/// be dynamically checking out the refcell, this happens at .await points. So having the
/// Shared<_> "on the outside" like `Shared<Program>` would not work as we would need to
/// check out the RefCell to access anything and we would hold on to that checkout across
/// yield boundaries.
///
/// We could use TLS but that wouldn't work well for multiple concurrently running tests,
/// as `cargo test` does. So instead we create a Program struct which holds the entire
/// context representing one running Program (made of one or more processes).
#[derive(Clone)]
pub struct Program {
    /// Map from BlockingHandle.index to process Pid.
    ///
    /// When a BlockedSyscall is encountered and blocks, we put it's handle index and PID
    /// in this map (the process is also moved from running_procs to blocked_procs). Later
    /// when the BlockingSyscall consumes the handle, we use it's handle index to know who
    /// to wake up. This dance is necessary since BlockedSyscall don't carry information
    /// about which process/syscall will eventually unblock it.
    blocked_proc_index: Shared<HashMap<usize, Pid>>,
    /// Uses OrdPids to ensure determininistic ordering when iterating through set.
    running_procs: Shared<BTreeSet<OrdPid>>,
    blocked_procs: Shared<HashSet<Pid>>,
    /// Blocking system calls are waiting on some event to unblock. We keep track of
    /// whether that event has unblocked here. Both events on a blocking syscall have a
    /// handle to some entry in this array.
    live_syscalls: Shared<Vec<bool>>,
    /// Global counter keeping track of what the next Pid to allocate will be.
    next_pid: Shared<Pid>,
    /// When we encounter a Fork event in `get_next_event` we create a new process and
    /// place it here. Once the user calls `Tracer::clone_tracer_for_new_process` we
    /// take that process from here and return it. This is to work around the Tracer
    /// trait API.
    awaiting_process: Shared<HashMap<Pid, Process>>,
}

impl Program {
    pub fn new(pid: Pid) -> Shared<Program> {
        let mut running_procs = BTreeSet::new();
        running_procs.insert(OrdPid(pid));

        let p = Program {
            blocked_proc_index: Rc::new(RefCell::new(HashMap::new())),
            live_syscalls: Rc::new(RefCell::new(Vec::new())),
            blocked_procs: Rc::new(RefCell::new(HashSet::new())),
            running_procs: Rc::new(RefCell::new(running_procs)),
            next_pid: Rc::new(RefCell::new(Pid::from_raw(pid.as_raw() + 1))),
            awaiting_process: Rc::new(RefCell::new(HashMap::new())),
        };

        Rc::new(RefCell::new(p))
    }

    // TODO: Generalize to handle other blocking events besides system calls? Like what?
    /// Unblock the blocked end and move blocked event from the blocked to running set.
    pub(crate) fn handle_blocking_event(
        &mut self,
        /*pid: Pid, Is this needed? */ blocking_syscall: BlockingSyscall,
    ) -> Regs<Unmodified> {
        blocking_syscall.unblock_blocked_end();

        let handle_index = blocking_syscall.get_handle_index();
        match self.blocked_proc_index.borrow_mut().remove(&handle_index) {
            Some(blocked_pid) => {
                // Move process from blocked to running.
                if matches!(self.blocked_procs.borrow_mut().take(&blocked_pid), None) {
                    panic!("Expected process {:?} to be in blocked_procs", blocked_pid);
                }
                if !self.running_procs.borrow_mut().insert(OrdPid(blocked_pid)) {
                    panic!(
                        "{:?} should not already be present in running_procs.",
                        blocked_pid
                    );
                }
            }
            None => {
                // Proc wasn't in blocked_procs, this is because the blocking
                // syscall executed before the blocked syscall. This is okay :)
                // Nothing to do.

                // TODO Verify process is in running queue
                // assert!(self.running_procs.contains(???))
            }
        }

        blocking_syscall.syscall.get_posthook_regs()
    }

    pub(crate) async fn handle_blocked_event(
        &mut self,
        pid: Pid,
        syscall: BlockedSyscall,
    ) -> Regs<Unmodified> {
        // Connect handle index to our PID so we can be efficiently woken up
        // later. Notice this still works even if the BlockingSyscall syscall
        // consumes the handle before us (the BlockedSyscall) runs, as then
        // the if statement that got us here would have returned true ;)
        let handle_index = syscall.get_handle_index();

        if matches!(
            self.blocked_proc_index
                .borrow_mut()
                .insert(handle_index, pid),
            Some(_)
        ) {
            // This should not be possible as the handle index allocator
            // should never recycle indices.
            panic!("Value already existed in blocked_proc_index.")
        }

        // Move process from running to blocked.
        if matches!(self.running_procs.borrow_mut().take(&OrdPid(pid)), None) {
            panic!("Expected process {:?} to be in running_procs", pid);
        }

        assert!(
            self.blocked_procs.borrow_mut().insert(pid),
            "{:?} should not already be present in blocked_procs.",
            pid
        );

        // Create event that will block when awaited. Notice the
        // MockedAsyncEvent does not have a handle to the program instead it
        // piggybacks off the reactor to "know" when it should return
        // Ready(event), that is, the first time it is queried it will return
        // pending, only the second time (once the reactor has informed the
        // STR which task to poll next), will it return true.
        let mocked_event =
            MockedAsyncEvent::new(pid, TraceEvent::Posthook(pid), syscall.clone_handle());

        // Process will be paused here due to await and the way we initialized
        // MockedAsyncEvent. We will also resume from here.
        match mocked_event.await {
            TraceEvent::Posthook(event_pid) => {
                assert_eq!(
                    pid, event_pid,
                    "Expected PID in TraceEvent to match posthook request PID."
                );
                syscall.syscall.get_posthook_regs()
            }
            event => {
                panic!("Unexpected event after posthook await: {:?}", event);
            }
        }
    }

    /// Add a process into the running process set.
    pub(crate) fn insert_running_proc(&self, pid: Pid) {
        if !self.running_procs.borrow_mut().insert(OrdPid(pid)) {
            panic!("{:?} should not already be present in running_procs.", pid);
        }
    }

    /// Generate a new unique PID to assign to a new process.
    pub(crate) fn generate_next_pid(&self) -> Pid {
        let pid = *self.next_pid.borrow();
        *self.next_pid.borrow_mut() = Pid::from_raw(pid.as_raw() + 1);
        pid
    }

    /// Create a new set of BlockingHandles used to "link" to separate system calls or
    /// events together. E.g. a read and write linked as they represent blocking
    /// on a pipe, or a waitpid waiting for an exit on some process.
    pub fn new_blocking_pair<S1, S2>(
        &mut self,
        blocking: S1,
        blocked: S2,
    ) -> (BlockingSyscall, BlockedSyscall)
    where
        S1: Syscall + 'static,
        S2: Syscall + 'static,
    {
        // Add new entry to live_syscalls
        let mut live_syscalls = self.live_syscalls.borrow_mut();
        live_syscalls.push(true);

        let index = live_syscalls.len() - 1;
        drop(live_syscalls);

        let bih = BlockingHandle::new(self.live_syscalls.clone(), index);
        let beh = BlockingHandle::new(self.live_syscalls.clone(), index);

        let bis = BlockingSyscall::new(bih, Box::new(blocking));
        let bes = BlockedSyscall::new(beh, Box::new(blocked));
        (bis, bes)
    }

    /// This function is called by the reactor to know which process should run next.
    ///
    /// We just iterate through our running processes and pick the next avaliable one.
    /// This is determininistic thanks to our use of BTreeSets.
    /// Panics if deadlock is detected, i.e. no available processes!
    pub(crate) fn pick_next_process(&self) -> Pid {
        let pid = self
            .running_procs
            .borrow_mut()
            .iter()
            .next()
            .expect("No next available process. This is a deadlock!")
            .0;
        info!("pick_next_process: Pid {:?} picked next.", pid);
        pid
    }
    pub(crate) fn add_awaiting_process(&self, child_pid: Pid, child_proc: Process) {
        self.awaiting_process
            .borrow_mut()
            .insert(child_pid, child_proc);
    }

    pub(crate) fn get_awaiting_process(&self, child_pid: Pid) -> Process {
        self.awaiting_process
            .borrow_mut()
            .remove(&child_pid)
            .expect("Expected child awaiting process.")
    }
}

/// Produces mocked events and pendings when polled by the executor.

/// Our reactor _is_ the Program as it knows all information about live processes
/// and who to run next. This is analogous to the PtraceReactor querying the global state
/// of the OS.
impl Reactor for Program {
    fn wait_for_event(&mut self) -> bool {
        use single_threaded_runtime::ptrace_event::WAKERS;
        // Ask the mocked program which process to do next.
        let pid = self.pick_next_process();

        // Call waker for correct pid.
        let waker = WAKERS.with(|wakers| {
            wakers
                .borrow_mut()
                .remove(&pid)
                .expect("Expected waker to be in our set.")
        });
        waker.wake();

        // TODO when should this function return true?
        return false;
    }
}
