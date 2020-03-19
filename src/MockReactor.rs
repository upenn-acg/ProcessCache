//! Testing infrastructure to test mocked streams of events.

use std::collections::HashSet;
use std::collections::HashMap;
use std::sync::Mutex;
use std::cell::RefCell;
use async_trait::async_trait;
use single_threaded_runtime::Reactor;
use nix::unistd::Pid;
use std::os::raw::c_long;
use std::os::raw::c_char;
use std::future::Future;
use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::regs::Modified;
use crate::regs::empty_regs;
use crate::tracer::TraceEvent;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Context;
use std::task::Poll;
use std::collections::VecDeque;
use std::marker::PhantomData;
use crate::tracer::Tracer;

use tracing::{event, span, Level, debug, info, trace};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

/// Allows us to use and store different types of system calls using
/// a dynamic trait object.
type BoxedSyscall = Box<dyn Syscall>;

/// Data shared across multiple different types. This data lives as long as the last
/// reference there is to it. I chose this approach over a global as we want it to
/// be thread safe when running tests.
type Shared<T> = Rc<RefCell<T>>;

/// All the different events we want to allow our mock trace to contain: blocking system
/// calls, non-blocking syscalls, and forking for multi process. Signals, threads, and
/// other events may come later. Blocking syscalls come in pairs: a blocking end and a
/// blocked end.
enum MockedTraceEvent {
    /// Represents a syscall that is blocking
    BlockingSyscall(BlockingSyscall<BlockingEnd>),
    BlockedSyscall(BlockingSyscall<BlockedEnd>),
    NonBlockingSyscall(BoxedSyscall),
    Fork(Vec<MockedTraceEvent>),
}

impl MockedTraceEvent {
    fn get_prehook_regs(&self) -> Regs<Unmodified> {
        use MockedTraceEvent::*;
        match self {
            BlockingSyscall(blocking_syscall) => {
                blocking_syscall.syscall.get_prehook_regs()
            }
            BlockedSyscall(blocked_syscall) => {
                blocked_syscall.syscall.get_prehook_regs()
            }
            NonBlockingSyscall(syscall) => {
                syscall.get_prehook_regs()
            }
            Fork(_) => {
                unimplemented!()
            }
        }
    }
}

/// Interface for describing system calls.
/// Allow us to implement per system call expected values.
trait Syscall {
    fn name(&self) -> &str;
    fn syscall_number(&self) -> u32;
    /// Default values system call should contain on prehook event.
    /// Should at least have system call number set.
    fn get_prehook_regs(&self) -> Regs<Unmodified>;
    /// Default values system call should contain on posthook event.
    /// Should at least have some meaningful return value set.
    fn get_posthook_regs(&self) -> Regs<Unmodified>;
}

struct ReadSyscall {}

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
        regs.to_unmodified()
    }

    fn get_posthook_regs(&self) -> Regs<Unmodified> {
        let mut regs = Regs::new(empty_regs()).make_modified();

        regs.write_syscall_number(libc::SYS_read as u64);
        regs.write_retval(1000 /*arbitrary bytes*/);
        regs.to_unmodified()
    }
}

/// Represents a system call that will either block another or is blocked.
/// `T` is either the BlockingEnd or the BlockedEnd.
/// (One day a const generic may go here instead of `T`!)
struct BlockingSyscall<T> {
    handle: BlockingHandle<T>,
    pub syscall: BoxedSyscall,
}

impl BlockingSyscall<BlockingEnd> {
    fn consume(&self) {
        debug!("BlockingSyscall<BlockingEnd>::consume()");
        self.handle.consume();
    }

    fn new(handle: BlockingHandle<BlockingEnd>, syscall: BoxedSyscall)
           -> BlockingSyscall<BlockingEnd> {
        BlockingSyscall { handle, syscall }
    }
}

impl BlockingSyscall<BlockedEnd> {
    fn is_blocked(&self) -> bool {
        self.handle.is_blocked()
    }
}

#[derive(Clone)]
enum BlockingEnd {}
#[derive(Clone)]
enum BlockedEnd {}

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
    /// Current PID that we are executing. While logically we are running mulitple
    /// processes at once, events arrive serialized.
    current_pid: Pid,
    exited_procs: Shared<HashSet<Pid>>,
    running_procs: Shared<HashSet<Pid>>,
    blocked_procs: Shared<HashSet<Pid>>,
    /// Blocking system calls are waiting on some event to unblock. We keep track of
    /// whether that event has unblocked here. Both events on a blocking syscall have a
    /// handle to some entry in this array.
    live_syscalls: Shared<Vec<bool>>,
    per_process_events: Shared<HashMap<Pid, VecDeque<MockedTraceEvent>>>,
    /// Keeps track of the current event per process.
    current_event: Shared<HashMap<Pid, MockedTraceEvent>>
}

impl Program {
    fn new(pid: Pid) -> Program {
        Program {
            current_pid: pid,
            exited_procs: Rc::new(RefCell::new(HashSet::new())),
            live_syscalls: Rc::new(RefCell::new(Vec::new())),
            blocked_procs: Rc::new(RefCell::new(HashSet::new())),
            running_procs: Rc::new(RefCell::new(HashSet::new())),
            per_process_events: Rc::new(RefCell::new(HashMap::new())),
            current_event: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    fn clone_with(&self, pid: Pid) -> Program {
        Program { current_pid: pid, ..self.clone() }
    }

    fn add_events(&mut self, events: VecDeque<MockedTraceEvent>, pid: Pid) {
        debug!("Program::add_events(pid: {})", pid);
        let mut per_process_events = self.per_process_events.borrow_mut();
        if matches!(per_process_events.insert(pid, events), Some(event)) {
            panic!("Unexpected events already present for {}", pid);
        }
    }

    /// Create a new set of BlockingHandles used to "link" to separate system calls or
    /// events together. E.g. a read and write linked as they represent blocking
    /// on a pipe, or a waitpid waiting for an exit on some process.
    fn new_blocking_pair(&mut self) -> (BlockingHandle<BlockingEnd>, BlockingHandle<BlockedEnd>) {
        // Add new entry to live_syscalls
        let mut live_syscalls = self.live_syscalls.borrow_mut();
        live_syscalls.push(true);

        let index = live_syscalls.len() - 1;
        drop(live_syscalls);

        (BlockingHandle::new(self.live_syscalls.clone(), index),
         BlockingHandle::new(self.live_syscalls.clone(), index))
    }

    /// This function is called by the reactor to know which process should run next.
    fn pick_next_process(&mut self) -> Pid {
        unimplemented!()
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
            wakers.borrow_mut().remove(&pid).
                expect("Expected waker to be in our set.")
        });
        waker.wake();

        // TODO when should this function return true?
        return false;
    }
}

/// Handle that a blocking system call can query to see if its partner system call
/// is blocking.
#[derive(Clone)]
struct BlockingHandle<T> {
    /// Shared vector of all live syscalls across all threads. API enforces that any given
    /// instance of this struct only accesses it's live_syscalls element at index!
    /// true represents a blocked system call, false represents unblocked.
    live_syscalls: Shared<Vec<bool>>,
    /// Only element BlockingHandle should be accessing.
    index: usize,
    phantom: PhantomData<T>
}

impl<T> BlockingHandle<T> {
    fn new(handle: Shared<Vec<bool>>, index: usize) -> BlockingHandle<T> {
        BlockingHandle{ live_syscalls: handle, index, phantom: PhantomData }
    }
}

impl BlockingHandle<BlockedEnd> {
    /// Only BlockedEnd handles may check if they're still blocked.
    fn is_blocked(&self) -> bool {
        *self.live_syscalls.borrow_mut().get(self.index).
            expect("Expected entry to be here.")
    }
}

impl BlockingHandle<BlockingEnd> {
    /// Only BlockingEnd handles may convey when they're done blocking.
    /// Next time the BlockedEnd pair call `.is_blocked()` it will be false.
    fn consume(&self) {
        *self.live_syscalls.borrow_mut().
            get_mut(self.index).expect("Expected entry to be here.") = false;
    }
}


/// TODO implement builder pattern for building up programs?
#[test]
fn run_program_test() {
    use crate::execution::run_program;
    tracing_subscriber::fmt::Subscriber::builder().
        with_env_filter(EnvFilter::from_default_env()).
        // with_target(false).
        without_time().
        init();

    let pid = Pid::from_raw(1);
    let mut program = Program::new(pid);

    let mut events: VecDeque<MockedTraceEvent> = VecDeque::new();

    let (we, re) = program.new_blocking_pair();
    let read_syscall = Box::new(ReadSyscall{});
    events.push_back(MockedTraceEvent::BlockingSyscall(BlockingSyscall::new(we, read_syscall)));

    program.add_events(events, pid);
    run_program(program);
}

/// Future representing a mocked objects which eventually produces a TraceEvent.
/// This allows us to set events as pending (blocked) causing the executor to
/// pick a different task to run.
pub struct MockedAsyncEvent {
    pid: Pid,
    trace_event: TraceEvent,
    pending: bool,
}

impl Future for MockedAsyncEvent {
    type Output = TraceEvent;

    /// The SingleThreadedRuntime expects to be able to .poll() a task, so task must be
    /// initialized with the right thing to do, either return ready, or pending. If pending,
    /// next time SingleThreadedRuntime won't ask the task, the reactor will be in charge of
    /// deciding which task is ready next, so when the task (MockedAsyncEvent) is polled a
    /// second time it should return ready with the correct event.
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<TraceEvent> {
        // TODO why is it only pending once?
        if self.pending {
            self.pending = false;
            Poll::Pending
        } else {
            Poll::Ready(self.trace_event.clone())
        }
    }
}

// By default, Rust doesn't allow trait methods to be async,
// but of course, there is a macro to fix that ;)
// Tell async trait macro we do not need our data to implement Send.
#[async_trait(?Send)]
impl Tracer for Program {
    type Reactor = Program;

    fn get_reactor(&self) -> Self::Reactor {
        trace!("get_reactor: MockedReactor created.");
        self.clone()
    }

    fn get_event_message(&self) -> c_long {
        unimplemented!()
    }

    fn clone_tracer_for_new_process(&self, new_child: Pid) -> Self {
        self.clone_with(new_child)
    }

    /// Return PID of current process represented by this tracer.
    fn get_current_process(&self) -> Pid {
        self.current_pid
    }

    // TODO make this a Result<String, ?> one day?
    fn read_cstring(&self, address: *const c_char, pid: Pid) -> String {
        unimplemented!()
    }

    fn read_value<T>(&self, address: *const T, pid: Pid) -> T {
        unimplemented!()
    }

    /// Return the current register state for the current_event for _pid_.
    /// Notice setting the register state is the responsibility of the MockedTraceEvent.
    fn get_registers(&self) -> Regs<Unmodified> {
        let event = self.current_event.borrow_mut();
        let event = event.get(&self.current_pid).expect("Missing current event.");
        event.get_prehook_regs()
    }

    /// Set registers will be as fancy as we want it to be. We could use the information
    /// provided by the user via regs, to replay system calls, etc. We probably don't want
    /// to implement anything that fancy.
    fn set_regs(&self, regs: &mut Regs<Modified>) {
        unimplemented!()
    }

    /// TODO I probably need some state to tell whether I'm in the pre-hook
    /// or posthook
    async fn posthook(&self) -> Regs<Unmodified> {
        trace!("Program::posthook(pid: {})", self.current_pid);

        // No other task should try to access this same event, so it is safe
        // to remove. If a task accidentally double calls "posthook" this could
        // fail, but that's kinda what we want?
        let event =
            self.current_event.borrow_mut().remove(&self.current_pid).expect("Missing current event.");

        use MockedTraceEvent::*;
        match event {
            BlockingSyscall(blocking_syscall) => {
                // Unblock other end.
                blocking_syscall.consume();
                blocking_syscall.syscall.get_posthook_regs()
            }
            BlockedSyscall(syscall) => {
                // Find out if it is blocked.
                if syscall.is_blocked() {
                    let present = self.running_procs.borrow_mut().remove(&self.current_pid);
                    if !present {
                        panic!("Expected process {} to be in running_procs", self.current_pid);
                    }

                    let not_there = self.blocked_procs.borrow_mut().insert(self.current_pid);
                    if ! not_there {
                        panic!("{} should not already be present in blocked_procs.",
                               self.current_pid);
                    }

                    // Create event that will block when awaited. Notice
                    // the MockedAsyncEvent does not have a handle to the program
                    // instead it piggybacks off the reactor to "know" when it
                    // should return Ready(event), that is, the first time it is
                    // queried it will return pending, only the second time (once
                    // the reactor has informed the STR which task to poll next),
                    // will it return true.
                    let mocked_event = MockedAsyncEvent { pid: self.current_pid,
                                                          trace_event: TraceEvent::Posthook(self.current_pid),
                                                          pending: true };
                    let event = mocked_event.await;
                    if let TraceEvent::Posthook(event_pid) = event {
                        let msg = "Expected pid returned from event to match posthook \
                                   request pid";
                        assert_eq!(self.current_pid, event_pid, "{:?}", msg);
                        syscall.syscall.get_posthook_regs()
                    } else {
                        panic!("Unexpected event after posthook await: {:?}", event);
                    }
                } else {
                    syscall.syscall.get_posthook_regs()
                }

            }
            NonBlockingSyscall(syscall) => {
                // Nothing to wait on, this is it.
                syscall.get_posthook_regs()
            }
            Fork(child_events) => {
                unimplemented!()
            }
        }
    }

    // TODO Result<TraceEvent, ?> ?
    /// Assumption: We will never block on get_next_event since we only return
    /// the prehook or other event here. The blocking will happen on posthook,
    /// "between" the system call.
    async fn get_next_event(&mut self) -> TraceEvent {
        trace!("Program::get_next_event(pid: {})", self.current_pid);
        // Code block required to convice Rust we're not borrowing a MutexGuart across
        // yield points.
        let event = {
            let mut per_process_events = self.per_process_events.borrow_mut();

            per_process_events.get_mut(&self.current_pid).
                expect("No such event for Pid").pop_front()
        };

        // End of the process, return exit event.
        if let None = event {
            let mut exited_procs = self.exited_procs.borrow_mut();
            if exited_procs.contains(&self.current_pid) {
                return TraceEvent::ProcessExited(self.current_pid);
            } else {
                exited_procs.insert(self.current_pid);
                return TraceEvent::PreExit(self.current_pid);
            }
        }

        let event = event.unwrap();

        // We cannot "merge" branches here, as all the _syscall_ have different
        // types.
        let trace_event = match &event {
            MockedTraceEvent::NonBlockingSyscall(syscall)  => {
                TraceEvent::Prehook(self.current_pid)
            }
            MockedTraceEvent::BlockedSyscall(syscall)  => {
                TraceEvent::Prehook(self.current_pid)
            }
            MockedTraceEvent::BlockingSyscall(syscall) => {
                TraceEvent::Prehook(self.current_pid)
            }
            MockedTraceEvent::Fork(child_events) => {
                unimplemented!()
            }
        };
        // Set this event as the current event for _pid_.
        self.current_event.borrow_mut().insert(self.current_pid, event);
        trace_event
    }
}
