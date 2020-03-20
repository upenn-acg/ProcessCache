//! Testing infrastructure to test mocked streams of events.

use std::collections::{HashSet, HashMap, BTreeSet};
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
use std::cmp::Ordering;

use tracing::{event, span, Level, debug, info, trace};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

/// New type pattern to allows us to implement ordering for Pids.
///
/// Required for determininistic map iterations.
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


/// Allows us to use and store different types of system calls using
/// a dynamic trait object.
type BoxedSyscall = Box<dyn Syscall>;

/// Data shared across multiple different types. This data lives as long as the last
/// reference there is to it. I chose this approach over a global as we want it to
/// be thread safe when running tests.
type Shared<T> = Rc<RefCell<T>>;

/// State for Events. Still adding new events.
enum AddingEvents {}
/// State for Events. Ready to be consumed.
enum Ready {}

/// List of MockedTraceEvents to execute.
struct Events<T> {
    events: VecDeque<MockedTraceEvent>,
    _state: PhantomData<T>,
}

impl Events<Ready> {
    fn pop_next_event(&mut self) -> Option<MockedTraceEvent> {
        self.events.pop_front()
    }
}

impl Events<AddingEvents> {
    fn new() -> Events<AddingEvents> {
        Events { events: VecDeque::new(), _state: PhantomData }
    }

    fn add_blocking(mut self, s: BlockingSyscall) -> Events<AddingEvents> {
        self.events.push_back(MockedTraceEvent::BlockingSyscall(s));
        Events { events: self.events, _state: PhantomData }
    }

    fn add_blocked(mut self, s: BlockedSyscall) -> Events<AddingEvents> {
        self.events.push_back(MockedTraceEvent::BlockedSyscall(s));
        Events { events: self.events, _state: PhantomData }
    }

    fn add_process(mut self, events: Events<Ready>) -> Events<AddingEvents> {
        self.events.push_back(MockedTraceEvent::Fork(ForkData::EventStream(events)));
        Events { events: self.events, _state: PhantomData }
    }

    fn add_syscall(mut self, s: impl Syscall + 'static) -> Events<AddingEvents> {
        self.events.push_back(MockedTraceEvent::Syscall(Box::new(s)));
        Events { events: self.events, _state: PhantomData }
    }

    /// Adds ending Prehook and ProcessExited events to event sequence.
    fn finished(mut self) -> Events<Ready> {
        self.events.push_back(MockedTraceEvent::PreExit);
        self.events.push_back(MockedTraceEvent::ProcessExited);
        Events { events: self.events, _state: PhantomData }
    }
}

/// This is Events<Ready> when first initialized and executed. When `get_next_event`
/// encounters MockedTraceEvent::Fork, we will set it to it's child Pid and move the
/// `Events<Ready>` value into `per_process_events`.
/// Pid is then used by get_event_message.
enum ForkData {
    EventStream(Events<Ready>),
    ChildPid(Pid),
}

/// All the different events we want to allow our mock trace to contain: blocking system
/// calls, non-blocking syscalls, and forking for multi process. Signals, threads, and
/// other events may come later. Blocking syscalls come in pairs: a blocking end and a
/// blocked end.
///
/// No PID information is carried by the MockedTraceEvent or Events<_>, this information
/// is a property of the running `Program`.
enum MockedTraceEvent {
    /// A syscall that is blocking a blocked syscall.
    BlockingSyscall(BlockingSyscall),
    /// A syscall blocked by some blocking syscall.
    BlockedSyscall(BlockedSyscall),
    Syscall(BoxedSyscall),
    /// Fork event
    Fork(ForkData),
    /// Event received right before process exits.
    PreExit,
    /// Process has exited and is no longer accepting tracer commands.
    ProcessExited,
}

impl MockedTraceEvent {
    /// Fetch the registers based on the type of event.
    fn get_prehook_regs(&self) -> Regs<Unmodified> {
        use MockedTraceEvent::*;
        match self {
            BlockingSyscall(blocking_syscall) => {
                blocking_syscall.syscall.get_prehook_regs()
            }
            BlockedSyscall(blocked_syscall) => {
                blocked_syscall.syscall.get_prehook_regs()
            }
            Syscall(syscall) => {
                syscall.get_prehook_regs()
            }
            Fork(_) => {
                unimplemented!()
            }
            ProcessExited =>
                panic!("get_prehook_regs(): ProcessExited has no registers."),
            PreExit =>
                panic!("get_prehook_regs(): PreExit has no registers."),
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

struct WriteSyscall {}

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
        regs.to_unmodified()
    }

    fn get_posthook_regs(&self) -> Regs<Unmodified> {
        let mut regs = Regs::new(empty_regs()).make_modified();

        regs.write_syscall_number(libc::SYS_write as u64);
        regs.write_retval(1000 /*arbitrary bytes*/);
        regs.to_unmodified()
    }
}

struct BlockingSyscall {
    handle: BlockingHandle<BlockingEnd>,
    pub syscall: BoxedSyscall,
}

impl BlockingSyscall {
    /// Notify BlockedSyscall that it may now continue.
    fn consume(&self) {
        debug!("BlockingSyscall::consume()");
        self.handle.consume();
    }

    /// Get unique index representing handle. Useful for uniquely identifying a unique
    /// pair of system calls.
    fn get_handle_index(&self) -> usize {
        self.handle.index
    }


    fn new(handle: BlockingHandle<BlockingEnd>, syscall: BoxedSyscall)
           -> BlockingSyscall {
        BlockingSyscall { handle, syscall }
    }
}

struct BlockedSyscall {
    handle: BlockingHandle<BlockedEnd>,
    pub syscall: BoxedSyscall,
}

impl BlockedSyscall {
    /// Get unique index representing handle. Useful for uniquely identifying a unique
    /// pair of system calls.
    fn get_handle_index(&self) -> usize {
        self.handle.index
    }

    fn is_blocked(&self) -> bool {
        self.handle.is_blocked()
    }

    fn new(handle: BlockingHandle<BlockedEnd>, syscall: BoxedSyscall)
           -> BlockedSyscall {
        BlockedSyscall { handle, syscall }
    }

    fn clone_handle(&self) -> BlockingHandle<BlockedEnd> {
        self.handle.clone()
    }
}

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
    per_process_events: Shared<HashMap<Pid, Events<Ready>>>,
    /// Global counter keeping track of what the next Pid to allocate will be.
    next_pid: Shared<Pid>,
    /// Keeps track of the current event per process.
    ///
    /// Get next events takes an event from per_process_events and sticks it here.
    /// MockedTraceEvent are removed by `Tracer::posthook`.
    current_per_process_event: Shared<HashMap<Pid, MockedTraceEvent>>
}

impl Program {
    fn new(pid: Pid) -> Program {
        let mut running_procs = BTreeSet::new();
        running_procs.insert(OrdPid(pid));
        let running_procs = Rc::new(RefCell::new(running_procs));

        Program {
            current_pid: pid,
            blocked_proc_index: Rc::new(RefCell::new(HashMap::new())),
            live_syscalls: Rc::new(RefCell::new(Vec::new())),
            blocked_procs: Rc::new(RefCell::new(HashSet::new())),
            running_procs,
            per_process_events: Rc::new(RefCell::new(HashMap::new())),
            next_pid: Rc::new(RefCell::new(Pid::from_raw(pid.as_raw() + 1))),
            current_per_process_event: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    fn insert_running_proc(&self, pid: Pid) {
        if ! self.running_procs.borrow_mut().insert(OrdPid(pid)) {
            panic!("{:?} should not already be present in running_procs.", pid);
        }
    }

    fn current_pid(&self) -> Pid {
        self.current_pid
    }

    fn generate_next_pid(&self) -> Pid {
        let pid = *self.next_pid.borrow();
        *self.next_pid.borrow_mut() = Pid::from_raw(pid.as_raw() + 1);
        pid
    }

    fn add_events(&mut self, events: Events<Ready>) {
        debug!("Program::add_events(pid: {:?})", self.current_pid());
        let mut per_process_events = self.per_process_events.borrow_mut();
        if matches!(per_process_events.insert(self.current_pid(), events), Some(event)) {
            panic!("Unexpected events already present for {:?}", self.current_pid());
        }
    }

    /// Create a new set of BlockingHandles used to "link" to separate system calls or
    /// events together. E.g. a read and write linked as they represent blocking
    /// on a pipe, or a waitpid waiting for an exit on some process.
    fn new_blocking_pair<S1, S2>(&mut self, blocking: S1,
                                 blocked: S2) -> (BlockingSyscall, BlockedSyscall)
    where S1: Syscall + 'static,
          S2: Syscall + 'static {
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
    fn pick_next_process(&mut self) -> Pid {
        let pid = self.running_procs.
            borrow_mut().
            iter().
            next().
            expect("No next available process. This is a deadlock!").0;
        info!("pick_next_process: Pid {:?} picked next.", pid);
        pid
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

#[derive(Clone)]
enum BlockingEnd {}
#[derive(Clone)]
enum BlockedEnd {}

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


// #[test]
// fn couple_syscalls_test() {
//     use crate::execution::run_program;
//     tracing_subscriber::fmt::Subscriber::builder().
//         with_env_filter(EnvFilter::from_default_env()).
//         without_time().
//         init();

//     let pid = Pid::from_raw(1);
//     let mut program = Program::new(pid);

//     let events = Events::new().
//         add_syscall(WriteSyscall {}).
//         add_syscall(ReadSyscall {});
//     program.add_events(events.finished(), pid);
//     run_program(program);
// }

// #[test]
// #[should_panic(expected = "No next available process. This is a deadlock!")]
// fn deadlocking_syscall_test() {
//     use crate::execution::run_program;
//     tracing_subscriber::fmt::Subscriber::builder().
//         with_env_filter(EnvFilter::from_default_env()).
//     // with_target(false).
//         without_time().
//         init();

//     let pid = Pid::from_raw(1);
//     let mut program = Program::new(pid);

//     let (write, read) = program.new_blocking_pair(WriteSyscall{}, ReadSyscall{});
//     let events = Events::new().
//         // This read will block forever...
//         add_blocked(read).
//         add_blocking(write);

//     program.add_events(events.finished(), pid);
//     run_program(program);
// }

#[test]
fn blocking_syscall_test() {
    use crate::execution::run_program;
    tracing_subscriber::fmt::Subscriber::builder().
        with_env_filter(EnvFilter::from_default_env()).
    // with_target(false).
        without_time().
        init();

    let pid = Pid::from_raw(1);
    let mut program = Program::new(pid);

    let (write, read) = program.new_blocking_pair(WriteSyscall{}, ReadSyscall{});

    let child_events =
        Events::new().
        add_blocking(write).
        finished();

    let events = Events::new().
        add_syscall(ReadSyscall {}).
        add_process(child_events).
        add_blocked(read);

    program.add_events(events.finished());
    run_program(program);
}

/// Future representing a mocked objects which eventually produces a TraceEvent.
/// This allows us to set events as pending (blocked) causing the executor to
/// pick a different task to run.
pub struct MockedAsyncEvent {
    pid: Pid,
    trace_event: TraceEvent,
    handle: BlockingHandle<BlockedEnd>,
    /// Check that our reactor is behaving accordingly by only ever having poll called twice:
    /// once the very first time this future is polled (where it should return Pending).
    /// And once more when it is rescheduled only when the event is ready (is_blocked() will return true).
    polled_once: bool
}

impl MockedAsyncEvent {
    fn new(pid: nix::unistd::Pid, trace_event: TraceEvent, handle: BlockingHandle<BlockedEnd>) -> MockedAsyncEvent {
        MockedAsyncEvent {pid , trace_event, handle, polled_once: false }
    }
}

impl Future for MockedAsyncEvent {
    type Output = TraceEvent;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<TraceEvent> {
        match (self.as_ref().handle.is_blocked(), self.polled_once) {
            // Syscall is blocked, but we have already polled once before...
            // The reactor should not have picked this process to run as it wasn't
            // ready. This is a bug.
            (true, true) => {
                panic!("Bug: Reactor should not have picked this process, it wasn't ready.");
            }
            // First time being polled. We yield.
            (true, false) => {
                info!("MockedAsyncEvent returned pending.");
                self.polled_once = true;
                Poll::Pending
            }
            // This is the good case where we ran once, set polled_once to true and are now
            // here.
            (false, true) => {
                info!("MockedAsyncEvent now ready on second poll.");
                Poll::Ready(self.trace_event.clone())
            }
            (false, false) => {
                panic!("polled_once is expected to be set to true on init");
            }
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
        // fetch child PID
        let borrow = self.current_per_process_event.borrow();
        let event = borrow.
            get(&self.current_pid()).
            expect(&format!("No event present pid {:?}", self.current_pid()));

        match event {
            MockedTraceEvent::Fork(ForkData::ChildPid(child_pid)) => {
                child_pid.as_raw().into()
            }
            MockedTraceEvent::Fork(ForkData::EventStream(_)) => {
                panic!("We should not get here with EventStream.");
            }
            _ => {
                unimplemented!("get_event_message only supports Fork currently.");
            }
        }
    }

    fn clone_tracer_for_new_process(&self, new_child: Pid) -> Self {
        info!("Creating Tracer for: {:?}", new_child);
        Program { current_pid: new_child, ..self.clone() }
    }

    /// Return PID of current process represented by this tracer.
    fn get_current_process(&self) -> Pid {
        self.current_pid()
    }

    // TODO make this a Result<String, ?> one day?
    fn read_cstring(&self, address: *const c_char, pid: Pid) -> String {
        unimplemented!()
    }

    fn read_value<T>(&self, address: *const T, pid: Pid) -> T {
        unimplemented!()
    }

    /// Return the current register state for the current event for the `current_pid`.
    /// Notice setting the register state is the responsibility of the MockedTraceEvent.
    fn get_registers(&self) -> Regs<Unmodified> {
        let map = self.current_per_process_event.borrow_mut();
        map.
            get(&self.current_pid).
            expect("No such PID in per_process_events map.").
            get_prehook_regs()
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
        use MockedTraceEvent::*;
        trace!("Program::posthook(pid: {:?})", self.current_pid());

        // No other task should try to access this same event, so it is safe
        // to remove. If a task accidentally double calls "posthook" this could
        // fail, but that's kinda what we want?
        let event = self.
            current_per_process_event.
            borrow_mut().
            remove(& self.current_pid()).
            expect("Missing process in current_per_process_event");

        match event {
            BlockingSyscall(blocking_syscall) => {
                // Unblock blocked end.
                blocking_syscall.consume();
                // Move blocked syscall from blocked processes back to running.
                let handle_index = blocking_syscall.get_handle_index();
                match self.blocked_proc_index.borrow_mut().remove(& handle_index) {
                    Some(blocked_pid) => {
                        // Move process from blocked to running.
                        if matches!(
                            self.blocked_procs.borrow_mut().take(&self.current_pid()),
                            None ) {
                            panic!("Expected process {:?} to be in running_procs",
                                   self.current_pid());
                        }

                        if ! self.running_procs.borrow_mut().insert(OrdPid(self.current_pid())) {
                            panic!("{:?} should not already be present in blocked_procs.",
                                   self.current_pid());
                        }
                    }
                    None => {
                        // Proc wasn't in blocked_procs, this is because the blocking
                        // syscall executed before the blocked syscall. This is okay :)
                        // Nothing to do.
                    }
                }

                blocking_syscall.syscall.get_posthook_regs()
            }
            BlockedSyscall(syscall) => {
                if !syscall.is_blocked() {
                    trace!("BlockedSyscall is not blocked anymore!");
                    syscall.syscall.get_posthook_regs()
                } else {
                    trace!("System call is blocked!");
                    // System call is blocked.

                    // Connect handle index to our PID so we can be efficiently woken up
                    // later. Notice this still works even if the BlockingSyscall syscall
                    // consumes the handle before us (the BlockedSyscall) runs, as then
                    // the if statement that got us here would have returned true ;)
                    let handle_index = syscall.get_handle_index();

                    if matches!(
                        self.blocked_proc_index.borrow_mut().
                            insert(handle_index, self.current_pid),
                        Some(_)) {
                        // This should not be possible as the handle index allocator
                        // should never recycle indices.
                        panic!("Value already existed in blocked_proc_index.")
                    }

                    // Move process from running to blocked.
                    if matches!(
                        self.running_procs.borrow_mut().take(&OrdPid(self.current_pid())),
                        None ) {
                        panic!("Expected process {:?} to be in running_procs",
                               self.current_pid());
                    }

                    assert!(self.blocked_procs.borrow_mut().insert(self.current_pid),
                            "{:?} should not already be present in blocked_procs.",
                            self.current_pid());

                    // Create event that will block when awaited. Notice the
                    // MockedAsyncEvent does not have a handle to the program instead it
                    // piggybacks off the reactor to "know" when it should return
                    // Ready(event), that is, the first time it is queried it will return
                    // pending, only the second time (once the reactor has informed the
                    // STR which task to poll next), will it return true.
                    let mocked_event =
                        MockedAsyncEvent::new(self.current_pid(),
                                              TraceEvent::Posthook(self.current_pid()),
                                              syscall.clone_handle());

                    // Process will be paused here due to await and the way we initialized
                    // MockedAsyncEvent. We will also resume from here.
                    match mocked_event.await {
                        TraceEvent::Posthook(event_pid) => {
                            let msg = "Expected pid returned from event to match posthook \
                                       request pid";
                            assert_eq!(self.current_pid(), event_pid, "{:?}", msg);
                            syscall.syscall.get_posthook_regs()
                        }
                        event => {
                            panic!("Unexpected event after posthook await: {:?}", event);
                        }
                    }
                }
            }
            Syscall(syscall) => {
                // Nothing to wait on, this is it.
                syscall.get_posthook_regs()
            }
            Fork(child_events) => {
                unimplemented!()
            }
            e => unimplemented!(),
        }
    }

    // TODO Result<TraceEvent, ?> ?
    /// Assumption: We will never block on get_next_event since we only return
    /// the prehook or other event here. The blocking will happen on posthook,
    /// "between" the system call.
    async fn get_next_event(&mut self) -> TraceEvent {
        trace!("Program::get_next_event(pid: {:?})", self.current_pid());

        let err = "Reached end of event stream. \
                   You have asked for a trace event from an already exited process.";
        let event = self.
            per_process_events.
            borrow_mut().
            get_mut(&self.current_pid).
            expect("No such event for Pid").
            pop_next_event().
            expect(err);

        // TODO
        if let MockedTraceEvent::Fork(ForkData::ChildPid(_)) = event {
            unreachable!("We should not never get here.");
        }
        if let MockedTraceEvent::Fork(ForkData::EventStream(child_events)) = event {
            // Create new process and add it to our mock program. We do not set
            // ourselves to the child_pid ProcessCache will do that when it calls
            // `clone_tracer_for_new_process`.
            let child_pid = self.generate_next_pid();
            self.insert_running_proc(child_pid);

            // Insert child events.
            self.per_process_events.borrow_mut().insert(child_pid, child_events);
            // Set this fork as our current event.
            self.current_per_process_event.
                borrow_mut().
                insert(self.current_pid(),
                       MockedTraceEvent::Fork(ForkData::ChildPid(child_pid)));
            return TraceEvent::Fork(self.current_pid());
        }

        // We cannot "merge" branches here, as all the _syscall_ have different
        // types.
        let trace_event = match & event {
            MockedTraceEvent::Syscall(syscall)  => {
                TraceEvent::Prehook(self.current_pid())
            }
            MockedTraceEvent::BlockedSyscall(syscall)  => {
                TraceEvent::Prehook(self.current_pid())
            }
            MockedTraceEvent::BlockingSyscall(syscall) => {
                TraceEvent::Prehook(self.current_pid())
            }

            MockedTraceEvent::Fork(child_events) => {
                panic!("This case handled above ^");
            }
            MockedTraceEvent::PreExit => {
                TraceEvent::PreExit(self.current_pid())
            }
            MockedTraceEvent::ProcessExited => {
                TraceEvent::ProcessExited(self.current_pid())
            }
        };

        self.current_per_process_event.
            borrow_mut().
            insert(self.current_pid(), event);
        trace_event
    }
}
