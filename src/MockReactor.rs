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

type BoxedSyscall = Box<dyn Syscall>;
type Shared<T> = Rc<RefCell<T>>;

enum MockedTraceEvent {
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

trait Syscall {
    fn name(&self) -> &str;
    fn syscall_number(&self) -> u32;
    fn get_prehook_regs(&self) -> Regs<Unmodified>;
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

struct BlockingSyscall<T> {
    handle: Handle<T>,
    pub syscall: BoxedSyscall,
}

impl BlockingSyscall<BlockingEnd> {
    fn consume(&self) {
        debug!("BlockingSyscall<BlockingEnd>::consume()");
        // TODO factor out to impl Handle<BlockingEnd> with unblock() method.
        self.handle.consume();
    }

    fn new(handle: Handle<BlockingEnd>, syscall: BoxedSyscall)
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

/// We need some variable that "owns" the live processes, and blocking system calls.
/// We could use TLS but that wouldn't work well for tests. So instead we create a Program
/// struct which holds the entire context representing one running Program (made of one or
/// more processes).
#[derive(Clone)]
struct ProgramHandle {
    exited_procs: Shared<HashSet<Pid>>,
    running_procs: Shared<HashSet<Pid>>,
    blocked_procs: Shared<HashSet<Pid>>,
    /// Blocking system calls are waiting on some event to unblock.
    /// We keep track of whether that event has unblocked here. Both
    /// events on a blocking syscall have a handle to some entry in this array.
    live_syscalls: Shared<Vec<bool>>,
    per_process_events: Shared<HashMap<Pid, VecDeque<MockedTraceEvent>>>,
    /// Keeps track of the current event per process.
    current_event: Shared<HashMap<Pid, MockedTraceEvent>>
}

impl ProgramHandle {
    fn new() -> ProgramHandle {
        ProgramHandle {
            exited_procs: Rc::new(RefCell::new(HashSet::new())),
            live_syscalls: Rc::new(RefCell::new(Vec::new())),
            blocked_procs: Rc::new(RefCell::new(HashSet::new())),
            running_procs: Rc::new(RefCell::new(HashSet::new())),
            per_process_events: Rc::new(RefCell::new(HashMap::new())),
            current_event: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    /// Return the current register state for the current_event for _pid_.
    /// Notice setting the register state is the responsibility of the MockedTraceEvent.
    fn get_registers(&self, pid: Pid) -> Regs<Unmodified> {
        let event = self.current_event.borrow_mut();
        let event = event.get(&pid).expect("Missing current event.");
        event.get_prehook_regs()
    }

    fn add_events(&mut self, events: VecDeque<MockedTraceEvent>, pid: Pid) {
        debug!("ProgramHandle::add_events(pid: {})", pid);
        let mut per_process_events = self.per_process_events.borrow_mut();
        if let Some(event) = per_process_events.insert(pid, events) {
            panic!("Unexpected events already present for {}", pid);
        }
    }


    /// TODO I probably need some state to tell whether I'm in the pre-hook
    /// or posthook
    async fn posthook(&self, pid: Pid) -> Regs<Unmodified> {
        trace!("ProgramHandle::posthook(pid: {})", pid);

        // No other task should try to access this same event, so it is safe
        // to remove. If a task accidentally double calls "posthook" this could
        // fail, but that's kinda what we want?
        let event =
            self.current_event.borrow_mut().remove(&pid).expect("Missing current event.");

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
                    let present = self.running_procs.borrow_mut().remove(&pid);
                    if !present {
                        panic!("Expected process {} to be in running_procs", pid);
                    }

                    let not_there = self.blocked_procs.borrow_mut().insert(pid);
                    if ! not_there {
                        panic!("{} should not already be present in blocked_procs.",
                               pid);
                    }

                    // Create event that will block when awaited. Notice
                    // the MockedAsyncEvent does not have a handle to the program
                    // instead it piggybacks off the reactor to "know" when it
                    // should return Ready(event), that is, the first time it is
                    // queried it will return pending, only the second time (once
                    // the reactor has informed the STR which task to poll next),
                    // will it return true.
                    let mocked_event = MockedAsyncEvent { pid: pid,
                                                          trace_event: TraceEvent::Posthook(pid),
                                                          pending: true };
                    let event = mocked_event.await;
                    if let TraceEvent::Posthook(event_pid) = event {
                        let msg = "Expected pid returned from event to match posthook \
                                   request pid";
                        assert_eq!(pid, event_pid, "{:?}", msg);
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

    /// Assumption: We will never block on get_next_event since we only return
    /// the prehook or other event here. The blocking will happen on posthook,
    /// "between" the system call.
    async fn get_next_event(&mut self, pid: Pid) -> TraceEvent {
        trace!("ProgramHandle::get_next_event(pid: {})", pid);
        // Code block required to convice Rust we're not borrowing a MutexGuart across
        // yield points.
        let event = {
            let mut per_process_events = self.per_process_events.borrow_mut();

            per_process_events.get_mut(&pid).
                expect("No such event for Pid").pop_front()
        };

        // End of the process, return exit event.
        if let None = event {
            let mut exited_procs = self.exited_procs.borrow_mut();
            if exited_procs.contains(&pid) {
                return TraceEvent::ProcessExited(pid);
            } else {
                exited_procs.insert(pid);
                return TraceEvent::PreExit(pid);
            }
        }

        let event = event.unwrap();

        // We cannot "merge" branches here, as all the _syscall_ have different
        // types.
        let trace_event = match &event {
            MockedTraceEvent::NonBlockingSyscall(syscall)  => {
                TraceEvent::Prehook(pid)
            }
            MockedTraceEvent::BlockedSyscall(syscall)  => {
                TraceEvent::Prehook(pid)
            }
            MockedTraceEvent::BlockingSyscall(syscall) => {
                TraceEvent::Prehook(pid)
            }
            MockedTraceEvent::Fork(child_events) => {
                unimplemented!()
            }
        };
        // Set this event as the current event for _pid_.
        self.current_event.borrow_mut().insert(pid, event);
        trace_event
    }

    /// Create a new set of Handles used to "link" to separate system calls or
    /// events together. E.g. a read and write linked as they represent blocking
    /// on a pipe, or a waitpid waiting for an exit on some process.
    fn new_blocking_pair(&mut self) -> (Handle<BlockingEnd>, Handle<BlockedEnd>) {
        // Add new entry to live_syscalls
        let mut live_syscalls = self.live_syscalls.borrow_mut();
        live_syscalls.push(true);

        let index = live_syscalls.len() - 1;
        drop(live_syscalls);

        (Handle::new(self.live_syscalls.clone(), index),
         Handle::new(self.live_syscalls.clone(), index))
    }

    /// This function is called by the reactor to know which process should run next.
    fn pick_next_process(&mut self) -> Pid {
        unimplemented!()
    }
}

struct Program {
    program: ProgramHandle,
}

impl Program {
    fn new() -> Program {
        Program { program: ProgramHandle::new() }
    }

    fn add_events(&mut self, events: VecDeque<MockedTraceEvent>, pid: Pid) {
        self.program.add_events(events, pid);
    }

    fn new_blocking_pair(&mut self) -> (Handle<BlockingEnd>, Handle<BlockedEnd>) {
        self.program.new_blocking_pair()
    }

    fn get_handle(&self) -> ProgramHandle {
        self.program.clone()
    }
}

#[derive(Clone)]
struct Handle<T> {
    /// Vector of all live syscalls, Handle should only access the member specified
    /// by index.
    live_syscalls: Shared<Vec<bool>>,
    index: usize,
    phantom: PhantomData<T>
}

impl<T> Handle<T> {
    fn new(handle: Shared<Vec<bool>>, index: usize) -> Handle<T> {
        Handle{ live_syscalls: handle, index, phantom: PhantomData }
    }
}

impl Handle<BlockedEnd> {
    fn is_blocked(&self) -> bool {
        *self.live_syscalls.borrow_mut().get(self.index).
            expect("Expected entry to be here.")
    }
}

impl Handle<BlockingEnd> {
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
        with_target(false).
        without_time().
        init();

    let mut program = Program::new();
    let pid = Pid::from_raw(1);

    let mut events: VecDeque<MockedTraceEvent> = VecDeque::new();

    let (we, re) = program.new_blocking_pair();
    let syscall = Box::new(ReadSyscall{});
    events.push_back(MockedTraceEvent::BlockingSyscall(BlockingSyscall::new(we, syscall)));

    program.add_events(events, pid);
    let mt = MockedTracer { current_pid: pid,
                            program_handle: program.get_handle() };
    run_program(mt);
}

/// The SingleThreadedRuntime expects to be able to .poll() a task, so
/// task must be initialized with the right thing to do, either return
/// ready, or pending. If pending, next time SingleThreadedRuntime won't
/// ask the task, the reactor will be in charge of deciding which task
/// is ready next, so when the task (MockedAsyncEvent) is polled a second
/// time it should return ready with the correct event.
pub struct MockedAsyncEvent {
    pid: Pid,
    trace_event: TraceEvent,
    pending: bool,
}

impl Future for MockedAsyncEvent {
    type Output = TraceEvent;

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

pub struct MockedReactor {
    program: ProgramHandle,
}

impl Reactor for MockedReactor {
    fn wait_for_event(&mut self) -> bool {
        use single_threaded_runtime::ptrace_event::WAKERS;
        // Ask the mocked program which process to do next.
        let pid = self.program.pick_next_process();

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

pub struct MockedTracer {
    pub current_pid: Pid,
    program_handle: ProgramHandle,
}

#[async_trait(?Send)]
impl Tracer for MockedTracer {
    type Reactor = MockedReactor;


    fn get_reactor(&self) -> Self::Reactor {
        trace!("get_reactor: MockedReactor created.");
        MockedReactor { program: self.program_handle.clone() }
    }

    fn get_event_message(&self) -> c_long {
        unimplemented!()
    }

    fn clone_tracer_for_new_process(&self, new_child: Pid) -> Self {
        MockedTracer {
            current_pid: new_child,
            program_handle: self.program_handle.clone()
        }
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

    fn get_registers(&self) -> Regs<Unmodified> {
        self.program_handle.get_registers(self.current_pid)
    }

    /// Set registers will be as fancy as we want it to be. We could use the information
    /// provided by the user via regs, to replay system calls, etc. We probably don't want
    /// to implement anything that fancy.
    fn set_regs(&self, regs: &mut Regs<Modified>) {
        unimplemented!()
    }

    async fn posthook(&self) -> Regs<Unmodified> {
        self.program_handle.posthook(self.current_pid).await
    }

    // TODO Result<TraceEvent, ?> ?
    async fn get_next_event(&mut self) -> TraceEvent {
        self.program_handle.get_next_event(self.current_pid).await
    }
}
