use tracing::{event, span, Level, debug, info, trace};
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::marker::PhantomData;
use crate::system_call::BlockingSyscall;
use crate::system_call::BlockedSyscall;
use crate::system_call::Syscall;
use nix::unistd::Pid;
use crate::system_call::BoxedSyscall;
use tracer::regs::{Regs, Unmodified};
use tracer::TraceEvent;

use crate::blocking_event::{BlockingHandle, BlockedEnd};
use std::future::Future;

/// State for Events. Still adding new events.
pub enum AddingEvents {}
/// State for Events. Ready to be consumed.
pub enum Ready {}

/// List of MockedTraceEvents to execute.
pub struct Events<T> {
    events: VecDeque<MockedTraceEvent>,
    _state: PhantomData<T>,
}

impl Events<Ready> {
    pub fn pop_next_event(&mut self) -> Option<MockedTraceEvent> {
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
pub enum ForkData {
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
pub enum MockedTraceEvent {
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
    pub fn get_prehook_regs(&self) -> Regs<Unmodified> {
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
    pub fn new(pid: nix::unistd::Pid,
               trace_event: TraceEvent,
               handle: BlockingHandle<BlockedEnd>) -> MockedAsyncEvent {
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
