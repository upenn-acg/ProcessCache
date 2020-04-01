use async_trait::async_trait;
use std::collections::{HashSet, HashMap, BTreeSet};
use std::cell::RefCell;
use single_threaded_runtime::Reactor;
use nix::unistd::Pid;
use std::os::raw::c_long;
use std::os::raw::c_char;
use tracer::regs::{Regs,Unmodified, Modified};
use tracer::TraceEvent;
use tracer::Tracer;

use std::rc::Rc;
use std::cmp::Ordering;

use tracing::{event, span, Level, debug, info, trace};

use crate::blocking_event::BlockingHandle;
use crate::system_call::{BlockingSyscall, BlockedSyscall, Syscall};

use crate::events::{Events, Ready, {MockedTraceEvent, ForkData, MockedAsyncEvent}};
use crate::program::Shared;
use crate::program::Program;

pub struct Process {
    pid: Pid,
    /// List of events this process still has to execute.
    upcoming_events: Events<Ready>,
    /// Current event we're currently executing. We keep track of this as due to the async
    /// nature of our design, we may need to pause and come back. Similarly, the tracing
    /// program might do multiple query events on a single event.
    /// Get `Tracer::get_next_event` takes an event from `upcoming_events` and sticks it here.
    /// MockedTraceEvent are removed by `Tracer::posthook`.
    current_event: Option<MockedTraceEvent>,
    /// Handle to the global program this process is running under.
    program: Shared<Program>,
}

impl Process {
    pub fn new(pid: Pid, program: Shared<Program>, events: Events<Ready>) -> Process {
        Process {
            pid,
            upcoming_events: events,
            current_event: None,
            program
        }
    }

    fn pid(&self) -> Pid {
        self.pid
    }
}

// By default, Rust doesn't allow trait methods to be async,
// but of course, there is a macro to fix that ;)
// Tell async trait macro we do not need our data to implement Send.
#[async_trait(?Send)]
impl Tracer for Process {
    type Reactor = Program;

    fn get_reactor(&self) -> Self::Reactor {
        trace!("get_reactor: new mock tracer reactor created.");
        self.program.borrow().clone()
    }

    fn get_event_message(&self) -> c_long {
        // fetch child PID
        let event = self.current_event.as_ref().expect("get_event_message: No current_event");

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
        self.program.borrow().get_awaiting_process(new_child)
    }

    /// Return PID of current process represented by this tracer.
    fn get_current_process(&self) -> Pid {
        self.pid()
    }

    // TODO make this a Result<String, ?> one day?
    fn read_cstring(&self, address: *const c_char, pid: Pid) -> String {
        unimplemented!()
    }

    fn read_value<T>(&self, address: *const T, pid: Pid) -> T {
        unimplemented!()
    }

    /// Return the current register state for the current event for the `pid`.
    /// Notice setting the register state is the responsibility of the MockedTraceEvent.
    fn get_registers(&self) -> Regs<Unmodified> {
        self.current_event.as_ref().expect("Missing event").get_prehook_regs()
    }

    /// Set registers will be as fancy as we want it to be. We could use the information
    /// provided by the user via regs, to replay system calls, etc. We probably don't want
    /// to implement anything that fancy.
    fn set_regs(&self, regs: &mut Regs<Modified>) {
        unimplemented!()
    }

    /// TODO I probably need some state to tell whether I'm in the pre-hook
    /// or posthook
    async fn posthook(&mut self) -> Regs<Unmodified> {
        trace!("Program::posthook(pid: {:?})", self.pid());

        // No other task should try to access this same event, so it is safe
        // to remove. If a task accidentally double calls "posthook" this could
        // fail, but that's kinda what we want?
        let event = self.
            current_event.
            take().
            expect("Event missing");

        match event {
            MockedTraceEvent::BlockingSyscall(blocking_syscall) => {
                self.program.borrow_mut().handle_blocking_event(blocking_syscall)
            }
            MockedTraceEvent::BlockedSyscall(syscall) => {
                if !syscall.is_blocked() {
                    trace!("BlockedSyscall is not blocked anymore!");
                    syscall.syscall.get_posthook_regs()
                } else {
                    trace!("System call is blocked!");
                    self.program.
                        borrow_mut().
                        handle_blocked_event(self.pid(), syscall).await
                }
            }
            MockedTraceEvent::Syscall(syscall) => {
                // Nothing to wait on, this is it.
                syscall.get_posthook_regs()
            }
            MockedTraceEvent::Fork(_) => {
                panic!("Posthook not valid for Fork event.");
            }
            _exits => panic!("PreExit/ProcessExited not valid for Fork event."),
        }
    }

    // TODO Result<TraceEvent, ?> ?
    /// Assumption: We will never block on get_next_event since we only return
    /// the prehook or other event here. The blocking will happen on posthook,
    /// "between" the system call.
    // TODO If we ever want to implement process switching this would be where to
    // do it. The current implementation just executes the same process until a
    // blocking system call is encountered.
    async fn get_next_event(&mut self) -> TraceEvent {
        trace!("Program::get_next_event(pid: {:?})", self.pid());

        let event = self.
            upcoming_events.
            pop_next_event().
            expect("Reached end of event stream. \
                   You have asked for a trace event from an already exited process.");

        if let MockedTraceEvent::Fork(ForkData::ChildPid(_)) = event {
            // This is an internal enum used by us, the user shouldn't be able to ask for
            // `get_next_event` and end up here!
            unreachable!("We should not never get here.");
        }
        if let MockedTraceEvent::Fork(ForkData::EventStream(child_events)) = event {
            // Create new process and add it to our mock program. We do not set
            // ourselves to the child_pid ProcessCache will do that when it calls
            // `clone_tracer_for_new_process`.
            let child_pid = self.program.borrow_mut().generate_next_pid();
            self.program.borrow_mut().insert_running_proc(child_pid);

            let child_proc = Process::new(child_pid, self.program.clone(), child_events);
            self.program.borrow().add_awaiting_process(child_pid, child_proc);
            self.current_event = Some(MockedTraceEvent::Fork(ForkData::ChildPid(child_pid)));
            return TraceEvent::Fork(self.pid());
        }

        // We cannot "merge" branches here, as all the _syscall_ have different
        // types.
        let trace_event = match & event {
            MockedTraceEvent::Syscall(_)  => {
                TraceEvent::Prehook(self.pid())
            }
            MockedTraceEvent::BlockedSyscall(_)  => {
                TraceEvent::Prehook(self.pid())
            }
            MockedTraceEvent::BlockingSyscall(_) => {
                TraceEvent::Prehook(self.pid())
            }

            MockedTraceEvent::Fork(_) => {
                panic!("This case handled above ^");
            }
            MockedTraceEvent::PreExit => {
                TraceEvent::PreExit(self.pid())
            }
            MockedTraceEvent::ProcessExited => {
                TraceEvent::ProcessExited(self.pid())
            }
        };

        self.current_event = Some(event);
        trace_event
    }
}
