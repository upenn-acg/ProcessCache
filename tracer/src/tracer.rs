//! Abstraction layer so tracer implementation can be decoupled from interface.
//! Allows us to have ProcessCache work with different tracer implementations,
//! currently: MockTracer and Ptracer.
use crate::regs::Modified;
use crate::regs::Regs;
use crate::regs::Unmodified;
use async_trait::async_trait;
use libc::c_long;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use single_threaded_runtime::Reactor;
use std::os::raw::c_char;

#[derive(Debug, Clone)]
pub enum TraceEvent {
    Exec(Pid),
    /// This is the stop before the final, from here we know we will receive an
    /// actual exit.
    PreExit(Pid),
    /// This is really a seccomp event, but with our setup, it represents a
    /// prehook event.
    Prehook(Pid),
    /// This is the parent's PID, not the child.
    Fork(Pid),
    Clone(Pid),
    VFork(Pid),
    Posthook(Pid),
    ProcessExited(Pid),
    ReceivedSignal(Pid, Signal),
    KilledBySignal(Pid, Signal),
}

impl From<WaitStatus> for TraceEvent {
    fn from(w: WaitStatus) -> TraceEvent {
        match w {
            WaitStatus::PtraceEvent(pid, _, status) => match status as i32 {
                libc::PTRACE_EVENT_EXEC => TraceEvent::Exec(pid),
                libc::PTRACE_EVENT_EXIT => TraceEvent::PreExit(pid),
                libc::PTRACE_EVENT_SECCOMP => TraceEvent::Prehook(pid),
                libc::PTRACE_EVENT_FORK => TraceEvent::Fork(pid),
                libc::PTRACE_EVENT_CLONE => TraceEvent::Clone(pid),
                libc::PTRACE_EVENT_VFORK => TraceEvent::VFork(pid),
                _ => panic!("Unknown status from PtraceEven: {:?}", status as i32),
            },
            WaitStatus::PtraceSyscall(pid) => TraceEvent::Posthook(pid),
            WaitStatus::Exited(pid, _exit_code) => TraceEvent::ProcessExited(pid),
            WaitStatus::Stopped(pid, signal) => TraceEvent::ReceivedSignal(pid, signal),
            // Not really expecting to see these. Might need them later.
            WaitStatus::Signaled(pid, signal, _core_duped) => {
                TraceEvent::KilledBySignal(pid, signal)
            }
            WaitStatus::Continued(_) => panic!("from(): Continued not supported"),
            WaitStatus::StillAlive => panic!("from(): StillAlive not supported"),
        }
    }
}

#[async_trait(?Send)]
pub trait Tracer {
    type Reactor: Reactor;

    fn get_reactor(&self) -> Self::Reactor;

    fn get_event_message(&self) -> c_long;

    fn clone_tracer_for_new_process(&self, new_child: Pid) -> Self;

    /// Return PID of current process represented by this tracer.
    fn get_current_process(&self) -> Pid;

    // TODO make this a Result<String, ?> one day?
    fn read_cstring(&self, address: *const c_char, pid: Pid) -> String;

    fn read_value<T>(&self, address: *const T, pid: Pid) -> T;

    fn get_registers(&self) -> Regs<Unmodified>;

    fn set_regs(&self, regs: &mut Regs<Modified>);

    async fn posthook(&self) -> Regs<Unmodified>;
    // TODO Result<TraceEvent, ?> ?
    async fn get_next_event(&mut self) -> TraceEvent;
}
