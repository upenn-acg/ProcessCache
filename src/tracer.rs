use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEvent {
    Exec(Pid),
    /// This is a stop before the actual program exit, this is our last chance to ptrace-queries
    /// on the tracee. From here, we expect to receive a real program exit.
    PreExit(Pid),
    /// This is really a seccomp event, but with our setup, it represents a
    /// prehook event.
    Prehook(Pid),
    /// This is the parent's PID, not the child.
    Fork(Pid),
    Clone(Pid),
    VFork(Pid),
    Posthook(Pid),
    ProcessExited(Pid, i32),
    ReceivedSignal(Pid, Signal),
    KilledBySignal(Pid, Signal),
}

impl From<WaitStatus> for TraceEvent {
    fn from(w: WaitStatus) -> TraceEvent {
        match w {
            WaitStatus::PtraceEvent(pid, _, status) => match status {
                libc::PTRACE_EVENT_EXEC => TraceEvent::Exec(pid),
                libc::PTRACE_EVENT_EXIT => TraceEvent::PreExit(pid),
                libc::PTRACE_EVENT_SECCOMP => TraceEvent::Prehook(pid),
                libc::PTRACE_EVENT_FORK => TraceEvent::Fork(pid),
                libc::PTRACE_EVENT_CLONE => TraceEvent::Clone(pid),
                libc::PTRACE_EVENT_VFORK => TraceEvent::VFork(pid),
                _ => panic!("Unknown status from PtraceEven: {:?}", status),
            },
            WaitStatus::PtraceSyscall(pid) => TraceEvent::Posthook(pid),
            WaitStatus::Exited(pid, exit_code) => TraceEvent::ProcessExited(pid, exit_code),
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
