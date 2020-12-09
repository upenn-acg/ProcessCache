use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use nix::errno::Errno;
use nix::Error::Sys;

use crate::Reactor;
use std::cell::RefCell;
use std::collections::HashMap;
use std::task::Waker;

use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use tracing::{error, event, span, Level};

thread_local! {
    pub static WAKERS: RefCell<HashMap<Pid, Waker>> =
        RefCell::new(HashMap::new());
}

/// Future representing calling ptrace() and waitpid() on a Pid.
pub struct AsyncPtrace {
    pub pid: Pid,
}

#[allow(unused_imports)]
use log::{debug, info, trace};
use nix::sys::signal::Signal;
use nix::Error;
use std::collections::HashSet;

impl Future for AsyncPtrace {
    type Output = WaitStatus;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<WaitStatus> {
        let s = span!(Level::TRACE, "AsyncPtrace::poll()");
        let _e = s.enter();
        event!(Level::TRACE, ?self.pid, "Polling Once for");

        match waitpid(self.pid, Some(WaitPidFlag::WNOHANG)).expect("Unable to waitpid from poll") {
            WaitStatus::StillAlive => {
                WAKERS.with(|wakers| {
                    trace!("Inserting waker for {:?}", self.pid);
                    if let Some(_existing) =
                        wakers.borrow_mut().insert(self.pid, cx.waker().clone())
                    {
                        panic!("Waker already existed for {}", self.pid);
                    }
                });
                trace!("pending...");
                Poll::Pending
            }
            w => {
                trace!("ready!");
                Poll::Ready(w)
            }
        }
    }
}

#[derive(Default)]
pub struct PtraceReactor {}

impl PtraceReactor {
    pub fn new() -> PtraceReactor {
        PtraceReactor {}
    }
}

impl Reactor for PtraceReactor {
    fn wait_for_event(&mut self, live_procs: &HashSet<Pid>) -> bool {
        let s = span!(Level::INFO, "wait_for_event()");
        let _e = s.enter();

        trace!("Waiting for next ptrace event...");
        // Is there a way to wait on multiple FDs? I really wanna know
        // _all_ that are ready.
        let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let ignored = 0;
        let ret = unsafe {
            libc::waitid(
                libc::P_ALL,
                ignored,
                &mut siginfo as *mut libc::siginfo_t,
                libc::WNOWAIT | libc::WEXITED | libc::WSTOPPED,
            )
        };

        match ret {
            -1 => {
                let error = nix::Error::last();

                // Child finished it is done running.
                if let Sys(Errno::ECHILD) = error {
                    trace!("done!");
                    panic!("Does this ever happen?");
                // true
                } else {
                    panic!("Unexpected error reason: {}", error);
                }
            }
            0 => {
                // Some pid finished, query siginfo to see who it was.
                let pid = Pid::from_raw(unsafe { siginfo.si_pid() });
                trace!("... Next ptrace event arrived for Pid {}", pid);

                if !live_procs.contains(&pid) {
                    return self.handle_signal_fork_race(live_procs, &mut siginfo, pid);
                }

                let waker = WAKERS.with(|wakers| {
                    wakers
                        .borrow_mut()
                        .remove(&pid)
                        .expect("Expected waker to be in our set.")
                });

                waker.wake();
                false
            }
            n => panic!("Unexpected return code from waitid: {}", n),
        }
    }
}

impl PtraceReactor {
    /// When a new child is spawned ptrace tries to unhelpfully trap it and sends the
    /// event over to us. But there is no ordering guarantees between
    /// `ptrace::ForkEvent`s and this trap event. Sometimes the fork event comes first,
    /// we register this child with our executor and later ignore the trap, great! But
    /// sometimes the trap comes first and the reactor sees a PID it has no information
    /// about! Here we hackishly handle this special case by ignoring this SIGTRAP.
    fn handle_signal_fork_race(
        &mut self,
        live_procs: &HashSet<Pid>,
        siginfo: &mut libc::siginfo_t,
        pid: Pid,
    ) -> bool {
        match siginfo.si_code {
            libc::CLD_TRAPPED => {
                info!(
                    "Unknown PID {:?} encountered by reactor. Probably a SIGTRAP that \
                                   arrived before the fork_event. This is okay.",
                    pid
                );
                // Take this event off the internal wait* event queue, we want to read the
                // next event! Notice there is no need to ptrace(continue) this newly
                // spawned process. When its `run_process()` function runs, it will
                // do the ptrace(cont) for us. See `run_process()` docs for more info.
                match waitpid(pid, None) {
                    Ok(w) => {
                        // Paranoia.
                        assert!(
                            matches!(w, WaitStatus::Stopped(_, _)),
                            "waitpid returned different WaitStatus than \
                                 expected when handling signal/fork race."
                        );
                        // We need to re-do this function again. Recurse is the easiest way?
                        // :grimace-emoji:
                        return self.wait_for_event(live_procs);
                    }
                    Err(e) => {
                        panic!("Unable to take event off event queue: {:?}", e);
                    }
                }
            }
            c => {
                panic!("Unknown PID encountered by reactor. Siginfo.si_code {}", c);
            }
        }
    }
}
