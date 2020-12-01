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

use tracing::{event, span, Level};

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
    fn wait_for_event(&mut self) -> bool {
        let s = span!(Level::TRACE, "wait_for_event()");
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
                let pid = unsafe { siginfo.si_pid() };
                let pid = Pid::from_raw(pid);
                trace!("... Next ptrace event arrived for Pid {}", pid);

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
