use log::trace;
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

thread_local! {
    pub static WAKERS: RefCell<HashMap<Pid, Waker>> =
        RefCell::new(HashMap::new());
}

/// Future representing calling ptrace() and waitpid() on a Pid.
pub struct AsyncPtrace {
    pub pid: Pid,
    // We could have a reactor handle here. But the user shouldn't have to worry
    // about initializing a reactor.
}

impl Future for AsyncPtrace {
    type Output = WaitStatus;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<WaitStatus> {
        trace!("AsyncPtrace polling once for: {}", self.pid);

        match waitpid(self.pid, Some(WaitPidFlag::WNOHANG)).expect("Unable to waitpid from poll") {
            WaitStatus::StillAlive => {
                WAKERS.with(|wakers| {
                    wakers.borrow_mut().insert(self.pid, cx.waker().clone());
                });
                Poll::Pending
            }
            w => Poll::Ready(w),
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

// Currently libc::siginfo_t does not have the si_pid field.
// So we go to C to fetch the pid_t that was set by waitid().
extern "C" {
    fn getPid(infop: *mut libc::siginfo_t) -> libc::pid_t;
}

impl Reactor for PtraceReactor {
    fn wait_for_event(&mut self) -> bool {
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
                    true
                } else {
                    panic!("Unexpected error reason: {}", error);
                }
            }
            _ => {
                // Some pid finished, query siginfo to see who it was.
                let pid = unsafe { getPid(&mut siginfo as *mut libc::siginfo_t) };
                let pid = Pid::from_raw(pid);

                let waker = WAKERS.with(|wakers| {
                    wakers
                        .borrow_mut()
                        .remove(&pid)
                        .expect("Expected waker to be in our set.")
                });
                waker.wake();

                trace!("waitid() = {}", pid);
                false
            }
        }
    }
}
