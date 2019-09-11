use futures::future::Future;
use futures::future::LocalBoxFuture;
use futures::task::{Context, Poll, ArcWake};
use futures::task::waker;

use log::{trace, debug, info};
use nix::errno::Errno;
use nix::unistd::Pid;
use nix::Error::Sys;

use std::sync::Arc;

use std::cell::RefCell;
use std::collections::HashMap;
use crate::waker::WaitidWaker;

pub mod ptrace_event;
mod waker;

// Currently libc::siginfo_t does not have the si_pid field.
// So we go to C to fetch the pid_t that was set by waitid().
extern "C" {
    fn getPid(infop: *mut libc::siginfo_t) -> libc::pid_t;
}

thread_local! {
    pub static WAITING_TASKS: RefCell<HashMap<Pid, LocalBoxFuture<'static, ()>>> =
        RefCell::new(HashMap::new());
    pub static NEXT_TASK: RefCell<Option<LocalBoxFuture<'static, ()>>> = RefCell::new(None);
}

/// This is our futures runtime. It is responsible for accepting futures to run,
/// polling them, registering the Pid the future is waiting for, and scheduling,
/// the next task to run.

/// This executor is meant to be used in a ptrace context. So all tasks run
/// in the main process, as child-threads of a ptracer are not allowed to ptrace or
/// wait on the tracee.
#[derive(Clone)]
pub struct WaitidExecutor {}

impl WaitidExecutor {
    pub fn new() -> Self {
        WaitidExecutor { }
    }

    pub fn add_future<F>(&self, future: F, pid: Pid) -> ()
    where
        F: Future<Output = ()> + 'static,
    {
        info!("Adding new future through handle.");
        // Pin it, and box it up for storing.
        let mut future: LocalBoxFuture<'static, ()> = Box::pin(future);
        let ww = WaitidWaker{ pid };
        let waker = ww.wait_waker();

        match future.as_mut().poll(&mut Context::from_waker(& waker)) {
            Poll::Pending => {
                trace!("Polled once, still pending.");
                // Made progress but still pending. Add to our queue.
                WAITING_TASKS.with(|ht| {
                    // TODO What should happen if the  value is already present?
                    ht.borrow_mut().insert(pid, future);
                });
            }
            Poll::Ready(_) => {
                info!("Future finished successfull!");
                // All done don't bother adding...
            }
        }
    }

    pub fn run_all(&mut self) {
        info!("Running all futures.");
        let ignored = 0;

        // The future may have polled and finished in the add_future method.
        // Let program continue running (no more tasks for us to execute).
        if WAITING_TASKS.with(|tb| { tb.borrow().is_empty() }) {
            debug!("All done!");
            return;
        }

        let mut all_done = false;
        while !all_done {
            // Is there a way to wait on multiple FDs? I really wanna know
            // _all_ that are ready.
            let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                libc::waitid(
                    libc::P_ALL,
                    ignored,
                    &mut siginfo as *mut libc::siginfo_t,
                    libc::WNOWAIT | libc::WEXITED | libc::WSTOPPED,
                )
            };

            // Block here for actual events to come.
            match ret {
                -1 => {
                    let error = nix::Error::last();

                    // Child finished it is done running.
                    if let Sys(Errno::ECHILD) = error {
                        trace!("done!");
                        return;
                    } else {
                        panic!("Unexpected error reason: {}", error);
                    }
                }
                _ => {
                    // Some pid finished, query siginfo to see who it was.
                    let pid = unsafe { getPid(&mut siginfo as *mut libc::siginfo_t) };
                    let pid = Pid::from_raw(pid);
                    let ww = WaitidWaker{ pid };
                    let waker = ww.wait_waker();
                    waker.wake();

                    trace!("waitid() = {}", pid);

                    NEXT_TASK.with(|nt| {
                        let mut task = nt.borrow_mut().take()
                            .expect("No such entry, should have been there.");
                        let waker = ww.wait_waker();
                        // as_mut(&mut self) -> Pin<&mut <P as Deref>::Target>
                        let poll = task
                            .as_mut()
                            .poll(&mut Context::from_waker(&waker));

                        WAITING_TASKS.with(|tasks| {
                            match poll {
                                // Move task back to waiting tasks.
                                Poll::Pending => {
                                    tasks.borrow_mut().insert(pid, task);
                                }
                                // Task has ran all the way!
                                Poll::Ready(_) => {
                                    if tasks.borrow().is_empty() {
                                        debug!("All tasks finished!");
                                        all_done = true;
                                    }
                                }
                            }
                        });
                    });
                }
            }
        }
    }
}
