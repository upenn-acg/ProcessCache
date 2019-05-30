use futures::future::Future;
use futures::future::BoxFuture;
use futures::task::{Context, Poll, ArcWake};

use nix::errno::Errno;
use nix::unistd::{Pid};
use nix::Error::Sys;

use std::sync::Arc;

use std::cell::RefCell;
use std::collections::HashMap;

// Currently libc::siginfo_t does not have the si_pid field.
// So we go to C to fetch the pid_t that was set by waitid().
extern "C" {
    fn getPid(infop: *mut libc::siginfo_t) -> libc::pid_t;
}

// We actually end up needing both of  these hashmaps.
// basically, when running run a task, we have two borrow_mut() from the TAKS RefCell
// while we're polling i.e running the current task (future).
// However, from this task we may want to add a new future (using add_future())
// to take care of the child process.
// However if we were only to use the TASKS hashmap we end up running into a RefCell
// "already borrowed error". Instead we write this new future to NEW_TASKS and it's up
// to the executor to move new tasks on to the task (done in run_all);
thread_local! {
    pub static NEW_TASKS: RefCell<HashMap<Pid, BoxFuture<'static, ()>>> =
        RefCell::new(HashMap::new());
    pub static TASKS: RefCell<HashMap<Pid, BoxFuture<'static, ()>>> =
        RefCell::new(HashMap::new());
}

/// This is our futures runtime. It is responsible for accepting futures to run,
/// polling them, registering the Pid the future is waiting for, and scheduling,
/// the next task to run.

/// This executor is meant to be used in a ptrace context. So all tasks run
/// in the main process, as child-threads of a ptracer are not allowed to ptrace or
/// wait on the tracee.
#[derive(Clone)]
pub struct WaitidExecutor {}

struct WaitidWaker { }

impl ArcWake for WaitidWaker {
    fn wake_by_ref(_arc_self: &Arc<Self>) {
        // We should not ever call the waker. It is all done through thread local state.
        unreachable!();
    }
}

impl<'a> WaitidExecutor {
    pub fn new() -> Self {
        WaitidExecutor { }
    }

    pub fn add_future<F>(&self, future: F, pid: Pid) -> ()
    where
        F: Future<Output = ()> + Send + 'static,
    {
        trace!("Adding new future through handle.");
        // Pin it, and box it up for storing.
        let mut future: BoxFuture<'static, ()> = Box::pin(future);

        let waker = Arc::new(WaitidWaker { }).into_waker();
        match future.as_mut().poll(&mut Context::from_waker(& waker)) {
            Poll::Pending => {
                trace!("Polled once, still pending.");
                // Made progress but still pending. Add to our queue.
                NEW_TASKS.with(|ht| ht.borrow_mut().insert(pid, future));
            }
            Poll::Ready(_) => {
                trace!("Future finished successfull!");
                // All done don't bother adding...
            }
        }
    }

    pub fn run_all(&mut self) {
        trace!("Running all futures.");
        let ignored = 0;

        // The future may have polled and finished in the add_future method.
        // Let program continue running (no more tasks for us to execute).
        if TASKS.with(|tb| { tb.borrow().is_empty() }) &&
            NEW_TASKS.with(|tb| { tb.borrow().is_empty() }){
            debug!("All done!");
            return;
        }

        loop {
            // Move all newly created tasks into our TASK queue.
            if NEW_TASKS.with(|tb| { ! tb.borrow().is_empty() }) {
                NEW_TASKS.with(|new_tasks| {
                    TASKS.with(|tasks|{
                        for (k, v) in new_tasks.borrow_mut().drain() {
                            tasks.borrow_mut().insert(k, v);
                        }
                    });});
            }

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
                    if let Sys(Errno::ECHILD) = error {
                        trace!("done!");
                        return;
                    } else {
                        panic!("Unexpected error reason: {}", error);
                    }
                }
                _ => {
                    let pid = unsafe { getPid(&mut siginfo as *mut libc::siginfo_t) };
                    trace!("waitid() = {}", pid);

                    let poll = TASKS.with(|hashtable| {
                        let waker = Arc::new(WaitidWaker { }).into_waker();
                        hashtable
                            .borrow_mut()
                            .get_mut(&Pid::from_raw(pid))
                            .expect("No such entry, should have been there.")
                            .as_mut()
                            .poll(&mut Context::from_waker(& waker))
                    });

                    match poll {
                        Poll::Pending => {} // Made progress but still pending.
                        Poll::Ready(_) => {
                            TASKS.with(|tb| {
                                tb.borrow_mut().
                                    remove(& Pid::from_raw(pid)).
                                    expect("entry should have been there...");
                            });
                            if TASKS.with(|tb| { tb.borrow().is_empty() }) {
                                debug!("All done!");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}
