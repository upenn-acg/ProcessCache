use log::{debug, info, trace};
use nix::unistd::Pid;
use std::cell::RefCell;
use std::collections::HashMap;

pub mod ptrace_event;
pub mod task;

use crate::task::Task;
use std::task::Context;
use std::task::Poll;

thread_local! {
    pub static WAITING_TASKS: RefCell<HashMap<Pid, Task>> =
        RefCell::new(HashMap::new());
    pub static NEXT_TASK: RefCell<Option<Task>> = RefCell::new(None);
}

/// Allow our Executor to handle any single-threaded polling IO.
/// The only requirment is that the reactor blocks until an event comes,
/// and that it sets the next task to run in NEXT_TASK. Notice this means only one
/// task can be "ready" at a time, this is true for waitpid, but it may not be
/// true for a general block polling method, a more generalized executor would
/// support multiple ready tasks after `wait_for_event`.
pub trait Reactor {
    /// Return value indicates when all processes have finished running?
    fn wait_for_event(&mut self) -> bool;
}

/// This is our futures runtime. It is responsible for accepting futures to run,
/// polling them, registering the Pid the future is waiting for, and scheduling,
/// the next task to run.
pub struct SingleThreadedRuntime<R> {
    /// The reactor is RefCelled so it can be implemented with mutable methods.
    /// This "hides" the mutability as we want the methods of SingleThreadedRuntime
    /// to appear inmutable, this is needed as we need to dynamically add processes
    /// via run_process. So every run_process function needs a reference to
    /// SingleThreadedRuntime, this RefCell avoids issues with borrowing and
    /// mutability for the code that uses it.
    reactor: RefCell<R>,
}

impl<R: Reactor> SingleThreadedRuntime<R> {
    pub fn new(reactor: R) -> Self {
        SingleThreadedRuntime {
            reactor: RefCell::new(reactor),
        }
    }

    pub fn add_future(&self, mut task: Task) {
        info!("Adding new future through handle.");
        let waker = task.wait_waker();

        match task.future.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Pending => {
                trace!("Polled once, still pending.");
                // Made progress but still pending. Add to our queue.
                WAITING_TASKS.with(|ht| {
                    // TODO What should happen if the  value is already present?
                    ht.borrow_mut().insert(*task.pid, task);
                });
            }
            Poll::Ready(_) => {
                info!("Future finished successfull!");
                // All done don't bother adding...
            }
        }
    }

    pub fn run_all(&self) {
        info!("Running all futures.");
        // The future may have polled and finished in the add_future method.
        // Let program continue running (no more tasks for us to execute).
        let no_waiting_tasks = WAITING_TASKS.with(|tb| tb.borrow().is_empty());
        if no_waiting_tasks {
            debug!("All done!");
            return;
        }

        let mut all_done = false;

        while !all_done {
            // Block here for actual events to come.
            self.reactor.borrow_mut().wait_for_event();

            NEXT_TASK.with(|nt| {
                let mut task = nt
                    .borrow_mut()
                    .take()
                    .expect("No such entry, should have been there.");
                let waker = task.wait_waker();

                // as_mut(&mut self) -> Pin<&mut <P as Deref>::Target>
                let poll = task.future.as_mut().poll(&mut Context::from_waker(&waker));

                WAITING_TASKS.with(|tasks| {
                    match poll {
                        // Move task back to waiting tasks.
                        Poll::Pending => {
                            tasks.borrow_mut().insert(*task.pid, task);
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
