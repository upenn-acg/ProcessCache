use log::{debug, info, trace};
use nix::unistd::Pid;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

pub mod ptrace_event;
pub mod task;
use crate::task::Task;
use std::task::Context;
use std::task::Poll;
use tracing::{event, span, Level};

thread_local! {
    pub static WAITING_TASKS: RefCell<HashMap<Pid, Task>> =
        RefCell::new(HashMap::new());
    pub static NEXT_TASK: RefCell<Option<Task>> = RefCell::new(None);
}

/// Allow our Executor to handle any single-threaded polling IO.
/// The only requirement is that the reactor blocks until an event comes,
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
    /// Keep track of live processes. Allows us to detect duplicates.
    task_pids: RefCell<HashSet<Pid>>,
}

impl<R: Reactor> SingleThreadedRuntime<R> {
    pub fn new(reactor: R) -> Self {
        SingleThreadedRuntime {
            reactor: RefCell::new(reactor),
            task_pids: RefCell::new(HashSet::new()),
        }
    }

    /// Add future to our executor and poll once to start running it.
    pub fn add_future(&self, mut task: Task) {
        let s = span!(Level::INFO, "add_future()");
        s.in_scope(|| event!(Level::INFO, ?task.pid, "Adding new task to executor"));

        // Guard against the user passing the same PID for an existing task.
        if !self.task_pids.borrow_mut().insert(*task.pid) {
            panic!(
                "Pid {} already existed for another Task. This is a duplicate",
                task.pid
            );
        }

        let waker = task.get_waker();

        match task.future.as_mut().poll(&mut Context::from_waker(&waker)) {
            Poll::Pending => {
                s.in_scope(|| trace!("Still executing..."));

                WAITING_TASKS.with(|ht| {
                    if let Some(existing) = ht.borrow_mut().insert(*task.pid, task) {
                        panic!("Existing task already found for: {:?}", existing.pid);
                    }
                });
            }
            Poll::Ready(_) => {
                info!("Future finished successfully!");
                // All done don't bother adding...
            }
        }
    }

    pub fn run_all(&self) {
        trace!("Running all futures.");

        // The future may have polled and finished in the add_future method.
        // Let program continue running (no more tasks for us to execute).
        let no_waiting_tasks = WAITING_TASKS.with(|tb| tb.borrow().is_empty());
        if no_waiting_tasks {
            info!("No waiting tasks. All done!");
            return;
        }

        let mut all_done = false;
        while !all_done {
            WAITING_TASKS.with(|wt|{
                let mut v = vec![];
                for (_, task) in wt.borrow().iter() {
                    v.push(*task.pid);
                }
                trace!("Waiting Tasks: {:?}", v);
            });

            // Block here for actual events to come.
            // After this line, NEXT_TASK should contain the next task :b
            self.reactor.borrow_mut().wait_for_event();

            NEXT_TASK.with(|nt| {
                let mut task = nt
                    .borrow_mut()
                    .take()
                    .expect("No such entry, should have been there.");
                let waker = task.get_waker();

                // as_mut(&mut self) -> Pin<&mut <P as Deref>::Target>
                let poll = task.future.as_mut().poll(&mut Context::from_waker(&waker));

                WAITING_TASKS.with(|tasks| {
                    match poll {
                        // Move task back to waiting tasks.
                        Poll::Pending => {
                            if tasks.borrow_mut().insert(*task.pid, task).is_some() {
                                // Somehow the task was already in there...
                                panic!("Task already existed in tasks. This is a duplicate.");
                            }
                        }
                        // Event for this task has arrived.
                        Poll::Ready(_) => {
                            if tasks.borrow().is_empty() {
                                info!("All tasks finished!");
                                all_done = true;
                            }

                            // This task is forever done. Remove from our active Pid set.
                            if !self.task_pids.borrow_mut().remove(&task.pid) {
                                panic!("Pid {} not found in our active Pid list.", task.pid);
                            }
                            debug!("Task {} done!", task.pid);
                        }
                    }
                });
            });
        }
    }
}
