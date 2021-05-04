use nix::sys::signal::Signal;
use nix::unistd::Pid;
use std::collections::{HashMap, HashSet};

use crate::context;
use anyhow::{bail, Context, Result};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::ptr::null;
use std::rc::Rc;
use std::task::{Poll, RawWaker, RawWakerVTable, Waker};
#[allow(unused_imports)]
use tracing::{debug, error, event, info, span, trace, warn, Level};

/// Future representing getting the next ptrace event for `pid`.
pub struct AsyncPtrace {
    pub pid: Pid,
}

impl Future for AsyncPtrace {
    type Output = WaitStatus;

    /// Poll to see if ptrace event has arrived. Poll cannot return a Result.
    /// So we panic if failure occurs.
    fn poll(self: Pin<&mut Self>, _cx: &mut std::task::Context) -> Poll<WaitStatus> {
        match waitpid(self.pid, Some(WaitPidFlag::WNOHANG)).expect("Unable to waitpid from poll") {
            WaitStatus::StillAlive => Poll::Pending,
            w => Poll::Ready(w),
        }
    }
}

#[derive(Clone)]
pub struct AsyncRuntime {
    waiting_tasks: Rc<RefCell<HashMap<Pid, Task<Result<()>>>>>,
    /// We need to keep track if we saw an unknown child's PID before the parent's ForkEvent. This
    /// way we know whether the child needs to be ran since it is in a stopped state, or whether
    /// we just haven't seen this child yet.
    lost_children: Rc<RefCell<HashSet<Pid>>>,
}

impl AsyncRuntime {
    /// Our async runtime takes the function it should use to spawn tasks. We create new tasks from
    /// `run_fn` whenever a new PID is seen.
    pub fn new() -> Self {
        AsyncRuntime {
            waiting_tasks: Rc::new(RefCell::new(HashMap::new())),
            lost_children: Rc::new(RefCell::new(HashSet::new())),
        }
    }

    /// Execute with the process corresponding to `pid`.
    pub fn run_task(
        &self,
        initial_pid: Pid,
        starting_future: impl Future<Output = Result<()>> + 'static,
    ) -> Result<()> {
        let sys_span = span!(Level::INFO, "run_task");
        sys_span.in_scope(|| info!("Starting executor with task: {:?}", initial_pid));

        // Poll initial task once to get the whole thing rolling.
        let mut task = Task::new(starting_future, initial_pid);

        if self.poll_once(&mut task)? {
            return Ok(());
        } else {
            self.add_waiting_task(task)?;
        }

        loop {
            let mut next_task = self
                .next_ready_task()
                .with_context(|| context!("Reactor failed to get next event."))?;

            sys_span.in_scope(|| trace!("Next task arrived for {:?}", next_task.pid));
            match next_task.poll_task() {
                Poll::Ready(r) => {
                    r.with_context(|| context!("Task {:?} failed.", next_task.pid))?;

                    // All done executing futures!
                    if self.waiting_tasks.borrow().is_empty() {
                        info!("No more tasks to execute! Executor done.");
                        return Ok(());
                    }
                }
                Poll::Pending => {
                    self.add_waiting_task(next_task)?;
                }
            }
        }
    }

    fn poll_once(&self, task: &mut Task<Result<()>>) -> anyhow::Result<bool> {
        match task.poll_task() {
            Poll::Ready(r) => {
                r.with_context(|| context!("Initial task failed immediately with error."))?;
                return Ok(true);
            }
            Poll::Pending => Ok(false),
        }
    }

    /// Add a new task for the process identified by `pid` to run in our async runtime. This function
    /// should be called on a Fork/VFork/Clone event to spawn a task that will track the child
    /// process. Sometimes the ForkEvent arrives before the new child process is ready to be traced,
    /// but the child process may also be ready before the ForkEvent. If the child is ready, it will
    /// be polled once, otherwise the runtime will wait until the child arrives before polling it.
    pub fn add_new_task(
        &self,
        pid: Pid,
        future: impl Future<Output = Result<()>> + 'static,
    ) -> anyhow::Result<()> {
        info!("Adding new task for process {:?}", pid);

        // Poll task once!
        let mut starting_task = Task::new(future, pid);

        // We have seen this child, it is ready and waiting to be polled. *Facebook poke*
        if self.lost_children.borrow().contains(&pid) {
            self.lost_children.borrow_mut().remove(&pid);

            // Poll once to get running. Return if done.
            if self.poll_once(&mut starting_task)? {
                return Ok(());
            }
        }

        self.add_waiting_task(starting_task)?;
        Ok(())
    }

    fn add_waiting_task(&self, starting_task: Task<Result<()>>) -> Result<()> {
        if self
            .waiting_tasks
            .borrow_mut()
            .insert(starting_task.pid, starting_task)
            .is_some()
        {
            bail!(context!("Task already existed in waiting tasks."));
        }
        Ok(())
    }

    /// Poll all our running tasks to see which one is ready to be executed!
    fn next_ready_task(&self) -> Result<Task<Result<()>>> {
        let _e = span!(Level::INFO, "next_ready_task").entered();
        trace!("Waiting for next ptrace event...");

        // I wish there a way to get back all the PIDs that are ready...
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
            0 => {
                // Some pid is ready, query siginfo to see who it was.
                let pid = Pid::from_raw(unsafe { siginfo.si_pid() });
                trace!("... Next ptrace event arrived for Pid {}", pid);

                // We have never seen this PID before. This is most likely a race condition
                // caused by the SIGSTOP signal getting to us from the child before the parent
                // added the child task to the AsyncRuntime.
                if !self.waiting_tasks.borrow().contains_key(&pid) {
                    trace!("Lost child PID observed: {:?}", pid);

                    // Take the child's SIGSTOP event off the queue. This is necessary otherwise
                    // we won't be able to get the next event from the ptrace "event queue".
                    let status = waitpid(pid, None).with_context(|| {
                        context!("Unable to skip SIGSTOP from lost child process.")
                    })?;

                    if !matches!(status, WaitStatus::Stopped(_, Signal::SIGSTOP)) {
                        let e = format!("Unexpected WaitStatus from unknown child: {:?}", status);
                        warn!(%e);
                        bail!(context!("{}", e));
                    }

                    if !self.lost_children.borrow_mut().insert(pid) {
                        bail!(context!("Lost child has already been seen."));
                    }

                    // Recursively wait for next task. Eventually, we will get the ForkEvent in the
                    // parent which will put the correct event for the child.
                    self.next_ready_task()
                } else {
                    let mut wt = self.waiting_tasks.borrow_mut();
                    Ok(wt.remove(&pid).unwrap())
                }
            }
            -1 => {
                bail!(context!("waitid failed with {}", nix::Error::last()));
            }
            n => bail!(context!("Unexpected return code from waitid: {}", n)),
        }
    }
}

/// Represents a running future ready to be polled. Use `poll_task` function to poll it.
/// We do not use the `Waker` at all. We simply implement it to satisfy the type constraints on
/// the poll function. DO NOT call waker methods. They don't do anything.
pub struct Task<O> {
    pub pid: Pid,
    /// Instantiation of our futures are stored here!
    future: Pin<Box<dyn Future<Output = O>>>,
}

impl<O> Task<O> {
    pub fn new(future: impl Future<Output = O> + 'static, pid: Pid) -> Task<O> {
        Task {
            pid,
            future: Box::pin(future),
        }
    }

    /// Poll this task once.
    fn poll_task(&mut self) -> Poll<O> {
        let waker = self.get_waker();
        self.future
            .as_mut()
            .poll(&mut std::task::Context::from_waker(&waker))
    }

    /// Get waker that does nothing! Used to call `poll` method on our future.
    fn get_waker(&self) -> Waker {
        let raw = RawWaker::new(null(), &Task::<O>::WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }

    unsafe fn wake(_data: *const ()) {}
    unsafe fn clone(data: *const ()) -> RawWaker {
        RawWaker::new(data, &Task::<O>::WAKER_VTABLE)
    }
    unsafe fn wake_by_ref(_data: *const ()) {}
    unsafe fn drop(_data: *const ()) {}
    const WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        Task::<O>::clone,
        Task::<O>::wake,
        Task::<O>::wake_by_ref,
        Task::<O>::drop,
    );
}
