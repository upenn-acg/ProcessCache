use nix::unistd::Pid;
use std::collections::HashMap;

use crate::context;
use anyhow::{bail, Context, Result};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use std::future::Future;
use std::pin::Pin;
use std::ptr::null;
use std::task::{Poll, RawWaker, RawWakerVTable, Waker};
#[allow(unused_imports)]
use tracing::{error, event, info, span, trace, Level};

/// Future representing getting the next ptrace event for `pid`.
pub struct AsyncPtrace {
    pub pid: Pid,
}

impl Future for AsyncPtrace {
    type Output = WaitStatus;

    /// Poll to see if ptrace event has arrived.
    /// Poll cannot return Result. So we panic if failure occurs.
    fn poll(self: Pin<&mut Self>, _cx: &mut std::task::Context) -> Poll<WaitStatus> {
        match waitpid(self.pid, Some(WaitPidFlag::WNOHANG)).expect("Unable to waitpid from poll") {
            WaitStatus::StillAlive => Poll::Pending,
            w => Poll::Ready(w),
        }
    }
}

pub struct AsyncRuntime<F, Fut> {
    waiting_tasks: HashMap<Pid, Task<Fut>>,
    run_fn: F,
}

impl<F, Fut> AsyncRuntime<F, Fut>
where
    // All this says is that F returns an async function.
    F: Fn(Pid) -> Fut,
    // Definition of an async function, desugared.
    Fut: Future<Output = Result<()>> + 'static,
{
    /// Our async runtime takes the function it should use to spawn tasks. We create new tasks from
    /// `run_fn` whenever a new PID is seen.
    pub fn new(run_fn: F) -> Self {
        AsyncRuntime {
            waiting_tasks: HashMap::new(),
            run_fn,
        }
    }

    /// Execute with the process corresponding to `pid`.
    pub fn run_task(mut self, initial_pid: Pid) -> Result<()> {
        let sys_span = span!(Level::INFO, "run_task");
        sys_span.in_scope(|| info!("Starting executor with task: {:?}", initial_pid));

        let mut initial_task = Task::new((self.run_fn)(initial_pid), initial_pid);

        // Poll once to get running.
        match initial_task.poll_task() {
            Poll::Ready(r) => {
                return Ok(
                    r.with_context(|| context!("Initial task failed immediately with error."))?
                );
            }
            Poll::Pending => {
                // We just added this task. It should never exist already. We still check it?
                if let Some(_) = self.waiting_tasks.insert(initial_task.pid, initial_task) {
                    unreachable!("Task already existed. This should be impossible");
                }
            }
        }

        loop {
            let next_task = self
                .next_ptrace_event()
                .with_context(|| context!("Reactor failed to get next event."))?;

            sys_span.in_scope(|| trace!("Next task arrived for {:?}", next_task.pid));
            match next_task.poll_task() {
                Poll::Ready(r) => {
                    let pid = next_task.pid;
                    r.with_context(|| context!("Task {:?} failed.", pid))?;

                    self.waiting_tasks.remove(&pid).with_context(|| {
                        context!("Failed to remove done task from waiting tasks.")
                    })?;

                    // All done executing futures!
                    if self.waiting_tasks.is_empty() {
                        info!("No more tasks to execute! Executor done.");
                        return Ok(());
                    }
                }
                Poll::Pending => {
                    // No need to add next_task back to waiting_tasks. It is still there, we merely
                    // have a reference.
                }
            }
        }
    }

    fn next_ptrace_event(&mut self) -> Result<&mut Task<Fut>> {
        let s = span!(Level::INFO, "next_ptrace_event()");
        let _e = s.enter();

        trace!("Waiting for next ptrace event...");
        // I wish there a way to get back all the PIDs that are ready.
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
                bail!(context!("Waitid failed with {}", nix::Error::last()));
            }
            0 => {
                // Some pid is ready, query siginfo to see who it was.
                let pid = Pid::from_raw(unsafe { siginfo.si_pid() });
                trace!("... Next ptrace event arrived for Pid {}", pid);

                if !self.waiting_tasks.contains_key(&pid) {
                    // We just checked this, no need to check return value of insert.
                    self.waiting_tasks
                        .insert(pid, Task::new((self.run_fn)(pid), pid));
                }

                let ret = self
                    .waiting_tasks
                    .get_mut(&pid)
                    .with_context(|| context!("Cannot get next task from waiting tasks."))?;
                Ok(ret)
            }
            n => bail!(context!("Unexpected return code from waitid: {}", n)),
        }
    }
}

/// Represents a running future ready to be polled. Use `poll_task` function to poll it.
/// We do not use the `Waker` at all. We simply implement it to satisfy the type contraints on
/// the poll function. DO NOT call waker methods. They don't do anything.
pub struct Task<Fut> {
    pub pid: Pid,
    /// Instantiation of our futures are stored here!
    future: Pin<Box<Fut>>,
}

impl<Fut> Task<Fut>
where
    Fut: Future + 'static,
{
    const WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        Task::<Fut>::clone,
        Task::<Fut>::wake,
        Task::<Fut>::wake_by_ref,
        Task::<Fut>::drop,
    );

    pub fn new(future: Fut, pid: Pid) -> Task<Fut> {
        Task {
            pid,
            future: Box::pin(future),
        }
    }

    /// Poll future.
    pub fn poll_task(&mut self) -> Poll<<Fut as Future>::Output> {
        let waker = self.get_waker();
        self.future
            .as_mut()
            .poll(&mut std::task::Context::from_waker(&waker))
    }

    unsafe fn wake(_data: *const ()) {}
    unsafe fn clone(data: *const ()) -> RawWaker {
        RawWaker::new(data, &Task::<Fut>::WAKER_VTABLE)
    }

    unsafe fn wake_by_ref(_data: *const ()) {}

    unsafe fn drop(_data: *const ()) {}

    pub fn get_waker(&self) -> Waker {
        let raw = RawWaker::new(null(), &Task::<Fut>::WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}
