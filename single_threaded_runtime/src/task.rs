use crate::NEXT_TASK;
use crate::WAITING_TASKS;

#[allow(unused_imports)]
use log::{info, trace, warn};

use nix::unistd::Pid;
use std::future::Future;
use std::pin::Pin;
use std::task::RawWaker;
use std::task::RawWakerVTable;
use std::task::Waker;

const WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(Task::clone, Task::wake, Task::wake_by_ref, Task::drop);

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T>>>;

pub struct Task {
    pub pid: Pin<Box<Pid>>,
    pub future: LocalBoxFuture<()>,
}

impl Task {
    pub fn new<F>(future: F, pid: Pid) -> Task
    where
        F: Future<Output = ()> + 'static,
    {
        // Pin it, and box it up for storing.
        Task {
            pid: Box::pin(pid),
            future: Box::pin(future),
        }
    }

    /// We cannot return a proper error from here as the function type wouldn't match for
    /// RawWakerVTable.
    unsafe fn wake(data: *const ()) {
        let pid = *(data as *const Pid);
        trace!("Waking up task: {}", pid);

        WAITING_TASKS.with(|tasks| {
            let task = tasks.borrow_mut().remove(&pid);
            if task.is_none() {
                panic!("Task {} not found in task list for waiting task.", pid);
            }

            NEXT_TASK.with(|next_task| {
                if next_task.borrow().is_some() {
                    panic!("Expected next task to be empty.");
                }

                next_task.replace(task);
            });
        });
    }
    unsafe fn clone(data: *const ()) -> RawWaker {
        RawWaker::new(data, &WAKER_VTABLE)
    }

    unsafe fn wake_by_ref(_data: *const ()) {}

    unsafe fn drop(_data: *const ()) {}

    pub fn get_waker(&self) -> Waker {
        // info!("get_waker() pid {}", self.pid);
        let p: *const () = &(*self.pid) as *const Pid as *const ();

        let raw = RawWaker::new(p, &WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}
