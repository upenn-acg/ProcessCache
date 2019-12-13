use nix::unistd::Pid;
use log::trace;
use crate::WAITING_TASKS;
use crate::NEXT_TASK;
use std::pin::Pin;
use std::task::RawWakerVTable;
use std::task::RawWaker;
use std::task::Waker;
use std::future::Future;

const WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(Task::clone,
                                                         Task::wake,
                                                         Task::wake_by_ref,
                                                         Task::drop);

type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub struct Task {
    pub pid: Pin<Box<Pid>>,
    pub future: LocalBoxFuture<'static, ()>,
}

impl Task {
    pub fn new<F>(future: F, pid: Pid) -> Task
    where F: Future<Output = ()> + 'static {
        // Pin it, and box it up for storing.
        Task { pid: Box::pin(pid), future: Box::pin(future)}
    }

    unsafe fn wake(data: *const ()) {
        let pid = *(data as *const Pid);
        trace!("Waking up: {:?}", pid);

        WAITING_TASKS.with(|tasks| {
            let task = tasks.borrow_mut().remove(&pid);
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

    unsafe fn wake_by_ref(_data: *const ()) {

    }
    unsafe fn drop(_data: *const ()) {

    }

    pub fn wait_waker(&self) -> Waker {
        let raw = RawWaker::new(&(*self.pid) as *const Pid as *const (), &WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}
