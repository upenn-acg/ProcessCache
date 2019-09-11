use log::trace;
use std::ptr::null;
use futures::task::{RawWaker, RawWakerVTable, Waker};
use nix::unistd::Pid;
use crate::WAITING_TASKS;

const WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(WaitidWaker::clone,
                                                         WaitidWaker::wake,
                                                         WaitidWaker::wake_by_ref,
                                                         WaitidWaker::drop);
use crate::NEXT_TASK;
pub struct WaitidWaker {
    pub pid: Pid
}

impl WaitidWaker {
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

    unsafe fn wake_by_ref(data: *const ()) {

    }
    unsafe fn drop(data: *const ()) {

    }

    pub fn wait_waker(&self) -> Waker {
        let raw = RawWaker::new(&self.pid as *const Pid as *const (), &WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}
