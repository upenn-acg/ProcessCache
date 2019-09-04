use futures::core_reexport::pin::Pin;
use futures::future::Future;
use futures::task::{Context, Poll};

use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{Pid};
use log::trace;

/// Future representing calling ptrace() and waitpid() on a Pid.
pub struct AsyncPtrace {
    pub pid: Pid,
}

impl Future for AsyncPtrace {
    type Output = WaitStatus;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<WaitStatus> {
        trace!("AsyncPtrace polling once for: {}", self.pid);
        match waitpid(self.pid, Some(WaitPidFlag::WNOHANG)).
            expect("Unable to waitpid from poll") {
            WaitStatus::StillAlive => {
                Poll::Pending
            }
            w => Poll::Ready(w),
        }
    }
}
