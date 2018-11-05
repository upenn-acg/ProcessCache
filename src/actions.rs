use std::collections::HashSet;
use nix::unistd::Pid;
use nix::sys::signal::Signal;

/// Action represents events that a coroutine yields to wait for.
/// The main thread takes this action, and runs ptrace until the correct
/// action is found. A coroutine may wait on multiple action waiting for either or
/// to arrive. Thus the main thread returns the action that actually happened.
#[derive(PartialEq, Debug, Eq, Hash, Clone)]
pub enum Action {
    /// Seccomp event, basically, a pre-hook event. TODO later we may parameterize it
    /// with a system call number we're waiting for.
    Seccomp,
    /// Execve event, only happens on successful call to execve.
    Execve,
    /// Wait for the post-hook, otherwise the posthook is entirely skipped.
    PostHook,
    /// Ptrace's exit notification before the true exit.
    EventExit,
    /// True exit.
    ActualExit,
    /// Inform the main thread that this coroutine is done running and should free
    /// it's memory.
    Done,
    /// Inform the the main thread that this process has exited for good.
    /// There is clean up it should do.
    ProcessExited,
    /// Add New Process, with pid to our live_process set.
    AddNewProcess(Pid),
    /// For event caught! Call handler.
    Fork,
    /// Received a signal.
    Signal(Signal),
}

impl Into<Actions> for Action {
    fn into(self) -> Actions {
        let mut set = HashSet::new();
        set.insert(self);
        set
    }
}


pub type Actions = HashSet<Action>;


pub fn new_actions(array: &[Action]) -> Actions {
    // array.into_iter().fold(HashSet::new(), |set, e| h.insert(*e)).collect()
    let mut set: HashSet<Action> = HashSet::new();

    for e in array {
        set.insert(e.clone());
    }

    set
}

