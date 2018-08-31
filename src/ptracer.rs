/// As we're accepting arbitrary interleaving between ptrace child processes
/// we must keep track of whether we have already ptrace-continued a process and are
/// merely waiting for it's even to return through wait() or we must ptrace first.
#[derive(PartialEq, Copy, Clone)]
pub enum NextAction {
    Continue,
    Wait,
}

/// Keep track of which system call hook we're currently on.
#[derive(PartialEq, Copy, Clone)]
pub enum SystemCallMode {
    PreHook,
    PostHook,
}
