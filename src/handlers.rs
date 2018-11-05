use actions::*;
use ptracer::*;
use nix::sys::wait::*;
use coroutines::Yielder;
use nix::unistd::Pid;
use libc::c_char;
use std::ptr::null;
use nix::sys::signal::Signal;
use system_call_names::*;

pub fn handle_exit(mut y: Yielder) {
    debug!("handle_exit: waiting for actual exit event...");
    // Wait for actual exit to come.
    let actions = new_actions(& [Action::ActualExit]);
    y.yield_with(actions);

    // In ActualExit
    debug!("handle_exit: saw actual exit event.");
    let actions = new_actions(& [Action::ProcessExited, Action::Done]);
    y.yield_with(actions);
}

pub fn handle_execve(regs: Regs<Unmodified>, pid: Pid, mut y: Yielder) {
    let arg1 = regs.arg1() as *const c_char;
    let exe = read_string(arg1, pid);
    info!("[{}] executable: {}", pid, exe);

    let argv = regs.arg2() as *const *const c_char;

    // Read all of argv
    for i in 0.. {
        let p = read_value(unsafe { argv.offset(i) }, pid);
        if p == null() { break; }

        let arg = read_string(p, pid);
        info!("[{}] arg{}: {}", pid, i, arg);
    }

    let res = await_execve(y);
    info!("await_execve results: {:?}", res);

    fn await_execve(mut y: Yielder) -> Action {
        // Wait for either postHook of execve (in case of failure),
        // Or execve event on succ
        let actions = new_actions(& [Action::PostHook, Action::Execve]);
        y.yield_with(actions);
        y.get_yield().unwrap()
    }
}
