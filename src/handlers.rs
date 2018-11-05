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

    info!("res: {:?}", res);

    fn await_execve(mut y: Yielder) -> Action {
        // Wait for either postHook of execve (in case of failure),
        // Or execve event on succ
        let actions = new_actions(& [Action::PostHook, Action::Execve]);
        y.yield_with(actions);
        y.get_yield().unwrap()
    }
}


/// Starts as a seccomp event for fork, vfork, or clone.
/// We skip the post-hook event, we may receive either a fork event, or a signal
/// from the child.

/// Fork events represent an special case. We usually expect to call
/// ptrace(Continue | Syscall) and then waitpid to receive the single event that stopped
/// the process. However, fork events are special, it represents the only time (as far as
/// I know) where a single ptrace(Continue | Syscall) event maps to two different waitpid
/// events.
/// So the order in which get these two events isn't deterministic. We call ptrace(Continue)
/// here, on the parent, followed by a waitpid on the parent event, followed, by a waitpid
/// on the child signal event.
pub fn handle_fork(parent: Pid, mut y: Yielder) {
    info!("handle_fork: Waiting for event or signal...");
    use nix::sys::ptrace::Event::*;

    const ERESTARTNOINTR: i32 = -513;
    let mut signal = None;

    loop {
        ptrace_syscall(parent, ContinueEvent::Continue, signal);
        signal = None;

        match waitpid(parent, None).expect("handle_fork: Failed waitpid.") {
            WaitStatus::PtraceEvent(pid, signal, status)
                if PTRACE_EVENT_FORK  as i32 == status ||
                PTRACE_EVENT_CLONE as i32 == status ||
                PTRACE_EVENT_VFORK as i32 == status => {
                    info!("Got forking event!");
                    break;
                }

            WaitStatus::PtraceEvent(pid, signal, status)
                if PTRACE_EVENT_SECCOMP as i32 == status => {
                    let mut regs = Regs::get_regs(pid);
                    let syscall = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];
                    let errno = regs.retval() as i32;
                    println!("Unexpected. Seccomp event for: {}", syscall);
                    continue;
                }

            WaitStatus::Stopped(pid, my_signal) => {
                println!("Signal probably interrupted fork! {:?}", signal);
                signal = Some(my_signal);
            }
            s => {
                println!("ERROR: {:?} Unexpected event from handle_fork: {:?}", parent, s);
            }
        }
    }

    let child: Pid = Pid::from_raw(ptrace_getevent(parent) as i32);
    debug!("waiting for signal to arrive from: {}", child);

    // wait for child signal to arrive.
    let wait_status = ::nix::sys::wait::waitpid(child, None).
        expect("Unable to call waitpid on child for ForkEvent");

    // This should be a signal!
    match wait_status {
        WaitStatus::Stopped(pid, signal) => {
            debug!("signal arrived all done!");
        }
        s => panic!("ForkEvent: Unexpected event from handle_fork: {:?}", s),
    }

    // Let child continue, this way, we're set up for our waitpid(None) loop in the
    // main thread.
    ptrace_syscall(child, ContinueEvent::Continue, None).
        expect("Unable to call ptrace_syscall for child in handle_fork.");

    // Great, both events arrived and now we know who the child is.
    // Return name of new process for main thread to add:
    let actions = new_actions(& [Action::Done, Action::AddNewProcess(child)]);
    y.yield_with(actions);
}

fn check(name: &str, retval: i64) -> i64 {
  use std::process::exit;

  if retval == -1 {
    println!("{} check error\n", name);
    exit(1);
  }

  return retval;
}

fn isPtraceEvent(status: i32,  event: i32) -> bool {
    use libc::SIGTRAP;
    return (status >> 8) == (SIGTRAP | (event << 8));
}
