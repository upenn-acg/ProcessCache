use util::*;

use system_call_names::SYSTEM_CALL_NAMES;

use libc::{user_regs_struct};
use libc::c_char;

use nix::sys::wait::*;
use nix::unistd::*;

use nix::sys::ptrace::Event::*;
use nix::sys::signal::Signal;

use std::collections::HashMap;
use log::Level;

use ptracer;
use nix;
use ptracer::*;

use generator::{get_yield, yield_with, Gn, Generator, Scope};


pub fn run_tracer(starting_pid: Pid) -> nix::Result<()> {
    use nix::sys::wait::WaitStatus::*;

    // Wait for child to be ready.
    let _s: WaitStatus = waitpid(starting_pid, None)?;

    // Child ready!
    ptrace_set_options(starting_pid)?;

    // Loop over all events in the program.
    let current_pid = starting_pid;

    loop {
        ptrace_syscall(current_pid, None)?;

        // Wait for any event from any tracee.
        match waitpid(current_pid, None)? {
            // We have exited all the way. Don't keep track of this process anymore.
            Exited(pid, _) => {
                break;
            }

            // Our process has been killed by signal
            Signaled(pid, signal, _) => {
                info!("[{}] Our process has been killed by signal {:?}", pid, signal);
                break;
            }

            // We were stopped by a signal, deliver this signal to the tracee.
            Stopped(pid, signal) => {
                info!("[{}] Received stopped event {:?}", pid, signal);
            }

            PtraceEvent(pid,_, status)
                if PTRACE_EVENT_FORK  as i32 == status ||
                   PTRACE_EVENT_CLONE as i32 == status ||
                   PTRACE_EVENT_VFORK as i32 == status => {
                       info!("[{}] Saw clone event.", pid);
                   }

            PtraceEvent(pid,_, status)
                if PTRACE_EVENT_EXEC as i32 == status => {
                    info!("[{}] Saw exec event.", pid);
                }

            PtraceEvent(pid,_, status)
                if PTRACE_EVENT_EXIT as i32 == status => {
                    info!("[{}] Saw exit event.", pid);
                }

            PtraceSyscall(pid) => {
                let regs = Regs::get_regs(pid);
                let name = SYSTEM_CALL_NAMES[regs.orig_rax() as usize];
                info!("[{}] {}", pid, name);

                if name == "getcwd" {
                    let mut g = Gn::new_scoped(|mut s| {
                        getcwd(regs, pid, s);
                        Action::Done
                    });

                    g.resume();

                    // Let coroutine run until we hit an action.
                    ptrace_syscall(current_pid, None)?;

                    // Wait for any event from any tracee.
                    waitpid(current_pid, None)?;
                    g.resume();
                }
            }

            s => {
                panic!("Unhandled case for WaitStatus: {:?}", s);
            }
        };

    }

    info!("Process finished!");

    Ok(())
}

// pub struct Scope<A, T>;
// receives A's, Sends T's
fn getcwd(regs: Regs, pid: Pid, mut gen: Scope<(), Action>){
    // Pre-hook
    let regs = await_posthook(regs, pid, gen);
    // Post-hoo
    let buf: *const c_char = regs.arg1();
    let length: isize = regs.arg2();
    let cwd = read_string(buf, pid);
    info!("cwd({}, {})", cwd, length);
}

fn await_posthook<T>(regs: Regs, pid: Pid, mut gen: Scope<T, Action>) -> Regs {
    // Blocks until event arrives.
    gen.yield_with(Action::PostHook(regs, pid));
    // new_regs
    Regs::get_regs(pid)
}

enum Action {
    PostHook(Regs, Pid),
    Done,
}




