#![feature(generators, generator_trait)]
extern crate libc;
extern crate nix;
extern crate byteorder;
extern crate structopt;
extern crate env_logger;
#[macro_use] extern crate log;

mod system_call_names;
mod util;
mod args;

use util::*;
use args::*;
use structopt::StructOpt;

use system_call_names::SYSTEM_CALL_NAMES;

use libc::{c_void, user_regs_struct};
use nix::sys::ptrace;
use nix::sys::wait::*;
use nix::unistd::*;
use std::ffi::CString;

use std::ops::{Generator, GeneratorState};

use nix::sys::wait::WaitStatus::*;
use nix::sys::ptrace::Event;
use nix::sys::ptrace::Event::*;
use nix::sys::signal::Signal;
use nix::Error::Sys;
use nix::sys::signal::raise;

use log::Level;
use std::collections::HashMap;
use std::process::exit;

struct Command(String, Vec<String>);

impl Command {
    fn new(exe: String, args: Vec<String>) -> Self {
        Command(exe, args)
    }
}

/// Strace program written in Rust.
fn main() -> nix::Result<()> {
    // Init logger with no timestamp data.
    env_logger::Builder::from_default_env().default_format_timestamp(false).init();

    let opt = Opt::from_args();
    let command = Command::new(opt.exe, opt.exe_args);

    match fork()? {
        ForkResult::Parent { child } => run_tracer(child),
        ForkResult::Child => run_tracee(command),
    }
}

/// This function should be called after a fork.
/// uses execve to call the tracee program and have it ready to be ptraced.
fn run_tracee(command: Command) -> nix::Result<()> {
    // New ptracee and set ourselves to be traced.
    ptrace::traceme()?;
    // Stop ourselves until the tracer is ready. This ensures the tracer has time
    // to get set up.
    raise(Signal::SIGSTOP)?;

    // Convert arguments to correct arguments.
    let exe = CString::new(command.0).unwrap();
    let mut args: Vec<CString> = command
        .1
        .into_iter()
        .map(|s| CString::new(s).unwrap())
        .collect();
    args.insert(0, exe.clone());

    if let Err(e) = execvp(&exe, &args) {
        error!("Error executing execve for your program {:?}. Reason {}", args, e);
        // TODO parent does not know that child exited it may report a weird abort
        // message.
        exit(1);
    }

    Ok(())
}

fn run_tracer(starting_pid: Pid) -> nix::Result<()> {
    /// As we're accepting arbitrary interleaving between ptrace child processes
    /// we must keep track of whether we have already ptrace-continued a process and are
    /// merely waiting for it's even to return through wait() or we must ptrace first.
    #[derive(PartialEq)]
    enum PtraceNextAction {
        Continue,
        Wait,
    }
    use nix::sys::wait::WaitStatus::*;
    let mut process_status : HashMap<Pid, PtraceNextAction> = HashMap::new();
    let mut signal_to_deliver : HashMap<Pid, Option<Signal>> = HashMap::new();
    process_status.insert(starting_pid, PtraceNextAction::Continue);
    signal_to_deliver.insert(starting_pid, None);


    // Wait for child to be ready.
    let _s: WaitStatus = waitpid(starting_pid, None)?;

    // Child ready!
    ptrace_set_options(starting_pid)?;

    // Loop over all events in the program.
    let mut current_pid = starting_pid;

    loop {
        // Let tracee continue until next ptrace event.
        if *process_status.get(& current_pid).unwrap() == PtraceNextAction::Continue {
            trace!("[{}] ptrace continue.", current_pid);

            let signal = * signal_to_deliver.get(& current_pid).unwrap();
            ptrace_syscall(current_pid, signal).expect("Unable to call ptrace");

            // Reset values.
            signal_to_deliver.insert(current_pid, None);
            process_status.insert(current_pid, PtraceNextAction::Wait);
        }

        // Wait for any event from any tracee.
        current_pid = match waitpid(None, Some(WaitPidFlag::WNOHANG))? {

            // We have exited all the way. Don't keep track of this process anymore.
            Exited(pid, _) => {
                process_status.remove(& pid);
                info!("Process exited");
                if process_status.is_empty() {
                    info!("All done!");
                    break;
                }
                // We just checked if the pids is empty, this is impossible to panic.
                current_pid = *process_status.iter().next().unwrap().0;
                continue;
            }

            // Our process has been killed by signal
            Signaled(pid, signal, _) => {
                info!("[{}] Our process has been killed by signal {:?}", pid, signal);
                pid
            }

            // We were stopped by a signal, deliver this signal to the tracee.
            Stopped(pid, signal) => {
                info!("[{}] Received stopped event {:?}", pid, signal);
                signal_to_deliver.insert(pid, Some(signal));
                pid
            }

            // We're running waitpid as non-blocking, it is "too fast" and will race
            // the kernel to waitpid events. So we must sometimes loop multiple times
            // before the event is there.

            // Otherwise, it might be this process is waiting for a resource. Let
            // somebody else run.
            StillAlive => {
                debug!("[{}] Nothing to wait on, looking for new process.", current_pid);
                for pid in &process_status{
                    if *pid.0 != current_pid {
                        current_pid = *pid.0;
                        debug!("New process picked: {}", current_pid);
                        break;
                    }
                };

                continue;
            }

            PtraceEvent(pid,_, status)
                if PTRACE_EVENT_FORK  as i32 == status ||
                   PTRACE_EVENT_CLONE as i32 == status ||
                   PTRACE_EVENT_VFORK as i32 == status => {
                       info!("[{}] Saw clone event.", pid);
                       pid
                   }

            PtraceEvent(pid,_, status)
                if PTRACE_EVENT_EXEC as i32 == status => {
                    info!("[{}] Saw exec event.", pid);
                    pid
                }

            PtraceEvent(pid,_, status)
                if PTRACE_EVENT_EXIT as i32 == status => {
                    info!("[{}] Saw exit event.", pid);
                    pid
                }

            PtraceSyscall(pid) => {
                let regs = get_regs(pid);
                handle_system_call(regs, pid);
                pid
            }

            s => {
                panic!("Unhandled case for WaitStatus: {:?}", s);
            }
        };

        process_status.insert(current_pid, PtraceNextAction::Continue);
        signal_to_deliver.entry(current_pid).or_insert(None);
    }

    info!("Process finished!");

    Ok(())
}

fn handle_execve(regs: user_regs_struct, pid : Pid) ->
impl Generator<Yield=(), Return=()> {
    use ExecveResults::*;

    move || {
        if log_enabled!(Level::Info) {
            let arg1 = regs.rdi as *mut c_void;
            let path = read_string(arg1, pid);
            info!("execve: path {}", path);
        }
        debug!("path printed.");
        match await_execve(pid) {
            // System call failed with -1 => No Execve Event
            PostHook(_) => {
                debug!("execve returned -1");
            }
            // Success! Execve event, wait for post hook event.
            ExecveEvent => {
                await_post_hook(pid);
            }
        }

        if false {
            yield ();
        }
    }
}

enum ExecveResults{
    PostHook(user_regs_struct),
    ExecveEvent,
}

fn await_execve(pid: Pid) -> ExecveResults {
    use ExecveResults::*;

    ptrace::syscall(pid).unwrap();
    match waitpid(pid, None).unwrap() {
        // PTRACE_EVENT_EXEC
        PtraceEvent(_,_, status) if PTRACE_EVENT_EXEC as i32 == status => {
            info!("Saw execve event!");
            ExecveEvent
        }
        // Execve Post Hook
        PtraceSyscall(_) => {
            info!("Saw post-hook event");
            PostHook(get_regs(pid))
        }
        e => panic!("Unexpected ptrace even when awaiting_post_hook: {:?}", e),
    }

}

fn await_event(pid: Pid, ptrace_event: Event){
    ptrace::syscall(pid).unwrap();
    match waitpid(pid, None).unwrap() {
        PtraceEvent(_,_, status) if ptrace_event as i32 == status => {
            info!("await_event: saw an execve event!");
        }
        e => panic!("Unexpected ptrace {:?} when awaiting event.", e),
    }
}

fn await_post_hook(pid: Pid) -> user_regs_struct {
    info!("awaiting post hook for {}", pid);
    // Let tracee continue until next event.

    ptrace::syscall(pid).unwrap();
    match waitpid(pid, None).unwrap() {
            PtraceSyscall(_) => get_regs(pid),
            e => panic!("Unexpected ptrace even when awaiting_post_hook: {:?}", e),
    }
}

fn handle_system_call(regs: user_regs_struct, pid : Pid){
    // info!("[{}] {}", pid, name);
    // match name {
        // "execve" => {
            // let mut g = handle_execve(regs, pid);
            // match unsafe { g.resume() } {
                // GeneratorState::Complete(_) => {},
                // _ => panic!("unexpected value from resume"),
            // };
        // }
        // _ => { },
    // }
}
