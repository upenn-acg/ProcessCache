extern crate libc;
extern crate nix;
extern crate byteorder;
extern crate structopt;
extern crate env_logger;
#[macro_use] extern crate log;

mod system_call_names;
mod util;
mod args;
mod ptracer;

use util::*;
use args::*;
use structopt::StructOpt;

use system_call_names::SYSTEM_CALL_NAMES;

use libc::{user_regs_struct};
use nix::sys::ptrace;
use nix::sys::wait::*;
use nix::unistd::*;
use std::ffi::CString;

use nix::sys::ptrace::Event::*;
use nix::sys::signal::Signal;
use nix::sys::signal::raise;

use log::Level;
use std::collections::HashMap;
use std::process::exit;
use ptracer::SystemCallMode;

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

struct ProcessStatus {
    action: ptracer::NextAction,
    // Signal to deliver next.
    signal: Option<Signal>,
    syscall_mode: ptracer::SystemCallMode,
}

impl ProcessStatus {
    fn new() -> ProcessStatus {
        ProcessStatus {
            action: ptracer::NextAction::Continue,
            signal: None,
            syscall_mode: ptracer::SystemCallMode::PreHook,
        }
    }

    fn reset_signal(&mut self){
        self.signal = None;
    }

    fn to_action_continue(&mut self){
        self.action = ptracer::NextAction::Continue;
    }

    fn to_action_wait(&mut self){
        self.action = ptracer::NextAction::Wait;
    }
}

fn run_tracer(starting_pid: Pid) -> nix::Result<()> {
    use nix::sys::wait::WaitStatus::*;
    let mut process_status : HashMap<Pid, ProcessStatus> = HashMap::new();
    process_status.insert(starting_pid, ProcessStatus::new());

    // Wait for child to be ready.
    let _s: WaitStatus = waitpid(starting_pid, None)?;

    // Child ready!
    ptrace_set_options(starting_pid)?;

    // Loop over all events in the program.
    let mut current_pid = starting_pid;

    loop {
        // Let tracee continue until next ptrace event.
        let action = process_status.get(& current_pid).unwrap().action;
        if action == ptracer::NextAction::Continue {
            trace!("[{}] ptrace continue.", current_pid);

            let signal = process_status.get(& current_pid).unwrap().signal;
            ptrace_syscall(current_pid, signal).expect("Unable to call ptrace");
            // Change to wait.
            process_status.get_mut(& current_pid).unwrap().to_action_wait();

            // Reset value.
            process_status.get_mut(& current_pid).unwrap().reset_signal();
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
                // This may be a new pid add it if not present!
                process_status.entry(pid).or_insert(ProcessStatus::new());
                process_status.get_mut(& pid).unwrap().signal = Some(signal);
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

                    // Find new process to run, in case this process is blocked on some
                    // system call.
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
                let syscall_mode = &mut process_status.get_mut(& pid).unwrap().syscall_mode;
                handle_system_call(regs, pid, * syscall_mode);

                *syscall_mode = match syscall_mode {
                    SystemCallMode::PreHook => SystemCallMode::PostHook,
                    SystemCallMode::PostHook => SystemCallMode::PreHook,
                };

                pid
            }

            s => {
                panic!("Unhandled case for WaitStatus: {:?}", s);
            }
        };

        // If we got here, the process should do a ptrace continue again.
        process_status.get_mut(& current_pid).unwrap().to_action_continue();
    }

    info!("Process finished!");

    Ok(())
}

fn handle_system_call(regs: user_regs_struct,
                      pid : Pid,
                      syscall_mode: ptracer::SystemCallMode){
    if syscall_mode == ptracer::SystemCallMode::PreHook {
        // if debug_level()
        let name = SYSTEM_CALL_NAMES[regs.orig_rax as usize];
        info!("[{}] {}", pid, name);
    }
}
