extern crate libc;
extern crate nix;
extern crate byteorder;
#[macro_use] extern crate log;
extern crate env_logger;
#[macro_use] extern crate structopt;

mod system_call_names;
mod util;
mod args;
use std::collections::HashSet;
use std::collections::HashMap;

use util::*;
use args::*;
use structopt::StructOpt;
use nix::sys::ptrace::Event::*;

use system_call_names::SYSTEM_CALL_NAMES;

use libc::{c_void, user_regs_struct};
use nix::sys::ptrace;
use nix::sys::wait::*;
use nix::unistd::*;
use nix::sys::signal::{raise, Signal};
use std::ffi::CString;

struct Command(String, Vec<String>);

impl Command {
    fn new(exe: String, args: Vec<String>) -> Self {
        Command(exe, args)
    }
}

/// Strace program written in Rust.
fn main() -> nix::Result<()> {
    env_logger::init();

    let opt = Opt::from_args();
    let command = Command::new(opt.exe, opt.exe_args);

    // Trace all
    let all_syscalls: HashSet<&str> =
        SYSTEM_CALL_NAMES.into_iter().map(|s| *s).collect();

    for entry in &opt.to_trace {
        if !all_syscalls.contains(entry.as_str()) {
            eprintln!("Invalid system call specified: {}", entry);
            return Ok(());
        }
    }

    for entry in &opt.dont_trace {
        if !all_syscalls.contains(entry.as_str()) {
            eprintln!("Invalid system call specified: {}", entry);
            return Ok(());
        }
    }

    let syscall_set =
        get_hashset_from_args(&opt.to_trace, &opt.dont_trace, all_syscalls);

    match fork()? {
        ForkResult::Parent { child } => run_tracer(child, &syscall_set),
        ForkResult::Child => run_tracee(command),
    }
}

fn run_tracee(command: Command) -> nix::Result<()> {
    // New ptracee and set ourselves to be traced.
    ptrace::traceme()?;

    // Stop ourselves until the tracer is ready. This ensures the tracer has time
    // to get set up.
    raise(Signal::SIGSTOP)?;

    let exe = CString::new(command.0).unwrap();
    let mut args: Vec<CString> = command
        .1
        .into_iter()
        .map(|s| CString::new(s).unwrap())
        .collect();
    args.insert(0, exe.clone());

    execvp(&exe, &args).map(|_| ())
}

fn run_tracer(starting_pid: Pid, to_trace: &HashSet<&str>) -> nix::Result<()> {
    use nix::sys::wait::WaitStatus::*;

    // Wait for child to be ready.
    let _s: WaitStatus = waitpid(starting_pid, None)?;
    println!("return status: {:?}", _s);

    // Child ready!
    ptrace_set_options(starting_pid)?;

    // Loop over all events in the program.
    let mut live_processes: HashSet<Pid> = HashSet::new();

    // Change to per process hash table.
    let mut pre_syscall: HashMap<Pid, bool> = HashMap::new();

    // Let tracee continue until next event.
    ptrace::syscall(starting_pid)?;

    loop {
        // Wait for next event...
        let pid = match waitpid(None, None)? {
            Exited(pid, _) => {
                info!("Exit event.");
                live_processes.remove(& pid);
                pre_syscall.remove(& pid);
                if live_processes.is_empty() {
                    break;
                }
                continue;
            },
            Signaled(pid, signal, _) => {
                info!("[{}] Process Killed by Signal {:?}", pid, signal);
                pid}
            PtraceEvent(pid, _, event) => {
                info!("[{}] Ptrace Event {:?}", pid, event);
                pid
            }
            Stopped(pid, signal) => {
                info!("[{}] Ptrace signal caught {:?}", pid, signal);
                pid
            }
            PtraceSyscall(pid) => {
                if ! live_processes.contains(& pid) {
                    live_processes.insert(pid);
                }

                if let None = pre_syscall.get(& pid) {
                    pre_syscall.insert(pid, true);
                }

                let regs = get_regs(pid);
                let name = SYSTEM_CALL_NAMES[regs.orig_rax as usize];
                let hook_status = pre_syscall.get_mut(& pid).unwrap();

                // Ony print info for relevant system calls.
                if to_trace.contains(name){
                    handle_system_call_event(name, *hook_status, regs, pid);
                }

                *hook_status = ! *hook_status;
                pid
            }
            s => {
                panic!("Unhandled case for WaitStatus: {:?}", s);
            }
        };

        ptrace::syscall(pid)?;
    }

    println!("Process finished!");
    Ok(())
}

fn handle_system_call_event(name: &str, pre_system_call: bool,
                            regs: user_regs_struct, pid : Pid) {
    if pre_system_call {
        info!("Pre-hook event. Nothing to do.");
        let mut print_args = "".to_string();

        if name == "execve" || name == "access" {
            let arg1 = regs.rdi as *mut c_void;
            let path = read_string(arg1, pid);
            print_args = format!("\"{}\"", path).to_string();
        }

        print!("[{}]: {}({}) = ", pid, name, print_args);
    }else{
        info!("Post-hook event.");

        if (regs.rax as i32).abs() > 10000 {
            println!("0x{:x}", regs.rax as i32);
        } else {
            println!("{}", regs.rax as i32);
        }

    }
}

fn get_hashset_from_args<'a>(to_trace: &'a [String], dont_trace: &'a [String],
                             all_syscalls: HashSet<&'a str>) -> HashSet<&'a str> {
    fn to_hashset<'a>(v: &'a [String]) -> HashSet<&'a str> {
        v.iter().map(AsRef::as_ref).collect()
    }

    // Populate our set of system calls we're interested in tracing.
    if ! to_trace.is_empty() {
        return to_hashset(&to_trace);
    } else if ! dont_trace.is_empty() {
        let dont: HashSet<&'a str> = to_hashset(&dont_trace);
        return all_syscalls.difference(&dont).map(|e| *e).collect();
    } else {
        return all_syscalls;
    }
}
