extern crate libc;
extern crate nix;

mod system_call_names;
mod ptracer;

use system_call_names::SYSTEM_CALL_NAMES;

use libc::{c_void, user_regs_struct, PT_NULL};
use nix::sys::ptrace;
use nix::sys::ptrace::*;
use nix::sys::signal::{raise, Signal};
use nix::sys::wait::*;
use nix::unistd::*;
use std::ffi::CString;
use std::mem;

use std::collections::HashSet;

#[macro_use]
extern crate structopt;
use structopt::StructOpt;

struct Command(String, Vec<String>);

impl Command {
    fn new(exe: String, args: Vec<String>) -> Self {
        Command(exe, args)
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "stracer", about = "A simple stracer written in Rust")]
struct Opt {
    #[structopt(short = "t", long = "to_trace")]
    to_trace: Vec<String>,

    #[structopt(short = "d", long = "dont_trace", conflicts_with = "to_trace")]
    dont_trace: Vec<String>,

    exe: String,
    exe_args: Vec<String>,
}

/// Strace program written in Rust.
fn main() -> nix::Result<()> {
    let opt = Opt::from_args();
    println!("{:?}", opt);
    let command = Command::new(opt.exe, opt.exe_args);

    // Trace all
    let all_syscall_set: HashSet<&str> = SYSTEM_CALL_NAMES.into_iter().map(|s| *s).collect();

    for entry in &opt.to_trace {
        if !all_syscall_set.contains(entry.as_str()) {
            eprintln!("Invalid system call specified: {}", entry);
            return Ok(());
        }
    }

    for entry in &opt.dont_trace {
        if !all_syscall_set.contains(entry.as_str()) {
            eprintln!("Invalid system call specified: {}", entry);
            return Ok(());
        }
    }

    let syscall_set = get_hashset_from_args(&opt.to_trace, &opt.dont_trace, all_syscall_set);

    match fork()? {
        ForkResult::Parent { child } => run_tracer(child, &syscall_set),
        ForkResult::Child => run_tracee(command),
    }
}

fn run_tracee(command: Command) -> nix::Result<()> {
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

    execvp(&exe, &args).map(|_| ()) // Map from Void to ()
}

fn run_tracer(starting_pid: Pid, to_trace: &HashSet<&str>) -> nix::Result<()> {
    use nix::sys::wait::WaitStatus::*;

    // Wait for child to be ready.
    let _s: WaitStatus = waitpid(starting_pid, None)?;

    // Child ready!
    ptrace_set_options(starting_pid)?;

    // Loop over all events in the program.
    let current_pid = starting_pid;
    let mut pre_system_call = true;

    loop {
        // Let tracee continue until next event.
        ptrace::syscall(current_pid).unwrap();
        // Wait for next event...
        match waitpid(current_pid, None)? {
            Exited(_, _) => break,
            Signaled(_, _, _) => {}
            PtraceEvent(_, _, _) => {}
            PtraceSyscall(_) => {
                let regs = get_regs(current_pid);
                let name = system_call_names::SYSTEM_CALL_NAMES[regs.orig_rax as usize].to_string();

                pre_system_call = handle_system_call_event(&name, pre_system_call, to_trace);
            }
            s => {
                panic!("Unhandled case for WaitStatus: {:?}", s);
            }
        }
    }

    println!("Process finished!");
    Ok(())
}

fn handle_system_call_event(
    systemcall: &str,
    pre_system_call: bool,
    to_trace: &HashSet<&str>,
) -> bool {
    if pre_system_call && to_trace.contains(systemcall) {
        println!("[I]: {}", systemcall);
    }
    !pre_system_call
}

fn get_hashset_from_args<'a>(
    to_trace: &'a [String],
    dont_trace: &'a [String],
    all_syscalls: HashSet<&'a str>,
) -> HashSet<&'a str> {
    fn to_hashset<'a>(v: &'a [String]) -> HashSet<&'a str> {
        v.iter().map(AsRef::as_ref).collect()
    }

    // Populate our set of system calls we're interested in tracing.
    if !to_trace.is_empty() {
        to_hashset(&to_trace)
    } else if !dont_trace.is_empty() {
        let all_syscalls: HashSet<&'a str> = SYSTEM_CALL_NAMES.into_iter().map(|s| *s).collect();
        let dont: HashSet<&'a str> = to_hashset(&dont_trace);
        all_syscalls.difference(&dont).map(|e| *e).collect()
    } else {
        all_syscalls
    }
}

fn ptrace_set_options(pid: Pid) -> nix::Result<()> {
    let options = Options::PTRACE_O_TRACESYSGOOD
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACEEXIT
        | Options::PTRACE_O_TRACEEXEC;
    ptrace::setoptions(pid, options)
}

/// Nix does not yet have a way to fetch registers. We use our own instead.
/// Given the pid of a process that is currently being traced. Return the registers
/// for that process.
fn get_regs(pid: Pid) -> user_regs_struct {
    unsafe {
        let mut regs: user_regs_struct = mem::uninitialized();

        #[allow(deprecated)]
        let res = ptrace::ptrace(
            Request::PTRACE_GETREGS,
            pid,
            PT_NULL as *mut c_void,
            &mut regs as *mut _ as *mut c_void,
        );
        match res {
            Ok(_) => regs,
            Err(e) => panic!("Get regs failed: {:?}", e),
        }
    }
}
