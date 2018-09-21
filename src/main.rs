extern crate libc;
extern crate nix;
extern crate byteorder;
#[macro_use] extern crate structopt;
extern crate env_logger;
#[macro_use] extern crate log;
extern crate generator;
extern crate seccomp_sys;

mod system_call_names;
mod args;
#[macro_use] mod ptracer;
mod execution;
mod seccomp;

use args::*;
use structopt::StructOpt;

use nix::sys::ptrace;

use nix::unistd::*;
use std::ffi::CString;

use nix::sys::signal::Signal;
use nix::sys::signal::raise;

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
        ForkResult::Parent { child } => execution::run_program(child),
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

    // WARNING: The seccomp filter must be loaded after the call to ptraceme() and
    // raise.
    let loader = seccomp::RuleLoader::new();

    // Barely called.
    // loader.intercept(SYS_unlink as i32);
    // loader.intercept(SYS_pipe as i32);
    // loader.intercept(SYS_getrusage as i32);
    // loader.intercept(SYS_chmod as i32);
    // loader.intercept(SYS_chdir as i32);

    // Called a lot
    // loader.intercept(SYS_openat as i32);
    // loader.intercept(SYS_rt_sigprocmask as i32);
    // loader.intercept(SYS_futex as i32);
    // loader.intercept(SYS_fstat as i32);
    // loader.intercept(SYS_close as i32);

    loader.load_to_kernel();

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
