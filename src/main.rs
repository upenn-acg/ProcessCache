use tracing_subscriber::filter::EnvFilter;

mod execution;
mod ptracer;
mod regs;
mod seccomp;
mod system_call_names;
mod tracer;

pub use crate::execution::trace_program;
pub use crate::ptracer::Ptracer;
use tracing::{debug, error};

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::unistd::{execvp, fork, ForkResult};
use std::ffi::CString;
use std::process::exit;
use structopt::StructOpt;

#[allow(unused_imports)]
use anyhow::{Context, Result};

#[derive(Clone)]
pub struct Command(String, Vec<String>);

impl Command {
    pub fn new(exe: String, args: Vec<String>) -> Self {
        Command(exe, args)
    }
}

// Super annoying thing: I can't seem to put them in the order I want, instead,
// it is based on alphabetical order...
// This is even after using the correct flag through clap.
#[derive(StructOpt, Debug)]
#[structopt(name = "trackerIO", about = "TrackerIO: Program IO Tracking.")]
pub struct Opt {
    pub exe: String,
    pub args: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();

    let opt = Opt::from_args();
    let command = Command::new(opt.exe, opt.args);

    run_tracer_and_tracee(command)?;
    Ok(())
}

fn run_tracer_and_tracee(command: Command) -> anyhow::Result<()> {
    use nix::sys::wait::waitpid;

    match fork()? {
        ForkResult::Parent { child: tracee_pid } => {
            // Wait for program to be ready.
            waitpid(tracee_pid, None).context("Unable to wait for child to be ready")?;

            debug!("Child returned ready!");
            Ptracer::set_trace_options(tracee_pid)?;

            execution::trace_program(tracee_pid)?;
            Ok(())
        }
        ForkResult::Child => run_tracee(command),
    }
}

/// This function should be called after a fork.
/// uses execve to call the tracee program and have it ready to be ptraced.
pub(crate) fn run_tracee(command: Command) -> anyhow::Result<()> {
    use nix::sys::signal::raise;
    use std::ffi::CStr;

    // New ptracee and set ourselves to be traced.
    ptrace::traceme()?;
    // Stop ourselves until the tracer is ready. This ensures the tracer has time
    // to get set up.
    raise(Signal::SIGSTOP)?;

    // WARNING: The seccomp filter must be loaded after the call to ptraceme() and
    // raise(...).
    let mut loader = seccomp::RuleLoader::new()?;

    loader.intercept(libc::SYS_creat)?;
    loader.intercept(libc::SYS_clone)?;
    loader.intercept(libc::SYS_clone3)?;
    loader.intercept(libc::SYS_fork)?;
    loader.intercept(libc::SYS_execve)?;
    loader.intercept(libc::SYS_execveat)?;
    loader.intercept(libc::SYS_exit)?;
    loader.intercept(libc::SYS_exit_group)?;
    loader.intercept(libc::SYS_fork)?;
    loader.intercept(libc::SYS_open)?;
    loader.intercept(libc::SYS_openat)?;
    loader.intercept(libc::SYS_vfork)?;
    loader.load_to_kernel()?;

    // Convert arguments to correct arguments.
    let exe = CString::new(command.0).unwrap();
    let mut args: Vec<CString> = command
        .1
        .into_iter()
        .map(|s| CString::new(s).unwrap())
        .collect();
    args.insert(0, exe.clone());

    let args_cstr: Vec<&CStr> = (&args).iter().map(|s: &CString| s.as_c_str()).collect();

    if let Err(e) = execvp(&exe, args_cstr.as_slice()) {
        error!(
            "Error executing execve for your program {:?}. Reason {}",
            args, e
        );
        // TODO parent does not know that child exited it may report a weird abort
        // message.
        exit(1);
    }

    Ok(())
}
