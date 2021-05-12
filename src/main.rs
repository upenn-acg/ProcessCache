use tracing_subscriber::filter::EnvFilter;

mod async_runtime;
mod cache;
mod execution;
mod ptracer;
mod regs;
mod seccomp;
mod system_call_names;
mod tracer;
mod utils;

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
    /// Executable to run. Will use $PATH.
    pub exe: String,
    /// Print system calls when they return -1, off by default.
    #[structopt(short, long)]
    pub print_syscalls_on_error: bool,
    /// Write IOTracking info to this file, if it is specified.
    /// If not specified, it'll write to "output.txt"
    #[structopt(short, long, default_value = "output.txt")]
    pub output_file: String,
    /// Arguments to executable.
    pub args: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();

    let opt = Opt::from_args();
    // let print_all_syscalls = opt.print_syscalls_on_error;
    // let output_file_name = opt.output_file;

    let command = Command::new(opt.exe, opt.args);

    run_tracer_and_tracee(command)?;
    Ok(())
}

fn run_tracer_and_tracee(command: Command) -> anyhow::Result<()> {
    use nix::sys::wait::waitpid;

    match fork()? {
        ForkResult::Parent { child: tracee_pid } => {
            // Wait for program to be ready.
            waitpid(tracee_pid, None)
                .with_context(|| context!("Unable to wait for child to be ready"))?;

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
    our_seccomp_rules().with_context(|| context!("Unable to load seccomp rules."))?;

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

fn our_seccomp_rules() -> anyhow::Result<()> {
    let mut loader = seccomp::RuleLoader::new()?;

    loader.intercept(libc::SYS_access)?;
    loader.intercept(libc::SYS_creat)?;
    loader.intercept(libc::SYS_clone)?;
    loader.intercept(libc::SYS_clone3)?;
    loader.intercept(libc::SYS_execve)?;
    loader.intercept(libc::SYS_execveat)?;
    loader.intercept(libc::SYS_exit)?;
    loader.intercept(libc::SYS_exit_group)?;
    loader.intercept(libc::SYS_fork)?;
    loader.intercept(libc::SYS_fstat)?;
    loader.intercept(libc::SYS_lstat)?;
    loader.intercept(libc::SYS_newfstatat)?;
    loader.intercept(libc::SYS_open)?;
    loader.intercept(libc::SYS_openat)?;
    loader.intercept(libc::SYS_pread64)?;
    loader.intercept(libc::SYS_read)?;
    loader.intercept(libc::SYS_stat)?;
    loader.intercept(libc::SYS_vfork)?;
    loader.intercept(libc::SYS_write)?;

    loader.let_pass(libc::SYS_brk)?;
    loader.let_pass(libc::SYS_arch_prctl)?;
    loader.let_pass(libc::SYS_mmap)?;
    // loader.let_pass(libc::SYS_read)?; // empty main
    // loader.let_pass(libc::SYS_write)?;
    loader.let_pass(libc::SYS_mprotect)?;
    // loader.let_pass(libc::SYS_pread64)?; // empty main
    loader.let_pass(libc::SYS_munmap)?;
    loader.let_pass(libc::SYS_set_tid_address)?;
    loader.let_pass(libc::SYS_set_robust_list)?;
    loader.let_pass(libc::SYS_rt_sigaction)?;
    loader.let_pass(libc::SYS_rt_sigprocmask)?;
    loader.let_pass(libc::SYS_prlimit64)?;
    loader.let_pass(libc::SYS_statfs)?;
    loader.let_pass(libc::SYS_ioctl)?;
    loader.let_pass(libc::SYS_futex)?;
    loader.let_pass(libc::SYS_lseek)?;
    loader.let_pass(libc::SYS_sched_getaffinity)?;
    loader.let_pass(libc::SYS_sigaltstack)?;
    loader.let_pass(libc::SYS_getgid)?;
    loader.let_pass(libc::SYS_getuid)?;
    loader.let_pass(libc::SYS_getpid)?;
    loader.let_pass(libc::SYS_geteuid)?;
    loader.let_pass(libc::SYS_getppid)?;
    loader.let_pass(libc::SYS_getegid)?;
    loader.let_pass(libc::SYS_fadvise64)?;
    loader.let_pass(libc::SYS_mremap)?;
    loader.let_pass(libc::SYS_rt_sigreturn)?;

    // TODO Less clear whether it should be handled.
    loader.let_pass(libc::SYS_sysinfo)?;
    loader.intercept(libc::SYS_socket)?;
    loader.intercept(libc::SYS_connect)?;
    loader.let_pass(libc::SYS_getrandom)?;
    loader.let_pass(libc::SYS_lgetxattr)?;
    loader.let_pass(libc::SYS_getxattr)?;
    loader.let_pass(libc::SYS_statx)?;
    loader.let_pass(libc::SYS_getrusage)?;
    loader.let_pass(libc::SYS_chmod)?;
    loader.let_pass(libc::SYS_pselect6)?;

    // TODO: Probably should handle later...
    loader.let_pass(libc::SYS_rename)?;
    loader.let_pass(libc::SYS_mkdir)?;
    loader.let_pass(libc::SYS_umask)?;
    loader.let_pass(libc::SYS_faccessat)?;
    loader.let_pass(libc::SYS_dup2)?;
    loader.let_pass(libc::SYS_pipe)?;
    loader.let_pass(libc::SYS_chdir)?;
    loader.let_pass(libc::SYS_readlink)?;
    loader.let_pass(libc::SYS_fcntl)?;
    loader.let_pass(libc::SYS_getcwd)?;
    // loader.let_pass(libc::SYS_access)?; // empty main
    loader.let_pass(libc::SYS_close)?;
    loader.let_pass(libc::SYS_getdents64)?;
    loader.let_pass(libc::SYS_wait4)?;

    // TODO: Handle for empty main
    loader.let_pass(libc::SYS_poll)?;

    loader.load_to_kernel()
}
