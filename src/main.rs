// We comment out certain benchmarking functions and then uncomment... and so on...
// So I don't want to have to import them over and over each time.
#[allow(unused_imports)]
use cache_benchmarking::{
    remove_bioinfo_entries_from_existing_cache, remove_buildbwa_entries_from_existing_cache,
    remove_buildminigraph_entries_from_existing_cache,
    remove_buildraxml_entries_from_existing_cache,
};
use cache_utils::ExecCommand;
use tracing_subscriber::filter::EnvFilter;

mod async_runtime;
mod cache;
mod cache_benchmarking;
mod cache_utils;
mod computed_hashes;
mod condition_generator;
mod condition_utils;
mod execution;
mod execution_utils;
mod ptracer;
mod recording;
mod redirection;
mod regs;
mod seccomp;
mod syscalls;
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

// Super annoying thing: I can't seem to put them in the order I want, instead,
// it is based on alphabetical order...
// This is even after using the correct flag through clap.
#[derive(StructOpt, Debug)]
#[structopt(
    name = "ProcessCache",
    about = "ProcessCache: Automatic Caching for Unmodified Linux Programs"
)]
pub struct Opt {
    /// Executable to run. Will use $PATH.
    pub exe: String,
    /// Print system calls when they return -1, off by default.
    /// Note: This was from the early days of this project and has not been updated
    /// in some time! It probably doesn't work. I have made a note to fix it.
    #[structopt(short, long)]
    pub print_syscalls_on_error: bool,
    /// Write ProcessCache info to this file, if the name of the file is specified.
    /// If not specified, it'll write to "output.txt"
    /// Note: This was from the early days of this project and has not been updated
    /// in some time! It probably doesn't work. I have made a note to fix it.
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
    let command = ExecCommand::new(opt.exe, opt.args);

    // This variable tells Process Cache if you want the system to:
    // - Look in its existing cache for the JOB specified
    // - Remove this percent of the jobs.
    // - Short circuit and exit.
    // This is *not* normal user behavior, these programs exist
    // to facilitate benchmarking, making it simple to create
    // conditions in the cache so that, within one benchmark,
    // either:
    // - all jobs are skipped
    // - 95% of jobs are skipped (meaning 5% of the inputs changed)
    // - 50% of jobs are skipped (50% of the inputs changed)
    // - 10% of jobs are skipped (90% of inputs changed)
    // This helps exercise the flexibility of ProcessCache, we can
    // skip all of your program, or some of your program! Perfect
    // conditions are not required to benefit from ProcessCache :-)
    let percent_to_remove = 0;
    // let percent_to_remove = 5;
    // let percent_to_remove = 50;
    // let percent_to_remove = 90;

    // If percent_to_remove == 0, we just run ProcessCache normally.
    if percent_to_remove != 0 {
        // BWA BUILD
        // remove_buildbwa_entries_from_existing_cache(percent_to_remove);
        // RAXML BUILD
        // remove_buildraxml_entries_from_existing_cache(percent_to_remove);
        // MINIGRAPH BUILD
        // remove_buildminigraph_entries_from_existing_cache(percent_to_remove);
        // BIOINFO JOBS
        remove_bioinfo_entries_from_existing_cache(percent_to_remove);

        // Short circuit.
        return Ok(());
    }

    run_tracer_and_tracee(command)?;
    Ok(())
}

fn run_tracer_and_tracee(command: ExecCommand) -> anyhow::Result<()> {
    use nix::sys::wait::waitpid;

    match fork()? {
        ForkResult::Parent { child: tracee_pid } => {
            // Wait for program to be ready.
            waitpid(tracee_pid, None)
                .with_context(|| context!("Unable to wait for child to be ready"))?;

            debug!("Child returned ready!");
            Ptracer::set_trace_options(tracee_pid)
                .with_context(|| context!("Unable to set ptracing options."))?;

            execution::trace_program(tracee_pid)
                .with_context(|| context!("Failed while tracing program."))?;
            Ok(())
        }
        ForkResult::Child => run_tracee(command),
    }
}

/// This function should be called after a fork.
/// uses execve to call the tracee program and have it ready to be ptraced.
pub(crate) fn run_tracee(command: ExecCommand) -> anyhow::Result<()> {
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

    let args_cstr: Vec<&CStr> = (args).iter().map(|s: &CString| s.as_c_str()).collect();

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
    // TODO: Alphabatize
    loader.intercept(libc::SYS_access)?;
    loader.intercept(libc::SYS_chdir)?;
    loader.intercept(libc::SYS_creat)?;
    loader.intercept(libc::SYS_clone)?;
    loader.intercept(libc::SYS_clone3)?;
    loader.intercept(libc::SYS_close)?;
    // loader.intercept(libc::SYS_connect)?;
    loader.intercept(libc::SYS_execve)?;
    loader.intercept(libc::SYS_execveat)?;
    loader.intercept(libc::SYS_exit)?;
    loader.intercept(libc::SYS_exit_group)?;
    loader.intercept(libc::SYS_fork)?;
    loader.intercept(libc::SYS_fstat)?;
    loader.intercept(libc::SYS_getdents)?;
    loader.intercept(libc::SYS_getdents64)?;
    loader.intercept(libc::SYS_lstat)?;
    loader.intercept(libc::SYS_mkdir)?;
    loader.intercept(libc::SYS_mkdirat)?;
    loader.intercept(libc::SYS_open)?;
    loader.intercept(libc::SYS_openat)?;
    // loader.intercept(libc::SYS_pipe)?;
    // loader.intercept(libc::SYS_pipe2)?;
    loader.intercept(libc::SYS_rename)?;
    loader.intercept(libc::SYS_renameat)?;
    loader.intercept(libc::SYS_renameat2)?;
    // loader.intercept(libc::SYS_socket)?;
    loader.intercept(libc::SYS_stat)?;
    loader.intercept(libc::SYS_statfs)?;
    loader.intercept(libc::SYS_vfork)?;
    loader.intercept(libc::SYS_unlink)?;
    loader.intercept(libc::SYS_unlinkat)?;

    loader.let_pass(libc::SYS_arch_prctl)?;
    loader.let_pass(libc::SYS_brk)?;
    loader.let_pass(libc::SYS_chmod)?;
    loader.let_pass(libc::SYS_chown)?;
    loader.let_pass(libc::SYS_connect)?;
    loader.let_pass(libc::SYS_epoll_create1)?;
    loader.let_pass(libc::SYS_epoll_ctl)?;
    loader.let_pass(libc::SYS_epoll_wait)?;
    loader.let_pass(libc::SYS_fadvise64)?;
    loader.let_pass(libc::SYS_fsync)?;
    loader.let_pass(libc::SYS_getegid)?;
    loader.let_pass(libc::SYS_geteuid)?;
    loader.let_pass(libc::SYS_getgid)?;
    loader.let_pass(libc::SYS_getpgrp)?;
    loader.let_pass(libc::SYS_getpid)?;
    loader.let_pass(libc::SYS_getppid)?;
    loader.let_pass(libc::SYS_gettid)?;
    loader.let_pass(libc::SYS_getuid)?;
    loader.let_pass(libc::SYS_ioctl)?;
    loader.let_pass(libc::SYS_lseek)?;
    loader.let_pass(libc::SYS_mmap)?;
    loader.let_pass(libc::SYS_mprotect)?;
    loader.let_pass(libc::SYS_mremap)?;
    loader.let_pass(libc::SYS_munmap)?;
    loader.let_pass(libc::SYS_newfstatat)?;
    loader.let_pass(libc::SYS_pipe)?;
    loader.let_pass(libc::SYS_pipe2)?;
    loader.let_pass(libc::SYS_prlimit64)?;
    loader.let_pass(libc::SYS_recvfrom)?;
    loader.let_pass(libc::SYS_rseq)?;
    loader.let_pass(libc::SYS_rt_sigaction)?;
    loader.let_pass(libc::SYS_rt_sigprocmask)?;
    loader.let_pass(libc::SYS_rt_sigreturn)?;
    loader.let_pass(libc::SYS_sched_getaffinity)?;
    loader.let_pass(libc::SYS_sendto)?;
    loader.let_pass(libc::SYS_set_tid_address)?;
    loader.let_pass(libc::SYS_set_robust_list)?;
    loader.let_pass(libc::SYS_socket)?;
    loader.let_pass(libc::SYS_sigaltstack)?;

    // TODO: Either unsure if/how to handle or
    // might need to be handled later.
    loader.let_pass(libc::SYS_clock_gettime)?;
    loader.let_pass(libc::SYS_dup)?;
    loader.let_pass(libc::SYS_dup2)?;
    loader.let_pass(libc::SYS_faccessat)?;
    loader.let_pass(libc::SYS_fcntl)?;
    loader.let_pass(libc::SYS_futex)?;
    loader.let_pass(libc::SYS_getcwd)?;
    loader.let_pass(libc::SYS_getrandom)?;
    loader.let_pass(libc::SYS_getrlimit)?;
    loader.let_pass(libc::SYS_getrusage)?;
    loader.let_pass(libc::SYS_getxattr)?;
    loader.let_pass(libc::SYS_lgetxattr)?;
    loader.let_pass(libc::SYS_madvise)?;
    loader.let_pass(libc::SYS_poll)?;
    loader.let_pass(libc::SYS_pread64)?;
    loader.let_pass(libc::SYS_pselect6)?;
    loader.let_pass(libc::SYS_read)?;
    loader.let_pass(libc::SYS_readlink)?;
    loader.let_pass(libc::SYS_sysinfo)?;
    loader.let_pass(libc::SYS_statx)?;
    loader.let_pass(libc::SYS_timerfd_create)?;
    loader.let_pass(libc::SYS_timerfd_settime)?;
    loader.let_pass(libc::SYS_times)?;
    loader.let_pass(libc::SYS_umask)?;
    loader.let_pass(libc::SYS_uname)?;
    loader.let_pass(libc::SYS_utimensat)?;
    loader.let_pass(libc::SYS_wait4)?;
    loader.let_pass(libc::SYS_write)?;
    loader.let_pass(libc::SYS_writev)?;
    loader.load_to_kernel()
}
