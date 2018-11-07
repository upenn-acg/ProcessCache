extern crate libc;
extern crate nix;
extern crate byteorder;
#[macro_use] extern crate structopt;
extern crate env_logger;
#[macro_use] extern crate log;
extern crate generator;
extern crate seccomp_sys;

#[macro_use] mod coroutines;
mod handlers;
mod system_call_names;
mod args;
mod ptracer;
mod execution;
mod seccomp;
mod actions;

use args::*;

// Most used
use libc::{ SYS_lstat, SYS_openat, SYS_rt_sigaction, SYS_read, SYS_close, SYS_stat,
            SYS_rt_sigprocmask, SYS_lseek, SYS_mmap, SYS_fstat, SYS_mprotect,
            SYS_access, SYS_msgrcv, SYS_msgsnd, SYS_write, SYS_semop,
            SYS_brk, SYS_getpid, SYS_fcntl, SYS_wait4};

// Least used
use libc::{ SYS_dup3,  SYS_nanosleep,  SYS_mremap,  SYS_setsid,  SYS_kill,  SYS_select,
            SYS_seccomp, SYS_chown,  SYS_msgctl,  SYS_semctl,  SYS_creat,  SYS_fsync,
            SYS_readlinkat,  SYS_prctl,  SYS_symlink,  SYS_sigaltstack,
            SYS_fchown,  SYS_llistxattr,  SYS_madvise,  SYS_rmdir};


// Must use
use libc::{ SYS_fork, SYS_vfork, SYS_execve, SYS_clone};

use args::*;
use structopt::StructOpt;

use nix::sys::ptrace;

use nix::unistd::*;
use std::ffi::CString;

use nix::sys::signal::Signal;
use nix::sys::signal::raise;

use std::process::exit;


fn get_runtype(name: &str) -> Option<RunType> {
    use RunType::*;
    let name: &str = & name.to_lowercase();
    match name {
        "all" => Some(All),
        "none" => Some(None),
        "top20" => Some(Top20),
        "bottom20" => Some(Bottom20),
        _ => Option::None
    }
}

struct Command(String, Vec<String>);

impl Command {
    fn new(exe: String, args: Vec<String>) -> Self {
        Command(exe, args)
    }
}

/// Strace program written in Rust.
fn main() -> nix::Result<()> {
    // Init logger with no timestamp data.
    env_logger::Builder::from_default_env().
        default_format_timestamp(false).
        default_format_module_path(false).
        init();

    let opt = Opt::from_args();
    let command = Command::new(opt.prog, opt.prog_args);

    let run_type = match get_runtype(& opt.arg_type){
        Some(rt) => rt,
        None => {
            eprintln!("Invalid runtype: {}", opt.arg_type);
            exit(1);
        }
    };


    match fork()? {
        ForkResult::Parent { child } => execution::run_program(child),
        ForkResult::Child => run_tracee(command, run_type),
    }
}

/// This function should be called after a fork.
/// uses execve to call the tracee program and have it ready to be ptraced.
fn run_tracee(command: Command, rt: RunType) -> nix::Result<()> {
    // New ptracee and set ourselves to be traced.
    ptrace::traceme()?;
    // Stop ourselves until the tracer is ready. This ensures the tracer has time
    // to get set up.
    raise(Signal::SIGSTOP)?;

    // WARNING: The seccomp filter must be loaded after the call to ptraceme() and
    // raise.
    let loader = seccomp::RuleLoader::new(& rt);

    // Necessary for implementation.
    loader.intercept(SYS_execve as i32);
    loader.intercept(SYS_clone as i32);
    loader.intercept(SYS_fork as i32);
    loader.intercept(SYS_vfork as i32);

    if rt == RunType::Bottom20 {
    // not called often
        loader.intercept(SYS_dup3 as i32);
        loader.intercept(SYS_nanosleep as i32);
        loader.intercept(SYS_mremap as i32);
        loader.intercept(SYS_setsid as i32);
        loader.intercept(SYS_kill as i32);
        loader.intercept(SYS_select as i32);
        loader.intercept(SYS_seccomp as i32);
        loader.intercept(SYS_chown as i32);
        loader.intercept(SYS_msgctl as i32);
        loader.intercept(SYS_semctl as i32);
        loader.intercept(SYS_creat as i32);
        loader.intercept(SYS_fsync as i32);
        loader.intercept(SYS_readlinkat as i32);
        loader.intercept(SYS_prctl as i32);
        loader.intercept(SYS_symlink as i32);
        loader.intercept(SYS_sigaltstack as i32);
        loader.intercept(SYS_fchown as i32);
        loader.intercept(SYS_llistxattr as i32);
        loader.intercept(SYS_madvise as i32);
        loader.intercept(SYS_rmdir as i32);
    }

    // Called a lot
    if rt == RunType::Top20 {
        loader.intercept(SYS_lstat as i32);
        loader.intercept(SYS_openat as i32);
        loader.intercept(SYS_rt_sigaction as i32);
        loader.intercept(SYS_read as i32);
        loader.intercept(SYS_close as i32);
        loader.intercept(SYS_stat as i32);
        loader.intercept(SYS_rt_sigprocmask as i32);
        loader.intercept(SYS_lseek as i32);
        loader.intercept(SYS_mmap as i32);
        loader.intercept(SYS_fstat as i32);
        loader.intercept(SYS_mprotect as i32);
        loader.intercept(SYS_access as i32);
        loader.intercept(SYS_msgrcv as i32);
        loader.intercept(SYS_msgsnd as i32);
        loader.intercept(SYS_write as i32);
        loader.intercept(SYS_semop as i32);
        loader.intercept(SYS_brk as i32);
        loader.intercept(SYS_getpid as i32);
        loader.intercept(SYS_fcntl as i32);
        loader.intercept(SYS_wait4 as i32);
    }

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
