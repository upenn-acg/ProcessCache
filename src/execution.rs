#[allow(unused_imports)]
use libc::{c_char, syscall, AT_SYMLINK_NOFOLLOW, O_ACCMODE, O_CREAT, O_RDONLY, O_RDWR, O_WRONLY};
#[allow(unused_imports)]
use nix::fcntl::{readlink, OFlag};
use nix::sys::stat::stat;
use nix::unistd::Pid;
use std::path::PathBuf;

use crate::async_runtime::AsyncRuntime;
use crate::cache::{AccessType, Execution, FileAccess, RcExecutions};
use crate::context;
use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::system_call_names::get_syscall_name;
use crate::tracer::TraceEvent;
use crate::Ptracer;

#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

use anyhow::{bail, Context, Result};
use std::ffi::OsString;

pub fn trace_program(first_proc: Pid, rc_execs: RcExecutions) -> Result<()> {
    info!("Running whole program");

    let async_runtime = AsyncRuntime::new();
    let f = trace_process(
        async_runtime.clone(),
        Ptracer::new(first_proc),
        rc_execs.clone(),
    );
    async_runtime
        .run_task(first_proc, f)
        .with_context(|| context!("Program tracing failed. Task returned error."))?;

    // TODO: Print out the unique execs.
    // There should just be one.
    for exec in rc_execs.rc_execs.borrow().execs.iter() {
        println!("Execution: {:?}", exec);
    }
    Ok(())
}

/// NOTE: The process should start in a STOPPED state. Ptrace does this by default so it should just
/// work.
/// For all child processes (assuming we're are ptracing a process tree) technically there is a
/// ptrace::STOPPED event on the wait-event queue, but it seems calling ptrace(continue) will get
/// rid of this event (this is the first thing that `get_next_event()` does in `trace_process()`.
/// So we actually can just ignore this event. This is actually what we want and how we handle the
/// race between a ptrace::FORK_EVENT and this ptrace::STOPPED from the parent. Also relevant:
/// https://stackoverflow.com/questions/29997244/occasionally-missing-ptrace-event-vfork-when-running-ptrace
pub async fn trace_process(
    async_runtime: AsyncRuntime,
    mut tracer: Ptracer,
    rc_execs: RcExecutions,
) -> Result<()> {
    let s = span!(Level::INFO, stringify!(trace_proces), pid=?tracer.curr_proc);
    s.in_scope(|| info!("Starting Process"));
    let mut signal = None;

    loop {
        let event = tracer
            .get_next_event(signal)
            .await
            .with_context(|| context!("Unable to get next event in execution loop."))?;
        // Clear out signal after use.
        signal = None;

        match event {
            TraceEvent::Exec(pid) => {
                s.in_scope(|| debug!("Saw exec event for pid {}", pid));
            }
            TraceEvent::PreExit(_pid) => {
                s.in_scope(|| debug!("Saw preexit event."));
                break;
            }
            TraceEvent::Prehook(pid) => {
                let e = s.enter();

                // The default seccomp rule for unspecified system call rules is to send us
                // a u32::MAX. If we see one, it is an unhandled system call!
                let event_message = tracer
                    .get_event_message()
                    .with_context(|| context!("Cannot get event message on prehook"))?
                    as u32;

                // Why do we use u16::MAX? See `RuleLoader::new`.
                if event_message == u16::MAX as u32 {
                    let regs = tracer.get_registers().with_context(|| {
                        context!("Unable to fetch regs for unspecified syscall")
                    })?;

                    let syscall = regs.syscall_number::<usize>();
                    let name = get_syscall_name(syscall)
                        .with_context(|| context!("Unable to get syscall name for {}", syscall))?;
                    bail!(context!("Unhandled system call {:?}", name));
                }

                // Otherwise the syscall name holds the system call number :)
                // We do this to avoid unnecessarily fetching registers.
                let name = get_syscall_name(event_message as usize).with_context(|| {
                    context!("Unable to get syscall name for syscall={}.", event_message)
                })?;

                let sys_span = span!(Level::INFO, "Syscall", name);
                let ee = sys_span.enter();
                // Print system call event.
                info!("");

                // Special cases, we won't get a posthook event. Instead we will get
                // an execve event or a posthook if execve returns failure. We don't
                // bother handling it, let the main loop take care of it.
                // TODO: Handle them properly...
                match name {
                    "exit_group" | "clone" | "vfork" | "fork" | "clone2" | "clone3" => {
                        debug!("Special event. Do not go to posthook.");
                        continue;
                    }
                    "execve" => {
                        let regs = tracer
                            .get_registers()
                            .with_context(|| context!("Execve getting registers."))?;

                        let _res = handle_execve(regs, tracer.clone(), rc_execs.clone())
                            .await
                            .with_context(|| format!("handle_execve({:?}) failed", pid));
                        continue;
                    }
                    _ => {}
                }

                trace!("Waiting for posthook event...");
                drop(e);
                drop(ee);
                let regs: Regs<Unmodified> = tracer.posthook().await?;
                trace!("Waiting for posthook event...");

                // In posthook.
                let _ = s.enter();
                let _ = sys_span.enter();
                let retval = regs.retval::<i32>();

                span!(Level::INFO, "Posthook", retval).in_scope(|| info!(""));

                match name {
                    "access" => handle_access(&rc_execs, &regs, &tracer)?,
                    "creat" | "openat" | "open" => handle_open(&rc_execs, &regs, name, &tracer)?,
                    "fstat" | "lstat" | "newfstatat" | "stat" => {
                        handle_stat(&rc_execs, &regs, name, &tracer)?
                    }
                    "pread64" | "read" => handle_read(&rc_execs, &regs, name, &tracer)?,
                    "write" => handle_write(&rc_execs, &regs, &tracer)?,
                    _ => {}
                }
            }
            TraceEvent::Fork(_) | TraceEvent::VFork(_) | TraceEvent::Clone(_) => {
                let child = Pid::from_raw(tracer.get_event_message()? as i32);
                s.in_scope(|| {
                    debug!("Fork Event. Creating task for new child: {:?}", child);
                    debug!("Parent pid is: {}", tracer.curr_proc);
                });

                let f = trace_process(
                    async_runtime.clone(),
                    Ptracer::new(child),
                    rc_execs.clone(),
                );
                async_runtime.add_new_task(child, f)?;
            }

            TraceEvent::Posthook(_) => {
                // The posthooks should be handled internally by the system
                // call handler functions.
                bail!("We should not see posthook events.");
            }

            // Received a signal event.
            TraceEvent::ReceivedSignal(pid, caught_signal) => {
                signal = Some(caught_signal);
                s.in_scope(|| debug!(?signal, "pid {} received signal {:?}", pid, signal));
            }

            TraceEvent::KilledBySignal(pid, signal) => {
                s.in_scope(|| debug!(?signal, "Process {} killed by signal {:?}", pid, signal));
            }
            TraceEvent::ProcessExited(_pid) => {
                // No idea how this could happen.
                unreachable!("Did not expect to see ProcessExited event here.");
            }
        }
    }

    // Saw pre-exit event, wait for final exit event.
    match tracer.get_next_event(None).await? {
        TraceEvent::ProcessExited(pid) => {
            s.in_scope(|| debug!("Saw actual exit event for pid {}", pid));
        }
        other => bail!(
            "Saw other event when expecting ProcessExited event: {:?}",
            other
        ),
    }

    Ok(())
}

fn handle_access(rc_execs: &RcExecutions, regs: &Regs<Unmodified>, tracer: &Ptracer) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_access", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File metadata event: (access)");
    });

    let ret_val = regs.retval::<i32>();
    let syscall_succeeded = ret_val == 0;

    // retval = 0 is success for this syscall.
    if syscall_succeeded {
        let bytes = regs.arg1::<*const c_char>();
        let path = tracer
            .read_c_string(bytes)
            .with_context(|| context!("Cannot read `access` path."))?;

        let stat_struct =
            stat(path.as_str()).with_context(|| context!("Cannot read tracee's stat struct."))?;
        let inode = stat_struct.st_ino;

        let mut pathbuf = PathBuf::new();
        pathbuf.push(path);
        // Need to make a FileAccess.
        let reg_file = FileAccess::new(None, inode, Some(pathbuf), String::from("access"));
        rc_execs.add_new_access(AccessType::Metadata, reg_file);
    }
    Ok(())
}

async fn handle_execve(
    regs: Regs<Unmodified>,
    mut tracer: Ptracer,
    rc_execs: RcExecutions,
) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_execve", pid=?tracer.curr_proc);
    let path_name = tracer.read_c_string(regs.arg1())?;

    let args = tracer
        .read_c_string_array(regs.arg2())
        .with_context(|| context!("Reading arguments to execve"))?;

    let envp = tracer.read_c_string_array(regs.arg3())?;
    sys_span.in_scope(|| {
        debug!("execve(\"{:?}\", {:?})", path_name, args);
        trace!("envp={:?}", envp);
    });

    // Execve doesn't return when it succeeds.
    // If we get Ok, it failed.
    // If we get Err, it succeeded.
    // And yes I realize that is confusing.
    // TODO: may not always work?
    let syscall_succeeded = tracer.posthook().await.is_err();

    // TODO: also track failed execves
    if syscall_succeeded {
        let cwd_link = format!("/proc/{}/cwd", tracer.curr_proc);
        let cwd_path =
            readlink(cwd_link.as_str()).with_context(|| context!("Failed to readlink (cwd)"))?;
        let cwd = cwd_path.to_str().unwrap().to_owned();
        let mut pathbuf = PathBuf::new();
        pathbuf.push(cwd);
        let execution = Execution::new(args, pathbuf, envp, path_name);

        rc_execs.add_new_uniq_exec(execution);
    }

    Ok(())
}

fn handle_open(
    rc_execs: &RcExecutions,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let fd = regs.retval::<i32>();
    let pid = tracer.curr_proc;
    let sys_span = span!(Level::INFO, "handle_open", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File open event: ({})", syscall_name);
    });

    let syscall_succeeded = fd > 0;
    if syscall_succeeded {
        let is_create = if syscall_name == "creat" {
            // creat() uses write only as the mode
            true
        } else {
            let flags = if syscall_name == "open" {
                regs.arg2::<i32>()
            } else {
                regs.arg3::<i32>()
            };
            flags & O_CREAT != 0
        };

        // Successful, get full path
        let full_path = path_from_fd(pid, fd).with_context(|| context!("Failed to readlink"))?;
        let full_path = full_path.to_str().unwrap().to_owned();

        let stat_struct = stat(full_path.as_str())
            .with_context(|| context!("Cannot read tracee's stat struct."))?;
        let inode = stat_struct.st_ino;

        // Successful and not a create, we need to track this read to metadata.
        let access_type = if is_create {
            AccessType::FileCreate
        } else {
            AccessType::Metadata
        };

        let mut pathbuf = PathBuf::new();
        pathbuf.push(full_path);
        let file = FileAccess::new(Some(fd), inode, Some(pathbuf), String::from(syscall_name));

        rc_execs.add_new_access(access_type, file);
    }
    Ok(())
}

fn path_from_fd(pid: Pid, fd: i32) -> nix::Result<OsString> {
    let proc_path = format!("/proc/{}/fd/{}", pid, fd);
    readlink(proc_path.as_str())
}

/// Handle read and pread64.
/// We consider a 'read' system call to be a contents access.
fn handle_read(
    rc_execs: &RcExecutions,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let _e = span!(Level::INFO, "handle_read", pid=?tracer.curr_proc).entered();
    debug!("File read event via: {}", syscall_name);

    let fd: i32 = regs.arg1();
    // retval = 0 is end of file but success.
    // retval > 0 is number of bytes read.
    // retval < ERROR.
    let syscall_succeeded = regs.retval::<i32>() >= 0;

    // TODO: Also track failed accesses.
    if syscall_succeeded {
        // Get the path from the fd.
        let full_path = path_from_fd(tracer.curr_proc, fd)?;
        let full_path = full_path.to_str().unwrap().to_owned();

        let stat_struct = stat(full_path.as_str())?;
        let inode = stat_struct.st_ino;

        let mut pathbuf = PathBuf::new();
        pathbuf.push(full_path);
        rc_execs.add_new_access(
            AccessType::ReadContents,
            FileAccess::new(Some(fd), inode, Some(pathbuf), String::from(syscall_name)),
        );
    }
    Ok(())
}

// First, we will just handle SUCCESS and FAIL of STAT calls
// SUCCESS: RET VAL = 0
fn handle_stat(
    rc_execs: &RcExecutions,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_stat", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File stat event: ({})", syscall_name);
    });
    let ret_val: i32 = regs.retval();
    let syscall_succeeded = ret_val == 0;

    // Return value == 0 means success
    if syscall_succeeded {
        let (fd, path) = if syscall_name == "fstat" {
            let fd: i32 = regs.arg1();
            (Some(fd), None)
        } else {
            // lstat, newstatat, stat
            let arg: *const c_char = match syscall_name {
                "lstat" | "stat" => regs.arg1(),
                // newstatat
                "newfstatat" => regs.arg2(),
                other => bail!(context!("Unhandled syscall: {}", other)),
            };

            let path = tracer.read_c_string(arg)?;
            let mut pathbuf = PathBuf::new();
            pathbuf.push(path);
            (None, Some(pathbuf))
        };

        let stat_struct = tracer.read_value::<libc::stat>(regs.arg2())?;
        let inode = stat_struct.st_ino;

        let file = FileAccess::new(fd, inode, path, String::from(syscall_name));
        rc_execs.add_new_access(AccessType::Metadata, file);
    }

    Ok(())
}
fn handle_write(rc_execs: &RcExecutions, regs: &Regs<Unmodified>, tracer: &Ptracer) -> Result<()> {
    // Okay, so here we have to deal with:
    // stderr (fd 2)
    // stdout (fd 1)
    // fd > 2 regular file write (for now just files)
    //
    // Don't care about stdin (fd 0)

    let sys_span = span!(Level::INFO, "handle_write", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File contents write event: (write)");
    });

    // retval = 0 is end of file but success.
    // retval > 0 is number of bytes read.
    // retval < 0 is ERROR
    let ret_val: i32 = regs.retval();
    let syscall_succeeded = ret_val >= 0;
    if syscall_succeeded {
        // Contents.
        // Fd is an arg.
        let fd = regs.arg1::<i32>();

        // Get the path from the fd.
        let full_path = path_from_fd(tracer.curr_proc, fd)
            .with_context(|| context!("Can't get path from fd."))?;
        let full_path = full_path.to_str().unwrap().to_owned();

        // Have to get the inode.
        let stat_struct = stat(full_path.as_str())
            .with_context(|| context!("Cannot stat file descriptor's path."))?;
        let inode = stat_struct.st_ino;

        match fd {
            // Don't care about stdin.
            0 => (),
            1 => {
                let stdout = tracer.read_c_string(regs.arg2())?;
                rc_execs.add_stdout(stdout);
            }
            2 => {
                let stderr = tracer.read_c_string(regs.arg2())?;
                rc_execs.add_stderr(stderr);
            }
            _ => {
                let mut pathbuf = PathBuf::new();
                pathbuf.push(full_path);
                let file = FileAccess::new(Some(fd), inode, Some(pathbuf), String::from("write"));
                rc_execs.add_new_access(AccessType::WriteContents, file);
            }
        }
    }
    Ok(())
}
