#[allow(unused_imports)]
use libc::{c_char, syscall, AT_SYMLINK_NOFOLLOW, O_ACCMODE, O_CREAT, O_RDONLY, O_RDWR, O_WRONLY};
#[allow(unused_imports)]
use nix::fcntl::{readlink, OFlag};
use nix::sys::stat::stat;
use nix::unistd::Pid;
use std::path::PathBuf;

use crate::async_runtime::AsyncRuntime;
use crate::cache::{
    ExecAccesses, ExecMetadata, Execution, FileAccess, GlobalExecutions, OpenMode, RcExecution,
};
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

pub fn trace_program(first_proc: Pid) -> Result<()> {
    info!("Running whole program");

    let async_runtime = AsyncRuntime::new();
    // We have to create the first execution struct outside
    // trace process, so we don't accidentally overwrite it
    // within trace_process().

    // We need to pass an execution struct to trace_process(),
    // because the function needs to be able to pass an execution
    // struct to a child process. But, we don't actually ADD the
    // execution struct to global_executions here, this happens
    // in the prehook of an execve call, after we get the next event
    // and verify it is not a posthook (would be a failed execve) but
    // an exec event, meaning the execve succeeded, so it should be
    // added to global_executions.
    let first_execution = RcExecution::new(Execution::Pending);
    let global_executions = GlobalExecutions::new();

    let f = trace_process(
        async_runtime.clone(),
        Ptracer::new(first_proc),
        first_execution,
        global_executions.clone(),
    );
    async_runtime
        .run_task(first_proc, f)
        .with_context(|| context!("Program tracing failed. Task returned error."))?;

    for exec in global_executions.executions.borrow().iter() {
        println!("Execution: {:?}", exec);
    }
    let length = global_executions.get_execution_count();
    println!("Number of executions: {}", length);
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
    mut curr_execution: RcExecution,
    global_executions: GlobalExecutions,
) -> Result<()> {
    let s = span!(Level::INFO, stringify!(trace_process), pid=?tracer.curr_proc);
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
            // If we see an exec event from ptrace, we know it was successful.
            TraceEvent::Exec(pid) => {
                s.in_scope(|| debug!("Saw exec event for pid {}", pid));
                // Handling stuff related to execve should NOT be done here, as the registers have already been
                // blown away.
            }
            TraceEvent::PreExit(_pid) => {
                s.in_scope(|| debug!("Saw preexit event."));
                break;
            }
            TraceEvent::Prehook(_) => {
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
                    "execve" => {
                        let regs = tracer
                            .get_registers()
                            .with_context(|| context!("Failed to get regs in exec event"))?;
                        let arg = regs.arg1();
                        let path_name = tracer.read_c_string(arg)?;
                        debug!("PATH NAME: {}", path_name);

                        let args = tracer
                            .read_c_string_array(regs.arg2())
                            .with_context(|| context!("Reading arguments to execve"))?;
                        let envp = tracer.read_c_string_array(regs.arg3())?;

                        let cwd_link = format!("/proc/{}/cwd", tracer.curr_proc);
                        let cwd_path = readlink(cwd_link.as_str())
                            .with_context(|| context!("Failed to readlink (cwd)"))?;
                        let cwd = cwd_path.to_str().unwrap().to_owned();
                        let cwd_pathbuf = PathBuf::from(cwd);

                        let next_event = tracer.get_next_event(None).await.with_context(|| {
                            context!("Unable to get next event after execve prehook.")
                        })?;

                        let new_execution = match next_event {
                            TraceEvent::Exec(_) => {
                                // The execve succeeded!
                                // Create a Successful Execution and add to global executions.
                                s.in_scope(|| {
                                    debug!("Execve succeeded!");
                                });
                                RcExecution::new(Execution::Successful(
                                    ExecMetadata::new(),
                                    ExecAccesses::new(),
                                    tracer.curr_proc,
                                ))
                            }
                            _ => {
                                // The execve failed!
                                // Create a Failed Execution and add to global executions.
                                s.in_scope(|| {
                                    debug!("Execve failed.");
                                });
                                RcExecution::new(Execution::Failed(
                                    ExecMetadata::new(),
                                    tracer.curr_proc,
                                ))
                            }
                        };

                        // This is a NEW exec, we must update the current
                        // execution to this new one.
                        // I *THINK* I want to update this whether it succeeds or fails.
                        // Because both of those technically are executions.
                        new_execution.add_identifiers(args, cwd_pathbuf, envp, path_name);
                        global_executions.add_new_execution(new_execution.clone());
                        curr_execution = new_execution;
                        continue;
                    }
                    "exit" | "exit_group" | "clone" | "vfork" | "fork" | "clone2" | "clone3" => {
                        debug!("Special event: {}. Do not go to posthook.", name);
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
                    "access" => handle_access(&curr_execution, &regs, &tracer)?,
                    "creat" | "openat" | "open" => {
                        handle_open(&curr_execution, &regs, name, &tracer)?
                    }
                    "fstat" | "newfstatat" | "stat" => {
                        handle_stat(&curr_execution, &regs, name, &tracer)?
                    }
                    "pread64" | "read" => handle_read(&curr_execution, &regs, name, &tracer)?,
                    "write" | "writev" => handle_write(&curr_execution, &regs, &tracer)?,
                    _ => {}
                }
            }
            TraceEvent::Fork(_) | TraceEvent::VFork(_) | TraceEvent::Clone(_) => {
                let child = Pid::from_raw(tracer.get_event_message()? as i32);
                s.in_scope(|| {
                    debug!("Fork Event. Creating task for new child: {:?}", child);
                    debug!("Parent pid is: {}", tracer.curr_proc);
                });

                curr_execution.add_child_process(child);
                let f = trace_process(
                    async_runtime.clone(),
                    Ptracer::new(child),
                    curr_execution.clone(),
                    global_executions.clone(),
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
            TraceEvent::ProcessExited(_pid, _exit_code) => {
                // No idea how this could happen.
                unreachable!("Did not expect to see ProcessExited event here.");
            }
        }
    }

    // Saw pre-exit event, wait for final exit event.
    match tracer.get_next_event(None).await? {
        TraceEvent::ProcessExited(pid, exit_code) => {
            s.in_scope(|| debug!("Saw actual exit event for pid {}", pid));

            // Add exit code to the exec struct, if this is the
            // pid that exec'd the exec. execececececec.
            curr_execution.add_exit_code(exit_code, pid);
        }
        other => bail!(
            "Saw other event when expecting ProcessExited event: {:?}",
            other
        ),
    }

    Ok(())
}

fn handle_access(execution: &RcExecution, regs: &Regs<Unmodified>, tracer: &Ptracer) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_access", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File metadata event: (access)");
    });
    let ret_val = regs.retval::<i32>();
    // retval = 0 is success for this syscall.
    let syscall_succeeded = ret_val == 0;
    let bytes = regs.arg1::<*const c_char>();
    let register_path = tracer
        .read_c_string(bytes)
        .with_context(|| context!("Cannot read `access` path."))?;
    let syscall_name = String::from("access");

    let file_access = if syscall_succeeded {
        // If the call is successful we can
        // get the inode.
        let stat_struct = stat(register_path.as_str())
            .with_context(|| context!("Cannot read tracee's stat struct."))?;
        let inode = stat_struct.st_ino;
        let path = PathBuf::from(register_path);

        FileAccess::SuccessfulMetadataAccess {
            fd: None,
            inode,
            path: Some(path),
            syscall_name,
        }
    } else {
        let path = PathBuf::from(register_path);
        let path = Some(path);
        FileAccess::FailedMetadataAccess {
            fd: None,
            path,
            syscall_name,
        }
    };

    execution.add_new_access(file_access);
    Ok(())
}

fn handle_open(
    execution: &RcExecution,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let pid = tracer.curr_proc;
    let sys_span = span!(Level::INFO, "handle_open", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File open event: ({})", syscall_name);
    });

    let ret_val = regs.retval::<i32>();
    let syscall_succeeded = ret_val > 0;

    let (is_create, open_mode) = if syscall_name == "creat" {
        // creat() uses write only as the mode
        (true, OpenMode::WriteOnly)
    } else {
        let flags = if syscall_name == "open" {
            regs.arg2::<i32>()
        } else {
            regs.arg3::<i32>()
        };
        let is_create = flags & O_CREAT != 0;
        let mode = match flags & O_ACCMODE {
            O_RDONLY => OpenMode::ReadOnly,
            O_RDWR => OpenMode::ReadWrite,
            O_WRONLY => OpenMode::WriteOnly,
            _ => panic!("Open flags do not match any mode!"),
        };
        (is_create, mode)
    };

    let file_access = if syscall_succeeded {
        // Successful, get full path
        // ret_val is the file descriptor if successful
        let syscall_name = String::from(syscall_name);
        let full_path =
            path_from_fd(pid, ret_val).with_context(|| context!("Failed to readlink"))?;
        let full_path = full_path.to_str().unwrap().to_owned();
        let stat_struct = stat(full_path.as_str())
            .with_context(|| context!("Cannot read tracee's stat struct."))?;
        let inode = stat_struct.st_ino;
        let path = PathBuf::from(full_path);

        if is_create {
            FileAccess::SuccessfulFileCreate {
                fd: ret_val,
                inode,
                path,
                syscall_name,
            }
        } else {
            FileAccess::SuccessfulFileOpen {
                fd: ret_val,
                inode,
                open_mode,
                path,
                syscall_name,
            }
        }
    } else {
        // Failed, no fd, get whatever path is available from the parameters of the syscall.
        let bytes = match syscall_name {
            "creat" | "open" => regs.arg1::<*const c_char>(),
            "openat" => regs.arg2::<*const c_char>(),

            _ => panic!("Not handling an appropriate system call from handle_open!"),
        };
        let syscall_name = String::from(syscall_name);

        let path = tracer
            .read_c_string(bytes)
            .with_context(|| context!("Cannot read `access` path."))?;
        let path = PathBuf::from(path);
        if is_create {
            FileAccess::FailedFileCreate { path, syscall_name }
        } else {
            FileAccess::FailedFileOpen {
                open_mode,
                path,
                syscall_name,
            }
        }
    };
    execution.add_new_access(file_access);
    Ok(())
}

/// Handle read and pread64.
/// We consider a 'read' system call to be a contents access.
fn handle_read(
    execution: &RcExecution,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let _e = span!(Level::INFO, "handle_read", pid=?tracer.curr_proc).entered();
    debug!("File read event via: {}", syscall_name);

    // retval = 0 is end of file but success.
    // retval > 0 is number of bytes read.
    // retval < ERROR.
    let fd: i32 = regs.arg1();
    let syscall_succeeded = regs.retval::<i32>() >= 0;
    let syscall_name = String::from(syscall_name);

    let file_access = if syscall_succeeded {
        // Get the path from the fd.
        let full_path = path_from_fd(tracer.curr_proc, fd)?;
        let full_path = full_path.to_str().unwrap().to_owned();

        let stat_struct = stat(full_path.as_str())?;
        let inode = stat_struct.st_ino;
        let path = PathBuf::from(full_path);

        FileAccess::SuccessfulFileRead {
            fd,
            inode,
            path,
            syscall_name,
        }
    } else {
        FileAccess::FailedFileRead { fd, syscall_name }
    };

    execution.add_new_access(file_access);
    Ok(())
}

// Currently: stat, fstat, newfstat64
// Metadata access
fn handle_stat(
    execution: &RcExecution,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_stat", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File stat event: ({})", syscall_name);
    });
    // Return value == 0 means success
    let ret_val: i32 = regs.retval();
    let syscall_succeeded = ret_val == 0;

    let (fd, path) = if syscall_name == "fstat" {
        (Some(regs.arg1::<i32>()), None)
    } else {
        // newstatat, stat
        // TODO: handle lstat? Or don't? I don't know? What **do** I know?
        // TODO: handle DIRFD in newfstatat
        let arg: *const c_char = match syscall_name {
            "stat" => regs.arg1(),
            // newstatat
            "newfstatat" => regs.arg2(),
            other => bail!(context!("Unhandled syscall: {}", other)),
        };

        let path = tracer
            .read_c_string(arg)
            .with_context(|| context!("Can't get path from path arg."))?;
        let pathbuf = PathBuf::from(path);
        (None, Some(pathbuf))
    };

    let file_access = if syscall_succeeded {
        let stat_struct = tracer
            .read_value::<libc::stat>(regs.arg2())
            .with_context(|| context!("Can't read stat struct"))?;
        let inode = stat_struct.st_ino;
        // TODO: maybe get the nice full path if it's successful, using a stat call?
        // This still gives you info, just not as much.
        FileAccess::SuccessfulMetadataAccess {
            fd,
            inode,
            path,
            syscall_name: String::from(syscall_name),
        }
    } else {
        FileAccess::FailedMetadataAccess {
            fd,
            path,
            syscall_name: String::from(syscall_name),
        }
    };
    execution.add_new_access(file_access);

    Ok(())
}

fn handle_write(execution: &RcExecution, regs: &Regs<Unmodified>, tracer: &Ptracer) -> Result<()> {
    // Okay, so here we have to deal with:
    // stderr (fd 2)
    // stdout (fd 1)
    // fd > 2 regular file write (for now just files)
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
    // Contents.
    // Fd is an arg.
    let fd = regs.arg1::<i32>();
    let syscall_name = String::from("write");

    let file_access = if syscall_succeeded {
        match fd {
            // TODO: stdin?
            1 => {
                let stdout = tracer
                    .read_c_string(regs.arg2())
                    .with_context(|| context!("Can't read stdout to string."))?;
                FileAccess::Stdout(stdout)
            }
            2 => {
                let stderr = tracer
                    .read_c_string(regs.arg2())
                    .with_context(|| context!("Can't read stderr to string."))?;
                FileAccess::Stderr(stderr)
            }
            _ => {
                // Get the path from the fd because the call was successful.
                let path = path_from_fd(tracer.curr_proc, fd)
                    .with_context(|| context!("Can't get path from fd."))?;
                let path = path.to_str().unwrap().to_owned();

                // Have to get the inode.
                let stat_struct = stat(path.as_str())
                    .with_context(|| context!("Cannot stat file descriptor's path."))?;
                let inode = stat_struct.st_ino;
                let path = PathBuf::from(path);
                FileAccess::SuccessfulFileWrite {
                    fd,
                    inode,
                    path,
                    syscall_name,
                }
            }
        }
    } else {
        FileAccess::FailedFileWrite { fd, syscall_name }
    };
    execution.add_new_access(file_access);

    Ok(())
}

fn path_from_fd(pid: Pid, fd: i32) -> nix::Result<OsString> {
    let proc_path = format!("/proc/{}/fd/{}", pid, fd);
    readlink(proc_path.as_str())
}
