#[allow(unused_imports)]
use libc::{c_char, syscall, AT_SYMLINK_NOFOLLOW, O_ACCMODE, O_CREAT, O_RDONLY, O_RDWR, O_WRONLY};
#[allow(unused_imports)]
use nix::fcntl::{readlink, OFlag};
use nix::unistd::Pid;
// use std::borrow::Borrow;
use std::fs;
use std::path::PathBuf;

use crate::async_runtime::AsyncRuntime;
use crate::cache::{
    generate_hash, get_cached_root_execution, serialize_execs_to_cache, serve_outputs_from_cache,
    ExecAccesses, ExecMetadata, Execution, FileAccess, OpenMode, RcExecution, IO,
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

pub fn trace_program(first_proc: Pid) -> Result<()> {
    info!("Running whole program");

    let async_runtime = AsyncRuntime::new();
    // We have to create the first execution struct outside
    // trace process, so we don't accidentally overwrite it
    // within trace_process().

    let first_execution = RcExecution::new(Execution::PendingRoot);

    let f = trace_process(
        async_runtime.clone(),
        Ptracer::new(first_proc),
        first_execution.clone(),
    );
    async_runtime
        .run_task(first_proc, f)
        .with_context(|| context!("Program tracing failed. Task returned error."))?;

    // Serialize the execs to the cache!
    // Only serialize to cache if not PendingRoot?
    // PendingRoot == we skipped the execution because
    // it had a cached match and was therefore skippable.
    if !first_execution.is_pending_root() {
        serialize_execs_to_cache(first_execution)?;
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
    mut curr_execution: RcExecution,
) -> Result<()> {
    let s = span!(Level::INFO, stringify!(trace_process), pid=?tracer.curr_proc);
    let _ = s.enter();
    s.in_scope(|| info!("Starting Process"));
    let mut signal = None;
    let mut skip_execution = false;

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
                        let executable = tracer.read_c_string(arg)?;

                        let args = tracer
                            .read_c_string_array(regs.arg2())
                            .with_context(|| context!("Reading arguments to execve"))?;
                        let envp = tracer.read_c_string_array(regs.arg3())?;

                        let cwd_link = format!("/proc/{}/cwd", tracer.curr_proc);
                        let cwd_path = readlink(cwd_link.as_str())
                            .with_context(|| context!("Failed to readlink (cwd)"))?;
                        let cwd = cwd_path.to_str().unwrap().to_owned();
                        let starting_cwd = PathBuf::from(cwd);

                        let next_event = tracer.get_next_event(None).await.with_context(|| {
                            context!("Unable to get next event after execve prehook.")
                        })?;

                        let new_execution = create_new_execution(
                            args,
                            tracer.curr_proc,
                            &curr_execution,
                            envp,
                            executable,
                            next_event,
                            starting_cwd,
                        )?;

                        s.in_scope(|| debug!("Checking cache for execution"));
                        if curr_execution.is_pending_root() {
                            if let Some(cached_exec) =
                                get_cached_root_execution(tracer.curr_proc, new_execution.clone())
                            {
                                let new_exec_succeeded = new_execution.is_successful();
                                let cached_exec_succeeded = cached_exec.is_successful();

                                // If we have that the execution failed when we had cached it, but this time it succeeded,
                                // let's just panic for now. Later, I imagine we want to maybe replace the failed
                                // cached execution with a successful one? Like we'd record this new run. But idk.
                                if !cached_exec_succeeded && new_exec_succeeded {
                                    panic!("Cached version failed, but running this time the execution succeeds!!");
                                }

                                // We don't skip if it failed. We just let it fail.
                                if cached_exec_succeeded && new_exec_succeeded {
                                    s.in_scope(|| info!("Initiating skip of execution!"));
                                    skip_execution = true;
                                    s.in_scope(|| info!("Serving outputs"));
                                    serve_outputs_from_cache(tracer.curr_proc, &cached_exec)?;
                                }
                            } else {
                                curr_execution.update_root(new_execution);
                            }
                        } else {
                            // parent right now
                            // TODO: check the pids
                            let new_rcexecution = RcExecution::new(new_execution);
                            curr_execution.add_child_execution(new_rcexecution.clone());
                            curr_execution = new_rcexecution;
                        }
                        continue;
                    }
                    "exit" | "exit_group" | "clone" | "vfork" | "fork" | "clone2" | "clone3" => {
                        debug!("Special event: {}. Do not go to posthook.", name);
                        continue;
                    }
                    _ => {
                        // Check if we should skip this execution.
                        // If we are gonna skip, we have to change:
                        // rax, orig_rax, arg1

                        if skip_execution {
                            debug!("Trying to change system call after the execve into exit call! (Skip the execution!)");
                            let regs = tracer
                                .get_registers()
                                .with_context(|| context!("Failed to get regs in stat event"))?;
                            let mut regs = regs.make_modified();
                            let exit_syscall_num = libc::SYS_exit as u64;

                            // Change the arg1 to correct exit code?
                            regs.write_arg1(0);
                            // Change the orig rax val don't ask me why
                            regs.write_syscall_number(exit_syscall_num);
                            // Change the rax val
                            regs.write_rax(exit_syscall_num);

                            tracer.set_regs(&mut regs)?;
                            continue;
                        }
                    }
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
                    _ => {}
                }
            }
            TraceEvent::Fork(_) | TraceEvent::VFork(_) | TraceEvent::Clone(_) => {
                let child = Pid::from_raw(tracer.get_event_message()? as i32);
                s.in_scope(|| {
                    debug!("Fork Event. Creating task for new child: {:?}", child);
                    debug!("Parent pid is: {}", tracer.curr_proc);
                });

                // When a process forks, we pass the current execution struct to the
                // child process' future as both the curr execution and the parent execution.
                // If the child process then calls "execve",
                // this new execution will replace the current execution for the child
                // process' future and its parent execution
                let f = trace_process(
                    async_runtime.clone(),
                    Ptracer::new(child),
                    curr_execution.clone(),
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
            // TODO: Should these just be called from a function called
            // like "do_exit_stuff" (obviously something better but you
            // get me)
            if !skip_execution {
                // This is a new (or at least new version?) execution,
                // add/update all the necessary stuff in the cache.
                curr_execution.add_exit_code(exit_code, pid);
                curr_execution.add_output_file_hashes(pid)?;
                curr_execution.copy_outputs_to_cache()?;
            }
        }
        other => bail!(
            "Saw other event when expecting ProcessExited event: {:?}",
            other
        ),
    }

    Ok(())
}

// Handling the access system call.
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
    debug!("register path: {}", register_path);

    let path_arg = PathBuf::from(register_path);

    let full_path = get_full_path(Some(PathArg::Path(path_arg)), tracer.curr_proc)?;
    debug!("made it past get_full_path");

    let file_access = generate_file_access(
        full_path,
        IO::Input,
        tracer.curr_proc,
        syscall_name,
        syscall_succeeded,
    );
    execution.add_new_file_event(tracer.curr_proc, file_access, IO::Input);
    Ok(())
}

fn create_new_execution(
    args: Vec<String>,
    caller_pid: Pid,
    // Before we create a new execution, we should check that this
    // process has not already done a successful execve. We are
    // currently NOT handling single proc doing execve execve execve...
    curr_exec: &RcExecution,
    envp: Vec<String>,
    executable: String,
    next_event: TraceEvent,
    starting_cwd: PathBuf,
) -> Result<Execution> {
    let s = span!(Level::INFO, stringify!(trace_process), pid=?caller_pid);
    let _ = s.enter();

    // If the current execution is pending root, great,
    // our root process is trying to do its first exec.
    // If the curr execution struct's pid is different than the
    // caller's pid, this means this is a child process who is
    // doing its first exec! (the difference in pids is that the curr
    // execution struct's pid is the parent of the caller pid)
    if curr_exec.is_pending_root() || curr_exec.caller_pid() != caller_pid {
        let mut new_execution = match next_event {
            TraceEvent::Exec(_) => {
                // The execve succeeded!
                // If it's in the cache, change the
                s.in_scope(|| {
                    debug!("Execve succeeded!");
                });

                Execution::Successful(ExecMetadata::new(), ExecAccesses::new(), Vec::new())
            }
            _ => {
                // The execve failed!
                // Create a Failed Execution and add to global executions.
                s.in_scope(|| {
                    debug!("Execve failed.");
                });
                Execution::Failed(ExecMetadata::new())
            }
        };

        // This is a NEW exec, we must update the current
        // execution to this new one.
        // I *THINK* I want to update this whether it succeeds or fails.
        // Because both of those technically are executions.
        new_execution.add_identifiers(args, caller_pid, envp, executable, starting_cwd);

        Ok(new_execution)
    } else {
        panic!("Process has already exec'd and is trying to exec again!");
    }
}

/// Open, openat, creat.
/// Opening for read/write, write,
/// and creating files are all considered outputs,
/// just opening a file for reading is considered
/// an input.
fn handle_open(
    execution: &RcExecution,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let pid = tracer.curr_proc;
    let sys_span = span!(Level::INFO, "handle_open", pid=?tracer.curr_proc);
    let _ = sys_span.enter();

    sys_span.in_scope(|| {
        debug!("File open event: ({})", syscall_name);
    });

    let ret_val = regs.retval::<i32>();
    let syscall_succeeded = ret_val > 0;

    let open_mode = if syscall_name == "creat" {
        // creat() uses write only as the mode
        OpenMode::WriteOnly
    } else {
        let flags = if syscall_name == "open" {
            regs.arg2::<i32>()
        } else {
            regs.arg3::<i32>()
        };
        match flags & O_ACCMODE {
            O_RDONLY => OpenMode::ReadOnly,
            O_RDWR => OpenMode::ReadWrite,
            O_WRONLY => {
                sys_span.in_scope(|| {
                    debug!("Opening write only");
                });
                OpenMode::WriteOnly
            }
            _ => panic!("Open flags do not match any mode!"),
        }
    };

    let io = match open_mode {
        OpenMode::ReadOnly => IO::Input,
        _ => IO::Output,
    };

    let path_arg_bytes = match syscall_name {
        "creat" | "open" => regs.arg1::<*const c_char>(),
        "openat" => regs.arg2::<*const c_char>(),
        _ => panic!("Not handling an appropriate system call from handle_open!"),
    };

    let path_arg = tracer
        .read_c_string(path_arg_bytes)
        .with_context(|| context!("Cannot read `open` path."))?;
    let file_name_arg = PathBuf::from(path_arg);
    let path_arg = if syscall_succeeded {
        Some(PathArg::Path(file_name_arg))
    } else {
        None
    };

    let full_path = get_full_path(path_arg, pid)?;
    sys_span.in_scope(|| info!("Full path: {:?}", full_path));
    let syscall_name = String::from(syscall_name);

    let file_event = generate_file_access(full_path, io, pid, syscall_name, syscall_succeeded);
    execution.add_new_file_event(tracer.curr_proc, file_event, io);

    Ok(())
}

// Currently: stat, fstat, newfstat64
// We consider these syscalls to be inputs.
// Well the files they are acting upon anyway!
fn handle_stat(
    execution: &RcExecution,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_stat", pid=?tracer.curr_proc);
    let _ = sys_span.enter();
    sys_span.in_scope(|| {
        debug!("File stat event: ({})", syscall_name);
    });
    // Return value == 0 means success
    let ret_val: i32 = regs.retval();
    let syscall_succeeded = ret_val == 0;

    let full_path_arg = if syscall_name == "fstat" {
        let fd = regs.arg1::<i32>();
        if syscall_succeeded {
            // TODO: Do something about stdin, stderr, stdout???
            if fd < 3 {
                return Ok(());
            }
            Some(PathArg::Fd(3))
        } else {
            None
        }
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
        Some(PathArg::Path(PathBuf::from(path)))
    };

    // Either way we are calling this function with a PathArg and it's **generic** over the PathArg enum :3
    let full_path = get_full_path(full_path_arg, tracer.curr_proc)?;

    let syscall_name = String::from(syscall_name);
    let file_event = generate_file_access(
        full_path,
        IO::Input,
        tracer.curr_proc,
        syscall_name,
        syscall_succeeded,
    );
    execution.add_new_file_event(tracer.curr_proc, file_event, IO::Input);

    Ok(())
}

enum PathArg {
    Fd(i32),
    Path(PathBuf),
}

fn path_from_fd(pid: Pid, fd: i32) -> anyhow::Result<PathBuf> {
    let proc_path = format!("/proc/{}/fd/{}", pid, fd);
    let proc_path = readlink(proc_path.as_str())?;
    Ok(PathBuf::from(proc_path))
}

// Take in the path arg, either a string path or the
// fd the system call provides.
// If the the system call name is fstat (i.e. path arg = None),
// full path = PathBuf::new().
// Create the canonicalized
// version of the path and return it.
fn get_full_path(path_arg: Option<PathArg>, calling_pid: Pid) -> anyhow::Result<PathBuf> {
    let sys_span = span!(Level::INFO, stringify!(get_full_path), pid=?calling_pid);
    let _ = sys_span.enter();
    sys_span.in_scope(|| {
        debug!("Getting full path.");
    });
    match path_arg {
        Some(PathArg::Fd(fd)) => path_from_fd(calling_pid, fd),
        Some(PathArg::Path(path)) => {
            sys_span.in_scope(|| {
                debug!("Going to canonicalize: {}", stringify!(&path));
            });
            fs::canonicalize(&path).or(Ok(path))
        }
        None => Ok(PathBuf::new()),
    }
}

// Generate file access if appropriate,
// return None if directory or standard out
// or whatever else that's not a real file.
// ----------------------------------------
// Idk why this was an Option<FileAccess>.
// Inside the function, I may or may not want the hash,
// but I do always want a FileAccess struct back,
// successful or not!
fn generate_file_access(
    full_path: PathBuf,
    io_type: IO,
    pid: Pid,
    syscall_name: String,
    syscall_succeeded: bool,
) -> FileAccess {
    // Why pass in the file name when there's a perfectly good file_name, just sittin' in the full_path??
    // Who else likes Seinfeld? Just me? Alright.
    // We generate the hash for the output at the end of the execution.

    if syscall_succeeded {
        let hash = match io_type {
            IO::Input => {
                if full_path.starts_with("/dev/pts")
                    || full_path.starts_with("/dev/null")
                    || full_path.starts_with("/etc/")
                    || full_path.starts_with("/proc/")
                    || full_path.is_dir()
                {
                    None
                } else {
                    let path = full_path.clone().into_os_string().into_string().unwrap();
                    Some(generate_hash(pid, path))
                }
            }
            _ => None,
        };
        FileAccess::Success(full_path, hash, syscall_name)
    } else {
        FileAccess::Failure(full_path, syscall_name)
    }
}
