#[allow(unused_imports)]
use libc::{
    c_char, syscall, AT_FDCWD, AT_SYMLINK_NOFOLLOW, CLONE_THREAD, O_ACCMODE, O_APPEND, O_CREAT,
    O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
};
#[allow(unused_imports)]
use nix::fcntl::{readlink, OFlag};
use nix::unistd::Pid;
use std::path::{Path, PathBuf};

use crate::async_runtime::AsyncRuntime;
use crate::cache::{
    /*generate_hash,*/ ExecFileEvents, ExecMetadata, Execution, OpenMode, RcExecution,
    SyscallEvent,
};

use crate::context;
use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::system_call_names::get_syscall_name;
use crate::tracer::TraceEvent;
use crate::Ptracer;
use crate::{context, redirection};

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
    // CWD of the root process + "/cache/"
    let mut cache_dir = std::env::current_dir().with_context(|| context!("Cannot get CWD."))?;
    cache_dir.push("cache/");

    fs::create_dir_all(&cache_dir)
        .with_context(|| context!("Failed to create cache dir: {:?}", cache_dir))?;

    let f = trace_process(
        async_runtime.clone(),
        Ptracer::new(first_proc),
        first_execution.clone(),
        Rc::new(cache_dir.clone()),
    );
    async_runtime
        .run_task(first_proc, f)
        .with_context(|| context!("Program tracing failed. Task returned error."))?;

    // Serialize the execs to the cache!
    // Only serialize to cache if not PendingRoot?
    // PendingRoot == we skipped the execution because
    // it had a cached match and was therefore skippable.
    // if !first_execution.is_pending_root() {
    //     serialize_execs_to_cache(first_execution.clone())
    //         .with_context(|| context!("Unable to serialize execs to our cache file."))?;
    // }
    // println!(
    //     "number of child execs: {}",
    //     first_execution.child_executions().len()
    // );

    // println!(
    //     "file events: {:?}",
    //     first_execution.file_events()
    // );

    println!("executions: {:?}", first_execution);
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
    cache_dir: Rc<PathBuf>,
) -> Result<()> {
    let s = span!(Level::INFO, stringify!(trace_process), pid=?tracer.curr_proc);
    s.in_scope(|| info!("Starting Process"));
    let mut signal = None;
    let mut skip_execution = false;
    let mut iostream_redirected = false;

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

                // For file creation type events (creat, open, openat), we want to know if the file already existed
                // before the syscall happens (i.e. in the prehook).
                let mut file_existed_at_start = false;

                // Special cases, we won't get a posthook event. Instead we will get
                // an execve event or a posthook if execve returns failure. We don't
                // bother handling it, let the main loop take care of it.
                // TODO: Handle them properly...

                match name {
                    "creat" | "open" | "openat" => {
                        // Get the full path and check if the file exists.
                        let full_path = get_full_path(&curr_execution, name, &tracer)?;
                        file_existed_at_start = full_path.exists();
                    }
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

                        // We are in the posthook now!
                        let new_execution = create_new_execution(
                            args,
                            tracer.curr_proc,
                            &curr_execution,
                            envp,
                            executable,
                            next_event,
                            starting_cwd,
                        )?;

                        if curr_execution.is_pending_root() {
                            // Old stuff:
                            //     if let Some(cached_exec) =
                            //         get_cached_root_execution(tracer.curr_proc, new_execution.clone())
                            //     {
                            //         let new_exec_succeeded = new_execution.is_successful();
                            //         let cached_exec_succeeded = cached_exec.is_successful();

                            //         // If we have that the execution failed when we had cached it, but this time it succeeded,
                            //         // let's just panic for now. Later, I imagine we want to maybe replace the failed
                            //         // cached execution with a successful one? Like we'd record this new run. But idk.
                            //         if !cached_exec_succeeded && new_exec_succeeded {
                            //             panic!("Cached version failed, but running this time the execution succeeds!!");
                            //         }

                            //         // We don't skip if it failed. We just let it fail.
                            //         if cached_exec_succeeded && new_exec_succeeded {
                            //             s.in_scope(|| info!("Initiating skip of execution!"));
                            //             skip_execution = true;
                            //             s.in_scope(|| info!("Serving outputs"));
                            //             serve_outputs_from_cache(tracer.curr_proc, &cached_exec)?;
                            //         }
                            //     } else {
                            //         curr_execution.update_root(new_execution);
                            //     }
                            // } else {
                            // We panic in create_new_execution() if a process is trying to execve a second time.
                            // So if we get here, it's not pending root, it's at least the parent after it's execve
                            // call. And it's not parent doing a second execve, it must be the child doing an execve.
                            // If we check the pid of the curr_exec vs new_rcexecution they should differ.
                            // TODO: check the pids

                            // Old stuff for adding child executions I think?
                            // curr_execution.update_root(new_execution.clone());
                            // let new_rcexecution = RcExecution::new(new_execution);
                            // curr_execution.add_child_execution(new_rcexecution.clone());
                            // curr_execution = new_rcexecution;

                            // I *think* this is all I have to do to update the execution right now
                            // because I am only worrying about ONE at a time.
                            curr_execution.update_root(new_execution.clone());
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

                        if !iostream_redirected {
                            const STDOUT_FD: u32 = 1;
                            // TODO: Deal with PID recycling?
                            let stdout_file: String =
                                format!("stdout_{:?}", tracer.curr_proc.as_raw());

                            // This is the first real system call this program is doing after exec-ing.
                            // We will redirect their stdout output here by writing it to a file.
                            redirection::redirect_io_stream(&stdout_file, STDOUT_FD, &mut tracer)
                                .await
                                .with_context(|| context!("Unable to redirect stdout."))?;

                            // TODO: Add stderr redirection.

                            iostream_redirected = true;
                            // Continue to let original system call run.
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

                span!(Level::INFO, "Posthook", retval).in_scope(|| info!(name));

                match name {
                    "access" => handle_access(&curr_execution, &tracer)?,
                    "creat" | "openat" | "open" => {
                        handle_open(&curr_execution, file_existed_at_start, name, &tracer)?
                    }
                    // TODO: newfstatat
                    "stat" => handle_stat(&curr_execution, name, &tracer)?,
                    _ => {}
                }
            }
            TraceEvent::Clone(_) => {
                // We treat clone differently from fork because clone has the dangerous
                // CLONE_THREAD flag. Well it's not dangerous, but we don't handle threads
                // so we want to panic if we detect a program trying to clone one.

                let regs = tracer
                    .get_registers()
                    .with_context(|| context!("Failed to get regs in exec event"))?;

                // From dettrace:
                // kinda unsure why this is unsigned
                // msg = "clone";
                // unsigned long flags = (unsigned long)tracer.arg1();
                // isThread = (flags & CLONE_THREAD) != 0;

                // flags are the 3rd arg to clone.
                let flags = regs.arg3::<i32>();
                if (flags & CLONE_THREAD) != 0 {
                    panic!("THREADSSSSSSSSSS!");
                }

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
                    cache_dir.clone(),
                );
                async_runtime.add_new_task(child, f)?;
            }
            TraceEvent::Fork(_) | TraceEvent::VFork(_) => {
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
                    cache_dir.clone(),
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
                // TODO: ya know, properly cache
                curr_execution.add_exit_code(exit_code, pid);
                // curr_execution.add_output_file_hashes(pid)?;
                // curr_execution.copy_outputs_to_cache()?;
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
fn handle_access(execution: &RcExecution, tracer: &Ptracer) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_access", pid=?tracer.curr_proc);
    let _ = sys_span.enter();

    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in handle_access()"))?;
    let ret_val = regs.retval::<i32>();
    // retval = 0 is success for this syscall.
    let syscall_name = String::from("access");
    let full_path = get_full_path(execution, &syscall_name, tracer)?;

    sys_span.in_scope(|| {
        debug!("Generating access syscall event!");
    });
    let access_syscall_event = if full_path.starts_with("/dev/pts")
        || full_path.starts_with("/dev/null")
        || full_path.starts_with("/etc/")
        || full_path.starts_with("/lib/")
        || full_path.starts_with("/proc/")
        || full_path.is_dir()
    {
        None
    } else {
        match ret_val {
            0 => Some(SyscallEvent::Access),
            -2 => Some(SyscallEvent::AccessFileDidntExist),
            -13 => Some(SyscallEvent::AccessAccessDenied),
            e => panic!("Unexpected error returned by access syscall!: {}", e),
        }
    };

    if let Some(event) = access_syscall_event {
        execution.add_new_file_event(tracer.curr_proc, event, full_path);
    }

    // let starting_hash = if full_path.exists() && open_syscall_event.is_some() {
    //     Some(generate_hash(
    //         pid,
    //         full_path.clone().into_os_string().into_string().unwrap(),
    //     ))
    // } else {
    //     None
    // };

    // if let Some(hash) = starting_hash {
    //     execution.add_starting_hash(full_path, hash);
    // }
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
    let s = span!(Level::INFO, stringify!(create_new_execution), pid=?caller_pid);
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
                s.in_scope(|| {
                    debug!("Execve succeeded!");
                });

                Execution::Successful(Vec::new(), ExecFileEvents::new(), ExecMetadata::new())
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

        new_execution.add_identifiers(args, caller_pid, envp, executable, starting_cwd);

        Ok(new_execution)
    } else {
        panic!("Process has already exec'd and is trying to exec again!");
    }
}

fn handle_open(
    execution: &RcExecution,
    file_existed_at_start: bool,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_open", pid=?tracer.curr_proc);
    let _ = sys_span.enter();

    // For creat / open(at), a return value > 0
    // indicates success.
    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in handle_open()"))?;
    let ret_val = regs.retval::<i32>();
    let syscall_outcome = if ret_val > 0 {
        Ok(ret_val)
    } else {
        Err(ret_val)
    };

    let (creat_flag, excl_flag, offset_mode, open_mode) = if syscall_name == "creat" {
        let creat_flag = true;
        let excl_flag = false;
        let offset_mode = Some(OffsetFlag::Trunc);
        // creat() uses write only as the mode
        (creat_flag, excl_flag, offset_mode, OpenMode::WriteOnly)
    } else {
        let flags = if syscall_name == "open" {
            regs.arg2::<i32>()
        } else {
            regs.arg3::<i32>()
        };

        let open_mode = match flags & O_ACCMODE {
            O_RDONLY => OpenMode::ReadOnly,
            O_RDWR => OpenMode::ReadWrite,
            O_WRONLY => {
                sys_span.in_scope(|| {
                    debug!("Opening write only");
                });
                OpenMode::WriteOnly
            }
            _ => panic!("Open flags do not match any mode!"),
        };
        let creat_flag = ((flags & O_CREAT) == O_CREAT);
        let excl_flag = ((flags & O_EXCL) == O_EXCL);
        let offset_mode = if ((flags & O_APPEND) == O_APPEND) {
            Some(OffsetFlag::Append)
        } else if ((flags & O_TRUNC) == O_TRUNC) {
            Some(OffsetFlag::Trunc)
        } else {
            None
        };

        (creat_flag, excl_flag, offset_mode, open_mode)
    };

    let path_arg_bytes = match syscall_name {
        "creat" | "open" => regs.arg1::<*const c_char>(),
        "openat" => regs.arg2::<*const c_char>(),
        _ => panic!("Inappropriate system call in handle_open()!"),
    };

    let path_arg = tracer
        .read_c_string(path_arg_bytes)
        .with_context(|| context!("Cannot read `open` path."))?;
    let file_name_arg = PathBuf::from(path_arg);
    sys_span.in_scope(|| info!("File name arg: {:?}", file_name_arg));

    let full_path = get_full_path(execution, syscall_name, tracer)?;
    sys_span.in_scope(|| info!("Full path: {:?}", full_path));

    // We need to check the current exec's map of files it has accessed,
    // to see if the file has been accessed before.
    // If it has, we just add to that vector of events.
    // If it hasn't we need to add the full path -> file struct
    // to the vector of files this exec has accessed.

    let open_syscall_event = generate_open_syscall_file_event(
        creat_flag,
        excl_flag,
        file_existed_at_start,
        &full_path,
        offset_mode,
        open_mode,
        syscall_outcome,
    );

    // let starting_hash = if full_path.exists() && open_syscall_event.is_some() {
    //     Some(generate_hash(
    //         pid,
    //         full_path.clone().into_os_string().into_string().unwrap(),
    //     ))
    // } else {
    //     None
    // };

    if let Some(event) = open_syscall_event {
        execution.add_new_file_event(tracer.curr_proc, event, full_path);
    }

    // if let Some(hash) = starting_hash {
    //     execution.add_starting_hash(full_path, hash);
    // }
    Ok(())
}

// Handling the stat system call.
fn handle_stat(execution: &RcExecution, syscall_name: &str, tracer: &Ptracer) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_stat", pid=?tracer.curr_proc);
    let _ = sys_span.enter();

    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in handle_stat()"))?;
    let ret_val = regs.retval::<i32>();
    // retval = 0 is success for this syscall.
    let full_path = get_full_path(execution, syscall_name, tracer)?;

    sys_span.in_scope(|| {
        debug!("Generating stat syscall event!");
    });
    let stat_syscall_event = if full_path.starts_with("/dev/pts")
        || full_path.starts_with("/dev/null")
        || full_path.starts_with("/etc/")
        || full_path.starts_with("/lib/")
        || full_path.starts_with("/proc/")
        || full_path.is_dir()
    {
        None
    } else {
        match ret_val {
            0 => Some(SyscallEvent::Stat),
            -2 => Some(SyscallEvent::StatFileDidntExist),
            -13 => Some(SyscallEvent::StatAccessDenied),
            e => panic!("Unexpected error returned by stat syscall!: {}", e),
        }
    };

    if let Some(event) = stat_syscall_event {
        execution.add_new_file_event(tracer.curr_proc, event, full_path);
    }

    // let starting_hash = if full_path.exists() && open_syscall_event.is_some() {
    //     Some(generate_hash(
    //         pid,
    //         full_path.clone().into_os_string().into_string().unwrap(),
    //     ))
    // } else {
    //     None
    // };

    // if let Some(hash) = starting_hash {
    //     execution.add_starting_hash(full_path, hash);
    // }
    Ok(())
}

// Currently: stat, fstat, newfstat64
// We consider these syscalls to be inputs.
// Well the files they are acting upon anyway!
fn get_full_path(
    curr_execution: &RcExecution,
    syscall_name: &str,
    tracer: &Ptracer,
) -> anyhow::Result<PathBuf> {
    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in exec event"))?;

    let path_arg_bytes = match syscall_name {
        "access" | "creat" | "open" | "stat" => regs.arg1::<*const c_char>(),
        "openat" => regs.arg2::<*const c_char>(),
        _ => panic!("Not handling an appropriate system call in get_full_path!"),
    };

    let path_arg = tracer
        .read_c_string(path_arg_bytes)
        .with_context(|| context!("Cannot read `open` path."))?;
    let file_name_arg = PathBuf::from(path_arg);

    let full_path = if file_name_arg.starts_with("/") {
        file_name_arg
    } else {
        match syscall_name {
            "access" | "creat" | "open" | "stat" => {
                let cwd = curr_execution.starting_cwd();
                cwd.join(file_name_arg)
            }
            "openat" => {
                let dir_fd = regs.arg1::<i32>();
                let dir_path = if dir_fd == AT_FDCWD {
                    curr_execution.starting_cwd()
                } else {
                    path_from_fd(tracer.curr_proc, dir_fd)?
                };

                debug!("in get_full_path(), dir fd is: {}", dir_fd);
                dir_path.join(file_name_arg)
            }
            s => panic!("Unhandled syscall in get_full_path(): {}!", s),
        }
    };

    Ok(full_path)
}

fn path_from_fd(pid: Pid, fd: i32) -> anyhow::Result<PathBuf> {
    debug!("In path_from_fd()");
    let proc_path = format!("/proc/{}/fd/{}", pid, fd);
    let proc_path = readlink(proc_path.as_str())?;
    Ok(PathBuf::from(proc_path))
}

enum OffsetFlag {
    Append,
    Trunc,
}

// "Create" designates that O_CREAT was used.
// This doesn't mean it succeeded to create, just
// that the flag was used.

fn generate_open_syscall_file_event(
    creat_flag: bool,
    excl_flag: bool,
    file_existed_at_start: bool,
    full_path: &Path,
    offset_flag: Option<OffsetFlag>,
    open_mode: OpenMode,
    syscall_outcome: Result<i32, i32>,
) -> Option<SyscallEvent> {
    // Trust me Dewey, you don't want no part of this.
    if full_path.starts_with("/dev/pts")
        || full_path.starts_with("/dev/null")
        || full_path.starts_with("/etc/")
        || full_path.starts_with("/lib/")
        || full_path.starts_with("/proc/")
        || full_path.is_dir()
    {
        return None;
    }

    if excl_flag && !creat_flag {
        panic!("Do not support for now. Also excl_flag but not creat_flag, baby what is you doin?");
    }

    if creat_flag {
        if excl_flag {
            match syscall_outcome {
                Ok(_) => Some(SyscallEvent::CreateCreatedFileExclusively),
                Err(ret_val) => match ret_val {
                    -13 => Some(SyscallEvent::CreateAccessDenied),
                    -17 => Some(SyscallEvent::CreateFailedToCreateFileExclusively),
                    _ => panic!(
                        "O_CREAT + O_EXCL, syscall failed, but not for EACCES or EEXIST :{}",
                        ret_val
                    ),
                },
            }
        } else {
            match syscall_outcome {
                Ok(_) => {
                    if file_existed_at_start {
                        match (offset_flag, open_mode) {
                            (_, OpenMode::ReadOnly) => {
                                panic!("O_CREAT + O_RDONLY AND the system call succeeded????")
                            }
                            (_, OpenMode::ReadWrite) => panic!("Do not support RW for now..."),
                            (None, OpenMode::WriteOnly) => {
                                panic!("Do not support O_WRONLY without offset flag!")
                            }
                            (Some(OffsetFlag::Append), OpenMode::WriteOnly) => {
                                Some(SyscallEvent::OpenAppendingToFile)
                            }
                            (Some(OffsetFlag::Trunc), OpenMode::WriteOnly) => {
                                Some(SyscallEvent::OpenTruncateFile)
                            }
                        }
                    } else {
                        Some(SyscallEvent::CreateCreatedFile)
                    }
                }
                Err(ret_val) => match ret_val {
                    -2 => Some(SyscallEvent::CreateFailedPathComponentDoesntExist),
                    -13 => Some(SyscallEvent::CreateAccessDenied),
                    _ => panic!("O_CREAT and failed but not because access denied or path component doesn't exist?"),
                },
            }
        }
    } else {
        // Only opens file, no need to worry about it creating a file.
        match syscall_outcome {
            Ok(_) => match (offset_flag, open_mode) {
                // TODO: Hmm. There should be a case for
                // (None, OpenMode::ReadOnly)
                // Successfully opened a file for reading (NO O_CREAT FLAG), this means the
                // file existed.
                (None, OpenMode::ReadOnly) => Some(SyscallEvent::OpenReadOnly),
                (Some(_), OpenMode::ReadOnly) => panic!("Undefined by POSIX/LINUX."),
                (_, OpenMode::ReadWrite) => panic!("Do not support RW for now..."),
                (None, OpenMode::WriteOnly) => {
                    panic!("Do not support O_WRONLY without offset flag!")
                }
                (Some(OffsetFlag::Append), OpenMode::WriteOnly) => {
                    Some(SyscallEvent::OpenAppendingToFile)
                }
                (Some(OffsetFlag::Trunc), OpenMode::WriteOnly) => {
                    Some(SyscallEvent::OpenTruncateFile)
                }
            },
            Err(ret_val) => match ret_val {
                // ENOENT
                -2 => Some(SyscallEvent::OpenFileDidntExist),
                // EACCES
                -13 => Some(SyscallEvent::OpenAccessDenied),
                _ => panic!(
                    "Failed to open file NOT because ENOENT or EACCES, err num: {}",
                    ret_val
                ),
            },
        }
    }
}
