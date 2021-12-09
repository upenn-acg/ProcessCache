#[allow(unused_imports)]
use libc::{
    c_char, syscall, AT_SYMLINK_NOFOLLOW, CLONE_THREAD, O_ACCMODE, O_CREAT, O_RDONLY, O_RDWR,
    O_WRONLY,
};
#[allow(unused_imports)]
use nix::fcntl::{readlink, OFlag};
use nix::unistd::Pid;
use std::fs::{self, canonicalize};
use std::path::PathBuf;
use std::rc::Rc;

use crate::async_runtime::AsyncRuntime;
use crate::cache::{
    generate_hash, /*get_cached_root_execution,*/ serialize_execs_to_cache,
    serve_outputs_from_cache, AccessFailure, ExecFileAccesses, ExecMetadata, Execution, FileAccess,
    FileAction, OpenMode, RcExecution,
};
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

                        s.in_scope(|| debug!("Checking cache for execution"));
                        if curr_execution.is_pending_root() {
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
                            curr_execution.update_root(new_execution.clone());
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

                span!(Level::INFO, "Posthook", retval).in_scope(|| info!(""));

                match name {
                    // "access" => handle_access(&curr_execution, &regs, &tracer)?,
                    "creat" | "openat" | "open" => {
                        handle_open(&curr_execution, &regs, name, &tracer)?
                    }
                    // "fstat" | "newfstatat" | "stat" => {
                    //     handle_stat(&curr_execution, &regs, name, &tracer)?
                    // }
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
fn handle_access(execution: &RcExecution, regs: &Regs<Unmodified>, tracer: &Ptracer) -> Result<()> {
    unimplemented!();
    // let sys_span = span!(Level::INFO, "handle_access", pid=?tracer.curr_proc);
    // sys_span.in_scope(|| {
    //     debug!("File metadata event: (access)");
    // });
    // let ret_val = regs.retval::<i32>();
    // // retval = 0 is success for this syscall.
    // let syscall_succeeded = ret_val == 0;
    // let bytes = regs.arg1::<*const c_char>();
    // let register_path = tracer
    //     .read_c_string(bytes)
    //     .with_context(|| context!("Cannot read `access` path."))?;
    // let syscall_name = String::from("access");
    // debug!("register path: {}", register_path);

    // let path_arg = PathBuf::from(register_path);

    // let full_path = get_full_path(Some(PathArg::Path(path_arg)), tracer.curr_proc)?;
    // debug!("made it past get_full_path");

    // let file_access = generate_file_access(
    //     full_path,
    //     IO::Input,
    //     tracer.curr_proc,
    //     syscall_name,
    //     syscall_succeeded,
    // );

    // if let Some(access) = file_access {
    //     execution.add_new_file_event(tracer.curr_proc, access, IO::Input);
    // }
    // Ok(())
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

                Execution::Successful(Vec::new(), ExecFileAccesses::new(), ExecMetadata::new())
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

/// Open, openat, creat.
/// I am gonna just handle open and openat for now, and only for opening and not for file creation.
/// Opening for read/write, write,
/// and creating files are all considered outputs,
/// just opening a file for reading is considered
/// an input.
/// TODO!!!!! A function for generating file accesses that is implemented in cache.rs
/// so that FileAction, FileAccess, AccessFailure don't have to be pub
fn handle_open(
    execution: &RcExecution,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let pid = tracer.curr_proc;
    let sys_span = span!(Level::INFO, "handle_open", pid=?tracer.curr_proc);
    let _ = sys_span.enter();

    let ret_val = regs.retval::<i32>();
    let syscall_outcome = if ret_val > 0 {
        SyscallOutcome::Success
    } else {
        SyscallOutcome::Failure(ret_val)
    };

    let (is_file_create, open_mode) = if syscall_name == "creat" {
        // creat() uses write only as the mode
        (true, OpenMode::WriteOnly)
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
        let is_file_create = ((flags & O_CREAT) == O_CREAT);

        (is_file_create, open_mode)
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
    // sys_span.in_scope(|| "made it to canonicalize");
    // let full_path = get_full_path(path_arg, pid)?;
    // let full_path = canonicalize(file_name_arg)?;

    // If a path is absolute it will start with "/"
    // and so we don't need to call get_full_path().
    let exec_cwd = execution.starting_cwd();
    let full_path = if !file_name_arg.starts_with("/") {
        file_name_arg
    } else {
        let path_arg = if ret_val > 0 {
            PathArg::ExistingFile(file_name_arg)
        } else {
            PathArg::NonExistingFile {
                cwd: exec_cwd,
                path: file_name_arg,
            }
        };
        get_full_path(Some(path_arg), tracer.curr_proc)?
    };
    sys_span.in_scope(|| info!("Full path: {:?}", full_path));

    // We need to check the current exec's map of files it has accessed,
    // to see if the file has been accessed before.
    // If it has, we just add to that vector of events.
    // If it hasn't we need to add the full path -> file struct
    // to the vector of files this exec has accessed.

    // TODO: lol make this a function
    let file_access = generate_file_access(
        full_path.clone(),
        is_file_create,
        pid,
        open_mode,
        syscall_outcome,
    );

    let starting_hash = if full_path.exists() && file_access.is_some() {
        Some(generate_hash(
            pid,
            full_path.clone().into_os_string().into_string().unwrap(),
        ))
    } else {
        None
    };

    if let Some(access) = file_access {
        execution.add_new_file_event(tracer.curr_proc, access, full_path.clone());
    }

    if let Some(hash) = starting_hash {
        execution.add_starting_hash(full_path, hash);
    }
    Ok(())
}

// Currently: stat, fstat, newfstat64
// We consider these syscalls to be inputs.
// Well the files they are acting upon anyway!
// fn handle_stat(
//     execution: &RcExecution,
//     regs: &Regs<Unmodified>,
//     syscall_name: &str,
//     tracer: &Ptracer,
// ) -> Result<()> {
//     unimplemented!();
// let sys_span = span!(Level::INFO, "handle_stat", pid=?tracer.curr_proc);
// let _ = sys_span.enter();
// sys_span.in_scope(|| {
//     debug!("File stat event: ({})", syscall_name);
// });
// // Return value == 0 means success
// let ret_val: i32 = regs.retval();
// let syscall_succeeded = ret_val == 0;

// let full_path_arg = if syscall_name == "fstat" {
//     let fd = regs.arg1::<i32>();
//     if syscall_succeeded {
//         // TODO: Do something about stdin, stderr, stdout???
//         if fd < 3 {
//             return Ok(());
//         }
//         Some(PathArg::Fd(3))
//     } else {
//         None
//     }
// } else {
//     // newstatat, stat
//     // TODO: handle lstat? Or don't? I don't know? What **do** I know?
//     // TODO: handle DIRFD in newfstatat
//     let arg: *const c_char = match syscall_name {
//         "stat" => regs.arg1(),
//         // newstatat
//         "newfstatat" => regs.arg2(),
//         other => bail!(context!("Unhandled syscall: {}", other)),
//     };

//     let path = tracer
//         .read_c_string(arg)
//         .with_context(|| context!("Can't get path from path arg."))?;
//     Some(PathArg::Path(PathBuf::from(path)))
// };

// // Either way we are calling this function with a PathArg and it's **generic** over the PathArg enum :3
// let full_path = get_full_path(full_path_arg, tracer.curr_proc)?;

// let syscall_name = String::from(syscall_name);
// let file_event = generate_file_access(
//     full_path,
//     IO::Input,
//     tracer.curr_proc,
//     syscall_name,
//     syscall_succeeded,
// );

// if let Some(access) = file_event {
//     execution.add_new_file_event(tracer.curr_proc, access, IO::Input);
// }

// Ok(())
// }

enum PathArg {
    ExistingFile(PathBuf),
    NonExistingFile { cwd: PathBuf, path: PathBuf },
}

fn path_from_fd(pid: Pid, fd: i32) -> anyhow::Result<PathBuf> {
    let proc_path = format!("/proc/{}/fd/{}", pid, fd);
    let proc_path = readlink(proc_path.as_str())?;
    Ok(PathBuf::from(proc_path))
}

// Take in the path arg, either a string path or the
// fd the system call provides.
// Optionally pass in the cwd (if the syscall failed because the file doesn't
// exist, we can't use canonicalize())
// If the the system call name is fstat (i.e. path arg = None),
// full path = PathBuf::new().
// Create the canonicalized
// version of the path and return it.
// TODO: If the path is already a full path just return it? maybe should check and not call this function instead?
fn get_full_path(path_arg: Option<PathArg>, calling_pid: Pid) -> anyhow::Result<PathBuf> {
    let sys_span = span!(Level::INFO, stringify!(get_full_path), pid=?calling_pid);
    let _ = sys_span.enter();
    sys_span.in_scope(|| {
        debug!("Getting full path.");
    });

    match path_arg {
        // TODO: Evolve PathArg to include if it succeeded?
        Some(PathArg::NonExistingFile { cwd, path }) => {
            sys_span.in_scope(|| {
                debug!(
                    "Syscall failed, going to use cwd: {} to make full path for: {}!",
                    stringify!(&cwd),
                    stringify!(&path)
                );
            });
            Ok(cwd.join(path))
        }
        Some(PathArg::ExistingFile(path)) => {
            sys_span.in_scope(|| {
                debug!("Going to call canonicalize: {}", stringify!(&path));
            });
            let full_path = canonicalize(path)?;
            Ok(full_path)
        }
        None => Ok(PathBuf::new()),
    }
}

enum SyscallOutcome {
    Success,
    Failure(i32),
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
    is_file_create: bool,
    pid: Pid,
    open_mode: OpenMode,
    syscall_outcome: SyscallOutcome,
) -> Option<FileAccess> {
    // Why pass in the file name when there's a perfectly good file_name, just sittin' in the full_path??
    // Who else likes Seinfeld? Just me? Alright.
    // We generate the hash for the output at the end of the execution.

    if full_path.starts_with("/dev/pts")
        || full_path.starts_with("/dev/null")
        || full_path.starts_with("/etc/")
        || full_path.starts_with("/proc/")
        || full_path.is_dir()
    {
        return None;
    }

    // let path = full_
    // if syscall_succeeded {
    //     let hash = match io_type {
    //         IO::Input => {
    //             let path = full_path.clone().into_os_string().into_string().unwrap();
    //             Some(generate_hash(pid, path))
    //         }

    //         _ => None,
    //     };
    //     Some(FileAccess::Success(full_path, hash, syscall_name))
    // } else {
    //     Some(FileAccess::Failure(full_path, syscall_name))
    // }

    // TODO: lol make this a function
    match (is_file_create, open_mode, syscall_outcome) {
        (true, OpenMode::ReadOnly, _) => panic!("File create and mode is read only!!"),
        (false, OpenMode::ReadOnly, SyscallOutcome::Success) => {
            Some(FileAccess::Successful(FileAction::Read))
        }
        // TODO: stuff other than "does not exist" (EACCES, ENOENT)
        (false, OpenMode::ReadOnly, SyscallOutcome::Failure(ret_val)) => match ret_val {
            -2 => Some(FileAccess::Failed(AccessFailure::DoesNotExist)),
            -13 => Some(FileAccess::Failed(AccessFailure::Permissions)),
            e => panic!("Unrecognized error number for open!: {}", e),
        },
        (true, OpenMode::WriteOnly | OpenMode::ReadWrite, SyscallOutcome::Success) => {
            Some(FileAccess::Successful(FileAction::Created))
        }
        (false, OpenMode::WriteOnly | OpenMode::ReadWrite, SyscallOutcome::Success) => {
            Some(FileAccess::Successful(FileAction::Modified))
        }
        (true, OpenMode::WriteOnly | OpenMode::ReadWrite, SyscallOutcome::Failure(_)) => {
            // How can it fail to create a file?
            // TODO: Figure all that out
            // For now, let's just handle "the file already exists"
            // I'll strace it in a sec
            Some(FileAccess::Failed(AccessFailure::AlreadyExists))
        }
        (false, OpenMode::WriteOnly | OpenMode::ReadWrite, SyscallOutcome::Failure(ret_val)) => {
            match ret_val {
                -2 => Some(FileAccess::Failed(AccessFailure::DoesNotExist)),
                -13 => Some(FileAccess::Failed(AccessFailure::Permissions)),
                e => panic!("Unrecognized error number for open!: {}", e),
            }
        }
    }
}
