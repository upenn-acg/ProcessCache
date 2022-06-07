#[allow(unused_imports)]
use libc::{
    c_char, c_int, syscall, AT_FDCWD, AT_SYMLINK_NOFOLLOW, CLONE_THREAD, O_ACCMODE, O_APPEND,
    O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, R_OK, W_OK, X_OK,
};
#[allow(unused_imports)]
use nix::fcntl::{readlink, OFlag};
use nix::sys::stat::FileStat;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;

use crate::async_runtime::AsyncRuntime;
use crate::cache::{retrieve_existing_cache, serialize_execs_to_cache};
use crate::cache_utils::{hash_command, Command};

use crate::context;
use crate::execution_utils::{generate_open_syscall_file_event, get_full_path, path_from_fd};
use crate::recording::{ExecMetadata, Execution, Proc, RcExecution};
use crate::redirection;
use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::syscalls::{MyStat, SyscallEvent, SyscallFailure, SyscallOutcome};
use crate::system_call_names::get_syscall_name;
use crate::tracer::TraceEvent;
use crate::Ptracer;

#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

use anyhow::{bail, Context, Result};

pub fn trace_program(first_proc: Pid, full_tracking_on: bool) -> Result<()> {
    info!("Running whole program");

    let async_runtime = AsyncRuntime::new();
    // We have to create the first execution struct outside
    // trace process, so we don't accidentally overwrite it
    // within trace_process().

    let first_execution = RcExecution::new(Execution::new(Proc(first_proc)));
    // CWD of the root process + "/cache/"
    let mut cache_dir = std::env::current_dir().with_context(|| context!("Cannot get CWD."))?;
    cache_dir.push("cache/");

    fs::create_dir_all(&cache_dir)
        .with_context(|| context!("Failed to create cache dir: {:?}", cache_dir))?;

    let f = trace_process(
        async_runtime.clone(),
        full_tracking_on,
        Ptracer::new(first_proc),
        first_execution.clone(),
        Rc::new(cache_dir.clone()),
    );
    async_runtime
        .run_task(first_proc, f)
        .with_context(|| context!("Program tracing failed. Task returned error."))?;

    // Get existing cache if it exists.
    // Call add_to_curr_cache() or whatever.
    // Serialize the data structure and write it to the cache.
    // Copy output files... carefully --> can't just do /cache/commandhash/yada
    // because of potential collisions on the hash.
    // TODO: decide what full_tracking_on *means* and actually implement it to do that lol.
    if !full_tracking_on && !first_execution.is_empty_root_exec() {
        // const CACHE_LOCATION: &str = "./cache/cache";
        // let cache_path = PathBuf::from(CACHE_LOCATION);

        // TODO: add to existing cache
        // let mut existing_cache = if !cache_path.exists() {
        //     File::create(cache_path).unwrap();
        //     HashMap::new()
        // } else if let Some(existing_cache) = retrieve_existing_cache() {
        //     existing_cache
        // } else {
        //     HashMap::new()
        // };

        let mut new_cache = HashMap::new();
        first_execution.populate_cache_map(&mut new_cache);
        serialize_execs_to_cache(new_cache);
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
    full_tracking_on: bool,
    mut tracer: Ptracer,
    mut curr_execution: RcExecution,
    cache_dir: Rc<PathBuf>, // TODO: what is this??
) -> Result<()> {
    let s = span!(Level::INFO, stringify!(trace_process), pid=?tracer.curr_proc);
    s.in_scope(|| info!("Starting Process"));
    let mut signal = None;
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
                let mut nlinks_before = 0;
                // For unlink, we want to know the number of hardlinks.
                // For now, let's panic if it's > 1.

                // Special cases, we won't get a posthook event. Instead we will get
                // an execve event or a posthook if execve returns failure. We don't
                // bother handling it, let the main loop take care of it.
                // TODO: Handle them properly...

                match name {
                    // "chdir" => panic!("Program called chdir!!!"),
                    // "chmod" => panic!("Program called chmod!!!"),
                    "chown" => panic!("Program called chown!!!"),
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

                        let exec_path_buf = PathBuf::from(executable.clone());
                        debug!("Raw executable: {:?}", exec_path_buf);
                        let exec_path_buf = if exec_path_buf.is_relative() {
                            fs::canonicalize(exec_path_buf).unwrap()
                        } else {
                            exec_path_buf
                        };
                        debug!("Execve event, executable: {:?}", exec_path_buf);

                        // Check the cache for the thing
                        if let Some(cache) = retrieve_existing_cache() {
                            let command = Command(
                                exec_path_buf
                                    .clone()
                                    .into_os_string()
                                    .into_string()
                                    .unwrap(),
                                args.clone(),
                            );
                            if let Some(entry) = cache.get(&command) {
                                debug!("Checking all preconditions: execution is: {:?}", command);

                                // let mut found_one = false;
                                // for entry in entry_list {
                                if full_tracking_on {
                                    entry.check_all_preconditions_regardless()
                                } else if entry.check_all_preconditions() {
                                    // Check if we should skip this execution.
                                    // If we are gonna skip, we have to change:
                                    // rax, orig_rax, arg1
                                    debug!("Trying to change system call after the execve into exit call! (Skip the execution!)");
                                    entry.apply_all_transitions();
                                    let regs = tracer.get_registers().with_context(|| {
                                        context!("Failed to get regs in skip exec event")
                                    })?;
                                    let mut regs = regs.make_modified();
                                    let exit_syscall_num = libc::SYS_exit as u64;

                                    // Change the arg1 to correct exit code?
                                    regs.write_arg1(0);
                                    // Change the orig rax val don't ask me why
                                    regs.write_syscall_number(exit_syscall_num);
                                    // Change the rax val
                                    regs.write_rax(exit_syscall_num);

                                    tracer.set_regs(&mut regs)?;
                                    // entry.apply_all_transitions();
                                    // found_one = true;
                                    // break;
                                }
                                // }
                                // if found_one {
                                //     continue;
                                // }
                            }
                        }

                        let next_event = tracer.get_next_syscall().await.with_context(|| {
                            context!("Unable to get posthook after execve prehook.")
                        })?;
                        let mut new_exec_metadata = ExecMetadata::new(Proc(tracer.curr_proc));
                        new_exec_metadata.add_identifiers(
                            args,
                            envp,
                            exec_path_buf
                                .clone()
                                .into_os_string()
                                .into_string()
                                .unwrap(),
                            starting_cwd,
                        );

                        // TODO: handle child execs
                        // TODO: don't add 2 successful execs from same proc, panic instead.
                        match next_event {
                            TraceEvent::Exec(_) => {
                                // The execve succeeded!
                                s.in_scope(|| {
                                    debug!("Execve succeeded!");
                                });

                                // If we haven't seen a successful execve by this pid yet,
                                // update.
                                if curr_execution.is_empty_root_exec() {
                                    curr_execution.update_successful_exec(new_exec_metadata);
                                } else if curr_execution.pid() != tracer.curr_proc {
                                    // New rc exec for the child exec.
                                    // Add to parent's struct.
                                    // set curr execution to the new one.
                                    let mut new_child_exec = Execution::new(Proc(tracer.curr_proc));
                                    new_child_exec.update_successful_exec(new_exec_metadata);
                                    let new_rc_child_exec = RcExecution::new(new_child_exec);
                                    curr_execution.add_child_execution(new_rc_child_exec.clone());
                                    curr_execution = new_rc_child_exec;
                                } else {
                                    panic!("Process already called successful execve and is trying to do another!!");
                                }
                            }
                            TraceEvent::Posthook(_) => {
                                s.in_scope(|| {
                                    debug!("Execve failed!");
                                });
                                let regs = tracer.get_registers().with_context(|| {
                                    context!("Failed to get regs in handle_stat()")
                                })?;
                                let ret_val = regs.retval::<i32>();
                                let failed_exec = {
                                    match ret_val {
                                        -2 => SyscallEvent::FailedExec(
                                            SyscallFailure::FileDoesntExist,
                                        ),
                                        -13 => SyscallEvent::FailedExec(
                                            SyscallFailure::PermissionDenied,
                                        ),
                                        e => panic!(
                                            "Unexpected error returned by stat syscall!: {}",
                                            e
                                        ),
                                    }
                                };
                                curr_execution.add_new_file_event(
                                    tracer.curr_proc,
                                    failed_exec,
                                    exec_path_buf,
                                );
                            }
                            e => panic!("Unexpected event after execve prehook: {:?}", e),
                        }
                        continue;
                    }
                    "exit" | "exit_group" | "clone" | "vfork" | "fork" | "clone2" | "clone3" => {
                        debug!("Special event: {}. Do not go to posthook.", name);
                        continue;
                    }
                    // "umask" => panic!("Program called umask!!"),
                    "unlink" | "unlinkat" => {
                        use std::os::unix::fs::MetadataExt;
                        let full_path = get_full_path(&curr_execution, name, &tracer)?;
                        if full_path.exists() {
                            let meta = full_path.as_path().metadata().unwrap();
                            nlinks_before = meta.nlink();
                        } else {
                            nlinks_before = 0;
                        }
                    }
                    _ => {
                        if !iostream_redirected {
                            const STDOUT_FD: u32 = 1;
                            const STDERR_FD: u32 = 2;
                            // TODO: Deal with PID recycling?
                            let exec = curr_execution.executable();
                            let args = curr_execution.args();
                            let comm_hash = hash_command(Command(exec, args));
                            let cache_subdir = fs::canonicalize("./cache").unwrap();
                            let cache_subdir = cache_subdir.join(format!("{:?}", comm_hash));
                            if !cache_subdir.exists() {
                                fs::create_dir(cache_subdir.clone()).unwrap();
                            }
                            let stdout_file = cache_subdir
                                .join(format!("stdout_{:?}", tracer.curr_proc.as_raw()));
                            // let stderr_file: String = format!(
                            //     "/cache/{:?}/stderr_{:?}",
                            //     comm_hash,
                            //     tracer.curr_proc.as_raw()
                            // );
                            // This is the first real system call this program is doing after exec-ing.
                            // We will redirect their stdout and stderr output here by writing them to files.
                            redirection::redirect_io_stream(
                                stdout_file.to_str().unwrap(),
                                STDOUT_FD,
                                &mut tracer,
                            )
                            .await
                            .with_context(|| context!("Unable to redirect stdout."))?;
                            // redirection::redirect_io_stream(&stderr_file, STDERR_FD, &mut tracer)
                            //     .await
                            //     .with_context(|| context!("Unable to redirect stderr."))?;
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
                    "fstat" | "stat" => handle_stat(&curr_execution, name, &tracer)?,
                    "rename" | "renameat" | "renameat2" => {
                        handle_rename(&curr_execution, name, &tracer)?
                    }
                    "unlink" | "unlinkat" => {
                        if nlinks_before == 1 {
                            // before facts? (success)
                            // - exists
                            // - contents
                            // - write access to dir
                            // - x access to dir
                            // after facts? (success)
                            // - doesnt exist
                            handle_unlink(&curr_execution, name, &tracer)?
                        }
                    }
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
                    full_tracking_on,
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
                    full_tracking_on,
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
            s.in_scope(|| debug!("Exit code: {}", exit_code));
            // Add exit code to the exec struct, if this is the
            // pid that exec'd the exec. execececececec.
            // TODO: don't add this here if skipping?
            curr_execution.add_exit_code(exit_code);
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

    // TODO: panic if more than one?
    let flags = regs.arg2::<i32>();

    let event = match ret_val {
        0 => SyscallEvent::Access(flags, SyscallOutcome::Success),
        -2 => SyscallEvent::Access(flags, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
        // It could be that the user doesn't have one of the permissions they specified as a parameter
        // OR it could be that they don't have search permissions on some dir in the path to the resource.
        // And we don't know so permission is gonna have to be unknown.
        -13 => SyscallEvent::Access(
            flags,
            SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
        ),
        e => panic!("Unexpected error returned by access syscall!: {}", e),
    };

    execution.add_new_file_event(tracer.curr_proc, event, full_path);
    Ok(())
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
        // creat() uses write only as the mode
        (creat_flag, excl_flag, OFlag::O_TRUNC, OFlag::O_WRONLY)
    } else {
        let flag_arg = if syscall_name == "open" {
            regs.arg2::<i32>()
        } else {
            regs.arg3::<i32>()
        };

        let option_flags = OFlag::from_bits(flag_arg);
        let (creat_flag, excl_flag, offset_mode, open_mode) = if let Some(flags) = option_flags {
            let open_mode = match flag_arg & O_ACCMODE {
                O_RDONLY => OFlag::O_RDONLY,
                O_RDWR => OFlag::O_RDWR,
                O_WRONLY => OFlag::O_WRONLY,
                _ => panic!("open flags do not match any mode!"),
            };

            let creat_flag = flags.contains(OFlag::O_CREAT);
            let excl_flag = flags.contains(OFlag::O_EXCL);
            let offset_mode = if flags.contains(OFlag::O_APPEND) {
                OFlag::O_APPEND
            } else if flags.contains(OFlag::O_TRUNC) {
                OFlag::O_TRUNC
            } else {
                OFlag::O_RDONLY
            };

            (creat_flag, excl_flag, offset_mode, open_mode)
        } else {
            panic!("Unexpected open flags value!!");
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
        full_path.clone(),
        offset_mode,
        open_mode,
        syscall_outcome,
    );

    if let Some(event) = open_syscall_event {
        execution.add_new_file_event(tracer.curr_proc, event, full_path);
    }
    Ok(())
}

fn handle_rename(execution: &RcExecution, syscall_name: &str, tracer: &Ptracer) -> Result<()> {
    debug!("WE ARE IN HANDLE RENAME");
    let sys_span = span!(Level::INFO, "handle_rename", pid=?tracer.curr_proc);
    let _ = sys_span.enter();
    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in handle_rename()"))?;

    let ret_val = regs.retval::<i32>();
    // retval = 0 is success for this syscall.
    let (full_old_path, full_new_path) = match syscall_name {
        "rename" => {
            let old_path_arg_bytes = regs.arg1::<*const c_char>();
            let old_path_arg = tracer
                .read_c_string(old_path_arg_bytes)
                .with_context(|| context!("Cannot read `open` path."))?;
            let new_path_arg_bytes = regs.arg1::<*const c_char>();
            let new_path_arg = tracer
                .read_c_string(new_path_arg_bytes)
                .with_context(|| context!("Cannot read `open` path."))?;
            (PathBuf::from(old_path_arg), PathBuf::from(new_path_arg))
        }
        "renameat" | "renameat2" => {
            debug!("RENAMEAT2");
            let old_path_arg = regs.arg2::<*const c_char>();
            let old_file_name = tracer
                .read_c_string(old_path_arg)
                .with_context(|| context!("Cannot read `rename` path"))?;

            let new_path_arg = regs.arg4::<*const c_char>();
            let new_file_name = tracer
                .read_c_string(new_path_arg)
                .with_context(|| context!("Cannot read `rename` path"))?;
            (PathBuf::from(old_file_name), PathBuf::from(new_file_name))
        }
        _ => panic!("Calling unrecognized syscall in handle_rename()"),
    };

    let rename_event = match ret_val {
        0 => SyscallEvent::Rename(
            full_old_path.clone(),
            full_new_path.clone(),
            SyscallOutcome::Success,
        ),
        // Probably the old file doesn't exist. Empty new path is also possible.
        -2 => SyscallEvent::Rename(
            full_old_path.clone(),
            full_new_path.clone(),
            SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
        ),
        -13 => SyscallEvent::Rename(
            full_old_path.clone(),
            full_new_path.clone(),
            SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
        ),
        e => panic!("Unexpected error returned by rename syscall!: {}", e),
    };

    execution.add_new_file_event(tracer.curr_proc, rename_event, full_old_path);
    // execution.add_new_file_event(tracer.curr_proc, rename_event, full_new_path);
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
    let full_path = match syscall_name {
        "fstat" => {
            let fd = regs.arg1::<i32>();
            if fd > 2 {
                Some(path_from_fd(tracer.curr_proc, fd)?)
            } else {
                None
            }
        }
        "stat" => Some(get_full_path(execution, syscall_name, tracer)?),
        _ => panic!("Calling unrecognized syscall in handle_stat()"),
    };

    let stat_syscall_event = {
        match ret_val {
            0 => {
                let stat_ptr = regs.arg2::<u64>();
                let stat_struct = tracer.read_value(stat_ptr as *const FileStat)?;
                let my_stat = MyStat {
                    st_dev: stat_struct.st_dev,
                    st_ino: stat_struct.st_ino,
                    st_nlink: stat_struct.st_nlink,
                    st_mode: stat_struct.st_mode,
                    st_uid: stat_struct.st_uid,
                    st_gid: stat_struct.st_gid,
                    st_rdev: stat_struct.st_rdev,
                    st_size: stat_struct.st_size,
                    st_blksize: stat_struct.st_blksize,
                    st_blocks: stat_struct.st_blocks,
                };
                // TODO: actually do something with this fucking struct.
                // Some(SyscallEvent::Stat(StatStruct::Struct(stat_struct), SyscallOutcome::Success(0)))
                SyscallEvent::Stat(Some(my_stat), SyscallOutcome::Success)
            }
            -2 => SyscallEvent::Stat(None, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
            -13 => SyscallEvent::Stat(None, SyscallOutcome::Fail(SyscallFailure::PermissionDenied)),
            e => panic!("Unexpected error returned by stat syscall!: {}", e),
        }
    };

    if let Some(path) = full_path {
        execution.add_new_file_event(tracer.curr_proc, stat_syscall_event, path);
    }
    Ok(())
}

fn handle_unlink(execution: &RcExecution, name: &str, tracer: &Ptracer) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_unlink", pid=?tracer.curr_proc);
    let _ = sys_span.enter();

    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in handle_unlink()"))?;
    let ret_val = regs.retval::<i32>();
    // retval = 0 is success for this syscall. lots of them it would seem.
    let full_path = get_full_path(execution, name, tracer)?;

    let delete_syscall_event = match ret_val {
        0 => SyscallEvent::Delete(SyscallOutcome::Success),
        -2 => SyscallEvent::Delete(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
        -13 => SyscallEvent::Delete(SyscallOutcome::Fail(SyscallFailure::PermissionDenied)),
        e => panic!("Unexpected error returned by unlink syscall!: {:?}", e),
    };

    execution.add_new_file_event(tracer.curr_proc, delete_syscall_event, full_path);
    Ok(())
}
