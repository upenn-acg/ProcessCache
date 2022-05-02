#[allow(unused_imports)]
use libc::{
    c_char, c_int, syscall, AT_FDCWD, AT_SYMLINK_NOFOLLOW, CLONE_THREAD, O_ACCMODE, O_APPEND,
    O_CREAT, O_EXCL, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, R_OK, W_OK, X_OK,
};
#[allow(unused_imports)]
use nix::fcntl::{readlink, OFlag};
use nix::sys::stat::FileStat;
use nix::unistd::{AccessFlags, Pid};
use std::collections::HashSet;
use std::path::PathBuf;

use crate::async_runtime::AsyncRuntime;
use crate::cache::{ExecMetadata, Execution, RcExecution};
use crate::condition_generator::{
    generate_hash, MyStat, SyscallEvent, SyscallFailure, SyscallOutcome,
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
    );
    async_runtime
        .run_task(first_proc, f)
        .with_context(|| context!("Program tracing failed. Task returned error."))?;

    // Want: generate_cachable_exec(first_exec: RcExecution) -> CachedExecution
    //       iterate through the execution and its child execs
    //       create pre and postconditions
    // let cachable_exec = generate_cachable_exec(first_execution.clone());
    // let (exec_full_path, args) = first_execution.get_exec_path_and_args();
    // // Want: write_to_cache(cachable_exec: CachedExecution)
    // serialize_execs_to_cache(exec_full_path, args, cachable_exec.clone());
    // cachable_exec.print_pre_and_postconditions();
    // first_execution.print_basic_exec_info();

    first_execution.print_pre_and_postconditions();
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
                let mut nlinks_before = 0;
                // For unlink, we want to know the number of hardlinks.
                // For now, let's panic if it's > 1.

                // Special cases, we won't get a posthook event. Instead we will get
                // an execve event or a posthook if execve returns failure. We don't
                // bother handling it, let the main loop take care of it.
                // TODO: Handle them properly...

                match name {
                    "chdir" => panic!("Program called chdir!!!"),
                    "chmod" => panic!("Program called chmod!!!"),
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
                        let full_exec_path = starting_cwd.join(exec_path_buf.file_name().unwrap());
                        debug!("Execve event, executable: {:?}", full_exec_path.clone());

                        // let next_event = tracer.get_next_event(None).await.with_context(|| {
                        //     context!("Unable to get next event after execve prehook.")
                        // })?;

                        let next_event = tracer.get_next_syscall().await.with_context(|| {
                            context!("Unable to get posthook after execve prehook.")
                        })?;
                        let mut new_exec_metadata = ExecMetadata::new();
                        new_exec_metadata.add_identifiers(args, envp, full_exec_path, starting_cwd);

                        // TODO: handle child execs
                        // TODO: don't add 2 successful execs from same proc, panic instead.
                        match next_event {
                            TraceEvent::Exec(_) => {
                                // The execve succeeded!
                                s.in_scope(|| {
                                    debug!("Execve succeeded!");
                                });

                                // if lookup_exec_in_cache(new_exec_call.clone()).is_some() {
                                //     println!("Found the exec in the cache");
                                // }
                                // If we haven't seen a successful execve by this pid yet,
                                // update.
                                if curr_execution.is_empty_root_exec() {
                                    curr_execution.update_successful_exec(new_exec_metadata);
                                } else if curr_execution.pid() != tracer.curr_proc {
                                    // New rc exec for the child exec.
                                    // Add to parent's struct.
                                    // set curr execution to the new one.
                                    let mut new_child_exec = Execution::new();
                                    new_child_exec.update_successful_exec(new_exec_metadata);
                                    let new_rc_child_exec = RcExecution::new(new_child_exec);
                                    curr_execution.add_child_execution(new_rc_child_exec.clone());
                                    curr_execution = new_rc_child_exec;
                                } else {
                                    panic!("Process already called succesful execve and is trying to do another!!");
                                }
                            }
                            TraceEvent::Posthook(_) => {
                                s.in_scope(|| {
                                    debug!("Execve failed!");
                                });
                                curr_execution.add_failed_exec(new_exec_metadata);
                            }
                            e => panic!("Unexpected event after execve prehook: {:?}", e),
                        }
                        continue;
                    }
                    "exit" | "exit_group" | "clone" | "vfork" | "fork" | "clone2" | "clone3" => {
                        debug!("Special event: {}. Do not go to posthook.", name);
                        continue;
                    }
                    "unlink" | "unlinkat " => {
                        use std::os::unix::fs::MetadataExt;
                        let full_path = get_full_path(&curr_execution, name, &tracer)?;
                        let meta = full_path.as_path().metadata().unwrap();
                        nlinks_before = meta.nlink();
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
                    "fstat" | "stat" => handle_stat(&curr_execution, name, &tracer)?,
                    "rename" | "renameat" => handle_rename(&curr_execution, name, &tracer)?,
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
            s.in_scope(|| debug!("Exit code: {}", exit_code));
            // Add exit code to the exec struct, if this is the
            // pid that exec'd the exec. execececececec.
            // TODO: Should these just be called from a function called
            // like "do_exit_stuff" (obviously something better but you
            // get me)
            // This is a new (or at least new version?) execution,
            // add/update all the necessary stuff in the cache.
            // TODO: ya know, properly cache
            curr_execution.add_exit_code(exit_code);
            // curr_execution.add_output_file_hashes(pid)?;
            // curr_execution.copy_outputs_to_cache()?;
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
        // TODO: panic if more than one?
        let flags_arg = regs.arg2::<i32>();
        let access_flags: Option<AccessFlags> = AccessFlags::from_bits(flags_arg);
        let mut flag_set = HashSet::new();
        if let Some(flags) = access_flags {
            if flags.contains(AccessFlags::F_OK) {
                flag_set.insert(AccessFlags::F_OK);
            } else {
                if flags.contains(AccessFlags::R_OK) {
                    flag_set.insert(AccessFlags::R_OK);
                }
                if flags.contains(AccessFlags::W_OK) {
                    flag_set.insert(AccessFlags::W_OK);
                }
                if flags.contains(AccessFlags::X_OK) {
                    flag_set.insert(AccessFlags::X_OK);
                }
            }
        } else {
            panic!("Access flags unexpected value!!");
        }

        match ret_val {
            0 => Some(SyscallEvent::Access(flag_set, SyscallOutcome::Success)),
            -2 => Some(SyscallEvent::Access(
                flag_set,
                SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
            )),
            // It could be that the user doesn't have one of the permissions they specified as a parameter
            // OR it could be that they don't have search permissions on some dir in the path to the resource.
            // And we don't know so permission is gonna have to be unknown.
            -13 => Some(SyscallEvent::Access(
                flag_set,
                SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
            )),
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
            // let open_mode = if flags.contains(OFlag::O_RDONLY) {
            //     println!("contains read only open mode!!");
            //     OFlag::O_RDONLY
            // } else if flags.contains(OFlag::O_RDWR) {
            //     println!("contains read write!!");
            //     OFlag::O_RDWR
            // } else if flags.contains(OFlag::O_WRONLY) {
            //     println!("contains write only!!");
            //     OFlag::O_WRONLY
            // } else {
            //     panic!("Unrecognized open mode!");
            // };

            let open_mode = match flag_arg & O_ACCMODE {
                O_RDONLY => OFlag::O_RDONLY,
                O_RDWR => OFlag::O_RDWR,
                O_WRONLY => OFlag::O_WRONLY,
                _ => panic!("open flags do not match any mode!"),
            };

            let creat_flag = flags.contains(OFlag::O_CREAT);
            let excl_flag = flags.contains(OFlag::O_EXCL);
            let offset_mode = if flags.contains(OFlag::O_APPEND) {
                // println!("contains append!!");
                OFlag::O_APPEND
            } else if flags.contains(OFlag::O_TRUNC) {
                // println!("contains trunc!!");
                OFlag::O_TRUNC
            } else {
                // println!("is read only!!");
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

    // if let Some(hash) = starting_hash {
    //     execution.add_starting_hash(full_path, hash);
    // }
    Ok(())
}

fn handle_rename(execution: &RcExecution, syscall_name: &str, tracer: &Ptracer) -> Result<()> {
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
            let old_dir_fd = regs.arg1::<i32>();
            let old_path_arg = regs.arg2::<*const c_char>();
            let old_file_name = tracer
                .read_c_string(old_path_arg)
                .with_context(|| context!("Cannot read `rename` path"))?;
            let old_dir_path = if old_dir_fd == AT_FDCWD {
                execution.starting_cwd()
            } else {
                path_from_fd(tracer.curr_proc, old_dir_fd)?
            };

            let new_dir_fd = regs.arg3::<i32>();
            let new_path_arg = regs.arg2::<*const c_char>();
            let new_file_name = tracer
                .read_c_string(new_path_arg)
                .with_context(|| context!("Cannot read `rename` path"))?;
            let new_dir_path = if new_dir_fd == AT_FDCWD {
                execution.starting_cwd()
            } else {
                path_from_fd(tracer.curr_proc, new_dir_fd)?
            };

            (
                old_dir_path.join(old_file_name),
                new_dir_path.join(new_file_name),
            )
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

    execution.add_new_file_event(tracer.curr_proc, rename_event.clone(), full_old_path);
    execution.add_new_file_event(tracer.curr_proc, rename_event, full_new_path);
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

    let stat_syscall_event = if let Some(path) = &full_path {
        if path.starts_with("/dev/pts")
            || path.starts_with("/dev/null")
            || path.starts_with("/etc/")
            || path.starts_with("/lib/")
            || path.starts_with("/proc/")
            || path.starts_with("/usr/")
            || path.is_dir()
        {
            None
        } else {
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
                        st_atime: stat_struct.st_atime,
                        st_atime_nsec: stat_struct.st_atime_nsec,
                        st_mtime: stat_struct.st_mtime,
                        st_mtime_nsec: stat_struct.st_mtime_nsec,
                        st_ctime: stat_struct.st_ctime,
                        st_ctime_nsec: stat_struct.st_ctime_nsec,
                    };
                    // TODO: actually do something with this fucking struct.
                    // Some(SyscallEvent::Stat(StatStruct::Struct(stat_struct), SyscallOutcome::Success(0)))
                    Some(SyscallEvent::Stat(Some(my_stat), SyscallOutcome::Success))
                }
                -2 => Some(SyscallEvent::Stat(
                    None,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                )),
                -13 => Some(SyscallEvent::Stat(
                    None,
                    SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                )),
                e => panic!("Unexpected error returned by stat syscall!: {}", e),
            }
        }
    } else {
        None
    };

    if let (Some(path), Some(event)) = (full_path, stat_syscall_event) {
        execution.add_new_file_event(tracer.curr_proc, event, path);
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
        "access" | "creat" | "open" | "stat" | "unlink" => regs.arg1::<*const c_char>(),
        "openat" | "unlinkat" => regs.arg2::<*const c_char>(),
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
            "access" | "creat" | "open" | "stat" | "unlink" => {
                let cwd = curr_execution.starting_cwd();
                cwd.join(file_name_arg)
            }
            "openat" | "unlinkat" => {
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

// "Create" designates that O_CREAT was used.
// This doesn't mean it succeeded to create, just
// that the flag was used.

fn generate_open_syscall_file_event(
    creat_flag: bool,
    excl_flag: bool,
    file_existed_at_start: bool,
    full_path: PathBuf,
    offset_mode: OFlag, // trunc, append, readonly. doesn't have to be a weird option anymore b/c
    open_mode: OFlag,
    syscall_outcome: Result<i32, i32>,
) -> Option<SyscallEvent> {
    // Trust me Dewey, you don't want no part of this.
    if full_path.starts_with("/dev/pts")
        || full_path.starts_with("/dev/null")
        || full_path.starts_with("/etc/")
        || full_path.starts_with("/lib/")
        || full_path.starts_with("/proc/")
        || full_path.starts_with("/usr/")
        || full_path.is_dir()
    {
        return None;
    }

    if excl_flag && !creat_flag {
        panic!("Do not support for now. Also excl_flag but not creat_flag, baby what is you doin?");
    }

    let starting_hash = if syscall_outcome.is_ok()
        && (offset_mode == OFlag::O_APPEND || offset_mode == OFlag::O_RDONLY)
    {
        Some(generate_hash(full_path))
    } else {
        None
    };
    if creat_flag {
        if excl_flag {
            match syscall_outcome {
                Ok(_) => Some(SyscallEvent::Create(
                    OFlag::O_CREAT,
                    SyscallOutcome::Success,
                )),
                Err(ret_val) => match ret_val {
                    -13 => Some(SyscallEvent::Create(
                        OFlag::O_CREAT,
                        // I know it's either WRITE or EXEC access denied.
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                    )),
                    -17 => Some(SyscallEvent::Create(
                        OFlag::O_CREAT,
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists),
                    )),
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
                        match (offset_mode, open_mode) {
                            (_, OFlag::O_RDONLY) => {
                                panic!("O_CREAT + O_RDONLY AND the system call succeeded????")
                            }
                            (_, OFlag::O_RDWR) => panic!("Do not support RW for now..."),
                            (OFlag::O_RDONLY, OFlag::O_WRONLY) => {
                                panic!("Do not support O_WRONLY without offset flag!")
                            }
                            (OFlag::O_APPEND, OFlag::O_WRONLY) => {
                                Some(SyscallEvent::Open(OFlag::O_APPEND, starting_hash, SyscallOutcome::Success))
                            }
                            (OFlag::O_TRUNC, OFlag::O_WRONLY) => {
                                Some(SyscallEvent::Open(OFlag::O_TRUNC, starting_hash, SyscallOutcome::Success))
                            }
                            (offset_flag, mode_flag) => panic!("Unexpected offset flag: {:?} and mode flag: {:?}", offset_flag, mode_flag),
                        }
                    } else {
                        Some(SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success))
                    }
                }
                Err(ret_val) => match ret_val {
                    // More accurately, some "path component" doesn't exist, but they don't know that,
                    // and so we don't, and so y'all get a generic error. 
                    // Linux is NOT a generous god.
                    // And neither am I.
                    -2 => Some(SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist))),
                    -13 => Some(SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Fail(SyscallFailure::PermissionDenied))),
                    _ => panic!("O_CREAT and failed but not because access denied or path component doesn't exist?"),
                }
            }
        }
    } else {
        // Only opens file, no need to worry about it creating a file.
        match syscall_outcome {
            Ok(_) => match (offset_mode, open_mode) {
                // TODO: Hmm. There should be a case for
                // (None, OpenOFlag::O_RDONLY)
                // Successfully opened a file for reading (NO O_CREAT FLAG), this means the
                // file existed.
                // Retval is pretty useless here but whatever.
                (OFlag::O_RDONLY, OFlag::O_RDONLY) => Some(SyscallEvent::Open(
                    OFlag::O_RDONLY,
                    starting_hash,
                    SyscallOutcome::Success,
                )),
                (OFlag::O_TRUNC | OFlag::O_APPEND, OFlag::O_RDONLY) => {
                    panic!("Undefined by POSIX/LINUX.")
                }
                (_, OFlag::O_RDWR) => panic!("Do not support RW for now..."),
                // "ReadOnly" is like my "None" offset flag. and it kinda makes sense
                (OFlag::O_RDONLY, OFlag::O_WRONLY) => {
                    panic!("Do not support O_WRONLY without offset flag!")
                }
                (OFlag::O_APPEND, OFlag::O_WRONLY) => Some(SyscallEvent::Open(
                    OFlag::O_APPEND,
                    starting_hash,
                    SyscallOutcome::Success,
                )),
                (OFlag::O_TRUNC, OFlag::O_WRONLY) => Some(SyscallEvent::Open(
                    OFlag::O_TRUNC,
                    starting_hash,
                    SyscallOutcome::Success,
                )),
                (offset_flag, mode_flag) => panic!(
                    "Unexpected offset flag: {:?} and mode flag: {:?}",
                    offset_flag, mode_flag
                ),
            },
            Err(ret_val) => match ret_val {
                // ENOENT
                -2 => Some(SyscallEvent::Open(
                    offset_mode,
                    starting_hash,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                )),
                // EACCES
                -13 => match offset_mode {
                    OFlag::O_APPEND | OFlag::O_TRUNC => Some(SyscallEvent::Open(
                        offset_mode,
                        starting_hash,
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                    )),
                    _ => Some(SyscallEvent::Open(
                        offset_mode,
                        starting_hash,
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                    )),
                },
                _ => panic!(
                    "Failed to open file NOT because ENOENT or EACCES, err num: {}",
                    ret_val
                ),
            },
        }
    }
}
