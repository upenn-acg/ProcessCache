use crossbeam::channel::{unbounded, Sender};
use libc::{c_char, AT_FDCWD, O_ACCMODE, O_RDONLY, O_RDWR, O_WRONLY};
use nix::{
    dir,
    fcntl::{readlink, AtFlags, OFlag},
    sys::{stat::FileStat, statfs::Statfs},
    unistd::Pid,
};

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    ffi::CStr,
    fs::{canonicalize, create_dir, create_dir_all},
    path::PathBuf,
    rc::Rc,
    thread,
};

use crate::{
    async_runtime::AsyncRuntime,
    cache_utils::{background_thread_serving_outputs, background_thread_serving_stdout},
    computed_hashes::RcComputedHashes,
    condition_generator::{Accessor, ExecSyscallEvents},
    condition_utils::{Fact, FileType},
    execution_utils::{
        background_thread_copying_outputs, get_total_syscall_event_count_for_root,
        getdents_file_type,
    },
    recording::{append_dir_events, generate_list_of_files_to_copy_to_cache, LinkType},
    redirection::{close_stdout_duped_fd, redirect_io_stream},
    syscalls::{AccessMode, CheckMechanism, DirEvent, FileEvent, MyStatFs, OffsetMode, OpenFlags},
};
use crate::{
    cache::{retrieve_existing_cache, serialize_execs_to_cache},
    syscalls::Stat,
};
use crate::{
    cache_utils::{hash_command, ExecCommand},
    condition_generator::generate_postconditions,
    recording::{append_file_events, copy_output_files_to_cache},
};

use crate::context;
use crate::execution_utils::{generate_open_syscall_file_event, get_full_path, path_from_fd};
use crate::recording::{ExecMetadata, Execution, Proc, RcExecution};
use crate::regs::{Regs, Unmodified};
use crate::syscalls::{MyStat, SyscallFailure, SyscallOutcome};
use crate::system_call_names::get_syscall_name;
use crate::tracer::TraceEvent;
use crate::Ptracer;

#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

use anyhow::{bail, Context, Result};

// Toggle additional metrics.
// Additional metrics include:
// - Space consumed
// - Total syscalls (intercepted)
// - Syscalls / sec
// - Total exec units
// - Total SyscallEvents (fact generation)
// - Total preconditions
// - Total postconditions
const ADDITIONAL_METRICS: bool = false;
// These flags are optimizations to P$.
// This one allows the user to skip caching the root execution
// because it may just not be worth it anyway (think raxml).
const DONT_CACHE_ROOT: bool = false;
// Probably always going to be true? Why wouldn't you want background
// thread copying for outputs, and at least parallel copying at the
// end of execution.
const BACKGROUND_THREADS: bool = true;
// Toggle parallelism for skipping jobs.
// This allows multiple threads to be spawned
// to serve output files from the cache.
const BACKGROUND_SERVING_THREADS: bool = true;
// Toggle this to handle stdout for this execution or ignore it.
const NO_STDOUT: bool = false;
// Flags for turning on and off different parts of ProcessCache.
// For profiling purposes.
// Run P$ with only ptrace system call interception.
const PTRACE_ONLY: bool = false;
// Run P$ with only ptrace system call interception and fact generation.
const FACT_GEN: bool = false;

pub fn trace_program(first_proc: Pid) -> Result<()> {
    info!("Running whole program");

    let async_runtime = AsyncRuntime::new();

    // CWD of the root process + "/cache/"
    let mut cache_dir = std::env::current_dir().with_context(|| context!("Cannot get CWD."))?;
    cache_dir.push("cache/");

    // We have to create the first execution struct outside
    // trace process, so we don't accidentally overwrite it
    // within trace_process().
    let first_execution = RcExecution::new(Execution::new(Proc(first_proc)));
    first_execution.set_to_root();

    if !(PTRACE_ONLY || FACT_GEN) {
        // Create the cache subdir for this execution.
        create_dir_all(&cache_dir)
            .with_context(|| context!("Failed to create cache dir: {:?}", cache_dir))?;
    }

    // Initialize the channel for communication between the tracer and background thread.
    let (caching_sender, caching_receiver) = unbounded();
    // Initialize the stdout serving channel and output file serving channel.
    let (stdout_sender, stdout_receiver) = unbounded();
    let (serving_file_sender, serving_file_receiver) = unbounded();

    // This is optional because the user may opt to not use
    // background threads.
    let option_handle_vec = if BACKGROUND_THREADS {
        let mut handle_vec = Vec::new();
        // Here is where we can modify the number of background threads.
        for _ in 0..5 {
            let r2 = caching_receiver.clone();
            let handle = thread::spawn(move || background_thread_copying_outputs(r2, NO_STDOUT));
            handle_vec.push(handle);
        }
        Some(handle_vec)
    } else {
        None
    };

    let option_caching_sender = if BACKGROUND_THREADS {
        Some(caching_sender)
    } else {
        None
    };

    let (option_stdout_vec, option_file_serving_vec) = if BACKGROUND_SERVING_THREADS {
        let mut stdout_handle_vec = Vec::new();
        let mut file_handle_vec = Vec::new();
        // HERE is where we can modify the number of background threads.
        for _ in 0..5 {
            let r2 = stdout_receiver.clone();
            let handle = thread::spawn(move || background_thread_serving_stdout(r2));
            stdout_handle_vec.push(handle);
        }
        for _ in 0..5 {
            let r2 = serving_file_receiver.clone();
            let handle = thread::spawn(move || background_thread_serving_outputs(r2));
            file_handle_vec.push(handle);
        }
        (Some(stdout_handle_vec), Some(file_handle_vec))
    } else {
        (None, None)
    };

    let (option_file_sender, option_stdout_sender) = if BACKGROUND_SERVING_THREADS {
        (Some(serving_file_sender), Some(stdout_sender))
    } else {
        (None, None)
    };

    // Instantiate the ComputedHashes map at the beginning before the execution starts.
    let computed_hashes = RcComputedHashes::new();

    // This allows us to pass these in this execution and to child execution's
    // to get accurate counts for total syscalls and total SyscallEvents.
    let total_intercepted_syscall_count = Rc::new(RefCell::new(0));
    let total_syscall_event_count = Rc::new(RefCell::new(0));

    let f = trace_process(
        async_runtime.clone(),
        Ptracer::new(first_proc),
        first_execution.clone(),
        Rc::new(cache_dir.clone()),
        option_caching_sender.clone(),
        computed_hashes,
        option_file_sender.clone(),
        option_stdout_sender.clone(),
        total_intercepted_syscall_count.clone(),
        total_syscall_event_count.clone(),
    );
    async_runtime
        .run_task(first_proc, f)
        .with_context(|| context!("Program tracing failed. Task returned error."))?;

    // If this is an empty root exec, we are probably skipping the exec.
    // So we don't want to calculate additional metrics or populate
    // the cache map and serialize it to the disk.
    if !(first_execution.is_empty_root_exec() || PTRACE_ONLY || FACT_GEN) {
        let mut cache_map = HashMap::new();
        first_execution.populate_cache_map(&mut cache_map);
        // ADDITIONAL METRICS: The total number of exec units for this execution
        // is the number of keys in this map!
        if ADDITIONAL_METRICS {
            println!(
                "TOTAL NUMBER OF INTERCEPTED SYSCALLS: {:?}",
                total_intercepted_syscall_count
            );
            println!(
                "TOTAL NUMBER OF EXEC UNITS: {:?}",
                cache_map.clone().keys().len()
            );
            println!(
                "TOTAL NUMBER OF SYSCALL EVENTS: {:?}",
                total_syscall_event_count
            );

            let first_command = first_execution.command();
            let first_cache_entry = cache_map.get(&first_command);
            if let Some(first_entry) = first_cache_entry {
                let (total_preconditions, total_postconditions) =
                    first_entry.total_pre_and_post_count();
                println!("TOTAL PRECONDITIONS: {:?}", total_preconditions);
                println!("TOTAL POSTCONDITIONS: {:?}", total_postconditions);
            }
        }
        // Here we serialize the cache map data structure to a file in the cache (/cache/cache).
        serialize_execs_to_cache(cache_map.clone());
    }

    // Clean up the background threads (for copying outputs to the cache and
    // serving from it) and their channels before we exit.
    if let Some(caching_sender) = option_caching_sender {
        drop(caching_sender);
    }
    if let Some(serving_file_sender) = option_file_sender {
        drop(serving_file_sender);
    }
    if let Some(stdout_sender) = option_stdout_sender {
        drop(stdout_sender);
    }

    if let Some(handle_vec) = option_handle_vec {
        for handle in handle_vec {
            let _ = handle.join();
        }
    }
    if let Some(file_serving_vec) = option_file_serving_vec {
        for handle in file_serving_vec {
            let _ = handle.join();
        }
    }
    if let Some(stdout_vec) = option_stdout_vec {
        for handle in stdout_vec {
            let _ = handle.join();
        }
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
/// This may have a lot of arguments but it is *THE* main function in this whole system, so we let
/// that slide.
#[allow(clippy::too_many_arguments)]
// TODO: This is kind of a laughable number of arguments at this point :P
pub async fn trace_process(
    async_runtime: AsyncRuntime,
    mut tracer: Ptracer,
    mut curr_execution: RcExecution,
    cache_dir: Rc<PathBuf>, // TODO: what is this??
    caching_send_end: Option<Sender<(LinkType, PathBuf, PathBuf)>>,
    computed_hashes: RcComputedHashes,
    file_send_end: Option<Sender<(Accessor, PathBuf, HashSet<Fact>)>>,
    stdout_send_end: Option<Sender<PathBuf>>,
    total_intercepted_syscall_count: Rc<RefCell<u64>>,
    total_syscall_event_count: Rc<RefCell<u64>>,
) -> Result<()> {
    let s = span!(Level::INFO, stringify!(trace_process), pid=?tracer.curr_proc);
    s.in_scope(|| info!("Starting Process"));
    let mut signal = None;
    let mut iostream_redirected = false;
    let caching_off = false;
    let mut skip_execution = false;
    let mut pls_close_stdout_fd = false;
    let mut stdout_fd_has_been_closed = false;
    // TODO: Deal with PID recycling?
    let stdout_file: String = format!("stdout_{:?}", tracer.curr_proc.as_raw());

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
                *total_intercepted_syscall_count.borrow_mut() += 1;

                // PTRACE_ONLY = we just want to intercept the events, but
                // do nothing at the event stops.
                if !PTRACE_ONLY {
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
                        let name = get_syscall_name(syscall).with_context(|| {
                            context!("Unable to get syscall name for {}", syscall)
                        })?;
                        bail!(context!("Unhandled system call {:?}", name));
                    }

                    // Otherwise the syscall name holds the system call number :)
                    // We do this to avoid unnecessarily fetching registers.
                    let name = get_syscall_name(event_message as usize).with_context(|| {
                        context!("Unable to get syscall name for syscall={}.", event_message)
                    })?;

                    let sys_span = span!(Level::INFO, "Syscall", name);
                    let ee = sys_span.enter();

                    if !NO_STDOUT {
                        // If close_stdout_fd == true, then we need to close our "stdout" fd.
                        // Whatever stdout is duped to.
                        // We only want to do this if we have NOT already done this.
                        if pls_close_stdout_fd && !stdout_fd_has_been_closed {
                            close_stdout_duped_fd(&curr_execution, &mut tracer)
                                .await
                                .with_context(|| context!("Unable to close stdout duped fd."))?;
                            pls_close_stdout_fd = false;
                            stdout_fd_has_been_closed = true;
                            // Continue to let original system call run.
                            continue;
                        }
                    }

                    // For file creation type events (creat, open, openat), we want to know if the file already existed
                    // before the syscall happens (i.e. in the prehook).
                    let mut file_existed_at_start = false;
                    // For unlink, we want to know the number of hardlinks.
                    let mut nlinks_before = 0;
                    // We have a "CheckMechanism" for input files (including files you write to that depend upon
                    // the starting contents, such as O_RDONLY, O_WRONLY + O_APPEND, and also O_WRONLY w/o offset mode)
                    // O_TRUNC means we don't care about the contents (so don't have to hash the file / get its mtime)

                    // Special cases, we won't get a posthook event. Instead we will get
                    // an execve event or a posthook if execve returns failure. We don't
                    // bother handling it, let the main loop take care of it.
                    // TODO: Handle them properly...

                    if !caching_off {
                        match name {
                            // "close" | "connect" | "pipe" | "pipe2" | "socket" => (),
                            "creat" | "open" | "openat" => {
                                // Get the full path and check if the file exists.
                                let full_path = get_full_path(&curr_execution, name, &tracer)?;
                                file_existed_at_start = full_path.exists();
                            }
                            "execve" => {
                                let regs = tracer.get_registers().with_context(|| {
                                    context!("Failed to get regs in exec event")
                                })?;
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
                                // Get the starting cwd for the process.
                                let starting_cwd = PathBuf::from(cwd);
                                debug!("Starting cwd: {:?}", starting_cwd);

                                // Create the full path to the executable.
                                let exec_path_buf = PathBuf::from(executable.clone());
                                debug!("Raw executable: {:?}", exec_path_buf);
                                debug!("args: {:?}", args);
                                let exec_path_buf = if exec_path_buf.is_relative() {
                                    canonicalize(exec_path_buf).unwrap()
                                } else {
                                    exec_path_buf
                                };
                                debug!("Execve event, executable: {:?}", exec_path_buf);

                                // Create this execution's unique ExecCommand struct.
                                let command = ExecCommand(
                                    exec_path_buf
                                        .clone()
                                        .into_os_string()
                                        .into_string()
                                        .unwrap(),
                                    args.clone(),
                                );
                                // Hash this struct. We use this hash as the name of the exec's subdir
                                // in the cache.
                                let hashed_command = hash_command(command.clone());
                                debug!(
                                    "EXECCOMMAND: {:?}, HASHED COMMAND: {:?}",
                                    command, hashed_command
                                );

                                // If this flag is on, it means we want ptrace interception
                                // and fact generation, but that's it. No checking the cache.
                                if !FACT_GEN {
                                    // Check the cache for the thing
                                    if let Some(cache) = retrieve_existing_cache() {
                                        let command = ExecCommand(
                                            exec_path_buf
                                                .clone()
                                                .into_os_string()
                                                .into_string()
                                                .unwrap(),
                                            args.clone(),
                                        );
                                        // Do we have this entry in the cache already?
                                        if let Some(entry) = cache.get(&command) {
                                            debug!(
                                                "Checking all preconditions: execution is: {:?}",
                                                command
                                            );
                                            // We check all the preconditions here.
                                            if entry.check_all_preconditions(tracer.curr_proc) {
                                                // Check if we should skip this execution.
                                                // If we are gonna skip, we have to change:
                                                // rax, orig_rax, arg1
                                                skip_execution = true;
                                                debug!("Trying to change system call after the execve into exit call! (Skip the execution!)");

                                                if BACKGROUND_SERVING_THREADS {
                                                    // Parallel serving.
                                                    // First apply dir transitions.
                                                    entry.apply_all_dir_transitions();

                                                    // Next send stdout files (paths) to threads to print.
                                                    let stdout_file_vec = entry.list_stdout_files();
                                                    if let Some(stdout_sender) =
                                                        stdout_send_end.clone()
                                                    {
                                                        for stdout_file in stdout_file_vec {
                                                            stdout_sender
                                                                .send(stdout_file)
                                                                .unwrap();
                                                        }
                                                    }

                                                    // Then send output files (paths) to threads to serve.
                                                    let posts = entry.postconditions();

                                                    if let Some(file_sender) = file_send_end.clone()
                                                    {
                                                        if let Some(postconditions) = posts {
                                                            let file_postconditions =
                                                                postconditions
                                                                    .file_postconditions();
                                                            let cache_subdir =
                                                                PathBuf::from("./cache/");
                                                            let comm_hash =
                                                                hash_command(entry.command());
                                                            let parent_cache_subdir = cache_subdir
                                                                .join(comm_hash.to_string());
                                                            for (accessor, fact_set) in
                                                                file_postconditions
                                                            {
                                                                file_sender
                                                                    .send((
                                                                        accessor,
                                                                        parent_cache_subdir.clone(),
                                                                        fact_set,
                                                                    ))
                                                                    .unwrap();
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    // Normal serving, single threaded.
                                                    entry.apply_all_transitions(NO_STDOUT);
                                                }

                                                let regs =
                                                    tracer.get_registers().with_context(|| {
                                                        context!(
                                                            "Failed to get regs in skip exec event"
                                                        )
                                                    })?;
                                                let mut regs = regs.make_modified();
                                                let exit_syscall_num = libc::SYS_exit as u64;

                                                // Change the arg1 to correct exit code.
                                                regs.write_arg1(0);
                                                // Change the orig rax val (Omar told me to, thus it is so.)
                                                regs.write_syscall_number(exit_syscall_num);
                                                // Change the rax val.
                                                regs.write_rax(exit_syscall_num);
                                                // Actually *set* those registers.
                                                tracer.set_regs(&mut regs)?;
                                                // Go to the next iteration of the loop so the process can exit.
                                                continue;
                                            }
                                        }
                                    }
                                }

                                let next_event =
                                    tracer.get_next_syscall().await.with_context(|| {
                                        context!("Unable to get posthook after execve prehook.")
                                    })?;

                                // // MTIME
                                // debug!("EXEC PATH BUF: {:?}", exec_path_buf);
                                // let curr_metadata = metadata(&exec_path_buf).unwrap();
                                // let exec_check = CheckMechanism::Mtime(curr_metadata.st_mtime());
                                // // HASHING
                                // // let exec_check =
                                // //     CheckMechanism::Hash(generate_hash(exec_path_buf.clone()));
                                // let new_exec_metadata = ExecMetadata::new(
                                //     Proc(tracer.curr_proc),
                                //     starting_cwd,
                                //     args,
                                //     envp,
                                //     exec_path_buf_string,
                                //     exec_check,
                                // );
                                match next_event {
                                    TraceEvent::Exec(_) => {
                                        // The execve succeeded!
                                        s.in_scope(|| {
                                            debug!("Execve succeeded!");
                                        });

                                        let exec_path_buf_string = exec_path_buf
                                            .clone()
                                            .into_os_string()
                                            .into_string()
                                            .unwrap();
                                        // MTIME
                                        debug!("EXEC PATH BUF: {:?}", exec_path_buf);
                                        // let curr_metadata = metadata(&exec_path_buf).unwrap();
                                        // let exec_check =
                                        //     CheckMechanism::Mtime(curr_metadata.st_mtime());
                                        // HASHING
                                        // Here we only generate the hash of the executable if we have
                                        // never seen this executable before in this execution.
                                        let exec_check = CheckMechanism::Hash(
                                            computed_hashes.get_computed_hash(exec_path_buf),
                                        );
                                        // This option always hashes the executable.
                                        // let exec_check = CheckMechanism::Hash(generate_hash(
                                        //     exec_path_buf.clone(),
                                        // ));
                                        // This does no check at all.
                                        // let exec_check = CheckMechanism::Hash(Vec::new());
                                        let new_exec_metadata = ExecMetadata::new(
                                            Proc(tracer.curr_proc),
                                            starting_cwd,
                                            args,
                                            envp,
                                            exec_path_buf_string,
                                            exec_check,
                                        );

                                        if curr_execution.is_empty_root_exec() {
                                            if DONT_CACHE_ROOT {
                                                // If we know it's the root exec that hasn't exec'd,
                                                // and we see the DONT_CACHE_ROOT flag is true, we update
                                                // this Execution to be ignored.
                                                println!("SETTING ROOT TO IGNORED");
                                                curr_execution.set_to_ignored(new_exec_metadata);
                                            } else {
                                                // Otherwise, we start caching by first updating the exec
                                                // metadata.
                                                curr_execution
                                                    .update_successful_exec(new_exec_metadata);
                                            }
                                        // This is a child exec.
                                        } else if curr_execution.pid() != tracer.curr_proc {
                                            // Get the stdout fd from the current exec if it exists.
                                            // let childs_stdout_fd = curr_execution
                                            //     .get_stdout_duped_fd(tracer.curr_proc);

                                            let childs_stdout_fd = if NO_STDOUT {
                                                None
                                            } else {
                                                curr_execution.get_stdout_duped_fd(tracer.curr_proc)
                                            };

                                            // New RcExecution for the child exec.
                                            let mut new_child_exec =
                                                Execution::new(Proc(tracer.curr_proc));
                                            new_child_exec
                                                .update_successful_exec(new_exec_metadata);
                                            let new_rc_child_exec =
                                                RcExecution::new(new_child_exec);

                                            if let Some(stdout_fd) = childs_stdout_fd {
                                                new_rc_child_exec.add_stdout_duped_fd(
                                                    stdout_fd,
                                                    tracer.curr_proc,
                                                );
                                                curr_execution
                                                    .remove_stdout_duped_fd(tracer.curr_proc)
                                            }
                                            // Add to parent's struct.
                                            curr_execution
                                                .add_child_execution(new_rc_child_exec.clone());
                                            // Set curr execution to the new one.
                                            curr_execution = new_rc_child_exec;
                                        } else {
                                            panic!("Process already called successful execve and is trying to do another!!");
                                        }
                                    }
                                    TraceEvent::Posthook(_) => {
                                        // If we get a posthook event after an Exec event, it means the exec
                                        // failed.
                                        s.in_scope(|| {
                                            debug!("Execve failed!");
                                        });
                                        let regs = tracer.get_registers().with_context(|| {
                                            context!("Failed to get regs in posthook")
                                        })?;
                                        let ret_val = regs.retval::<i32>();
                                        let failed_exec = {
                                            match ret_val {
                                                -2 => FileEvent::FailedExec(
                                                    SyscallFailure::FileDoesntExist,
                                                ),
                                                -13 => FileEvent::FailedExec(
                                                    SyscallFailure::PermissionDenied,
                                                ),
                                                e => panic!(
                                                    "Unexpected error returned by execve syscall!: {}",
                                                    e
                                                ),
                                            }
                                        };

                                        // We add this as a file event in the current exec, so we know to expect this exec to fail next time.
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
                            // Some events are special and we don't go to the posthook.
                            // For more info, I invite you to subject yourself to the ptrace
                            // man page :-)
                            "exit" | "exit_group" | "clone" | "vfork" | "fork" | "clone2"
                            | "clone3" => {
                                debug!("Special event: {}. Do not go to posthook.", name);
                                continue;
                            }
                            "unlink" | "unlinkat" => {
                                use std::os::unix::fs::MetadataExt;
                                let full_path = get_full_path(&curr_execution, name, &tracer)?;
                                // We get the total number of hardlinks in the unlink prehook.
                                // We need to get this value here because it may change by the
                                // time we get the posthook event.
                                if full_path.exists() {
                                    let meta = full_path.as_path().metadata().unwrap();
                                    nlinks_before = meta.nlink();
                                } else {
                                    nlinks_before = 0;
                                }
                            }
                            _ => {
                                if NO_STDOUT {
                                    iostream_redirected = true;
                                } else if !iostream_redirected {
                                    const STDOUT_FD: u32 = 1;
                                    // const STDERR_FD: u32 = 2;
                                    // TODO: Deal with PID recycling?

                                    // We don't have to worry about creating a cache subdir for this
                                    // exec if we are only doing ptrace or ptrace+factgen.
                                    if !(PTRACE_ONLY || FACT_GEN) {
                                        let exec = curr_execution.executable();
                                        let args = curr_execution.args();
                                        let comm_hash = hash_command(ExecCommand(exec, args));
                                        let cache_subdir = canonicalize("./cache").unwrap();
                                        let cache_subdir =
                                            cache_subdir.join(format!("{:?}", comm_hash));
                                        if !cache_subdir.exists() {
                                            create_dir(cache_subdir.clone()).unwrap();
                                        }
                                    }

                                    // This is the first real system call this program is doing after exec-ing.
                                    // We will redirect their stdout and stderr output here by writing them to files.
                                    redirect_io_stream(
                                        &stdout_file,
                                        STDOUT_FD,
                                        &mut tracer,
                                        &curr_execution,
                                    )
                                    .await
                                    .with_context(|| context!("Unable to redirect stdout."))?;
                                    // redirection::redirect_io_stream(&stderr_file, STDERR_FD, &mut tracer)
                                    //     .await
                                    //     .with_context(|| context!("Unable to redirect stderr."))?;
                                    // TODO: Add stderr redirection.

                                    // So we know this has been done successfully.
                                    iostream_redirected = true;

                                    // Continue to let original system call run.
                                    continue;
                                }
                            }
                        }
                    } else {
                        continue;
                    }

                    trace!("Waiting for posthook event...");
                    drop(e);
                    drop(ee);
                    let regs: Regs<Unmodified> = tracer.posthook().await?;
                    trace!("Waiting for posthook event...");

                    // In posthook.
                    let _ = s.enter();
                    let _ = sys_span.enter();
                    let ret_val = regs.retval::<i32>();

                    span!(Level::INFO, "Posthook", ret_val).in_scope(|| info!(name));

                    // Each syscall has its own handle_syscall() function in the posthook.
                    match name {
                        "access" => {
                            handle_access(&curr_execution, &tracer, &total_syscall_event_count)?
                        }
                        "chdir" => handle_chdir(&curr_execution, &tracer)?,
                        "close" => {
                            // The call was successful.
                            if ret_val == 0 && !stdout_fd_has_been_closed {
                                let fd = regs.arg1::<i32>();
                                // They are closing stdout.
                                // Weirdos.
                                // But this means we must also close our stdout file
                                // that we have been using to record the process'
                                // stdout output.
                                if !NO_STDOUT && fd == 1 {
                                    pls_close_stdout_fd = true;
                                }
                            }
                        }
                        "connect" | "pipe" | "pipe2" | "socket" => (),
                        "creat" | "openat" | "open" => handle_open(
                            &curr_execution,
                            file_existed_at_start,
                            name,
                            &tracer,
                            &total_syscall_event_count,
                        )?,
                        // TODO: newfstatat
                        "fstat" | "lstat" | "stat" => handle_stat_family(
                            &curr_execution,
                            name,
                            &tracer,
                            &total_syscall_event_count,
                        )?,
                        "getdents64" => handle_get_dents64(
                            &curr_execution,
                            &regs,
                            &tracer,
                            &total_syscall_event_count,
                        )?,
                        "mkdir" | "mkdirat" => handle_mkdir(
                            &curr_execution,
                            name,
                            &tracer,
                            &total_syscall_event_count,
                        )?,
                        "rename" | "renameat" | "renameat2" => handle_rename(
                            &curr_execution,
                            name,
                            &tracer,
                            &total_syscall_event_count,
                        )?,
                        "statfs" => {
                            handle_statfs(&curr_execution, &tracer, &total_syscall_event_count)?
                        }
                        "unlink" | "unlinkat" => {
                            // If the number of links before was 1, then the file
                            // will be deleted if this call is successful.
                            if nlinks_before == 1 {
                                handle_unlink(
                                    &curr_execution,
                                    name,
                                    &tracer,
                                    &total_syscall_event_count,
                                )?
                            }
                        }
                        _ => panic!("Unhandled system call: {:?}", name),
                    }
                }
            }
            TraceEvent::Clone(_) => {
                let child = Pid::from_raw(tracer.get_event_message()? as i32);
                s.in_scope(|| {
                    debug!("Fork Event. Creating task for new child: {:?}", child);
                    debug!("Parent pid is: {}", tracer.curr_proc);
                });

                // When a process forks/clones, we pass the current execution struct to the
                // child process' future as both the curr execution and the parent execution.
                // If the child process then calls "execve",
                // this new execution will replace the current execution for the child
                // process' future.
                let f = trace_process(
                    async_runtime.clone(),
                    Ptracer::new(child),
                    curr_execution.clone(),
                    cache_dir.clone(),
                    caching_send_end.clone(),
                    computed_hashes.clone(),
                    file_send_end.clone(),
                    stdout_send_end.clone(),
                    total_intercepted_syscall_count.clone(),
                    total_syscall_event_count.clone(),
                );
                async_runtime.add_new_task(child, f)?;
            }
            TraceEvent::Fork(_) | TraceEvent::VFork(_) => {
                let child = Pid::from_raw(tracer.get_event_message()? as i32);
                s.in_scope(|| {
                    debug!("Fork Event. Creating task for new child: {:?}", child);
                    debug!("Parent pid is: {}", tracer.curr_proc);
                });

                // When a process forks/clones, we pass the current execution struct to the
                // child process' future as both the curr execution and the parent execution.
                // If the child process then calls "execve",
                // this new execution will replace the current execution for the child
                // process' future.
                let f = trace_process(
                    async_runtime.clone(),
                    Ptracer::new(child),
                    curr_execution.clone(),
                    cache_dir.clone(),
                    caching_send_end.clone(),
                    computed_hashes.clone(),
                    file_send_end.clone(),
                    stdout_send_end.clone(),
                    total_intercepted_syscall_count.clone(),
                    total_syscall_event_count.clone(),
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

            // This is what we must do because this process is exiting.
            // - Append file event lists (between parent and children).
            // - Update the event lists of this execution struct.
            // - Generate postconditions.
            // - Use postconditions and copy output files to /cache/hash_of_my_command_key/output_file_x.

            // A note on postconditions:
            // If the parent has no files in common with its child, then the parent
            // can just copy over the child's computed postconditions to its own
            // instead of recomputing the child's along with its own.
            if !(skip_execution || PTRACE_ONLY || FACT_GEN) {
                // Add exit code to the exec struct, if this is the
                // pid that exec'd the exec. execececececec.
                if !curr_execution.is_ignored() {
                    curr_execution.add_exit_code(exit_code);
                }
                let children = curr_execution.children();
                let new_events = if children.is_empty() {
                    // If we have no children, we don't have to append
                    // any events.
                    curr_execution.syscall_events()
                } else {
                    let syscall_events = curr_execution.syscall_events();
                    let dir_events = syscall_events.dir_events();
                    let file_events = syscall_events.file_events();

                    // We will append to the original events.
                    let mut new_dir_events = dir_events;
                    let mut new_file_events = file_events;

                    for child in children {
                        let command = child.command();
                        append_file_events(
                            &mut new_file_events,
                            command.clone(),
                            child.syscall_events().file_events(),
                            child.pid(),
                        );
                        append_dir_events(
                            &mut new_dir_events,
                            command,
                            child.syscall_events().dir_events(),
                            child.pid(),
                        );
                    }
                    ExecSyscallEvents::new(new_dir_events, new_file_events)
                };

                // ADDITIONAL METRICS: Here is where we can count total number of syscalls in this whole
                // big execution.
                if ADDITIONAL_METRICS && curr_execution.is_root() {
                    let total_syscall_event_count =
                        get_total_syscall_event_count_for_root(new_events.clone());
                    println!("TOTAL SYSCALL EVENT COUNT: {:?}", total_syscall_event_count);
                }

                // Update the syscall events for the current exec with the newly combined
                // events from parent and children.
                curr_execution.update_syscall_events(new_events.clone());

                // If the execution was set to "ignored", we don't want to
                // generate + add postconditions.
                if !curr_execution.is_ignored() {
                    let postconditions = generate_postconditions(new_events);
                    curr_execution.update_postconditions(postconditions.clone());
                    let file_postconditions = postconditions.file_postconditions();

                    // Here is where we send the files to be copied to the background threads.
                    if let Some(caching_sender) = caching_send_end {
                        // Get the (source, dest) pairs of files to copy.
                        let file_pairs = generate_list_of_files_to_copy_to_cache(
                            &curr_execution,
                            file_postconditions,
                            NO_STDOUT,
                        );

                        // Send each pair across the channel.
                        for pair in file_pairs {
                            caching_sender.send(pair).unwrap();
                        }
                    } else {
                        // If we aren't using background threads to copy outputs, we have this function
                        // with a single synchronous thread copying the outputs.
                        copy_output_files_to_cache(&curr_execution, file_postconditions);
                    }
                }
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
fn handle_access(
    execution: &RcExecution,
    tracer: &Ptracer,
    total_syscall_event_count: &Rc<RefCell<u64>>,
) -> Result<()> {
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
        0 => FileEvent::Access(flags, SyscallOutcome::Success),
        -2 => FileEvent::Access(flags, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
        // It could be that the user doesn't have one of the permissions they specified as a parameter
        // OR it could be that they don't have search permissions on some dir in the path to the resource.
        // And we don't know so permission is gonna have to be unknown.
        -13 => FileEvent::Access(
            flags,
            SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
        ),
        e => panic!("Unexpected error returned by access syscall!: {}", e),
    };

    execution.add_new_file_event(tracer.curr_proc, event, full_path);
    *total_syscall_event_count.borrow_mut() += 1;
    Ok(())
}

fn handle_chdir(execution: &RcExecution, tracer: &Ptracer) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_chdir", pid=?tracer.curr_proc);
    let _ = sys_span.enter();

    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in handle_chdir()"))?;
    let ret_val = regs.retval::<i32>();

    // If they successfully change the cwd, we could check proc/pid/cwd for the full path to
    // the cwd. But, if they fail to, we'd have to do something else. I will leave that
    // to future Kelly.
    if ret_val == 0 {
        debug!("Successful chdir!!");
        let cwd_link = format!("/proc/{}/cwd", tracer.curr_proc);
        let cwd_path =
            readlink(cwd_link.as_str()).with_context(|| context!("Failed to readlink (cwd)"))?;
        let cwd = cwd_path.to_str().unwrap().to_owned();
        let cwd = PathBuf::from(cwd);
        execution.update_cwd(cwd);
    }

    Ok(())
}

/// Read directories returned by an intercepted system call to get_dents64. Return the d_name and
/// d_type fields from the get_dents64 struct.
fn handle_get_dents64(
    execution: &RcExecution,
    regs: &Regs<Unmodified>,
    tracer: &Ptracer,
    total_syscall_event_count: &Rc<RefCell<u64>>,
) -> Result<()> {
    // We only care about successful get_dents or when bytes were actually written.
    // if regs.retval::<i32>() <= 0 {
    //     return Ok(());
    // }

    let fd = regs.arg1::<i32>();
    let full_path = path_from_fd(tracer.curr_proc, fd)?;
    debug!("Full getdents64 path: {:?}", full_path);
    // Pointer to linux_dirent passed to get_dents64 system call.
    let mut dirp: *const u8 = regs.arg2::<*const u8>();
    // Number of bytes written by OS to dirp.
    let bytes_read = regs.retval::<i32>() as usize;
    let ret_val = regs.retval::<i32>();
    let max_size = unsafe { dirp.add(bytes_read) };
    let mut entries: Vec<(String, FileType)> = Vec::new();

    // Continue looping until out pointer jumps past dirp + bytes read.
    while dirp < max_size {
        let directory_entry = tracer
            .read_value::<libc::dirent64>(dirp as *const _)
            .with_context(|| context!("Cannot read first entry in dirp."))?;

        let cstr = unsafe { CStr::from_ptr(directory_entry.d_name.as_ptr()) };
        let file_name = cstr.to_owned();
        let file_type = directory_entry.d_type;
        let record_length = directory_entry.d_reclen;

        // Set dirp pointer to next entry.
        dirp = unsafe { dirp.add(record_length as usize) };

        let file_type = getdents_file_type(file_type);
        // let file_type = match file_type {
        //     dir::Type::Directory => FileType::Dir,
        //     dir::Type::File => FileType::File,
        //     dir::Type::Symlink => FileType::Symlink,
        //     t => panic!("what kind of file is this??: {:?}", t),
        // };
        // entries.push((file_name.into_string().unwrap(), file_type));

        match file_type {
            dir::Type::Directory => {
                entries.push((file_name.into_string().unwrap(), FileType::Dir));
            }
            dir::Type::File => {
                entries.push((file_name.into_string().unwrap(), FileType::File));
            }
            dir::Type::Symlink => {
                entries.push((file_name.into_string().unwrap(), FileType::Symlink));
            }
            // Otherwise do nothing.
            _ => (),
        }
    }

    let outcome = if ret_val >= 0 {
        SyscallOutcome::Success
    } else if ret_val == -2 {
        SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)
    } else {
        panic!("Unexpected return value from getdents! {:?}", ret_val)
    };

    let getdents_event = DirEvent::Read(full_path.clone(), entries, outcome);
    // We only cared if you actually read values.
    if ret_val > 0 {
        execution.add_new_dir_event(tracer.curr_proc, getdents_event, full_path);
        *total_syscall_event_count.borrow_mut() += 1;
    }

    Ok(())
}

fn handle_mkdir(
    execution: &RcExecution,
    syscall_name: &str,
    tracer: &Ptracer,
    total_syscall_event_count: &Rc<RefCell<u64>>,
) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_mkdir", pid=?tracer.curr_proc);
    let _ = sys_span.enter();

    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in handle_mkdir()"))?;

    let full_path = get_full_path(execution, syscall_name, tracer)?;
    let dir_fd = regs.arg1::<i32>();
    // TODO: not fully correct for mkdir...
    let root_dir = if syscall_name == "mkdir" || dir_fd == AT_FDCWD {
        execution.cwd()
    } else {
        let dir_fd = regs.arg1::<i32>();
        path_from_fd(tracer.curr_proc, dir_fd)?
    };
    let ret_val = regs.retval::<i32>();
    let syscall_outcome = match ret_val {
        0 => SyscallOutcome::Success,
        -13 => SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
        -17 => SyscallOutcome::Fail(SyscallFailure::AlreadyExists),
        // TODO: ENOENT?
        // TODO: ENOTDIR
        e => panic!("Unrecognized failure for mkdir: {:?}", e),
    };

    let mkdir_event = DirEvent::Create(root_dir, syscall_outcome);
    execution.add_new_dir_event(tracer.curr_proc, mkdir_event, full_path);
    *total_syscall_event_count.borrow_mut() += 1;
    Ok(())
}

fn handle_open(
    execution: &RcExecution,
    file_existed_at_start: bool,
    syscall_name: &str,
    tracer: &Ptracer,
    total_syscall_event_count: &Rc<RefCell<u64>>,
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

    let (creat_flag, excl_flag, offset_mode, access_mode) = if syscall_name == "creat" {
        let creat_flag = true;
        let excl_flag = false;
        // creat() uses write only as the mode
        (
            creat_flag,
            excl_flag,
            Some(OffsetMode::Trunc),
            AccessMode::Write,
        )
    } else {
        let flag_arg = if syscall_name == "open" {
            regs.arg2::<i32>()
        } else {
            regs.arg3::<i32>()
        };

        let option_flags = OFlag::from_bits(flag_arg);
        let (creat_flag, excl_flag, offset_mode, access_mode) = if let Some(flags) = option_flags {
            let access_mode = match flag_arg & O_ACCMODE {
                O_RDONLY => AccessMode::Read,
                O_RDWR => AccessMode::Both,
                O_WRONLY => AccessMode::Write,
                _ => panic!("open flags do not match any mode!"),
            };

            let creat_flag = flags.contains(OFlag::O_CREAT);
            let excl_flag = flags.contains(OFlag::O_EXCL);
            let offset_mode = if flags.contains(OFlag::O_APPEND) {
                Some(OffsetMode::Append)
            } else if flags.contains(OFlag::O_TRUNC) {
                Some(OffsetMode::Trunc)
            } else {
                None
            };

            (creat_flag, excl_flag, offset_mode, access_mode)
        } else {
            panic!("Unexpected open flags value!!");
        };

        (creat_flag, excl_flag, offset_mode, access_mode)
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
    sys_span.in_scope(|| debug!("Full path: {:?}", full_path));

    // We need to check the current exec's map of files it has accessed,
    // to see if the file has been accessed before.
    // If it has, we just add to that vector of events.
    // If it hasn't we need to add the full path -> file struct
    // to the vector of files this exec has accessed.

    let open_flags = OpenFlags {
        creat_flag,
        excl_flag,
        file_existed_at_start,
        offset_mode,
        access_mode,
    };

    let open_syscall_event =
        generate_open_syscall_file_event(execution, full_path.clone(), open_flags, syscall_outcome);

    if let Some(event) = open_syscall_event {
        *total_syscall_event_count.borrow_mut() += 1;
        execution.add_new_file_event(tracer.curr_proc, event, full_path);
    }
    Ok(())
}

// fn handle_pipe2(regs: &Regs<Unmodified>) -> Result<()> {
//     let flags = regs.arg2::<i32>();
//     let option_flags = OFlag::from_bits(flags);
//     if let Some(flags) = option_flags {
//         if !flags.contains(OFlag::O_CLOEXEC) {
//             panic!("Creating a pipe without the O_CLOEXEC flag!");
//         } else {
//             debug!("Happy lil O_CLOEXEC pipe :)");
//         }
//     }
//     Ok(())
// }

fn handle_rename(
    execution: &RcExecution,
    syscall_name: &str,
    tracer: &Ptracer,
    total_syscall_event_count: &Rc<RefCell<u64>>,
) -> Result<()> {
    debug!("WE ARE IN HANDLE RENAME");
    let sys_span = span!(Level::INFO, "handle_rename", pid=?tracer.curr_proc);
    let _ = sys_span.enter();
    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in handle_rename()"))?;

    let ret_val = regs.retval::<i32>();
    // retval = 0 is success for this syscall.
    let (full_old_path, full_new_path) = match syscall_name {
        // TODO: Use get_full_path()
        // probably not technically correct for rename but whatever right now
        "rename" => {
            let old_path_arg_bytes = regs.arg1::<*const c_char>();
            let old_path_arg = tracer
                .read_c_string(old_path_arg_bytes)
                .with_context(|| context!("Cannot read `rename` path."))?;
            let full_old_path = execution.cwd().join(old_path_arg);

            let new_path_arg_bytes = regs.arg2::<*const c_char>();
            let new_path_arg = tracer
                .read_c_string(new_path_arg_bytes)
                .with_context(|| context!("Cannot read `rename` path."))?;
            let full_new_path = execution.cwd().join(new_path_arg);
            (full_old_path, full_new_path)
        }
        // TODO: Use get_full_path()
        "renameat" | "renameat2" => {
            debug!("RENAMEAT2");
            let old_path_arg = regs.arg2::<*const c_char>();
            let old_file_name = tracer
                .read_c_string(old_path_arg)
                .with_context(|| context!("Cannot read `rename` path"))?;

            let dir_fd = regs.arg1::<i32>();
            let dir_path = if dir_fd == AT_FDCWD {
                execution.cwd()
            } else {
                path_from_fd(tracer.curr_proc, dir_fd)?
            };

            let old_full_path = dir_path.join(old_file_name);

            let new_path_arg = regs.arg4::<*const c_char>();
            let new_file_name = tracer
                .read_c_string(new_path_arg)
                .with_context(|| context!("Cannot read `rename` path"))?;

            let new_full_path = dir_path.join(new_file_name);
            (old_full_path, new_full_path)
        }
        _ => panic!("Calling unrecognized syscall in handle_rename()"),
    };

    debug!("full old path: {:?}", full_old_path);
    debug!("full new path: {:?}", full_new_path);
    let outcome = match ret_val {
        0 => SyscallOutcome::Success,
        // Probably the old file doesn't exist. Empty new path is also possible.
        -2 => SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
        -13 => SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
        -22 => SyscallOutcome::Fail(SyscallFailure::InvalArg),
        e => panic!("Unexpected error returned by rename syscall!: {}", e),
    };

    if full_old_path.extension().is_some() {
        // TODO: add an event for old and new path.
        debug!("It is a file!: {:?}", full_old_path);
        let event = FileEvent::Rename(full_old_path.clone(), full_new_path, outcome);
        execution.add_new_file_event(tracer.curr_proc, event, full_old_path);
        *total_syscall_event_count.borrow_mut() += 1;
    } else {
        debug!("It is a dir!: {:?}", full_old_path);
        let event = DirEvent::Rename(full_old_path.clone(), full_new_path, outcome);
        execution.add_new_dir_event(tracer.curr_proc, event, full_old_path);
        *total_syscall_event_count.borrow_mut() += 1;
    }

    Ok(())
}

// Handling the stat system calls.
fn handle_stat_family(
    execution: &RcExecution,
    syscall_name: &str,
    tracer: &Ptracer,
    total_syscall_event_count: &Rc<RefCell<u64>>,
) -> Result<()> {
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
        "lstat" | "stat" => Some(get_full_path(execution, syscall_name, tracer)?),
        _ => panic!("Calling unrecognized syscall in handle_stat()"),
    };

    let stat_syscall_event = {
        match ret_val {
            0 => {
                let stat_ptr = regs.arg2::<u64>();
                let stat_struct = tracer.read_value(stat_ptr as *const FileStat)?;
                // let st = tracer.read_value(stat_ptr as *const Statfs)?;
                // let whatever = st.filesystem_id();
                let my_stat = MyStat {
                    st_dev: stat_struct.st_dev,
                    st_ino: stat_struct.st_ino,
                    st_nlink: stat_struct.st_nlink,
                    st_mode: stat_struct.st_mode,
                    st_uid: stat_struct.st_uid,
                    st_gid: stat_struct.st_gid,
                    st_rdev: stat_struct.st_rdev,
                    // st_size: stat_struct.st_size,
                    st_blksize: stat_struct.st_blksize,
                    st_blocks: stat_struct.st_blocks,
                };
                if syscall_name == "lstat" {
                    FileEvent::Stat(Some(Stat::Lstat(my_stat)), SyscallOutcome::Success)
                } else {
                    FileEvent::Stat(Some(Stat::Stat(my_stat)), SyscallOutcome::Success)
                }
            }
            -2 => FileEvent::Stat(None, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
            // Bad fd error - Idc
            -9 => return Ok(()),
            -13 => FileEvent::Stat(None, SyscallOutcome::Fail(SyscallFailure::PermissionDenied)),
            e => panic!("Unexpected error returned by stat syscall!: {}", e),
        }
    };

    if let Some(path) = full_path {
        if !path.starts_with("/tmp")
            && !path.starts_with("/temp")
            && !path.starts_with("/proc")
            && !path.starts_with("/usr")
            && !path.starts_with("/etc")
            && !path.starts_with("/dev/null")
            && !path.ends_with(".")
            && path.is_file()
        {
            execution.add_new_file_event(tracer.curr_proc, stat_syscall_event, path);
            *total_syscall_event_count.borrow_mut() += 1;
        }
    }
    Ok(())
}

fn handle_statfs(
    execution: &RcExecution,
    tracer: &Ptracer,
    total_syscall_event_count: &Rc<RefCell<u64>>,
) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_statfs", pid=?tracer.curr_proc);
    let _ = sys_span.enter();

    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in handle_statfs()"))?;
    let ret_val = regs.retval::<i32>();
    let name = String::from("statfs");
    // retval = 0 is success for this syscall.
    let full_path = get_full_path(execution, &name, tracer)?;

    let stat_syscall_event = {
        match ret_val {
            0 => {
                let statfs_ptr = regs.arg2::<u64>();
                let statfs_struct = tracer.read_value(statfs_ptr as *const Statfs)?;
                // let st = tracer.read_value(stat_ptr as *const Statfs)?;
                // let whatever = st.filesystem_id();
                let my_statfs = MyStatFs {
                    optimal_transfer_size: statfs_struct.optimal_transfer_size(),
                    block_size: statfs_struct.block_size(),
                    maximum_name_length: statfs_struct.maximum_name_length(),
                    blocks: statfs_struct.blocks(),
                    blocks_free: statfs_struct.blocks_free(),
                    blocks_available: statfs_struct.blocks_available(),
                    files: statfs_struct.files(),
                    files_free: statfs_struct.files_free(),
                };

                DirEvent::Statfs(Some(my_statfs), SyscallOutcome::Success)
            }
            -2 => DirEvent::Statfs(None, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
            -13 => DirEvent::Statfs(None, SyscallOutcome::Fail(SyscallFailure::PermissionDenied)),
            e => panic!("Unexpected error returned by stat syscall!: {}", e),
        }
    };

    if !full_path.starts_with("/tmp")
        && !full_path.starts_with("/temp")
        && !full_path.starts_with("/proc")
        && !full_path.starts_with("/usr")
        && !full_path.starts_with("/etc")
        && !full_path.starts_with("/dev/null")
        && !full_path.ends_with(".")
        && !full_path.starts_with("/selinux")
        && !full_path.starts_with("/sys")
    {
        execution.add_new_dir_event(tracer.curr_proc, stat_syscall_event, full_path);
        *total_syscall_event_count.borrow_mut() += 1;
    }
    Ok(())
}

fn handle_unlink(
    execution: &RcExecution,
    name: &str,
    tracer: &Ptracer,
    total_syscall_event_count: &Rc<RefCell<u64>>,
) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_unlink", pid=?tracer.curr_proc);
    let _ = sys_span.enter();

    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in handle_unlink()"))?;
    let ret_val = regs.retval::<i32>();
    // retval = 0 is success for this syscall. lots of them it would seem.
    let full_path = get_full_path(execution, name, tracer)?;

    if full_path.is_dir() && name == "unlinkat" {
        let flag_arg = regs.arg3::<i32>();

        let option_flags = AtFlags::from_bits(flag_arg);
        if let Some(flags) = option_flags {
            if flags.contains(AtFlags::AT_REMOVEDIR) {
                let dir_event = match ret_val {
                    0 => DirEvent::Delete(SyscallOutcome::Success),
                    -2 => DirEvent::Delete(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
                    -13 => DirEvent::Delete(SyscallOutcome::Fail(SyscallFailure::PermissionDenied)),
                    e => panic!("Unexpected error returned by unlink syscall!: {:?}", e),
                };
                execution.add_new_dir_event(tracer.curr_proc, dir_event, full_path);
            }
        }
    } else {
        let file_event = match ret_val {
            0 => FileEvent::Delete(SyscallOutcome::Success),
            -2 => FileEvent::Delete(SyscallOutcome::Fail(SyscallFailure::FileDoesntExist)),
            -13 => FileEvent::Delete(SyscallOutcome::Fail(SyscallFailure::PermissionDenied)),
            e => panic!("Unexpected error returned by unlink syscall!: {:?}", e),
        };
        execution.add_new_file_event(tracer.curr_proc, file_event, full_path);
        *total_syscall_event_count.borrow_mut() += 1;
    }
    Ok(())
}
