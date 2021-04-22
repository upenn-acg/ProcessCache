use fmt::Display;
#[allow(unused_imports)]
use libc::{c_char, syscall, AT_SYMLINK_NOFOLLOW, O_ACCMODE, O_CREAT, O_RDONLY, O_RDWR, O_WRONLY};
#[allow(unused_imports)]
use nix::fcntl::{readlink, OFlag};
use nix::sys::stat::stat;
use nix::unistd::Pid;
use std::cell::RefCell;
use std::fmt;
// TODO: why two read links?!?!?
use std::fs::File;
use std::io::{BufWriter, Write};
use std::rc::Rc;

use crate::async_runtime::AsyncRuntime;
use crate::context;
use crate::idk::{AccessType, Execution, RcExecutions, RegFile};
use crate::log::{
    AccessEvent, ExecveEvent, ForkEvent, Mode, OpenEvent, ReadEvent, StatEvent, WriteEvent,
};
use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::system_call_names::get_syscall_name;
use crate::tracer::TraceEvent;
use crate::Ptracer;

#[allow(unused_imports)]
use tracing::{debug, error, info, span, trace, Level};

use anyhow::{bail, Context, Result};
pub struct Log {
    log: BufWriter<File>,
    print_all_syscalls: bool,
    #[allow(dead_code)]
    output_file_name: String,
}

impl Log {
    pub fn new(output_file_name: &str, print_all_syscalls: bool) -> Log {
        Log {
            log: BufWriter::new(File::create(output_file_name).unwrap()),
            print_all_syscalls,
            output_file_name: String::from(output_file_name),
        }
    }

    pub fn add_event(&mut self, event: &impl fmt::Display) -> Result<()> {
        let str = format!("{}", event);
        let bytes = str.as_bytes();
        self.log.write_all(bytes)?;

        Ok(())
    }

    pub fn flush(&mut self) {
        self.log.flush().unwrap();
    }

    pub fn print_all_syscalls(&self) -> bool {
        self.print_all_syscalls
    }
}

#[derive(Clone)]
pub struct LogWriter {
    log: Rc<RefCell<Log>>,
}

impl LogWriter {
    pub fn new(output_file_name: &str, print_all_syscalls: bool) -> LogWriter {
        LogWriter {
            log: Rc::new(RefCell::new(Log::new(output_file_name, print_all_syscalls))),
        }
    }

    pub fn add_event(&self, event: &impl Display) -> Result<()> {
        self.log.borrow_mut().add_event(event)
    }

    pub fn flush(&self) {
        self.log.borrow_mut().flush();
    }

    pub fn print_all_syscalls(&self) -> bool {
        self.log.borrow().print_all_syscalls()
    }
}

pub fn trace_program(first_proc: Pid, log_writer: LogWriter, rc_execs: RcExecutions) -> Result<()> {
    let f = |pid: Pid| trace_process(Ptracer::new(pid), log_writer.clone(), rc_execs.clone());
    let async_runtime = AsyncRuntime::new(f);

    info!("Running whole program");
    async_runtime
        .run_task(first_proc)
        .with_context(|| context!("Program tracing failed. Task returned error."))?;

    log_writer.flush();
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
/// race between a ptrace::FORK_EVENT and this ptrace::STOPPED from the parent. See
/// `handle_signal_fork_race()` in ptrace_event.rs for more info. Also relevant:
/// https://stackoverflow.com/questions/29997244/occasionally-missing-ptrace-event-vfork-when-running-ptrace
pub async fn trace_process(
    mut tracer: Ptracer,
    log_writer: LogWriter,
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

                    let syscall = regs.syscall_number() as usize;
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

                        let _res = handle_execve(
                            regs,
                            tracer.clone(),
                            log_writer.clone(),
                            rc_execs.clone(),
                        )
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
                let retval = regs.retval() as i32;

                span!(Level::INFO, "Posthook", retval).in_scope(|| info!(""));

                match name {
                    "access" => handle_access(&log_writer, &rc_execs, &regs, &tracer)?,
                    "creat" | "openat" | "open" => {
                        handle_open(&log_writer, &rc_execs, &regs, name, &tracer)?
                    }
                    "fstat" | "lstat" | "newfstatat" | "stat" => {
                        handle_stat(&log_writer, &rc_execs, &regs, name, &tracer)?
                    }
                    "pread64" | "read" => {
                        handle_read(&log_writer, &rc_execs, &regs, name, &tracer)?
                    }
                    "write" => handle_write(&log_writer, &rc_execs, &regs, &tracer)?,
                    _ => {}
                }
            }
            TraceEvent::Fork(_) | TraceEvent::VFork(_) | TraceEvent::Clone(_) => {
                let child = Pid::from_raw(tracer.get_event_message()? as i32);
                s.in_scope(|| {
                    debug!("Fork Event. Creating task for new child: {:?}", child);
                    debug!("Parent pid is: {}", tracer.curr_proc);
                });

                log_writer.add_event(&ForkEvent::new(child, tracer.curr_proc))?;
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

fn handle_access(
    log_writer: &LogWriter,
    rc_execs: &RcExecutions,
    regs: &Regs<Unmodified>,
    tracer: &Ptracer,
) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_access", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File metadata event: (access)");
    });

    let ret_val = regs.retval() as i32;
    let success = ret_val == 0;

    // retval = 0 is success for this syscall.
    if success || log_writer.print_all_syscalls() {
        let bytes = regs.arg1() as *const c_char;
        let path = tracer.read_c_string(bytes)?;

        let option_inode = if success {
            // Need to get the inode. Pretty sure this path is always absolute? (Only a sith deals in absolutes...
            // and also whoever designed the system call API...)
            let stat_struct = stat(path.as_str())?;
            Some(stat_struct.st_ino)
        } else {
            None
        };

        let access_event = AccessEvent::new(option_inode, path.clone(), tracer.curr_proc, success);
        log_writer.add_event(&access_event)?;
        if success {
            // Access is a metadata access. Lol. Meta.
            // No fd.

            // ID by the inode
            let inode = option_inode.unwrap();
            // Need to make a RegFile.
            let reg_file = RegFile::new(None, inode, Some(path));
            rc_execs.add_new_access(AccessType::Metadata, reg_file);
        }
    }
    Ok(())
}

async fn handle_execve(
    regs: Regs<Unmodified>,
    mut tracer: Ptracer,
    log_writer: LogWriter,
    rc_execs: RcExecutions,
) -> Result<()> {
    let sys_span = span!(Level::INFO, "handle_execve", pid=?tracer.curr_proc);
    let path_name = tracer.read_c_string(regs.arg1() as *const c_char)?;
    let args = tracer
        .read_c_string_array(regs.arg2() as *const *const c_char)
        .with_context(|| context!("Reading arguments to execve"))?;
    let envp = tracer.read_c_string_array(regs.arg3() as *const *const c_char)?;

    // Execve doesn't return when it succeeds.
    // If we get Ok, it failed.
    // If we get Err, it succeeded.
    // And yes I realize that is confusing.
    // TODO: may not always work?
    let success = tracer.posthook().await.is_err();
    if success || log_writer.print_all_syscalls() {
        sys_span.in_scope(|| {
            debug!("execve(\"{:?}\", {:?})", path_name, args);
            trace!("envp={:?}", envp);
        });
        // TODO: Consolidate when this becomes P$ (log will not be needed anymore)
        // These are essentially the same right now but I can't bring myself
        // to combine them
        let execve_event = ExecveEvent::new(args.clone(), path_name.clone());
        log_writer.add_event(&execve_event)?;
    }

    if success {
        let cwd_link = format!("/proc/{}/cwd", tracer.curr_proc);
        let cwd_path = readlink(cwd_link.as_str())?;
        let cwd = cwd_path.into_string().unwrap();
        let execution = Execution::new(args, cwd, envp, path_name);

        rc_execs.add_new_uniq_exec(execution);
    }

    Ok(())
}

fn handle_open(
    log_writer: &LogWriter,
    rc_execs: &RcExecutions,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let fd = regs.retval() as i32;
    let pid = tracer.curr_proc;
    let sys_span = span!(Level::INFO, "handle_open", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File open event: ({})", syscall_name);
    });

    if fd > 0 || log_writer.print_all_syscalls() {
        let (is_create, mode) = if syscall_name == "creat" {
            // creat() uses write only as the mode
            (true, Mode::WriteOnly)
        } else {
            let flags = if syscall_name == "open" {
                regs.arg2() as i32
            } else {
                regs.arg3() as i32
            };
            let is_create = flags & O_CREAT != 0;
            let mode = match flags & O_ACCMODE {
                O_RDONLY => Mode::ReadOnly,
                O_WRONLY => Mode::WriteOnly,
                O_RDWR => Mode::ReadWrite,
                _ => panic!("open flags do not match any mode"),
            };
            (is_create, mode)
        };

        let path_and_inode = if fd > 0 {
            // Successful, get full path
            let proc_path = format!("/proc/{}/fd/{}", pid, fd);
            let full =
                readlink(proc_path.as_str()).with_context(|| context!("Failed to readlink"))?;
            let stat_struct = stat(
                full.to_str()
                    .with_context(|| context!("full path to string failed"))?,
            )?;
            let inode = stat_struct.st_ino;

            let full_path = full.into_string().unwrap();
            (full_path, Some(inode))
        } else {
            // Failed, report no inode and relative path.
            let arg = if syscall_name == "openat" {
                regs.arg2() as *const c_char
            } else {
                regs.arg1() as *const c_char
            };
            let rel_path = tracer.read_c_string(arg)?;

            (rel_path, None)
        };

        let (path, inode) = path_and_inode;
        let open_event = OpenEvent::new(
            fd,
            inode,
            is_create,
            mode,
            path.clone(),
            pid,
            String::from(syscall_name),
        );

        log_writer.add_event(&open_event)?;

        // Successful and not create,
        // we need to track this read to
        // metadata.
        if !is_create && fd > 0 {
            // Right now only tracking READS individual execs do.
            // Creat + open(at) used to create files are not
            // being handled yet.

            let resource_fd = if fd > 0 { Some(fd) } else { None };
            // TODO: remove this unwrap()?
            let inode = inode.unwrap();
            let file = RegFile::new(resource_fd, inode, Some(path));
            rc_execs.add_new_access(AccessType::Metadata, file);
        }
    }
    Ok(())
}

// Handle read and pread64.
fn handle_read(
    log_writer: &LogWriter,
    rc_execs: &RcExecutions,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    // We want to either add or update
    // a resource entry with a contents access.
    // TODO: LOG WRITER

    let sys_span = span!(Level::INFO, "handle_read", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File contents access event: ({})", syscall_name);
    });

    let ret_val = regs.retval() as i32;
    // retval = 0 is end of file but success.
    // retval > 0 is number of bytes read.
    // retval < ERROR
    let success = ret_val >= 0;
    if success || log_writer.print_all_syscalls() {
        // Read is a contents access.
        // Fd is an arg.
        let fd = regs.arg1() as i32;

        // Get the path from the fd.
        let proc_path = format!("/proc/{}/fd/{}", tracer.curr_proc, fd);
        let full = readlink(proc_path.as_str())?;

        // Have to get the inode.
        let option_inode = if success {
            let stat_struct = stat(full.to_str().with_context(|| context!("who cares"))?)?;
            let inode = stat_struct.st_ino;
            Some(inode)
        } else {
            None
        };

        let full_path = full.into_string().unwrap();
        let read_event = ReadEvent::new(
            fd,
            option_inode,
            Some(full_path.clone()),
            tracer.curr_proc,
            String::from(syscall_name),
        );
        log_writer.add_event(&read_event)?;
        if success {
            // TODO: eww kelly
            let inode = option_inode.unwrap();
            let file = RegFile::new(Some(fd), inode, Some(full_path));
            rc_execs.add_new_access(AccessType::ReadContents, file);
        }
    }
    Ok(())
}

// First, we will just handle SUCCESS and FAIL of STAT calls
// SUCCESS: RET VAL = 0
fn handle_stat(
    log_writer: &LogWriter,
    rc_execs: &RcExecutions,
    regs: &Regs<Unmodified>,
    syscall_name: &str,
    tracer: &Ptracer,
) -> Result<()> {
    let ret_val = regs.retval() as i32;
    let pid = tracer.curr_proc;
    let success = ret_val == 0;

    let sys_span = span!(Level::INFO, "handle_stat", pid=?tracer.curr_proc);
    sys_span.in_scope(|| {
        debug!("File stat event: ({})", syscall_name);
    });

    // Return value == 0 means success
    if success || log_writer.print_all_syscalls() {
        let (fd, is_symlink, path) = if syscall_name == "fstat" {
            let fd = regs.arg1() as i32;
            (Some(fd), false, None)
        } else {
            // lstat, newstatat, stat
            let arg = match syscall_name {
                "lstat" | "stat" => regs.arg1() as *const c_char,
                // newstatat
                "newfstatat" => regs.arg2() as *const c_char,
                other => bail!(context!("Unhandled syscall: {}", other)),
            };

            let path = tracer.read_c_string(arg)?;

            let is_symlink = readlink(path.as_str()).is_ok();
            (None, is_symlink, Some(path))
        };

        // Don't want the inode if it failed (ret_val != 0)
        let inode = if success {
            let stat_ptr = regs.arg2() as *const libc::stat;
            let stat_struct = tracer.read_value(stat_ptr)?;
            Some(stat_struct.st_ino)
        } else {
            None
        };

        let at_symlink_nofollow = if syscall_name == "newfstatat" {
            let flags = regs.arg4() as i32;
            flags & AT_SYMLINK_NOFOLLOW != 0
        } else {
            false
        };

        let stat_event = StatEvent::new(
            at_symlink_nofollow,
            fd,
            inode,
            is_symlink,
            path.clone(),
            pid,
            success,
            String::from(syscall_name),
        );

        log_writer.add_event(&stat_event)?;

        // We don't want to keep track of this resource
        // for caching if it wasn't successfully accessed.
        if success {
            // TODO: get rid of unwrap() here?
            let inode = inode.unwrap();
            let file = RegFile::new(fd, inode, path);
            // TODO: Get rid of the unwrap here
            rc_execs.add_new_access(AccessType::Metadata, file);
        }
    }

    Ok(())
}
fn handle_write(
    log_writer: &LogWriter,
    rc_execs: &RcExecutions,
    regs: &Regs<Unmodified>,
    tracer: &Ptracer,
) -> Result<()> {
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
    let ret_val = regs.retval() as i32;
    let success = ret_val >= 0;
    if success || log_writer.print_all_syscalls() {
        // Contents.
        // Fd is an arg.
        let fd = regs.arg1() as i32;

        // Get the path from the fd.
        let proc_path = format!("/proc/{}/fd/{}", tracer.curr_proc, fd);
        let full = readlink(proc_path.as_str())?;

        // Have to get the inode.
        let option_inode = if success {
            let stat_struct = stat(full.to_str().with_context(|| context!("who cares"))?)?;
            let inode = stat_struct.st_ino;
            Some(inode)
        } else {
            None
        };
        let full_path = full.into_string().unwrap();

        let write_event =
            WriteEvent::new(fd, option_inode, Some(full_path.clone()), tracer.curr_proc);
        log_writer.add_event(&write_event)?;

        if success {
            // TODO: eww kelly
            let inode = option_inode.unwrap();
            let file = RegFile::new(Some(fd), inode, Some(full_path));
            rc_execs.add_new_access(AccessType::WriteContents, file);
        }
    }
    Ok(())
}
