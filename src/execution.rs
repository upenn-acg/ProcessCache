use crate::context;
use crate::system_call_names::get_syscall_name;

use fmt::Display;
#[allow(unused_imports)]
use libc::{c_char, syscall, AT_SYMLINK_NOFOLLOW, O_ACCMODE, O_CREAT, O_RDONLY, O_RDWR, O_WRONLY};
#[allow(unused_imports)]
use nix::fcntl::{readlink, OFlag};
use nix::sys::stat::stat;
use nix::unistd::Pid;
use single_threaded_runtime::task::Task;
use single_threaded_runtime::SingleThreadedRuntime;
//use core::num::flt2dec::strategy::dragon::format_exact;
use std::cell::RefCell;
use std::fmt;
use std::fs::{read_link, File};
use std::io::BufWriter;
use std::io::Write;
use std::rc::Rc;

use crate::log::{ExecveEvent, ForkEvent, Mode, OpenEvent, StatEvent};
use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::tracer::TraceEvent;

use crate::Ptracer;
#[allow(unused_imports)]
use single_threaded_runtime::ptrace_event::{AsyncPtrace, PtraceReactor};
use tracing::{debug, info, span, trace, Level};

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

pub fn trace_program(first_proc: Pid, log_writer: LogWriter) -> Result<()> {
    let executor = Rc::new(SingleThreadedRuntime::new(PtraceReactor::new()));
    let ptracer = Ptracer::new(first_proc);
    info!("Running whole program");

    let f = run_process(
        // Every executing process gets its own handle into the executor.
        executor.clone(),
        ptracer,
        log_writer.clone(),
    );

    executor
        .add_future(Task::new(f, first_proc))
        .with_context(|| context!("Cannot add initial future to executor."))?;
    executor
        .run_all()
        .with_context(|| context!("Executor failure while running our tasks."))?;

    log_writer.flush();
    Ok(())
}

/// Wrapper for displaying error messages. All error messages are handled here.
/// NOTE: The process should start in a STOPPED state. Ptrace does this by default so it should just
/// work.
/// For all child processes (assuming we're are ptracing a process tree) technically there is a
/// ptrace::STOPPED event on the wait-event queue, but it seems calling ptrace(continue) will get
/// rid of this event (this is the first thing that `get_next_event()` does in `do_run_process()`.
/// So we actually can just ignore this event. This is actually what we want and how we handle the
/// race between a ptrace::FORK_EVENT and this ptrace::STOPPED from the parent. See
/// `handle_signal_fork_race()` in ptrace_event.rs for more info. Also relevant:
/// https://stackoverflow.com/questions/29997244/occasionally-missing-ptrace-event-vfork-when-running-ptrace
pub async fn run_process(
    executor: Rc<SingleThreadedRuntime<PtraceReactor>>,
    tracer: Ptracer,
    log_writer: LogWriter,
) {
    let pid = tracer.curr_proc;
    let res = do_run_process(executor, tracer, log_writer.clone())
        .await
        .with_context(|| context!("Process {:?} failed.", pid));

    if let Err(e) = res {
        eprintln!("{:?}", e);
    }
}

pub async fn do_run_process(
    executor: Rc<SingleThreadedRuntime<PtraceReactor>>,
    mut tracer: Ptracer,
    log_writer: LogWriter,
) -> Result<()> {
    let s = span!(Level::INFO, "do_run_process", pid=?tracer.curr_proc);

    loop {
        match tracer.get_next_event().await? {
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

                        let _res = handle_execve(regs, tracer.clone(), log_writer.clone())
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
                    "creat" | "openat" | "open" => handle_open(regs, &tracer, &log_writer, name)?,
                    "fstat" | "lstat" | "newfstatat" | "stat" => {
                        handle_stat(regs, &tracer, &log_writer, name)?
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

                let fork_event = ForkEvent::new(child, tracer.curr_proc);
                log_writer.add_event(&fork_event)?;

                // Recursively call run process to handle the new child process!
                let f = run_process(executor.clone(), Ptracer::new(child), log_writer.clone());
                executor.add_future(Task::new(f, child)).with_context(|| {
                    context!("Failed to add new task for child process during clone event.")
                })?;
            }

            TraceEvent::Posthook(_) => {
                // The posthooks should be handled internally by the system
                // call handler functions.
                bail!("We should not see posthook events.");
            }

            // Received a signal event.
            TraceEvent::ReceivedSignal(pid, signal) => {
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
    match tracer.get_next_event().await? {
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

fn handle_open(
    regs: Regs<Unmodified>,
    tracer: &Ptracer,
    log_writer: &LogWriter,
    syscall_name: &str,
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

            let full_path = format!("{:?}", full);
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
            path,
            pid,
            String::from(syscall_name),
        );

        log_writer.add_event(&open_event)?;
    }
    Ok(())
}

// First, we will just handle SUCCESS and FAIL of STAT calls
// SUCCESS: RET VAL = 0
fn handle_stat(
    regs: Regs<Unmodified>,
    tracer: &Ptracer,
    log_writer: &LogWriter,
    syscall_name: &str,
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

            let is_symlink = read_link(path.clone()).is_ok();
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
            path,
            pid,
            success,
            String::from(syscall_name),
        );

        log_writer.add_event(&stat_event)?;
    }

    Ok(())
}

async fn handle_execve(
    regs: Regs<Unmodified>,
    mut tracer: Ptracer,
    log_writer: LogWriter,
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
    if tracer.posthook().await.is_err() || log_writer.print_all_syscalls() {
        sys_span.in_scope(|| {
            debug!("execve(\"{:?}\", {:?})", path_name, args);
            trace!("envp={:?}", envp);
        });
        let execve_event = ExecveEvent::new(args, path_name);
        log_writer.add_event(&execve_event)?;
    }

    Ok(())
}
