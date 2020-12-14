use crate::system_call_names::SYSTEM_CALL_NAMES;

use libc::{c_char, O_ACCMODE, O_CREAT, O_RDONLY, O_RDWR, O_WRONLY};
use nix::fcntl::readlink;
use nix::sys::stat::stat;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use single_threaded_runtime::task::Task;
use single_threaded_runtime::SingleThreadedRuntime;
use std::cell::RefCell;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;
use std::rc::Rc;

use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::tracer::TraceEvent;

use crate::Ptracer;
use single_threaded_runtime::ptrace_event::{AsyncPtrace, PtraceReactor};
use tracing::{debug, info, span, trace, Level};

use anyhow::{anyhow, bail, Context, Result};

#[derive(Clone)]
pub struct LogWriter {
    log: Rc<RefCell<BufWriter<File>>>,
}

impl LogWriter {
    pub fn new(file_name: &str) -> LogWriter {
        LogWriter {
            log: Rc::new(RefCell::new(BufWriter::new(
                File::create(file_name).unwrap(),
            ))),
        }
    }

    pub fn write(&self, text: &str) {
        let buf = text.as_bytes();
        self.log.borrow_mut().write_all(buf).unwrap();
    }

    pub fn flush(&self) {
        self.log.borrow_mut().flush().unwrap();
    }
}

pub fn trace_program(first_proc: Pid) -> nix::Result<()> {
    let executor = Rc::new(SingleThreadedRuntime::new(PtraceReactor::new()));
    let ptracer = Ptracer::new(first_proc);
    info!("Running whole program");

    let log_writer = LogWriter::new("output.txt");

    let f = run_process(
        // Every executing process gets its own handle into the executor.
        executor.clone(),
        ptracer,
        log_writer.clone(),
    );

    executor.add_future(Task::new(f, first_proc));
    executor.run_all();

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
        .with_context(|| format!("run_process({:?}) failed.", pid));

    if let Err(e) = res {
        eprintln!("{:?}", e);
    }
}

pub async fn do_run_process(
    executor: Rc<SingleThreadedRuntime<PtraceReactor>>,
    mut tracer: Ptracer,
    log_writer: LogWriter,
) -> Result<()> {
    let s = span!(Level::INFO, "run_process", pid=?tracer.curr_proc);

    loop {
        match tracer.get_next_event().await {
            TraceEvent::Exec(pid) => {
                s.in_scope(|| debug!("Saw exec event for pid {}", pid));
            }
            TraceEvent::PreExit(_pid) => {
                s.in_scope(|| debug!("Saw preexit event."));
                break;
            }
            TraceEvent::Prehook(pid) => {
                let e = s.enter();
                let regs = tracer
                    .get_registers()
                    .context("Prehook fetching registers.")?;
                let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];

                let sys_span = span!(Level::INFO, "Syscall", name);
                let ee = sys_span.enter();
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
                    _ => {}
                }

                if name == "execve" {
                    let regs = tracer
                        .get_registers()
                        .context("Execve getting registers.")?;

                    let res = handle_execve(regs, tracer.clone(), pid, log_writer.clone())
                        .await
                        .with_context(|| format!("handle_execve({:?}) failed", pid));
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
                let retval = regs.retval() as i32;

                span!(Level::INFO, "Posthook", retval).in_scope(|| info!(""));

                // Successful open
                if name == "openat" && retval > 0 {
                    handle_openat(regs, tracer.clone(), log_writer.clone(), pid);
                }
            }
            TraceEvent::Fork(_) | TraceEvent::VFork(_) | TraceEvent::Clone(_) => {
                let child = Pid::from_raw(tracer.get_event_message()? as i32);
                s.in_scope(|| {
                    debug!("Fork Event. Creating task for new child: {:?}", child);
                    debug!("Parent pid is: {}", tracer.curr_proc);
                });

                log_writer.write(&format!(
                    "Fork Event. Creating task for new child: {}. Parent pid is: {}\n",
                    child, tracer.curr_proc
                ));

                // Recursively call run process to handle the new child process!
                let f = run_process(executor.clone(), Ptracer::new(child), log_writer.clone());
                executor.add_future(Task::new(f, child));
            }

            TraceEvent::Posthook(_) => {
                // The posthooks should be handled internally by the system
                // call handler functions.
                anyhow!("We should not see posthook events.");
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
    match tracer.get_next_event().await {
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

fn handle_openat(regs: Regs<Unmodified>, tracer: Ptracer, log_writer: LogWriter, pid: Pid) {
    let sys_span = span!(Level::INFO, "handle_openat", pid=?tracer.curr_proc);

    let flag = regs.arg3() as i32;
    let fd = regs.retval() as i32;
    let full_path = format!("/proc/{}/fd/{}", pid, fd);
    let full = readlink(full_path.as_str()).expect("Failed to readlink for openat syscall");
    let inode = stat(full.to_str().expect("path to string failed"))
        .expect("stat failed")
        .st_ino;
    // let cpath = regs.arg2() as *const c_char;
    // let path = tracer
    //     .read_c_string(cpath)
    //     .expect("Failed to read string from tracee");

    if (flag & O_ACCMODE) == O_RDONLY {
        log_writer.write(&format!(
            "File opened for reading. Pid: {}, fd: {}, inode: {}, path: {}\n",
            pid,
            fd,
            inode,
            full.to_str().expect("path to string failed")
        ));
    } else if (flag & O_ACCMODE) == O_WRONLY {
        log_writer.write(&format!(
            "File opened for writing. Pid: {}, fd: {}, inode: {}, path: {}\n",
            pid,
            fd,
            inode,
            full.to_str().expect("path to string failed")
        ));
        if flag & O_CREAT != 0 {
            // File is being created.
            sys_span.in_scope(|| {
                debug!("File create event");
                debug!(
                    "Creator pid: {:?}, fd: {:?}, , inode: {:?}, path: {:?}",
                    pid,
                    fd,
                    inode,
                    full.to_str().expect("path to string failed")
                );
            });

            log_writer.write(&format!(
                "File create event (openat). Creator pid: {}, fd: {}, inode: {}, path: {}\n",
                pid,
                fd,
                inode,
                full.to_str().expect("path to string failed")
            ));
        }
    } else if (flag & O_ACCMODE) == O_RDWR {
        log_writer.write(&format!(
            "File opened for read/write. Pid: {}, fd: {}, inode: {}, path: {}\n",
            pid,
            fd,
            inode,
            full.to_str().expect("path to string failed")
        ));
    } else {
        anyhow!("Open syscall MUST have a mode");
    }
}

async fn handle_execve(
    regs: Regs<Unmodified>,
    mut tracer: Ptracer,
    pid: Pid,
    log_writer: LogWriter,
) -> Result<()> {
    let path_name = tracer.read_c_string(regs.arg1() as *const c_char)?;
    let args = unsafe { tracer.read_c_string_array(regs.arg2() as *const *const c_char) }
        .context("Reading arguments to execve")?;
    let envp = unsafe { tracer.read_c_string_array(regs.arg3() as *const *const c_char)? };

    // Execve doesn't return when it succeeds.
    // If we get Ok, it failed.
    // If we get Err, it succeeded.
    // And yes I realize that is confusing.
    if tracer.posthook().await.is_err() {
        debug!("execve(\"{:?}\", {:?})", path_name, args);
        trace!("envp={:?}", envp);
        log_writer.write(&format!("Execve event: {:?}, {:?}\n", path_name, args));
    }

    Ok(())
}
