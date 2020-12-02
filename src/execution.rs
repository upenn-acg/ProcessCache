use crate::system_call_names::SYSTEM_CALL_NAMES;

use libc::{c_char, O_CREAT};
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
use single_threaded_runtime::ptrace_event::PtraceReactor;
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
// fn signal_event_handler(&mut self, signal: Signal, pid: Pid) -> Option<Signal> {
//     // This is a regular signal, inject it to the process.
//     if self.live_processes.contains(& pid){
//         return Some(signal);
//     }

//     // This is a new child spawned by a fork event! This is the first time we're
//     // seeing it as a STOPPED event. Add it to our records.
//     if signal == Signal::SIGSTOP {
//         info!("New child is registered and it's STOPPED signal captured.");
//         self.live_processes.insert(pid);
//         self.proc_continue_event.insert(pid, ContinueEvent::Continue);

//         // NOTE: We want to ignore this signal! This is not something that should
//         // be propegated down to the process, it is only for US (the tracer).
//         return None;
//     }

//     panic!("Uknown signal {:?} for uknown process {:?}", signal, pid);

// }

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
pub async fn run_process(
    executor: Rc<SingleThreadedRuntime<PtraceReactor>>,
    tracer: Ptracer,
    log_writer: LogWriter,
) {
    let pid = tracer.current_process;
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
    let s = span!(Level::INFO, "run_process", pid=?tracer.current_process);

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
                if name == "exit_group" || name == "clone" {
                    debug!("continuing to next event..");
                    continue;
                }

                if name == "execve" {
                    let regs = tracer
                        .get_registers()
                        .context("Execve getting registers.")?;
                    let path_name = tracer.read_c_string(regs.arg1() as *const c_char);
                    let args =
                        unsafe { tracer.read_c_string_array(regs.arg2() as *const *const c_char) }
                            .context("Reading arguments to execve")?;
                    let envp =
                        unsafe { tracer.read_c_string_array(regs.arg3() as *const *const c_char)? };

                    debug!("execve(\"{:?}\", {:?})", path_name, args);
                    trace!("envp={:?}", envp);

                    log_writer.write("Execve event\n");
                    continue;
                }

                match name {
                    "openat" => {
                        let flag = regs.arg3() as i32;

                        if flag & O_CREAT != 0 {
                            // File is being created.
                            let cpath = regs.arg2() as *const c_char;
                            let path = tracer
                                .read_c_string(cpath)
                                .expect("Failed to read string from tracee");
                            let fd = regs.arg1() as i32;
                            sys_span.in_scope(|| {
                                debug!("File create event");
                                debug!("Creator pid: {:?}, fd: {:?}, path: {:?}", pid, fd, path);
                            });

                            log_writer.write(&format!(
                                "File create event (openat). Creator pid: {}, fd: {}, path: {}\n",
                                pid, fd, path
                            ));
                        }
                    }
                    "read" => {
                        debug!("Read event");

                        let fd = regs.arg1() as i32;
                        // Writing to the log for this read event.
                        log_writer.write(&format!("Reader pid: {}, fd: {}\n", pid, fd));
                    }
                    "write" => {
                        debug!("Write event");

                        let fd = regs.arg1() as i32;
                        // Writing to the log for this write event.
                        log_writer.write(&format!("Writer pid: {}, fd: {}\n", pid, fd));
                    }
                    _ => (),
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
            }
            TraceEvent::Fork(_) | TraceEvent::VFork(_) | TraceEvent::Clone(_) => {
                let child = Pid::from_raw(tracer.get_event_message()? as i32);
                s.in_scope(|| {
                    debug!("Fork Event. Creating task for new child: {:?}", child);
                    debug!("Parent pid is: {}", tracer.current_process);
                });

                log_writer.write(&format!(
                    "Fork Event. Creating task for new child: {}. Parent pid is: {}\n",
                    child, tracer.current_process
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
// async fn handle_getcwd(pid: Pid) {
//     // Pre-hook

//     let regs = posthook(pid).await;

//     // Post-hook
//     let buf = regs.arg1() as *const c_char;
//     let length = regs.arg1() as isize;
//     let cwd = read_string(buf, pid);
//     info!("cwd({}, {})", cwd, length);
// }

// Convert to new implementaiton.
// pub fn handle_execve(regs: Regs<Unmodified>, pid: Pid, mut y: Yielder) {
//     let arg1 = regs.arg1() as *const c_char;
//     let exe = read_string(arg1, pid);
//     debug!("[{}] executable: {}", pid, exe);

//     let argv = regs.arg2() as *const *const c_char;

//     // Read all of argv
//     for i in 0.. {
//         let p = read_value(unsafe { argv.offset(i) }, pid);
//         if p == null() { break; }

//         let arg = read_string(p, pid);
//         debug!("[{}] arg{}: {}", pid, i, arg);
//     }

//     let res = await_execve(y);
//     debug!("await_execve results: {:?}", res);

//     fn await_execve(mut y: Yielder) -> Action {
//         // Wait for either postHook of execve (in case of failure),
//         // Or execve event on succ
//         let actions = new_actions(& [Action::PostHook, Action::Execve]);
//         y.yield_with(actions);
//         y.get_yield().unwrap()
//     }
// }
