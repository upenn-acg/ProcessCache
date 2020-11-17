use crate::system_call_names::SYSTEM_CALL_NAMES;

use libc::{c_char, O_CREAT};
use nix::unistd::Pid;
use single_threaded_runtime::task::Task;
use single_threaded_runtime::Reactor;
use single_threaded_runtime::SingleThreadedRuntime;
use std::rc::Rc;
use tracer::regs::Regs;
use tracer::regs::Unmodified;
use tracer::TraceEvent;
use tracer::Tracer;

use crate::clocks::ProcessClock;

use tracing::{debug, info, span, Level};

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

/// It would seem that &RefCell would be enough. Rc<RefCell<_>> is needed to
/// convice Rust that the clocks will live long  enough, otherwise we run into
/// lifetime issues.
pub async fn run_process<T, R>(
    pid: Pid,
    executor: Rc<SingleThreadedRuntime<R>>,
    mut tracer: T,
    mut current_clock: ProcessClock,
) where
    R: Reactor + 'static,
    T: Tracer + 'static,
{
    let proc_span = span!(Level::INFO, "proc", ?pid);
    let _proc_span_enter = proc_span.enter();

    current_clock.add_new_process(pid);
    let mut process_clock = current_clock;

    loop {
        match tracer.get_next_event().await {
            TraceEvent::Exec(pid) => {
                debug!("Saw exec event for pid {}", pid);
            }
            TraceEvent::PreExit(_pid) => {
                debug!("Saw preexit event.");
                break;
            }
            TraceEvent::Prehook(pid) => {
                let regs = tracer.get_registers();
                let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];

                let syscall_span = span!(Level::INFO, "syscall", name);
                let _senter = syscall_span.enter();

                info!(?pid, ?name);

                // Special cases, we won't get a posthook event. Instead we will get
                // an execve event or a posthook if execve returns failure. We don't
                // bother handling it, let the main loop take care of it.
                // TODO: Handle them properly...
                if name == "exit_group" || name == "clone" {
                    debug!("continuing to next event..");
                    continue;
                }

                if name == "execve" {
                    debug!("Execve event");
                    continue;
                }

                match name {
                    "openat" => {
                        debug!("Openat event");
                        let flag = regs.arg3() as i32;

                        if flag & O_CREAT != 0 {
                            // File is being created.
                            let cpath = regs.arg2() as *const c_char;
                            let path = tracer.read_cstring(cpath, pid);
                            let fd = regs.arg1() as i32;
                            debug!("File create event (openat)");
                            debug!("Creator pid: {}, fd: {}, path: {}", pid, fd, path);
                        }
                    }
                    "read" => {
                        debug!("Read event");

                        let fd = regs.arg1() as i32;
                        debug!("Reader pid: {}, fd: {}", pid, fd);
                    }
                    "write" => {
                        debug!("Write event");

                        let fd = regs.arg1() as i32;
                        debug!("Writer pid: {}, fd: {}", pid, fd);
                    }
                    _ => (),
                }

                let regs: Regs<Unmodified> = tracer.posthook().await;

                debug!("in posthook");
                // In posthook.
                let retval = regs.retval() as i32;
                let posthook_span = span!(Level::INFO, "posthook", retval);
                let _penter = posthook_span.enter();
                //let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];
            }

            TraceEvent::Fork(_) | TraceEvent::VFork(_) | TraceEvent::Clone(_) => {
                let child = Pid::from_raw(tracer.get_event_message() as i32);
                debug!("Fork Event. Creating task for new child: {:?}", child);
                debug!("Parent pid is: {}", pid);
                // Recursively call run process to handle the new child process!
                wrapper(
                    child,
                    executor.clone(),
                    tracer.clone_tracer_for_new_process(child),
                    process_clock.clone(),
                );

                // Start of a new epoch, increment the parent's clock upon fork.
                process_clock.increment_own_time();
            }

            TraceEvent::Posthook(pid) => {
                debug!("Saw post hook event from pid {}", pid);
                // The posthooks should be handled internally by the system
                // call handler functions.
                panic!("We should not see posthook events.");
            }

            // Received a signal event.
            TraceEvent::ReceivedSignal(pid, signal) => {
                debug!(?signal, "pid {} received signal {:?}", pid, signal);
            }

            TraceEvent::KilledBySignal(pid, signal) => {
                debug!(?signal, "Process {} killed by signal {:?}", pid, signal);
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
            debug!("Saw actual exit event for pid {}", pid);
        }
        e => panic!(
            "Saw other event when expecting ProcessExited event: {:?}",
            e
        ),
    }
}

pub fn run_program<T>(tracer: T) -> nix::Result<()>
where
    T: Tracer + 'static,
{
    let executor = Rc::new(SingleThreadedRuntime::new(tracer.get_reactor()));
    debug!("Running whole program");
    let first_process = tracer.get_current_process();
    let f = run_process(
        first_process,
        executor.clone(),
        tracer,
        ProcessClock::new(first_process),
    );

    executor.add_future(Task::new(f, first_process));
    executor.run_all();

    // Not really useful to output the process clocks in their
    // final state.
    // for (pid, clock) in process_clocks.borrow().iter() {
    //     println!("Process clock for: {}", pid);
    //     for (p, t) in clock {
    //         println!("Pid: {}, Time: {:?}", p, t);
    //     }
    // }

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

/// We recursively call run_process from run_process. The futures state machine
/// does not like the recursive type. We use this wrapper to break the recursion.
fn wrapper<R>(
    pid: Pid,
    executor: Rc<SingleThreadedRuntime<R>>,
    tracer: impl Tracer + 'static,
    current_clock: ProcessClock,
) where
    R: Reactor + 'static,
{
    let f = run_process(pid, executor.clone(), tracer, current_clock);
    executor.add_future(Task::new(f, pid));
}
