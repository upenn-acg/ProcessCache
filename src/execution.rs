use crate::system_call_names::SYSTEM_CALL_NAMES;

use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::tracer::TraceEvent;
use crate::tracer::Tracer;
use nix::unistd::Pid;
use single_threaded_runtime::task::Task;
use single_threaded_runtime::Reactor;
use single_threaded_runtime::SingleThreadedRuntime;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::clocks::ProcessClock;

use tracing::{debug, info, span, Level};

thread_local! {
    pub static EXITED_CLOCKS: RefCell<HashMap<Pid, ProcessClock>> =
        RefCell::new(HashMap::new());
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
                if name == "execve" || name == "exit_group" || name == "clone" {
                    debug!("continuing to next event..");
                    continue;
                }

                match name {
                    "write" => {
                        handle_write_syscall(pid, regs, &process_clock);
                    }
                    "read" => {
                        handle_read_syscall();
                    }
                    _ => (),
                }

                let regs: Regs<Unmodified> = tracer.posthook().await;

                // In posthook.
                let retval = regs.retval() as i32;
                let posthook_span = span!(Level::INFO, "posthook", retval);
                let _penter = posthook_span.enter();
                let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];

                debug!("in posthook");
                #[allow(clippy::single_match)]
                match name {
                    "wait4" => {
                        handle_wait4_syscall(&regs, &mut process_clock);
                    }
                    _ => (),
                }
            }

            TraceEvent::Fork(pid) | TraceEvent::VFork(pid) | TraceEvent::Clone(pid) => {
                debug!("Fork Event from pid {}!", pid);
                let child = Pid::from_raw(tracer.get_event_message() as i32);

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

    // We only get here via a PreExit where we break out of the loop.
    // TODO should probably break on some signal events as well.

    // Put this process's logical clock in the global map of
    // process clocks. This child won't need its clock no 'mo.
    EXITED_CLOCKS.with(|exited_clocks| {
        if exited_clocks
            .borrow_mut()
            .insert(pid, process_clock)
            .is_some()
        {
            // This should never happen.
            panic!("EXITED_CLOCKS already had an entry for this PID");
        }
    });

    // Saw pre-exit event, wait for final exit event.
    match tracer.get_next_event().await {
        TraceEvent::ProcessExited(pid) => {
            debug!("Saw actual exit event for pid {}", pid);
        }
        e => panic!("Saw other event when expecting ProcessExited event: {:?}", e),
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

fn handle_write_syscall(
    pid: Pid,
    regs: Regs<Unmodified>,
    process_clock: &ProcessClock,
    /*resource_clock: &ResourceClock*/
) {
    let span = span!(Level::INFO, "handle_write_syscall()");
    let _enter = span.enter();

    let fd = regs.arg1() as u64;
    if fd != 1 {
        let _time = process_clock.get_current_time(pid);

        // let rc: ResourceClock = ResourceClock {
        //     read_clock: HashMap::new(),
        //     write_clock: (pid, *time),
        // };
        // let mut rcs_borrow = resource_clocks.borrow_mut();

        // if rcs_borrow.contains_key(&fd) {
        //     println!("Updating write clock for fd: {}", fd);
        //     println!("Write clock --> Pid: {}, Time: {:?}", pid, time);
        // } else {
        //     println!("Adding write clock for fd: {}", fd);
        //     println!("Write clock --> Pid: {} , Time: {:?}", pid, time);
        // }

        // let clock = rcs_borrow.entry(fd).or_insert(rc);
        // let ResourceClock {
        //     read_clock: _read_c,
        //     write_clock: write_c,
        // } = clock;
        // let (p, t) = write_c;
        // *p = pid;
        // *t = *time;
    }
}

fn handle_read_syscall() {
    // let fd = regs.arg1() as u64;
    // if fd != 1 {
    //     let pcs_borrow = process_clocks.borrow();
    //     let time = pcs_borrow.get(&pid).unwrap().get(&pid).unwrap();

    //     let mut new_read_clock: HashMap<Pid, _> = HashMap::new();
    //     new_read_clock.insert(pid, *time);
    //     // If we are making a new clock, because this is the first
    //     // time the resource is being accessed, just a dummy write clock.
    //     let new_write_clock = (Pid::from_raw(0 as i32), LogicalTime::new());
    //     let rc: ResourceClock = ResourceClock {
    //         read_clock: new_read_clock,
    //         write_clock: new_write_clock,
    //     };
    //     let mut rc_borrow = resource_clocks.borrow_mut();
    //     let clock = rc_borrow.entry(fd).or_insert(rc);
    //     let ResourceClock {
    //         read_clock: read_c,
    //         write_clock: _write_c,
    //     } = clock;
    //     read_c.insert(pid, *time);

    //     if rc_borrow.contains_key(&fd) {
    //         println!("Updating read clock for fd: {}", fd);
    //         println!("Read clock --> Pid: {}, Time: {:?}", pid, time);
    //     } else {
    //         println!("Adding read clock for fd: {}", fd);
    //         println!("Read clock --> Pid: {}, Time: {:?}", pid, *time);
    //     }
    // }
}

fn handle_wait4_syscall(regs: &Regs<Unmodified>, process_clock: &mut ProcessClock) {
    let p = regs.retval() as i32;
    if p != -1 {
        let child: Pid = Pid::from_raw(p);
        // This might happen because of a data race?
        let child_clock = EXITED_CLOCKS.with(|exited_clock| {
            exited_clock.borrow_mut().remove(&child).expect(
                "Child was reported as exited, \
                        but no entry for it found in EXITED_CLOCKS.",
            )
        });

        // Update our times based on any newer times that our child might have.
        for (process, other_time) in child_clock {
            match process_clock.get_current_time(process) {
                Some(our_time) => {
                    if other_time > our_time {
                        process_clock.update_entry(process, other_time);
                    }
                }
                None => {
                    process_clock.update_entry(process, other_time);
                }
            }
        }
    }
}
