use crate::system_call_names::SYSTEM_CALL_NAMES;
use std::cell::RefCell;
// use nix::sys::wait::*;
use crate::ptracer::ptrace_syscall;
use crate::ptracer::Unmodified;
use libc::c_char;
use nix;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::rc::Rc;
use wait_executor::ptrace_event::AsyncPtrace;
use wait_executor::ptrace_event::PtraceReactor;
use wait_executor::task::Task;
// use crate::ptracer::*;
use crate::ptracer::ptrace_getevent;
use crate::ptracer::ptrace_set_options;
use crate::ptracer::read_string;
use crate::ptracer::ContinueEvent;
use crate::ptracer::PtraceEvent;
use crate::ptracer::Regs;
use nix::sys::wait::WaitStatus;
use wait_executor::WaitidExecutor;

thread_local! {
    pub static EXITED_CLOCKS: RefCell<HashMap<Pid, ProcessClock>> =
        RefCell::new(HashMap::new());
}

enum PtraceNextStep {
    SkipCurrentPid,
    DoContinueEvent,
    EndProgram,
}

struct Execution {
    // A single continue variable isn't enough, we could receive events from any live
    // process, so we must know which one to use, per proc.
    proc_continue_event: HashMap<Pid, ContinueEvent>,
}

impl Execution {
    fn new(starting_pid: Pid) -> Execution {
        let mut proc_continue_event = HashMap::new();
        proc_continue_event.insert(starting_pid, ContinueEvent::Continue);

        Execution {
            proc_continue_event,
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
}
#[derive(Debug, PartialOrd, PartialEq, Clone, Copy)]
pub struct LogicalTime(u64);

impl LogicalTime {
    fn new() -> LogicalTime {
        LogicalTime(0)
    }

    fn increment(&mut self) {
        self.0 = self.0 + 1;
    }
}

#[derive(Clone)]
pub struct ProcessClock {
    clock: HashMap<Pid, LogicalTime>,
    our_pid: Pid,
}

impl ProcessClock {
    fn get_current_time(&self, pid: &Pid) -> Option<LogicalTime> {
        self.clock.get(pid).cloned()
    }

    fn add_new_process(&mut self, pid: &Pid) {
        self.clock.insert(*pid, LogicalTime::new());
    }

    fn new(pid: Pid) -> ProcessClock {
        ProcessClock { clock: HashMap::new(), our_pid: pid }
    }

    fn update_entry(&mut self, pid: &Pid, new_time: LogicalTime) {
        let time = self.clock.get_mut(pid).expect("No such entry to update.");
        *time = new_time;
    }

    fn increment_time(&mut self, pid: &Pid) {
        let time = self.clock.get_mut(pid).
            expect("increment_time: Requested time not found.");
        time.increment();
    }

    fn increment_own_time(&mut self) {
        let pid = self.our_pid;
        self.increment_time(&pid);
    }

    fn iter(self) -> std::collections::hash_map::IntoIter<Pid, LogicalTime> {
        self.clock.into_iter()
    }
}

// use std::collections::hash_map::Iter;
// impl IntoIterator for ProcessClock {
//     type item = (Pid, LogicalTime);
//     type IntoIterator = Iter<'a, Pid, LogicalTime>;
// }

pub struct ResourceClock {
    read_clock: HashMap<Pid, LogicalTime>,
    write_clock: (Pid, LogicalTime),
}

/// Wait until posthook event comes from specified Pid.
pub async fn posthook(pid: Pid) -> Regs<Unmodified> {
    let event = AsyncPtrace { pid };
    debug!("waiting for posthook event");

    ptrace_syscall(pid, ContinueEvent::SystemCall, None).
    // Might want to switch this to return the error instead of failing.
        expect("ptrace syscall failed.");
    match event.await {
        WaitStatus::PtraceSyscall(_) => {
            debug!("got posthook event");
            // refetch regs.
            return Regs::get_regs(pid);
        }
        e => panic!(format!("Unexpected {:?} event, expected posthook!", e)),
    };
}

// Todo extend with signals.
pub async fn next_ptrace_event(pid: Pid) -> WaitStatus {
    trace!("Waiting for next ptrace event.");

    // This cannot be a posthook event. Those are explicitly caught in the
    // seccomp handler.
    //ptrace_syscall(pid, ContinueEvent::Continue, None).
    // Might want to switch this to return the error instead of failing.
    //expect("ptrace continue failed.");

    // TODO Kelly Why are we looping here.
    loop {
        match ptrace_syscall(pid, ContinueEvent::Continue, None) {
            Err(_e) => continue,
            Ok(_v) => break,
        }
    }

    // Wait for ptrace event from this pid here.
    AsyncPtrace{ pid }.await.into()
}

/// It would seem that &RefCell would be enough. Rc<RefCell<_>> is needed to
/// convice Rust that the clocks will live long  enough, otherwise we run into
/// lifetime issues.
pub async fn run_process(
    pid: Pid,
    handle: WaitidExecutor<PtraceReactor>,
    mut current_clock: ProcessClock,
) {
    debug!("Starting to run process");

    current_clock.add_new_process(&pid);
    let mut process_clock = current_clock;

    loop {
        match next_ptrace_event(pid).await.into() {
            PtraceEvent::Exec(pid) => {
                debug!("[{}] Saw exec event.", pid);
            }
            PtraceEvent::PreExit(pid) => {
                debug!("[{}] Saw ptrace exit event.", pid);
                break;
            }
            PtraceEvent::Prehook(pid) => {
                debug!("[{}] Saw seccomp event.", pid);
                let regs = Regs::get_regs(pid);
                let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];

                info!("[{}] Intercepted: {}", pid, name);

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

                let regs = posthook(pid).await;
                // In posthook.

                let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];
                match name {
                    "wait4" => {
                        handle_wait4_syscall(pid, &regs, &mut process_clock);
                    }
                    _ => (),
                }

                info!("[{}] return value = {}", pid, regs.retval() as i32);
            }

            PtraceEvent::Fork(pid) | PtraceEvent::VFork(pid) | PtraceEvent::Clone(pid) => {
                debug!("[{}] Saw forking event!", pid);
                let child = Pid::from_raw(ptrace_getevent(pid) as i32);

                // Recursively call run process to handle the new child process!
                wrapper(
                    child,
                    &handle,
                    process_clock.clone(),
                );

                // Start of a new epoch, increment the parent's clock upon fork.
                process_clock.increment_own_time();
            }

            PtraceEvent::Posthook(pid) => {
                debug!("[{}] Saw post hook event.", pid);
                debug!("Probably a failed execve...");
            }

            // Received a signal event.
            PtraceEvent::ReceivedSignal(pid, signal) => {
                debug!("[{}] Received signal event {:?}", pid, signal);
            }

            PtraceEvent::KilledBySignal(pid, signal) => {
                debug!("[{}] Process killed by singal: {:?}", pid, signal);
            }
            PtraceEvent::ProcessExited(pid) => {
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
        if let Some(_) = exited_clocks.borrow_mut().insert(pid, process_clock) {
            // This should never happen.
            panic!("EXITED_CLOCKS already had an entry for this PID");
        }
    });

    // Saw pre-exit event, wait for final exit event.
    match next_ptrace_event(pid).await.into() {
        PtraceEvent::ProcessExited(pid) => {
            debug!("[{}] Saw actual exit event", pid);
        }
        _ => panic!("Saw other event when expecting ProcessExited event"),
    }
}

pub fn run_program(first_proc: Pid) -> nix::Result<()> {
    debug!("Running whole program");

    let event = AsyncPtrace { pid: first_proc };
    let reactor = PtraceReactor::new();
    let mut executor = WaitidExecutor::new(reactor);

    // let resource_map: HashMap<u64, ResourceClock> = HashMap::new();
    // let resource_clocks = Rc::new(RefCell::new(resource_map));

    // Wait for child to be ready.
    executor.add_future(Task::new(
        async {
            event.await;
        },
        first_proc,
    ));
    executor.run_all();
    debug!("Child returned ready!");

    // Child ready!
    ptrace_set_options(first_proc)?;

    let f = run_process(
        first_proc,
        executor.clone(),
        ProcessClock::new(first_proc),
    );
    executor.add_future(Task::new(f, first_proc));
    executor.run_all();

    // Not really useful to output the process clocks in their
    // final state.
    // for (pid, clock) in process_clocks.borrow().iter() {
    //     println!("Process clock for: {}", pid);
    //     for (p, t) in clock {
    //         println!("Pid: {}, Time: {:?}", p, t);
    //     }
    // }
    //         Action::KilledBySignal(signal) => {
    //             exe.handle_process_exit(current_pid);
    //             exe.remove_waiting_coroutine(& current_pid);
    //             ptrace_next_action = SkipCurrentPid;
    //         }
    //         Action::Fork => exe.fork_event_handler(current_pid),
    //         Action::Signal(signal) => {
    //             signal_to_inject = exe.signal_event_handler(signal, current_pid);
    //         }

    Ok(())
}

async fn handle_getcwd(pid: Pid) {
    // Pre-hook

    let regs = posthook(pid).await;

    // Post-hook
    let buf = regs.arg1() as *const c_char;
    let length = regs.arg1() as isize;
    let cwd = read_string(buf, pid);
    info!("cwd({}, {})", cwd, length);
}

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
fn wrapper(
    pid: Pid,
    handle: &WaitidExecutor<PtraceReactor>,
    current_clock: ProcessClock) {
    let f = run_process(
        pid,
        handle.clone(),
        current_clock,
    );
    handle.add_future(Task::new(f, pid));
}

fn handle_write_syscall(pid: Pid,
                        regs: Regs<Unmodified>,
                        process_clock: &ProcessClock,
                        /*resource_clock: &ResourceClock*/) {
    let fd = regs.arg1() as u64;
    if fd != 1 {
        let time = process_clock.get_current_time(&pid);

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

fn handle_wait4_syscall(pid: Pid,
                        regs: &Regs<Unmodified>,
                        process_clock: &mut ProcessClock) {
    let p = regs.retval() as i32;
    if p != -1 {
        let child: Pid = Pid::from_raw(p);
        // This might happen because of a data race?
        let child_clock = EXITED_CLOCKS.with(|exited_clock| {
            exited_clock.borrow_mut().remove(&child).
                expect("Child was reported as exited, \
                        but no entry for it found in EXITED_CLOCKS.")
        });

        // Update our times based on any newer times that our child might have.
        for (process, other_time) in child_clock.iter() {
            match process_clock.get_current_time(&process) {
                Some(our_time) => {
                    if other_time > our_time {
                        process_clock.update_entry(&process, other_time);
                    }
                }
                None => {
                    process_clock.update_entry(&process, other_time);
                }
            }
        }
    }
}
