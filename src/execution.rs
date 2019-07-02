use crate::system_call_names::SYSTEM_CALL_NAMES;

use nix::sys::wait::*;
use nix::unistd::*;

use crate::ptrace_event::AsyncPtrace;
use libc::{c_char};
use nix;
use nix::sys::ptrace::Event::*;

use std::collections::{HashMap};
use std::sync::{Arc, Mutex};

use crate::ptracer::*;
use crate::executor::WaitidExecutor;

use nix::sys::wait::WaitStatus::PtraceSyscall;

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

        Execution {proc_continue_event}
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

pub struct ResourceClock {
    read_clock: HashMap<Pid, u64>,
    write_clock: (Pid, u64),
}

pub async fn posthook(pid: Pid) -> Regs<Unmodified> {
    let event = AsyncPtrace { pid };
    debug!("waiting for posthook event");

    ptrace_syscall(pid, ContinueEvent::SystemCall, None).
    // Might want to switch this to return the error instead of failing.
        expect("ptrace syscall failed.");
    match event.await {
        PtraceSyscall(_) =>  {
            debug!("got posthook event");
            // refetch regs.
            return Regs::get_regs(pid);
        }
        e =>  panic!(format!("Unexpected {:?} event, expected posthook!", e)),
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
  
    loop {
        match ptrace_syscall(pid, ContinueEvent::Continue, None) {
           Err(_e) => continue,
           Ok(_v) => break,
        }
    }
    let event = AsyncPtrace { pid };
    event.await
}

pub async fn run_process(pid: Pid, 
                         handle: WaitidExecutor, 
                         resource_clocks: Arc<Mutex<HashMap<u64, ResourceClock>>>,
                         process_clocks: Arc<Mutex<HashMap<Pid, HashMap<Pid, u64>>>>,
                         parent_pid: Pid) -> () {
    debug!("Starting to run process");
    use nix::sys::wait::WaitStatus::*;

    let process_clocks = Arc::clone(&process_clocks);
    {
        let mut process_clocks = process_clocks.lock().unwrap();
        let mut new_clock: HashMap<Pid, u64> = HashMap::new();
        if parent_pid != Pid::from_raw(0 as i32) {
            let parent_map = process_clocks.get(&parent_pid).unwrap();
            for (process, time) in parent_map.iter() {
                new_clock.insert(*process, *time);
            }
        }
        new_clock.insert(pid, 1);
        process_clocks.insert(pid, new_clock);
    }
    //     let mut signal_to_inject: Option<Signal> = None;
    //     let mut ptrace_next_action = DoContinueEvent;
    loop {
        match next_ptrace_event(pid).await {
            PtraceEvent(pid,_, status)
                if PTRACE_EVENT_EXEC as i32 == status => {
                    debug!("[{}] Saw exec event.", pid);
                }

            // This is the stop before the final, from here we know we will receive an
            // actual exit.
            PtraceEvent(pid, _, status)
                if PTRACE_EVENT_EXIT as i32 == status => {
                    debug!("[{}] Saw ptrace exit event.", pid);
                }

            PtraceEvent(pid,_, status)
                if PTRACE_EVENT_SECCOMP as i32 == status => {
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

                    // TODO: This should probably be broken out into functions.
                    match name {
                        "write" => { 
                            let resource_clocks = Arc::clone(&resource_clocks);
                            let process_clocks = Arc::clone(&process_clocks);
                            let fd = regs.arg1() as u64;
                            if fd != 1 {
                                let mut resource_clocks = resource_clocks.lock().unwrap();
                                let process_clocks = process_clocks.lock().unwrap();
                                let time = process_clocks.get(&pid).unwrap().get(&pid).unwrap();
                                let new_read_clock: HashMap<Pid, u64> = HashMap::new();
                                let new_write_clock = (pid, *time);
                                let rc: ResourceClock = ResourceClock {
                                    read_clock: new_read_clock,
                                    write_clock: new_write_clock,
                                };
                                if resource_clocks.contains_key(&fd) {
                                    println!("Updating write clock for fd: {}", fd);
                                    println!("Write clock --> Pid: {}, Time: {}", pid, time);
                                } else {
                                    println!("Adding write clock for fd: {}", fd);
                                    println!("Write clock --> Pid: {} , Time: {}", pid, time);
                                }
                                let clock = resource_clocks.entry(fd).or_insert(rc);
                                let ResourceClock { 
                                    read_clock: _read_c, 
                                    write_clock: write_c } = clock;
                                let (p, t) = write_c;
                                *p = pid;
                                *t = *time;
                            }
                        }
                        "read" => {
                            let resource_clocks = Arc::clone(&resource_clocks);
                            let process_clocks = Arc::clone(&process_clocks);
                            let fd = regs.arg1() as u64;
                            if fd != 1 {
                                let mut resource_clocks = resource_clocks.lock().unwrap();
                                let process_clocks = process_clocks.lock().unwrap();
                                let time = process_clocks.get(&pid).unwrap().get(&pid).unwrap();
                                
                                let mut new_read_clock: HashMap<Pid, u64> = HashMap::new();
                                new_read_clock.insert(pid, *time);
                                // If we are making a new clock, because this is the first 
                                // time the resource is being accessed, just a dummy write clock.
                                let new_write_clock = (Pid::from_raw(0 as i32), 0);
                                let rc: ResourceClock = ResourceClock {
                                    read_clock: new_read_clock,
                                    write_clock: new_write_clock,
                                };
                                let clock = resource_clocks.entry(fd).or_insert(rc);
                                let ResourceClock {
                                    read_clock: read_c,
                                    write_clock: _write_c } = clock;
                                read_c.insert(pid, *time);

                                if resource_clocks.contains_key(&fd) {
                                    println!("Updating read clock for fd: {}", fd);
                                    println!("Read clock --> Pid: {}, Time: {}", pid, *time);
                                } else {
                                    println!("Adding read clock for fd: {}", fd);
                                    println!("Read clock --> Pid: {}, Time: {}", pid, *time);
                                }
                            }
                        }
                        _ => (),
                    }

                    let regs = posthook(pid).await;

                    let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];
                    match name {
                        "wait4" => {
                            let process_clocks = Arc::clone(&process_clocks);
                            match regs.retval() as i32 {
                                -1 => (),
                                p => {
                                    let mut process_clocks = process_clocks.lock().unwrap();
                                    let exited_child = Pid::from_raw(p);
                                    let child_map = process_clocks.get(&exited_child).unwrap();
                                    let old_map = process_clocks.get(&pid).unwrap();
                                    let mut new_map: HashMap<Pid, u64> = HashMap::new();
                                    for (process, time) in child_map.iter() {
                                        let my_time = match old_map.get(&process) {
                                                        Some(t) => t,
                                                        None => &0,
                                                    };
                                        match my_time < time {
                                            true => {
                                                new_map.insert(*process, *time);
                                            }
                                            false => (),
                                        }
                                    }
                                    process_clocks.insert(pid, new_map);
                                }
                            }
                        }
                        _ => (),
                    }
                    // In posthook.
                    info!("[{}] return value = {}", pid, regs.retval() as i32);
                }

            PtraceEvent(pid, _, status)
                if PTRACE_EVENT_FORK as i32 == status ||
                PTRACE_EVENT_CLONE as i32 == status ||
                PTRACE_EVENT_VFORK as i32 == status => {
                    debug!("[{}] Saw forking event!", pid);
                    let child = Pid::from_raw(ptrace_getevent(pid) as i32);
                    let resource_clocks = Arc::clone(&resource_clocks);
                    let p_clocks = Arc::clone(&process_clocks);
                    // we end up with a weird circular dependency for our types if we
                    // tried to call this directly so we have to wrap it and call it from
                    // this wrapper.
                    fn wrapper(pid: Pid, 
                               handle: WaitidExecutor,
                               resource_clocks: Arc<Mutex<HashMap<u64, ResourceClock>>>,
                               p_clocks: Arc<Mutex<HashMap<Pid, HashMap<Pid, u64>>>>,
                               parent_pid: Pid) {

                        // Recursively call run process to handle the new child process!
                        handle.add_future(run_process(pid, handle.clone(), resource_clocks, p_clocks, parent_pid), pid);
                    }
                    wrapper(child, handle.clone(), resource_clocks, p_clocks, pid);

                    // Increment the parent's clock upon fork.
                    let process_arc = Arc::clone(&process_clocks);
                    {
                        let mut process_mutex = process_arc.lock().unwrap();
                        let new_parent: HashMap<Pid, u64> = HashMap::new();
                        let parent_time = process_mutex.entry(pid)
                                                       .or_insert(new_parent)
                                                       .entry(pid)
                                                       .or_insert(0);
                        *parent_time += 1;
                        process_mutex.get_mut(&pid).unwrap().insert(child, 0);
                    }

                    //*process_mutex.get_mut(&pid).unwrap().get_mut(&pid).unwrap() += 1;
                    //let mut parent_clock = process_mutex.get_mut(&pid).unwrap();
                    //parent_clock.insert(child, 0);

                }

            PtraceSyscall(pid) => {
                debug!("[{}] Saw post hook event.", pid);
                debug!("Probably a failed execve...");
            }

            Exited(pid, _) => {
                debug!("[{}] Saw actual exit event", pid);
                break;
            }

            // Received a signal event.
            Stopped(pid, signal) => {
                debug!("[{}] Received signal event {:?}", pid, signal);

            }

            Signaled(pid, signal, _) => {
                debug!("[{}] Process killed by singal: {:?}", pid, signal);

            }

            s => {
                panic!("Unhandled case for get_action_pid(): {:?}", s);
            }
        }
    }
}

pub fn run_program(first_proc: Pid) -> nix::Result<()> {
    debug!("Running whole program");
    let event = AsyncPtrace { pid: first_proc };
    let mut pool = WaitidExecutor::new();

    let resource_map: HashMap<u64, ResourceClock> = HashMap::new();
    let resource_clocks = Arc::new(Mutex::new(resource_map));

    let process_map: HashMap<Pid, HashMap<Pid, u64>> = HashMap::new();
    let process_clocks = Arc::new(Mutex::new(process_map));

    // Wait for child to be ready.
    pool.add_future(async { event.await; }, first_proc);
    pool.run_all();
    debug!("Child returned ready!");

    // Child ready!
    ptrace_set_options(first_proc)?;
    
    let p_clocks = Arc::clone(&process_clocks);
    let resource_clocks = Arc::clone(&resource_clocks);
    let no_parent = Pid::from_raw(0 as i32);
    pool.add_future(run_process(first_proc, pool.clone(), resource_clocks, p_clocks, no_parent), first_proc);
    pool.run_all();

    let proc_clocks = Arc::clone(&process_clocks);
    let process_clocks_mutex = proc_clocks.lock().unwrap();
    for (pid, clock) in process_clocks_mutex.iter() {
        println!("Process clock for: {}", pid);
        for (p, t) in clock.iter() {
            println!("Pid: {}, Time: {}", p, t);
        }
    }
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

async fn handle_getcwd(pid: Pid){
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
