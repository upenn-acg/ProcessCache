use system_call_names::SYSTEM_CALL_NAMES;

use nix::sys::wait::*;
use nix::unistd::*;

use libc::{c_char};
use nix;
use nix::sys::ptrace::Event::*;

use log::Level;
use generator::Gn;

use std::collections::HashSet;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use ptracer::*;
use coroutines::{Yielder, Coroutine};
use actions::*;
use handlers::*;

pub fn run_program(first_proc: Pid) -> nix::Result<()> {
    // Wait for child to be ready.
    let _s: WaitStatus = waitpid(first_proc, None)?;

    // Child ready!
    ptrace_set_options(first_proc)?;

    ptrace_syscall(first_proc, ContinueEvent::Continue , None).
        expect(&format!("Failed to intial ptrace on first_proc {}.", first_proc));

    // Map which keeps track of what action each pid is waiting for.
    let mut waiting_coroutines: HashMap<Pid, (Actions, Coroutine)> = HashMap::new();

    // Keep track of all live processes, when none are left, we know that the program
    // is done running.
    // While a hashset is nice for being able to print the processes, and see their pids,
    // it is a bit heavyweight. It would make just as much sense to have a single i32,
    // to keep track of the number of live processes. TODO?
    let mut live_processes: HashSet<Pid> = HashSet::new();

    // A single continue variable isn't enough, we could receive events from any live
    // process, so we must know which one to use, per proc.
    let mut proc_continue_event: HashMap<Pid, ContinueEvent> = HashMap::new();
    proc_continue_event.insert(first_proc, ContinueEvent::Continue);

    live_processes.insert(first_proc);

    loop {
        let (current_pid, new_action) = get_next_action();

        // Handle death by signal
        if let Action::KilledBySignal(signal) = new_action {
            handle_process_exit(current_pid, &mut live_processes, &mut proc_continue_event);
            waiting_coroutines.remove(& current_pid);

            continue;
        }

        // Handle fork!
        if let Action::Fork = new_action {
            debug!("[{}] fork event!", current_pid);

            // We don't handle the child at all here. We wait for it's signal event
            // to come, we will know it's "it" since it will be the first time we ever
            // see it's pid with a STOPPED signal.
            if log_enabled!(Level::Debug) {
                let child = Pid::from_raw(ptrace_getevent(current_pid) as i32);
                debug!("New child with pid: {}", child);
            }

             // TODO this is hardcoded! This is bad! FIX
            ptrace_syscall(current_pid, ContinueEvent::SystemCall, None).
                expect("parent failed to continue...");
             continue;
        }

        // Handle signals!
        // Just insert them back to the process.
        if let Action::Signal(signal) = new_action {
            // TODO Refactor.

            // This is a new child spawned by a fork event! This is the first time we're
            // seeing it as a STOPPED event. Add it to our records.
            // NOTE: We want to ignore this signal! This is not something that should
            // be propegated down to the process, it is only for US (the tracer).
            if ! live_processes.contains(& current_pid){
                info!("New child is registered and it's STOPPED signal captured.");
                live_processes.insert(current_pid);
                proc_continue_event.insert(current_pid, ContinueEvent::Continue);
                ptrace_syscall(current_pid, ContinueEvent::Continue, None)
                    .expect("Failed to continue new child process.");
                continue;
            }
            let continue_type = *proc_continue_event.get(& current_pid).unwrap();

            ptrace_syscall(current_pid, continue_type, Some(signal))
                .expect("Failed to continue process with signal event.");

            // Explicitly go back to the top!
            continue;
        }

        if let Action::EventExit = new_action {
            if let Entry::Occupied(e) = waiting_coroutines.entry(current_pid){
                // This is probably happening inside a thread where the thread is
                // is saying is being exited due to an exit_group.
                trace!("An coroutine was already waiting for event!  \
                        Probably a post-hook, instead we saw an exit event.");

                // Remove the exiting entry. This way, the vacant branch below will
                // generate a new coroutine
                trace!("Removing coroutine for {}, sorry, it's time to exit!",
                       current_pid);
                e.remove_entry();
            }

            // Let this statement fall through!
        }


        // Only exit and system call events should come down here, we explicitly handle
        // all other kinds of events:

        // Reset to default, signals need this information otherwise.
        *proc_continue_event.get_mut(& current_pid).unwrap() = ContinueEvent::Continue;

        // Let a waiting coroutine run for this event, otherwise, create a new coroutine
        // to handle this event!
        // Returns which kind of ContinueEvent to use, i.e. should we go to the post-hook?

        // TODO: At some point we will probably have this entire match return a coroutine
        // which we then run, there really shouldn't be a difference whether the corotutine
        // is new or old. This will let us combine some duplicated cases/assumptions
        // we have right now.
        match waiting_coroutines.entry(current_pid) {
            Entry::Vacant(v) => {
                // No coroutine waiting for this (current_pid, event) spawn one!
                let mut cor = new_event_handler(current_pid, new_action);

                // Run until it yields!
                let waiting_on: Actions = cor.resume().unwrap();
                let goto_posthook = waiting_on.contains(& Action::PostHook);

                // This coroutine doesn't live long enough, to even need another loop.
                // It has done it's part.
                if ! waiting_on.contains(& Action::Done) {
                    trace!("Waiting for actions: {:?}", waiting_on);
                    v.insert((waiting_on, cor));
                }

                if goto_posthook {
                    *proc_continue_event.get_mut(& current_pid).unwrap() =
                        ContinueEvent::SystemCall;
                }
            }
            Entry::Occupied(mut entry) => {
                // There was a coroutine waiting for this event. Let it run and inform it
                // what event arrived.
                // TODO: UGLY REFACTOR

                // This pid/tid was not expecting to receive this action!
                if ! entry.get().0.contains(& new_action){
                    panic!("[{}] Existing coroutine {:?} was not expecting action: {:?}",
                           current_pid, entry, new_action);
                }

                // Found it! Run coroutine until it yields;
                let new_waiting_on: Actions = entry.get_mut().1.send(new_action);

                if new_waiting_on.contains(& Action::ProcessExited) {
                    let all_done = handle_process_exit(current_pid, &mut live_processes,
                                                       &mut proc_continue_event);
                    entry.remove_entry();
                    if all_done { break; } else { continue; }
                }

                // If this coroutine is done, erase it.
                if new_waiting_on.contains(& Action::Done) {
                    trace!("Coroutine done, dropping it.");
                    entry.remove_entry();
                }

                trace!("Waiting for actions: {:?}", new_waiting_on);
            }
        }; // end of match

        // Must refetch, may change after handling seccomp event.
        let continue_type = *proc_continue_event.get(& current_pid).unwrap();
        trace!("Calling ptrace_sycall with {:?}", continue_type);

        ptrace_syscall(current_pid, continue_type, None).
            expect( &format!("Failed to call ptrace on pid {}.", current_pid));

    } // end of loop

    Ok(())
}



/// TODO
pub fn get_next_action() -> (Pid, Action) {
    use nix::sys::wait::WaitStatus::*;

    match waitpid(None, None).expect("Failed to waitpid.") {
        PtraceEvent(pid,_, status)
            if PTRACE_EVENT_EXEC as i32 == status => {
                debug!("[{}] Saw exec event.", pid);
                return (pid, Action::Execve);
            }

        // This is the stop before the final, from here we know we will receive an
        // actual exit.
        PtraceEvent(pid, _, status)
            if PTRACE_EVENT_EXIT as i32 == status => {
                debug!("[{}] Saw ptrace exit event.", pid);
                return (pid, Action::EventExit)
            }

        PtraceEvent(pid,_, status)
            if PTRACE_EVENT_SECCOMP as i32 == status => {
                trace!("[{}] Saw seccomp event.", pid);
                return (pid, Action::Seccomp);
            }

        PtraceEvent(pid, signal, status)
            if PTRACE_EVENT_FORK as i32 == status ||
            PTRACE_EVENT_CLONE as i32 == status ||
            PTRACE_EVENT_VFORK as i32 == status => {
                trace!("[{}] Saw forking event!", pid);
                return (pid, Action::Fork)
            }

        PtraceSyscall(pid) => {
            trace!("[{}] Saw post hook event.", pid);
            return (pid, Action::PostHook);
        }

        Exited(pid, _) => {
            trace!("[{}] Saw actual exit event", pid);
            return (pid, Action::ActualExit)
        }

        // Received a signal event.
        Stopped(pid, signal) => {
            debug!("[{}] Received signal event {:?}", pid, signal);
            return (pid, Action::Signal(signal))
        }

        Signaled(pid, signal, _) => {
            debug!("[{}] Process killed by singal: {:?}", pid, signal);
            return (pid, Action::KilledBySignal(signal));
        }

        s => {
            panic!("Unhandled case for get_action_pid(): {:?}", s);
        }
    }
}

/// Cleans up process from our maps. Returns whether we're all_done running our tracer.
/// this is the case when the live_process map is empty.
fn handle_process_exit(pid: Pid,
                       live_processes: &mut HashSet<Pid>,
                       proc_continue_event: &mut HashMap<Pid, ContinueEvent>) -> bool {
    debug!("Process {} has exited.", pid);

    // Remove process forever.
    if ! live_processes.remove(& pid) {
        panic!("Cannot remove entry live_process. No such pid {}", pid);
    }
    if proc_continue_event.remove(& pid) == None {
        panic!("Cannot remove entry proc_continue_event. \
                No such pid {}", pid);
    }

    // No more processes exit, program.
    if live_processes.is_empty() {
        debug!("Whole program done!");
        return true;
    }else {
        trace!("Live processes: {:?}", live_processes);
        // Skip calling ptrace_sycall at the bottom of this loop,
        // this program has already exited.
        trace!("Skipping exited process' ptrace_continue.");
        return false;
    }
}

fn empty_coroutine(regs: Regs<Unmodified>, pid: Pid, mut y: Yielder) {
}


fn print_coroutine(regs: Regs<Unmodified>, pid: Pid, mut y: Yielder) {
    let regs = Regs::get_regs(pid);
    let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];
    info!("[{}] {}", pid, name);
    let regs = await_posthook(regs.same(), pid, y);
    trace!("in post hook :)");
    info!("[{}] return value = {}", pid, regs.retval() as i32);
}

fn handle_getcwd(regs: Regs<Unmodified>, pid: Pid, mut y: Yielder){
    // Pre-hook
    let regs = await_posthook(regs.same(), pid, y);

    // Post-hook
    let buf = regs.arg1() as *const c_char;
    let length = regs.arg1() as isize;
    let cwd = read_string(buf, pid);
    info!("cwd({}, {})", cwd, length);
}

/// Wait for post-hook even to arrive.
/// Returns the new register state after the post-hook event.
fn await_posthook(regs: Regs<Flushed>, pid: Pid,
                  mut y: Yielder) -> Regs<Unmodified> {
    // Blocks until event arrives.
    let actions = new_actions(& [Action::PostHook]);
    y.yield_with(actions);
    // new_regs
    Regs::get_regs(pid)
}

/// Return the coroutine which will handle this event!
pub fn new_event_handler<'a>(pid: Pid, action: Action) -> Coroutine<'a> {
    match action {
        // Basically a pre-hook event.
        Action::Seccomp => {
            trace!("New event handler for seccomp.");

            let regs = Regs::get_regs(pid);
            let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];

            match name {
                "execve" => return make_handler!(handle_execve, regs, pid),
                "exit" | "exit_group" => {
                    return make_handler!(empty_coroutine, regs, pid);
                }
                _ => {
                    return make_handler!(print_coroutine, regs, pid);
                }
            }
        }
        Action::EventExit => {
            trace!("New handler for exit event");
            let regs = Regs::get_regs(pid); 
            return make_handler!(handle_exit);
        }
        _ => panic!("get_coroutine: unexpected action: {:?}", action),
    };
}
