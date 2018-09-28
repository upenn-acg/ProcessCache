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
    // Assumption: at any given time only one entry for any tid/pid
    // is being waited for by a coroutine. The HashMap enforces this
    // naturally, TODO
    let mut waiting_coroutines: HashMap<Pid, (Actions, Coroutine)> = HashMap::new();

    // Keep track of all live processes, when none are left, we know that the program
    // is done running.
    let mut live_processes: HashSet<Pid> = HashSet::new();

    // A single continue variable isn't enough, we could receive events from any live
    // process, so we must know which one to use, per proc.
    let mut proc_continue_event: HashMap<Pid, ContinueEvent> = HashMap::new();
    proc_continue_event.insert(first_proc, ContinueEvent::Continue);

    live_processes.insert(first_proc);

    loop {
        let (current_pid, new_action) = get_next_action();
        // Get this procs continue event, as a mutable borrow for us to change.
        let mut continue_type = *proc_continue_event.get(& current_pid).unwrap();

        // Handle signals here, just insert them back to the process.
        if let Action::Signal(signal) = new_action {
            debug!("Calling ptrace_sycall with {:?}", continue_type);
            ptrace_syscall(current_pid, continue_type, None)?;
            continue;
        }
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

                // Check if we should add this process to the live processes!
                for action in &waiting_on {
                    if let Action::AddNewProcess(new_proc) = action {

                        if cfg!(debug_assertions){
                            if live_processes.contains(& new_proc) {
                                panic!("new process pid was already in live_processes.");
                            }
                        }

                        live_processes.insert(*new_proc);
                        proc_continue_event.insert(*new_proc, ContinueEvent::Continue);
                        break;
                    }
                }

                // This coroutine doesn't live long enough, to even need another loop.
                // It has done it's part.
                if ! waiting_on.contains(& Action::Done) {
                    debug!("Waiting for actions: {:?}", waiting_on);
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
                    println!("{:?}", entry);
                    panic!("[{}]Existing coroutine was not expecting action: {:?}",
                           current_pid, new_action);
                }

                // Found it! Run coroutine until it yields;
                let new_waiting_on: Actions = entry.get_mut().1.send(new_action);

                if new_waiting_on.contains(& Action::ProcessExited) {
                    info!("Process {} has exited.", current_pid);
                    // Remove process forever.
                    if ! live_processes.remove(& current_pid) {
                        panic!("Cannot remove entry live_process. No such pid {}", current_pid);
                    }
                    // No more processes exit, program.
                    if live_processes.is_empty() {
                        info!("Whole program done!");
                        break;
                    }else {
                        // Skip calling ptrace_sycall at the bottom of this loop,
                        // this program has already exited.
                        debug!("Skipping ptrace_continue.");
                        continue;
                    }
                }

                // If this coroutine is done, erase it.
                if new_waiting_on.contains(& Action::Done) {
                    debug!("Coroutine done, dropping it.");
                    entry.remove_entry();
                }

                debug!("Waiting for actions: {:?}", new_waiting_on);
            }
        }; // end of match

        // TODO support signals!
        debug!("Calling ptrace_sycall with {:?}", continue_type);
        ptrace_syscall(current_pid, continue_type, None).
            expect( &format!("Failed to call ptrace on pid {}.", current_pid));
        // Reset to default.
        *proc_continue_event.get_mut(& current_pid).unwrap() = ContinueEvent::Continue;
    } // end of loop

    Ok(())
}



/// TODO
pub fn get_next_action() -> (Pid, Action) {
    use nix::sys::wait::WaitStatus::*;

    match waitpid(None, None).expect("Failed to waitpid.") {
        PtraceEvent(pid,_, status)
            if PTRACE_EVENT_EXEC as i32 == status => {
                info!("[{}] Saw exec event.", pid);
                return (pid, Action::Execve);
            }

        // This is the stop before the final, from here we know we will receive an
        // actual exit.
        PtraceEvent(pid, _, status)
            if PTRACE_EVENT_EXIT as i32 == status => {
                info!("[{}] Saw ptrace exit event.", pid);
                return (pid, Action::EventExit)
            }

        PtraceEvent(pid,_, status)
            if PTRACE_EVENT_SECCOMP as i32 == status => {
                debug!("[{}] Saw seccomp event.", pid);
                return (pid, Action::Seccomp);
            }

        PtraceSyscall(pid) => {
            debug!("[{}] Saw post hook event.", pid);
            return (pid, Action::PostHook);
        }

        Exited(pid, _) => {
            debug!("[{}] Saw actual exit.", pid);
            return (pid, Action::ActualExit)
        }

        // Received a signal event.
        Stopped(pid, signal) => {
            info!("[{}] Received signal event {:?}", pid, signal);
            return (pid, Action::Signal(signal))
        }
        s => {
            // Notice we should never see a fork event. Since we handle that directly
            // from the fork handler function.
            panic!("Unhandled case for get_action_pid(): {:?}", s);
        }
    }
}

//             // Our process has been killed by signal
//             Signaled(pid, signal, _) => {
//                 info!("[{}] Our process has been killed by signal {:?}", pid, signal);
//                 break;
//             }

fn empty_coroutine(regs: Regs<Unmodified>, pid: Pid, mut y: Yielder) {
    let regs = Regs::get_regs(pid);
    let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];
    info!("empty_handler: [{}] {}", pid, name);
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
            debug!("New event handler for seccomp.");

            let regs = Regs::get_regs(pid);
            let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];

            match name {
                "execve" => return make_handler!(handle_execve, regs, pid),
                "fork" | "vfork" | "clone" => return make_handler!(handle_fork, pid),
                _ => return make_handler!(empty_coroutine, regs, pid),
            }

        }
        Action::EventExit => {
            debug!("New handler for exit event");
            let regs = Regs::get_regs(pid);
            return make_handler!(handle_exit);
        }
        _ => panic!("get_coroutine: unexpected action: {:?}", action),
    };
}
