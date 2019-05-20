use system_call_names::SYSTEM_CALL_NAMES;

use nix::sys::wait::*;
use nix::unistd::*;

use libc::{c_char};
use nix;
use nix::sys::ptrace::Event::*;

use log::Level;
use generator::Gn;

use std::collections::{HashSet, HashMap, hash_map::Entry};
use nix::sys::signal::Signal;

use ptracer::*;
use coroutines::{Yielder, Coroutine};
use actions::*;
use handlers::*;

enum PtraceNextStep {
    SkipCurrentPid,
    DoContinueEvent,
    EndProgram,
}

struct Execution<'a> {
    // Map which keeps track of what action each pid is waiting for.
    waiting_coroutines: HashMap<Pid, (Actions, Coroutine<'a>)>,

    // Keep track of all live processes, when none are left, we know that the program
    // is done running.
    // While a hashset is nice for being able to print the processes, and see their pids,
    // it is a bit heavyweight. It would make just as much sense to have a single i32,
    // to keep track of the number of live processes. TODO?
    live_processes: HashSet<Pid>,

    // A single continue variable isn't enough, we could receive events from any live
    // process, so we must know which one to use, per proc.
    proc_continue_event: HashMap<Pid, ContinueEvent>,
}

impl<'a> Execution<'a> {
    fn new(starting_pid: Pid) -> Execution<'a> {
        let waiting_coroutines = HashMap::new();
        let mut live_processes = HashSet::new();
        live_processes.insert(starting_pid);

        let mut proc_continue_event = HashMap::new();
        proc_continue_event.insert(starting_pid, ContinueEvent::Continue);

        Execution {waiting_coroutines, live_processes, proc_continue_event}
    }

    fn fork_event_handler(&mut self, pid: Pid){
        debug!("[{}] fork event!", pid);

        // We don't handle the child at all here. We wait for it's signal event
        // to come, we will know it's "it" since it will be the first time we ever
        // see it's pid with a STOPPED signal.
        if log_enabled!(Level::Debug) {
            let child = Pid::from_raw(ptrace_getevent(pid) as i32);
            debug!("New child with pid: {}", child);
        }
    }

    fn signal_event_handler(&mut self, signal: Signal, pid: Pid) -> Option<Signal> {
        // This is a regular signal, inject it to the process.
        if self.live_processes.contains(& pid){
            return Some(signal);
        }

        // This is a new child spawned by a fork event! This is the first time we're
        // seeing it as a STOPPED event. Add it to our records.
        if signal == Signal::SIGSTOP {
            info!("New child is registered and it's STOPPED signal captured.");
            self.live_processes.insert(pid);
            self.proc_continue_event.insert(pid, ContinueEvent::Continue);

            // NOTE: We want to ignore this signal! This is not something that should
            // be propegated down to the process, it is only for US (the tracer).
            return None;
        }

        panic!("Uknown signal {:?} for uknown process {:?}", signal, pid);

    }

    fn handle_action(&mut self, action: Action, pid: Pid) -> PtraceNextStep {
        trace!("Handling action {:?} for pid {}", action, pid);
        // This is probably happening inside a thread where the thread is exiting
        // due to an exit_group.
        if action == Action::EventExit && self.waiting_coroutines.contains_key(& pid) {
            trace!("An coroutine was already waiting for event!  \
                    Probably a post-hook, instead we saw an exit event.");

            // Remove the exiting entry. This way, the vacant branch below will
            // generate a new coroutine
            trace!("Removing coroutine for {}, it's time to exit!", pid);
            self.waiting_coroutines.remove(& pid).unwrap();
        }

        // Reset to default. We wait until here to set it to default
        // as the events above might need the original value.
        *self.proc_continue_event.get_mut(& pid).unwrap() = ContinueEvent::Continue;

        // Let a waiting coroutine run for this event, otherwise, create a new coroutine
        // to handle this event!
        // Returns which kind of ContinueEvent to use, i.e. should we go to the post-hook?
        if ! self.waiting_coroutines.contains_key(& pid) {
            trace!("No coroutine waiting for this (pid, event). Spawning one!");
            // No coroutine waiting for this (pid, event) spawn one!
            let mut cor = new_event_handler(pid, action);

            // Run until it yields!
            let waiting_on: Actions = cor.resume().unwrap();

            if waiting_on.contains(& Action::PostHook) {
                *self.proc_continue_event.get_mut(& pid).unwrap() =
                    ContinueEvent::SystemCall;
            }

            // This coroutine doesn't live long enough, to even need another loop.
            // It has done it's part, let it drop at the bottom of this scope.
            if ! waiting_on.contains(& Action::Done) {
                trace!("Waiting for actions: {:?}", waiting_on);
                self.waiting_coroutines.insert(pid, (waiting_on, cor));
            }
        }
        // There was a coroutine waiting for this event. Let it run and inform it
        // what event arrived.
        else {
            trace!("Existing coroutine waiting for this (pid, event)!");
            // This pid/tid was not expecting to receive this action!
            if ! self.waiting_coroutines.get(&pid).unwrap().0.contains(& action){
                panic!("[{}] Existing coroutine was not expecting action: {:?}",
                       pid, action);
            }

            // Found it! Run coroutine until it yields;
            let new_waiting_on: Actions =
                self.waiting_coroutines.get_mut(&pid).unwrap().1.send(action);

            if new_waiting_on.contains(& Action::ProcessExited) {
                let all_done = self.handle_process_exit(pid);
                self.waiting_coroutines.remove_entry(& pid);
                return if all_done { EndProgram } else { SkipCurrentPid };
            }

            // If this coroutine is done, erase it.
            else if new_waiting_on.contains(& Action::Done) {
                trace!("Coroutine done, dropping it.");
                self.waiting_coroutines.remove_entry(&pid);
            }

            trace!("Waiting for actions: {:?}", new_waiting_on);
        }

        DoContinueEvent
    }



    /// Cleans up process from our maps. Returns whether we're all_done running our tracer.
    /// this is the case when the live_process map is empty.
    fn handle_process_exit(&mut self, pid: Pid) -> bool {
        debug!("Process {} has exited.", pid);

        // Remove process forever.
        if ! self.live_processes.remove(& pid) {
            panic!("Cannot remove entry live_process. No such pid {}", pid);
        }
        if self.proc_continue_event.remove(& pid) == None {
            panic!("Cannot remove entry proc_continue_event. \
                    No such pid {}", pid);
        }

        // No more processes exit, program.
        if self.live_processes.is_empty() {
            debug!("Whole program done!");
            return true;
        }else {
            trace!("Live processes: {:?}", self.live_processes);
            return false;
        }
    }

    fn get_continue_type(&self, pid: &Pid) -> ContinueEvent {
        *self.proc_continue_event.get(pid).unwrap()
    }

    fn remove_waiting_coroutine(&mut self, pid: &Pid) {
        self.waiting_coroutines.remove(& pid).unwrap();
    }
}

use self::PtraceNextStep::*;

pub fn run_program(first_proc: Pid) -> nix::Result<()> {
    // Wait for child to be ready.
    let _s: WaitStatus = waitpid(first_proc, None)?;

    // Child ready!
    ptrace_set_options(first_proc)?;

    ptrace_syscall(first_proc, ContinueEvent::Continue , None).
        expect(&format!("Failed to intial ptrace on first_proc {}.", first_proc));

    let mut exe = Execution::new(first_proc);

    loop {
        let (current_pid, new_action) = get_next_action();
        let mut signal_to_inject: Option<Signal> = None;
        let mut ptrace_next_action = DoContinueEvent;

        match new_action {
            Action::KilledBySignal(signal) => {
                exe.handle_process_exit(current_pid);
                exe.remove_waiting_coroutine(& current_pid);
                ptrace_next_action = SkipCurrentPid;
            }
            Action::Fork => exe.fork_event_handler(current_pid),
            Action::Signal(signal) => {
                signal_to_inject = exe.signal_event_handler(signal, current_pid);
            }
            _ => {
                ptrace_next_action =
                    exe.handle_action(new_action, current_pid);
            }
        }

        match ptrace_next_action {
            SkipCurrentPid => continue,
            EndProgram => break,
            DoContinueEvent => {
                // Must refetch, may change after handling seccomp event.
                let continue_type = exe.get_continue_type(& current_pid);
                trace!("Calling ptrace_sycall with {:?}", continue_type);

                ptrace_syscall(current_pid, continue_type, signal_to_inject).
                    expect( &format!("Failed to call ptrace on pid {}.", current_pid));
            }
        }
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
fn await_posthook(regs: Regs<Flushed>, pid: Pid, mut y: Yielder) -> Regs<Unmodified> {
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
        _ => panic!("new_event_handler(): unexpected action: {:?}", action),
    };
}
