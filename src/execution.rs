use system_call_names::SYSTEM_CALL_NAMES;

use nix::sys::wait::*;
use nix::unistd::*;
use libc::c_char;
use std::ptr::null;

use nix::sys::ptrace::Event::*;

use log::Level;

use nix;
use ptracer::*;
use ptracer::Unmodified;

use generator::{Gn, Scope, GeneratorImpl};

/// Wrapper around our scope generator. Yields messages of type Actions
/// and receives an Action.
pub type Yielder = Scope<Action, Actions>;
pub type Coroutine<'a> = Box<GeneratorImpl<'a, Action, Actions>>;

fn make_handler<'a>(fun: fn(Regs<Unmodified>, Pid, Yielder),
                    regs: Regs<Unmodified>,
                    pid: Pid) -> Coroutine<'a> {
    Gn::new_scoped(move |mut s| {
        fun(regs, pid, s);
        Action::Done.into()
    })
}

/// Action represents events that a coroutine yields to wait for.
/// The main thread takes this action, and runs ptrace until the correct
/// action is found. A coroutine may wait on multiple action waiting for either or
/// to arrive. Thus the main thread returns the action that actually happened.
#[derive(PartialEq, Debug, Eq, Hash, Clone)]
pub enum Action {
    Seccomp,
    Execve,
    PostHook,
    Done,
}

impl Into<Actions> for Action {
    fn into(self) -> Actions {
        let mut set = HashSet::new();
        set.insert(self);
        set
    }
}

use std::collections::HashSet;
type Actions = HashSet<Action>;

pub fn run_program(first_proc: Pid) -> nix::Result<()> {
    use std::collections::HashMap;
    use std::collections::hash_map::Entry;

    // Wait for child to be ready.
    let _s: WaitStatus = waitpid(first_proc, None)?;

    // Child ready!
    ptrace_set_options(first_proc)?;

    // Map which keeps track of what action each pid is waiting for.
    // Assumption: at any given time only one entry for any tid/pid
    // is being waited for by a coroutine. The HashMap enforces this
    // naturally, TODO
    let mut waiting_coroutines: HashMap<Pid, (Actions, Coroutine)> = HashMap::new();

    // Loop over all events in the program.
    let mut current_pid = first_proc;

    let mut continue_type = ContinueEvent::Continue;

    loop {
        ptrace_syscall(current_pid, continue_type, None)?;

        let event = waitpid(None, None)?;
        let (pid, new_action) = get_action_and_pid(event);

        continue_type = match waiting_coroutines.entry(pid) {
            Entry::Vacant(v) => {
                // No coroutine waiting for this (pid, event) spawn one!
                let mut cor = new_event_handler(pid, new_action);

                // Run until it yields!
                let waiting_on: Actions = cor.resume().unwrap();
                let goto_posthook = waiting_on.contains(& Action::PostHook);

                v.insert((waiting_on, cor));

                if goto_posthook {
                    ContinueEvent::SystemCall
                }else{
                    ContinueEvent::Continue
                }
            }
            Entry::Occupied(mut entry) => {
                // TODO: UGLY REFACTOR

                // This pid/tid was not expecting to receive this action!
                if ! entry.get().0.contains(& new_action){
                    panic!("Unexpected action arrived: (pid: {}, action: {:?}",
                           pid, new_action);
                }
                // Found it! Run coroutine until it yields;
                let new_waiting_on: Actions = entry.get_mut().1.send(new_action);


                // We're done with this coroutine. Erase it.
                if new_waiting_on.contains(& Action::Done) {
                    entry.remove_entry();
                }

                ContinueEvent::Continue
            }
        }
    }
}

pub fn new_event_handler<'a>(pid: Pid, action: Action) -> Coroutine<'a> {
    use self::Action::*;
    let coroutine = match action {
        // Basically a pre-hook event.
        Seccomp => {
            debug!("New event handler for seccomp.");

            let regs = Regs::get_regs(pid);
            let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];

            match name {
                "execve" => return make_handler(handle_execve, regs, pid),
                _ => return make_handler(empty_coroutine, regs, pid),
            }

        }
        _ => panic!("get_coroutine: unexpected action: {:?}", action),
    };

    coroutine
}

pub fn get_action_and_pid(event: WaitStatus) -> (Pid, Action) {
    use nix::sys::wait::WaitStatus::*;

    match event {
        PtraceEvent(pid,_, status)
            if PTRACE_EVENT_EXEC as i32 == status => {
                info!("[{}] Saw exec event.", pid);
                return (pid, Action::Execve);
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

        s => {
            panic!("Unhandled case for get_action_pid(): {:?}", s);
        }
    }
}


// pub fn run_tracer(starting_pid: Pid) -> nix::Result<()> {
//     use nix::sys::wait::WaitStatus::*;

//     // Wait for child to be ready.
//     let _s: WaitStatus = waitpid(starting_pid, None)?;

//     // Child ready!
//     ptrace_set_options(starting_pid)?;

//     // Loop over all events in the program.
//     let current_pid = starting_pid;

//     // Assume we will continue for the next event, the only time where this is
//     // not true will be after a seccomp event since we will want to go to the
//     // post-hook we will use ptrace(SYSCALL) to go into the post-hook.
//     let mut continue_type = ContinueEvent::Continue;

//     loop {
//         ptrace_syscall(current_pid, continue_type, None)?;

//         // Wait for any event from any tracee.
//         match waitpid(current_pid, None)? {
//             // We have exited all the way. Don't keep track of this process anymore.
//             Exited(pid, _) => {
//                 break;
//             }

//             // Our process has been killed by signal
//             Signaled(pid, signal, _) => {
//                 info!("[{}] Our process has been killed by signal {:?}", pid, signal);
//                 break;
//             }

//             // We were stopped by a signal, deliver this signal to the tracee.
//             Stopped(pid, signal) => {
//                 info!("[{}] Received stopped event {:?}", pid, signal);
//             }

//             PtraceEvent(pid,_, status)
//                 if PTRACE_EVENT_FORK  as i32 == status ||
//                    PTRACE_EVENT_CLONE as i32 == status ||
//                    PTRACE_EVENT_VFORK as i32 == status => {
//                        info!("[{}] Saw clone event.", pid);
//                    }

//             PtraceEvent(pid,_, status)
//                 if PTRACE_EVENT_EXEC as i32 == status => {
//                     info!("[{}] Saw exec event.", pid);
//                 }

//             PtraceEvent(pid,_, status)
//                 if PTRACE_EVENT_EXIT as i32 == status => {
//                     info!("[{}] Saw exit event.", pid);
//                 }

//             // PtraceEvent(pid,_, status)
//             //     if PTRACE_EVENT_SECCOMP as i32 == status => {
//             //         info!("[{}] Saw seccomp event.", pid);
//             //         let regs = Regs::get_regs(pid);
//             //         let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];
//             //         info!("[{}] {}", pid, name);

//             //         let mut coroutine = match name {
//             //             "getcwd" => {
//             //                 make_handler!(getcwd, regs, pid)
//             //             }
//             //             _ => { },
//             //         }

//             //         // start coroutine.
//             //         // while ! g.is_done() {
//             //         //     match g.resume().unwrap() {
//             //         //         Action::PostHook(pid) => {
//             //         //             ptrace_syscall(pid, ContinueEvent::SystemCall, None)?;
//             //         //             waitpid(current_pid, None)?;
//             //         //             g.resume();
//             //         //         }
//             //         //         Action::Done => {}
//             //         //     }
//             //         // }
//             //     }

//             // PtraceSyscall(pid) => {
//             // 
//             // }

//             s => {
//                 panic!("Unhandled case for WaitStatus: {:?}", s);
//             }
//         };

//     }

//     info!("Process finished!");

//     Ok(())
// }

fn empty_coroutine(regs: Regs<Unmodified>, pid: Pid, mut y: Yielder) {
    let regs = Regs::get_regs(pid);
    let name = SYSTEM_CALL_NAMES[regs.syscall_number() as usize];
    info!("empty_handler: [{}] {}", pid, name);

    let regs = await_posthook(regs.same(), pid, y);
    info!("[{}] At post hook!", pid);
}

fn handle_execve(regs: Regs<Unmodified>, pid: Pid, mut y: Yielder) {
    let arg1 = regs.arg1() as *const c_char;
    let exe = read_string(arg1, pid);
    info!("[{}] executable: {}", pid, exe);

    let argv = regs.arg2() as *const *const c_char;

    // Read all of argv
    for i in 0.. {
        let p = read_value(unsafe { argv.offset(i) }, pid);
        if p == null() { break; }

        let arg = read_string(p, pid);
        info!("[{}] arg{}: {}", pid, i, arg);
    }

    let res = await_execve(y);

    info!("res: {:?}", res);
}

fn await_execve(mut y: Yielder) -> Action {
    let actions = make_actions(& [Action::PostHook, Action::Execve]);
    y.yield_with(actions);
    y.get_yield().unwrap()
}

// pub struct Scope<A, T>;
// receives A's, Sends T's
// fn getcwd(regs: Regs<Unmodified>, pid: Pid, mut gen: Scope<(), Action>){
//     // Pre-hook
//     let regs = await_posthook(regs.same(), pid, gen);

//     // Post-hook
//     let buf = regs.arg1() as *const c_char;
//     let length = regs.arg1() as isize;
//     let cwd = read_string(buf, pid);
//     info!("cwd({}, {})", cwd, length);
// }

fn await_posthook(regs: Regs<Flushed>, pid: Pid,
                  mut y: Yielder) -> Regs<Unmodified> {
    // Blocks until event arrives.
    let actions = make_actions(& [Action::PostHook]);
    y.yield_with(actions);
    // new_regs
    Regs::get_regs(pid)
}

fn make_actions(array: &[Action]) -> Actions {
    // array.into_iter().fold(HashSet::new(), |set, e| h.insert(*e)).collect()
    let mut set: HashSet<Action> = HashSet::new();

    for e in array {
        set.insert(e.clone());
    }

    set
}
