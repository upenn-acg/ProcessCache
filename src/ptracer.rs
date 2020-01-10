use libc::c_char;
use libc::{c_long, c_void, PT_NULL};
use nix::sys::ptrace;
use nix::sys::ptrace::{Options, Request};
use nix::unistd::*;
use single_threaded_runtime::ptrace_event::PtraceReactor;
use std::ffi::CString;
use std::mem;
use std::process::exit;

use byteorder::LittleEndian;
use nix::sys::signal::Signal;
use std::ptr;

use byteorder::WriteBytesExt;
use std::marker::PhantomData;

use crate::execution;
use crate::regs::Modified;
use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::tracer::TraceEvent;
use crate::tracer::Tracer;

use crate::seccomp;
use crate::Command;

use async_trait::async_trait;
use tracing::{debug, error, info, trace};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContinueEvent {
    Continue,
    SystemCall,
}

pub struct Ptracer {
    current_process: Pid,
    command: Command,
}

impl Ptracer {
    fn set_trace_options(pid: Pid) {
        let options = Options::PTRACE_O_EXITKILL
            | Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACEEXEC
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACEEXIT
            | Options::PTRACE_O_TRACESYSGOOD
            | Options::PTRACE_O_TRACESECCOMP;
        ptrace::setoptions(pid, options).expect("Unable to set ptrace options");
    }

    fn new(starting_process: Pid, command: Command) -> Ptracer {
        Ptracer {
            current_process: starting_process,
            command,
        }
    }
}

#[async_trait]
impl Tracer for Ptracer {
    type Reactor = PtraceReactor;

    fn get_reactor(&self) -> Self::Reactor {
        PtraceReactor::new()
    }

    fn get_event_message(&self) -> c_long {
        ptrace::getevent(self.current_process).expect("Unable to call geteventmsg.")
    }

    async fn posthook(&self) -> Regs<Unmodified> {
        use crate::ptracer::ContinueEvent;
        use single_threaded_runtime::ptrace_event::AsyncPtrace;

        info!("Waiting for posthook event.");
        let event = AsyncPtrace {
            pid: self.current_process,
        };

        // Might want to switch this to return the error instead of failing.
        ptrace_syscall(self.current_process, ContinueEvent::SystemCall, None)
            .expect("ptrace syscall failed.");

        match event.await.into() {
            TraceEvent::Posthook(_) => {
                debug!("got posthook event");
                // refetch regs.
                self.get_registers()
            }
            e => panic!(format!("Unexpected {:?} event, expected posthook!", e)),
        }
    }

    fn get_current_process(&self) -> Pid {
        self.current_process
    }

    fn clone_tracer_for_new_process(&self, new_child: Pid) -> Ptracer {
        Ptracer {
            current_process: new_child,
            command: self.command.clone(),
        }
    }

    fn read_cstring(&self, address: *const c_char, pid: Pid) -> String {
        let address = address as *mut c_void;
        let mut string = String::new();
        // Move 8 bytes up each time for next read.
        let mut count = 0;
        let word_size = 8;

        'done: loop {
            let mut bytes: Vec<u8> = vec![];
            let res = unsafe {
                #[allow(deprecated)]
                ptrace::ptrace(
                    Request::PTRACE_PEEKDATA,
                    pid,
                    address.offset(count),
                    ptr::null_mut(),
                )
                .expect("Failed to ptrace peek data")
            };

            bytes.write_i64::<LittleEndian>(res).unwrap();
            for b in bytes {
                if b != 0 {
                    string.push(b as char);
                } else {
                    break 'done;
                }
            }
            count += word_size;
        }

        trace!(read_string = ?string);
        string
    }

    fn read_value<T>(&self, address: *const T, pid: Pid) -> T {
        use nix::sys::uio::{process_vm_readv, IoVec, RemoteIoVec};
        use std::mem::size_of;

        // Ugh rust doesn't support this type as a const so I can use a stack allocated
        // array here.
        let type_size: usize = size_of::<T>();
        let remote = RemoteIoVec {
            base: address as usize,
            len: type_size,
        };
        let mut buffer = vec![0; type_size];

        // Local mutable burrow, buffer needs to by borrowed again later.
        {
            let local = IoVec::from_mut_slice(&mut buffer);
            process_vm_readv(pid, &[local], &[remote])
                .expect("process_vm_readv: Unable to read memory: ");
        }

        unsafe { ::std::ptr::read(buffer.as_ptr() as *const _) }
    }

    async fn get_next_event(&mut self) -> TraceEvent {
        use single_threaded_runtime::ptrace_event::AsyncPtrace;
        // info!("Waiting for next ptrace event.");

        // This cannot be a posthook event. Those are explicitly caught in the
        // seccomp handler.
        //ptrace_syscall(pid, ContinueEvent::Continue, None).
        // Might want to switch this to return the error instead of failing.
        //expect("ptrace continue failed.");

        // TODO Kelly Why are we looping here.
        use crate::ptracer::ContinueEvent;
        while let Err(_e) = ptrace_syscall(self.current_process, ContinueEvent::Continue, None) {}
        // Wait for ptrace event from this pid here.
        AsyncPtrace {
            pid: self.current_process,
        }
        .await
        .into()
    }

    /// Nix does not yet have a way to fetch registers. We use our own instead.
    /// Given the pid of a process that is currently being traced. Return the registers
    /// for that process.
    fn get_registers(&self) -> Regs<Unmodified> {
        let mut regs = mem::MaybeUninit::uninit();
        unsafe {
            #[allow(deprecated)]
            let res = ptrace::ptrace(
                Request::PTRACE_GETREGS,
                self.current_process,
                PT_NULL as *mut c_void,
                regs.as_mut_ptr() as *mut c_void,
            );
            match res {
                Ok(_) => {
                    let regs = regs.assume_init();
                    Regs::new(regs)
                }
                Err(e) => {
                    error!(
                        "[{}] Unable to fetch registers: {:?}",
                        self.current_process, e
                    );
                    exit(1);
                }
            }
        }
    }

    fn set_regs(&self, regs: &mut Regs<Modified>) {
        unsafe {
            #[allow(deprecated)]
            ptrace::ptrace(
                Request::PTRACE_SETREGS,
                self.current_process,
                PT_NULL as *mut c_void,
                regs as *mut _ as *mut c_void,
            )
            .unwrap_or_else(|_| panic!("Unable to set regs for pid: {}", self.current_process));
        }
    }
}

impl Ptracer {
    pub fn run_tracer_and_tracee(command: Command) -> nix::Result<()> {
        use nix::sys::wait::waitpid;

        match fork()? {
            ForkResult::Parent { child } => {
                // Wait for program to be ready.
                waitpid(child, None).expect("Unable to wait for child to be ready");

                debug!("Child returned ready!");
                Ptracer::set_trace_options(child);

                let ptracer = Ptracer::new(child, command);
                execution::run_program(ptracer)?;
                Ok(())
            }
            ForkResult::Child => Ptracer::run_tracee(command),
        }
    }

    /// This function should be called after a fork.
    /// uses execve to call the tracee program and have it ready to be ptraced.
    fn run_tracee(command: Command) -> nix::Result<()> {
        use nix::sys::signal::raise;

        // New ptracee and set ourselves to be traced.
        ptrace::traceme()?;
        // Stop ourselves until the tracer is ready. This ensures the tracer has time
        // to get set up.
        raise(Signal::SIGSTOP)?;

        // WARNING: The seccomp filter must be loaded after the call to ptraceme() and
        // raise(...).
        let loader = seccomp::RuleLoader::new();
        loader.load_to_kernel();

        // Convert arguments to correct arguments.
        let exe = CString::new(command.0).unwrap();
        let mut args: Vec<CString> = command
            .1
            .into_iter()
            .map(|s| CString::new(s).unwrap())
            .collect();
        args.insert(0, exe.clone());

        if let Err(e) = execvp(&exe, &args) {
            error!(
                "Error executing execve for your program {:?}. Reason {}",
                args, e
            );
            // TODO parent does not know that child exited it may report a weird abort
            // message.
            exit(1);
        }

        Ok(())
    }
}

/// Nix's version doesn't take a signal as an argument. This one does.
pub fn ptrace_syscall(
    pid: Pid,
    ce: ContinueEvent,
    signal_to_deliver: Option<Signal>,
) -> nix::Result<c_long> {
    let signal = match signal_to_deliver {
        None => std::ptr::null_mut::<c_void>(),
        Some(s) => s as i64 as *mut c_void,
    };

    let request = match ce {
        ContinueEvent::Continue => Request::PTRACE_CONT,
        ContinueEvent::SystemCall => Request::PTRACE_SYSCALL,
    };

    unsafe {
        #[allow(deprecated)]
        // Omit integer, not interesting.
        let ret: nix::Result<c_long> = ptrace::ptrace(request, pid, PT_NULL as *mut c_void, signal);
        ret
    }
}
