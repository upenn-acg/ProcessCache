use libc::c_char;
use libc::{c_long, c_void, PT_NULL};
use nix::sys::ptrace;
use nix::sys::ptrace::{Options, Request};
use nix::unistd::*;
use std::mem;

use byteorder::LittleEndian;
use nix::sys::signal::Signal;

use byteorder::WriteBytesExt;

use crate::regs::Modified;
use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::tracer::TraceEvent;
#[allow(unused_imports)]
use anyhow::{anyhow, bail, ensure, Context};

#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContinueEvent {
    Continue,
    SystemCall,
}

pub struct Ptracer {
    pub current_process: Pid,
}

impl Ptracer {
    pub(crate) fn set_trace_options(pid: Pid) -> anyhow::Result<()> {
        let options = Options::PTRACE_O_EXITKILL
            | Options::PTRACE_O_TRACECLONE
            | Options::PTRACE_O_TRACEEXEC
            | Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACEEXIT
            | Options::PTRACE_O_TRACESYSGOOD
            | Options::PTRACE_O_TRACESECCOMP;
        ptrace::setoptions(pid, options).context("Setting ptrace options.")?;
        Ok(())
    }

    pub(crate) fn new(starting_process: Pid) -> Ptracer {
        Ptracer {
            current_process: starting_process,
        }
    }

    pub(crate) fn get_event_message(&self) -> anyhow::Result<c_long> {
        ptrace::getevent(self.current_process).context("Unable to get event message")
    }

    pub(crate) async fn posthook(&mut self) -> anyhow::Result<Regs<Unmodified>> {
        use single_threaded_runtime::ptrace_event::AsyncPtrace;

        let event = AsyncPtrace {
            pid: self.current_process,
        };

        // Might want to switch this to return the error instead of failing.
        ptrace_syscall(self.current_process, ContinueEvent::SystemCall, None)
            .context("ptrace_syscall failed.")?;

        match event.await.into() {
            TraceEvent::Posthook(_) => {
                trace!("got posthook event");
                let regs = self
                    .get_registers()
                    .context("Fetching post-hook registers.")?;
                // refetch regs.
                Ok(regs)
            }
            e => bail!("Unexpected {:?} event, expected posthook!", e),
        }
    }

    #[allow(dead_code)]
    fn get_current_process(&self) -> Pid {
        self.current_process
    }

    pub(crate) fn read_c_string(&self, address: *const c_char) -> nix::Result<String> {
        let address = address as *mut c_void;
        let mut string = String::new();
        // Move 8 bytes up each time for next read.
        let mut count = 0;
        let word_size = 8;

        'done: loop {
            let mut bytes: Vec<u8> = vec![];
            let res = ptrace::read(self.current_process, unsafe { address.offset(count) })?;

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
        Ok(string)
    }

    fn read_value<T>(&self, address: *const T) -> anyhow::Result<T> {
        use nix::sys::uio::{process_vm_readv, IoVec, RemoteIoVec};
        use std::mem::size_of;

        // Ugh rust doesn't support this type as a const so I can't use a stack allocated
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
            process_vm_readv(self.current_process, &[local], &[remote])
                .context("process_vm_readv() failed.")?;
        }
        let res: T = unsafe { ::std::ptr::read(buffer.as_ptr() as *const _) };
        Ok(res)
    }

    pub(crate) async fn get_next_event(&mut self) -> TraceEvent {
        use single_threaded_runtime::ptrace_event::AsyncPtrace;
        // info!("Waiting for next ptrace event.");

        // This cannot be a posthook event. Those are explicitly caught in the
        // seccomp handler.
        //ptrace_syscall(pid, ContinueEvent::Continue, None).

        // TODO Kelly Why are we looping here.
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
    pub(crate) fn get_registers(&self) -> anyhow::Result<Regs<Unmodified>> {
        let mut regs = mem::MaybeUninit::uninit();
        let regs = unsafe {
            #[allow(deprecated)]
            ptrace::ptrace(
                Request::PTRACE_GETREGS,
                self.current_process,
                PT_NULL as *mut c_void,
                regs.as_mut_ptr() as *mut c_void,
            )
            .context("Unable to fetch registers")?;
            regs.assume_init()
        };

        Ok(Regs::new(regs))
    }

    #[allow(dead_code)]
    fn set_regs(&self, regs: &mut Regs<Modified>) -> anyhow::Result<()> {
        unsafe {
            #[allow(deprecated)]
            ptrace::ptrace(
                Request::PTRACE_SETREGS,
                self.current_process,
                PT_NULL as *mut c_void,
                regs as *mut _ as *mut c_void,
            )
            .map(|_| ())
            .with_context(|| format!("Unable to set regs for pid: {}", self.current_process))
        }
    }

    /// Read values of the type char** or char* name[] from a tracee.
    /// # Safety
    ///
    /// A valid tracee pointer must be passed or garbage will be read.
    pub unsafe fn read_c_string_array(
        &self,
        address: *const *const c_char,
    ) -> anyhow::Result<Vec<String>> {
        ensure!(!address.is_null(), "address is null.");

        let mut i = 0;
        let mut vec = Vec::new();
        loop {
            let elem_addr = address.offset(i);
            let c_str_starting_addr: *const c_char = self
                .read_value(elem_addr)
                .context("Reading tracee bytes...")?;

            // Always check if we hit the end of the array.
            if c_str_starting_addr.is_null() {
                break;
            } else {
                let elem = self.read_c_string(c_str_starting_addr)?;
                vec.push(elem);
            }

            i += 1;
        }
        Ok(vec)
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
        ptrace::ptrace(request, pid, PT_NULL as *mut c_void, signal)
    }
}
