use libc::c_char;
use libc::{c_long, c_void, PT_NULL};
use nix::sys::ptrace;
use nix::sys::ptrace::{Options, Request};
use nix::unistd::*;
use std::{mem, slice};

use byteorder::LittleEndian;
use nix::sys::signal::Signal;

use byteorder::WriteBytesExt;

use crate::context;
use crate::regs::Modified;
use crate::regs::Regs;
use crate::regs::Unmodified;
use crate::tracer::TraceEvent;
#[allow(unused_imports)]
use anyhow::{anyhow, bail, ensure, Context};

use crate::async_runtime::AsyncPtrace;
// use single_threaded_runtime::ptrace_event::AsyncPtrace;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContinueEvent {
    Continue,
    SystemCall,
}

#[derive(Clone)]
pub struct Ptracer {
    pub curr_proc: Pid,
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
        ptrace::setoptions(pid, options).with_context(|| context!("Setting ptrace options."))?;
        Ok(())
    }

    pub(crate) fn new(starting_process: Pid) -> Ptracer {
        Ptracer {
            curr_proc: starting_process,
        }
    }

    pub(crate) fn get_event_message(&self) -> anyhow::Result<c_long> {
        ptrace::getevent(self.curr_proc).with_context(|| context!("Unable to get event message"))
    }

    pub(crate) async fn posthook(&mut self) -> anyhow::Result<Regs<Unmodified>> {
        let event = AsyncPtrace {
            pid: self.curr_proc,
        };

        ptrace_syscall(self.curr_proc, ContinueEvent::SystemCall, None)
            .with_context(|| context!("Unable to fetch system call posthook."))?;

        match event.await.into() {
            TraceEvent::Posthook(_) => {
                trace!("got posthook event");
                let regs = self
                    .get_registers()
                    .with_context(|| context!("Fetching post-hook registers."))?;
                // refetched regs.
                Ok(regs)
            }
            e => bail!(
                "Unexpected {:?} event, expected {:?}!",
                e,
                TraceEvent::Posthook(self.curr_proc)
            ),
        }
    }

    #[allow(dead_code)]
    fn get_current_process(&self) -> Pid {
        self.curr_proc
    }

    pub(crate) fn read_c_string(&self, address: *const c_char) -> anyhow::Result<String> {
        ensure!(!address.is_null(), context!("Address is null."));

        let address = address as *mut c_void;
        let mut string = String::new();
        // Move 8 bytes up each time for next read.
        let mut count = 0;
        let word_size = 8;

        'done: loop {
            let mut bytes: Vec<u8> = vec![];
            let res = ptrace::read(self.curr_proc, unsafe { address.offset(count) })?;

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

        // trace!(read_string = ?string);
        Ok(string)
    }

    pub fn write_value<T: Copy>(&self, address: *const T, value: &T) -> anyhow::Result<()> {
        use nix::sys::uio::{process_vm_writev, IoVec, RemoteIoVec};
        use std::mem::size_of;

        ensure!(!address.is_null(), context!("Address is null."));

        // Ugh rust doesn't support this type as a const so I can't use a stack allocated
        // array here.
        let type_size: usize = size_of::<T>();
        let remote = RemoteIoVec {
            base: address as usize,
            len: type_size,
        };

        // Get raw bytes from `value`
        let p: *const T = value;
        let p: *const u8 = p as *const u8;
        // Representation of `value` as a slice of bytes.
        let byte_repr: &[u8] = unsafe {
            slice::from_raw_parts(p, mem::size_of::<T>())
        };

        // Local mutable burrow, buffer needs to by borrowed again later.
        {
            let local = IoVec::from_slice(byte_repr);
            process_vm_writev(self.curr_proc, &[local], &[remote])
                .with_context(|| context!("process_vm_writev() failed."))?;
        }
        Ok(())
    }

    pub fn read_value<T>(&self, address: *const T) -> anyhow::Result<T> {
        use nix::sys::uio::{process_vm_readv, IoVec, RemoteIoVec};
        use std::mem::size_of;

        ensure!(!address.is_null(), context!("Address is null."));

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
            process_vm_readv(self.curr_proc, &[local], &[remote])
                .with_context(|| context!("process_vm_readv() failed."))?;
        }
        let res: T = unsafe { ::std::ptr::read(buffer.as_ptr() as *const _) };
        Ok(res)
    }

    pub(crate) async fn get_next_event(
        &mut self,
        signal: Option<Signal>,
    ) -> anyhow::Result<TraceEvent> {
        // This cannot be a posthook event. Those are explicitly caught in the
        // seccomp handler.
        ptrace_syscall(self.curr_proc, ContinueEvent::Continue, signal)
            .with_context(|| context!("Unable to get next system call event."))?;
        // Wait for ptrace event from this pid here.
        let event = AsyncPtrace {
            pid: self.curr_proc,
        }
        .await
        .into();
        Ok(event)
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
                self.curr_proc,
                PT_NULL as *mut c_void,
                regs.as_mut_ptr() as *mut c_void,
            )
            .with_context(|| context!("Unable to fetch registers"))?;
            regs.assume_init()
        };

        Ok(Regs::new(regs))
    }

    #[allow(dead_code)]
    pub(crate) fn set_regs(&self, regs: &mut Regs<Modified>) -> anyhow::Result<()> {
        unsafe {
            #[allow(deprecated)]
            ptrace::ptrace(
                Request::PTRACE_SETREGS,
                self.curr_proc,
                PT_NULL as *mut c_void,
                regs as *mut _ as *mut c_void,
            )
            .map(|_| ())
            .with_context(|| format!("Unable to set regs for pid: {}", self.curr_proc))
        }
    }

    /// Read values of the type char** or char* name[] from a tracee.
    /// # Safety
    ///
    /// A valid tracee pointer must be passed or garbage will be read.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn read_c_string_array(
        &self,
        address: *const *const c_char,
    ) -> anyhow::Result<Vec<String>> {
        ensure!(!address.is_null(), context!("Address is null."));

        let mut i = 0;
        let mut vec = Vec::new();
        loop {
            //let elem_addr = address.offset(i);
            let c_str_starting_addr: *const c_char = self
                //.read_value(elem_addr)
                .read_value(unsafe { address.offset(i) })
                .with_context(|| context!("Reading tracee bytes..."))?;

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
) -> anyhow::Result<c_long> {
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
            .with_context(|| context!("Cannot call ptrace({:?}) for {:?}", request, pid))
    }
}
