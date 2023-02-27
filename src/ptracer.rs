use libc::c_char;
use libc::{c_long, c_void, PT_NULL};
use nix::sys::ptrace;
use nix::sys::ptrace::{Options, Request};
use nix::unistd::*;
use std::convert::TryInto;
use std::ffi::CString;
use std::mem::size_of;
use std::{mem, slice};

use nix::sys::signal::Signal;

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

#[derive(Clone, Copy, Debug)]
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

    /// Write a Rust string as a char* to the location specified by `address`.
    pub(crate) fn write_as_c_string(
        &self,
        string: &str,
        address: *const c_char,
    ) -> anyhow::Result<()> {
        ensure!(!address.is_null(), context!("Address is null."));

        // Convert into C String. New null terminated string is allocated.
        let cstring =
            CString::new(string).with_context(|| context!("Cannot convert to CString"))?;

        self.write_bytes(cstring.as_bytes_with_nul(), address as *const u8)
            .with_context(|| context!("Failed to write bytes."))?;

        Ok(())
    }

    /// Inject the system call specified by `syscall_number`. We can only inject at system call
    /// sites, e.g. pre-hook.
    /// `regs` should have the arguments you want to use for this injected system call.
    /// `original_regs` is the original, unmodified state of the registers when ptrace stopped
    /// at the pre-hook.
    /// You should call `restore_state` on the returned InjectedHandle to reset the register state
    /// after the system call has been injected.
    pub(crate) fn inject_system_call(
        &self,
        syscall_number: c_long,
        original_regs: Regs<Unmodified>,
        mut regs: Regs<Modified>,
    ) -> anyhow::Result<InjectedHandle> {
        let syscall_number = syscall_number.try_into().expect("cannot convert");
        // Change the orig rax val don't ask me why
        regs.write_syscall_number(syscall_number);
        // Change the rax val
        regs.write_rax(syscall_number);

        self.set_regs(&mut regs)?;
        Ok(InjectedHandle::new(original_regs))
    }

    /// "New" better version.
    pub(crate) fn read_c_string(&self, address: *const c_char) -> anyhow::Result<String> {
        ensure!(!address.is_null(), context!("Address is null."));

        const NAME_MAX: usize = 256;
        let mut c_string = String::with_capacity(NAME_MAX);
        let mut address_counter = address as *const u8;

        loop {
            // Read all bytes in a path.
            let mut bytes = self
                .read_bytes(address_counter, NAME_MAX)
                .with_context(|| context!("Cannot read bytes from memory."))?;
            address_counter = unsafe { address_counter.add(NAME_MAX) };

            match bytes.iter().position(|b| *b == 0) {
                None => {
                    let s: &str = std::str::from_utf8(bytes.as_slice()).unwrap();
                    c_string.push_str(s);
                }
                Some(null_index) => {
                    bytes.truncate(null_index);
                    let s: &str = std::str::from_utf8(bytes.as_slice()).unwrap();
                    c_string.push_str(s);
                    break;
                }
            }
        }

        Ok(c_string)
    }

    // pub(crate) fn read_c_string(&self, address: *const c_char) -> anyhow::Result<String> {
    //     ensure!(!address.is_null(), context!("Address is null."));

    //     let address = address as *mut c_void;
    //     let mut string = String::new();
    //     // Move 8 bytes up each time for next read.
    //     let mut count = 0;
    //     let word_size = 8;

    //     'done: loop {
    //         let mut bytes: Vec<u8> = vec![];
    //         let res = ptrace::read(self.curr_proc, unsafe { address.offset(count) })?;

    //         bytes.write_i64::<LittleEndian>(res).unwrap();
    //         for b in bytes {
    //             if b != 0 {
    //                 string.push(b as char);
    //             } else {
    //                 break 'done;
    //             }
    //         }
    //         count += word_size;
    //     }

    //     // trace!(read_string = ?string);
    //     Ok(string)
    // }

    /// TODO Not sure why the Copy trait bound is here. I was probably trying to say only "simple"
    /// types should be copied, e.g. types made up of just bytes. Should 'static be used as a
    /// better trait bound instead? Hmmm...
    pub fn write_value<T: Copy>(&self, address: *const T, value: &T) -> anyhow::Result<()> {
        // Get raw bytes from `value`
        let p: *const T = value;
        let p: *const u8 = p as *const u8;
        // Representation of `value` as a slice of bytes.
        let byte_repr: &[u8] = unsafe { slice::from_raw_parts(p, size_of::<T>()) };

        self.write_bytes(byte_repr, address as *const u8)
            .with_context(|| context!("write_bytes failed."))?;

        Ok(())
    }

    pub fn write_bytes(&self, bytes: &[u8], address: *const u8) -> anyhow::Result<()> {
        use nix::sys::uio::{process_vm_writev, IoVec, RemoteIoVec};

        ensure!(!address.is_null(), context!("Address is null."));

        let remote = RemoteIoVec {
            base: address as usize,
            len: bytes.len(),
        };

        // Local mutable burrow, buffer needs to be borrowed again later.
        {
            let local = IoVec::from_slice(bytes);
            process_vm_writev(self.curr_proc, &[local], &[remote])
                .with_context(|| context!("process_vm_writev() failed."))?;
        }
        Ok(())
    }

    pub fn read_value<T>(&self, address: *const T) -> anyhow::Result<T> {
        let type_size: usize = size_of::<T>();
        let bytes = self
            .read_bytes(address as *const u8, type_size)
            .with_context(|| context!("Cannot read bytes from tracee"))?;

        let res: T = unsafe { ::std::ptr::read(bytes.as_ptr() as *const _) };
        Ok(res)
    }

    fn read_bytes(&self, address: *const u8, bytes: usize) -> anyhow::Result<Vec<u8>> {
        use nix::sys::uio::{process_vm_readv, IoVec, RemoteIoVec};
        ensure!(!address.is_null(), context!("Address is null."));

        let remote = RemoteIoVec {
            base: address as usize,
            len: bytes,
        };
        let mut buffer = vec![0; bytes];

        // Local mutable burrow, buffer needs to by borrowed again later.
        {
            let local = IoVec::from_mut_slice(&mut buffer);
            process_vm_readv(self.curr_proc, &[local], &[remote])
                .with_context(|| context!("process_vm_readv() failed."))?;
        }
        Ok(buffer)
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

    pub(crate) async fn get_next_syscall(&mut self) -> anyhow::Result<TraceEvent> {
        // This cannot be a posthook event. Those are explicitly caught in the
        // seccomp handler.
        ptrace_syscall(self.curr_proc, ContinueEvent::SystemCall, None)
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

/// Handle returned by calling `inject_system_call`. Will reset the state of the injection
/// so tracee doesn't know injection ever happened.
pub struct InjectedHandle {
    regs: Regs<Unmodified>,
}

impl InjectedHandle {
    fn new(regs: Regs<Unmodified>) -> Self {
        InjectedHandle { regs }
    }

    /// Restores state to how it was before injection happened. You should call this after
    /// your injected system call returns!
    /// This will put the registers back to their original state. This includes setting the IP
    /// pointer back to so the original system call still takes place.
    pub fn restore_state(self, ptracer: &Ptracer) -> anyhow::Result<Regs<Unmodified>> {
        const SYSCALL_INSTRUCTION_SIZE: u64 = 2;

        let reset_rip = self.regs.rip::<u64>() - SYSCALL_INSTRUCTION_SIZE;
        let prev_syscall = self.regs.syscall_number();

        let mut regs = self.regs.make_modified();
        regs.write_rip(reset_rip);

        regs.write_rax(prev_syscall);
        ptracer
            .set_regs(&mut regs)
            .with_context(|| context!("Unable to restore register state."))?;
        Ok(regs.make_unmodified())
    }
}
