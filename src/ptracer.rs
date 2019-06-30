use libc::c_char;
use libc::{c_void, user_regs_struct, PT_NULL, c_long};
use std::mem;
use nix::sys::ptrace;
use nix::sys::ptrace::*;

use nix::unistd::*;
use libc::exit;
use nix::errno::errno;

use nix;
use nix::sys::signal::Signal;
use std::ptr;
use byteorder::LittleEndian;

use byteorder::WriteBytesExt;
use std::marker::PhantomData;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContinueEvent {Continue, SystemCall}

/// Represents a register which has never been written to.
pub enum Unmodified {}
/// Represents a register which has been changed. Data must be written to tracee
/// for changes to take effect.
pub enum Modified {}
/// Data has been written to tracee.
pub enum Flushed {}

pub struct Regs<T> {
    pub regs: user_regs_struct,
    _type: PhantomData<T>
}

/// Create function with named $fname which returns register contents in $reg:
///
/// register_function!(arg1, rdi); =>
///     pub fn arg1(&self) -> u64 {
///         self.regs.rdi
///     }
macro_rules! read_regs_function {
    ($fname:ident, $reg:ident) => {
        pub fn $fname(&self) -> u64 {
            self.regs.$reg
        }
    }
}

impl Regs<Unmodified> {
    read_regs_function!(arg1, rdi);
    read_regs_function!(arg2, rsi);
    read_regs_function!(arg3, rdx);
    read_regs_function!(arg4, r10);
    read_regs_function!(arg5, r8);
    read_regs_function!(arg6, r9);
    read_regs_function!(rip, rip);
    read_regs_function!(rsp, rsp);
    read_regs_function!(rax, rax);
    read_regs_function!(retval, rax);
    read_regs_function!(syscall_number, orig_rax);


    /// Nix does not yet have a way to fetch registers. We use our own instead.
    /// Given the pid of a process that is currently being traced. Return the registers
    /// for that process.
    pub fn get_regs(pid: Pid) -> Regs<Unmodified> {
        unsafe {
            let mut regs: user_regs_struct = mem::uninitialized();

            #[allow(deprecated)]
            let res = ptrace::ptrace(
                Request::PTRACE_GETREGS,
                pid,
                PT_NULL as *mut c_void,
                &mut regs as *mut _ as *mut c_void,
            );
            match res {
                Ok(_) => Regs{regs, _type: PhantomData},
                Err(e) => {
                    error!("[{}] Unable to fetch registers: {:?}", pid, e);
                    exit(1);
                }
            }
        }
    }

    /// Nothing has been changed. Mark as flushed but do no not call set_regs.
    pub fn same(self) -> Regs<Flushed> {
        Regs{regs: self.regs, _type: PhantomData}
    }

    /// Set registers as writeable. Changes will not be written to tracee until
    /// flush() is called.
    pub fn to_modified(self) -> Regs<Modified> {
        Regs{regs: self.regs, _type: PhantomData}
    }

}

/// Create function with named $fname which writes to register contents in $reg.
macro_rules! write_regs_function {
    ($fname:ident, $reg:ident) => {
        pub fn $fname(&mut self, value: u64) {
            self.regs.$reg = value;
        }
    }
}

impl Regs<Modified> {
    write_regs_function!(write_arg1, rdi);
    write_regs_function!(write_arg2, rsi);
    write_regs_function!(write_arg3, rdx);
    write_regs_function!(write_arg4, r10);
    write_regs_function!(write_arg5, r8);
    write_regs_function!(write_arg6, r9);
    write_regs_function!(write_rip, rip);
    write_regs_function!(write_rsp, rsp);
    write_regs_function!(write_rax, rax);
    write_regs_function!(write_retval, rax);
    write_regs_function!(write_syscall_number, orig_rax);

    pub fn set_regs(&mut self, pid: Pid) {
        unsafe {
            #[allow(deprecated)]
            ptrace::ptrace(Request::PTRACE_SETREGS, pid,
                           PT_NULL as *mut c_void,
                           &mut self.regs as *mut _ as *mut c_void).
                expect(& format!("Unable to set regs for pid: {}", pid));
        }
    }
}


pub fn ptrace_set_options(pid: Pid) -> nix::Result<()> {
    let options =
        Options::PTRACE_O_EXITKILL
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEEXEC
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACEEXIT
        | Options::PTRACE_O_TRACESYSGOOD
        | Options::PTRACE_O_TRACESECCOMP;
    ptrace::setoptions(pid, options)
}

/// Nix's version doesn't take a signal as an argument. This one does.
pub fn ptrace_syscall(pid: Pid, ce: ContinueEvent, signal_to_deliver: Option<Signal>)
                      -> nix::Result<c_long> {
    let signal = match signal_to_deliver {
        None => 0 as *mut c_void,
        Some(s) => s as i64 as *mut c_void,
    };

    let request = match ce {
        ContinueEvent::Continue => Request::PTRACE_CONT,
        ContinueEvent::SystemCall => Request::PTRACE_SYSCALL
    };

    unsafe {
        #[allow(deprecated)]
        // Omit integer, not interesting.
        let ret: nix::Result<c_long> = ptrace::ptrace(request, pid, PT_NULL as *mut c_void, signal);
        ret
    }
}

pub fn ptrace_getevent(pid: Pid) -> c_long {
    ptrace::getevent(pid).
        expect("Unable to call getevent.")
}

// Read string from user.
pub fn read_string(address: *const c_char, pid: Pid) -> String {
    let address  = address as *mut c_void;
    let mut string = String::new();
    // Move 8 bytes up each time for next read.
    let mut count = 0;
    let word_size = 8;

    'done: loop {
        let mut bytes: Vec<u8> = vec![];
        let res = unsafe {
            #[allow(deprecated)]
            ptrace::ptrace(Request::PTRACE_PEEKDATA,
                           pid,
                           address.offset(count),
                           ptr::null_mut()).expect("Failed to ptrace peek data")
        };

        bytes.write_i64::<LittleEndian>(res).unwrap();
        for b in bytes {
            if b != 0 {
                string.push(b as char);
            }else{
                break 'done;
            }
        }
        count += word_size;
    }

    string
}

pub fn read_value<T>(address: *const T, pid: Pid) -> T {
    use nix::sys::uio::{process_vm_readv, RemoteIoVec, IoVec};
    use std::mem::size_of;

    // Ugh rust doesn't support this type as a const so I can use a stack allocated
    // array here.
    let type_size: usize = size_of::<T>();
    let remote = RemoteIoVec{base: address as usize, len: type_size};
    let mut buffer = vec![0; type_size];

    // Local mutable burrow, buffer needs to by borrowed again later.
    {
        let local = IoVec::from_mut_slice(&mut buffer);
        process_vm_readv(pid, &[local], &[remote]).
            expect("process_vm_readv: Unable to read memory: ");
    }

    unsafe { ::std::ptr::read(buffer.as_ptr() as *const _) }
}
