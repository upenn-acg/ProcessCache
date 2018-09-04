use libc::c_char;
use libc::{c_void, user_regs_struct, PT_NULL};
use std::mem;
use nix::sys::ptrace;
use nix::sys::ptrace::*;
use byteorder::LittleEndian;
use nix::unistd::*;
use libc::exit;

pub struct Regs {
    regs: user_regs_struct,
}

// New Type to wrap.
pub struct RegisterVal(u64);

impl Regs {
    pub fn arg1<T : From<RegisterVal>>(&self) -> T {
        T::from(RegisterVal(self.regs.rdi))
    }

    pub fn arg2<T : From<RegisterVal>>(&self) -> T {
        T::from(RegisterVal(self.regs.rsi))
    }

    pub fn orig_rax(&self) -> u64 {
        self.regs.orig_rax
    }

    /// Nix does not yet have a way to fetch registers. We use our own instead.
    /// Given the pid of a process that is currently being traced. Return the registers
    /// for that process.
    pub fn get_regs(pid: Pid) -> Regs {
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
                Ok(_) => Regs{regs},
                Err(e) => {
                    error!("[{}] Unable to fetch registers: {:?}", pid, e);
                    exit(1);
                }
            }
        }
    }

}

impl From<RegisterVal> for *const c_char {
    fn from(t: RegisterVal) -> Self {
        t.0 as Self
    }
}

impl From<RegisterVal> for isize {
    fn from(t: RegisterVal) -> Self {
        t.0 as Self
    }
}
// pub struct Tracee<T> {
    
// }
