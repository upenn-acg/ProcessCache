use byteorder::{LittleEndian, WriteBytesExt};

use nix;
use libc::{c_void, user_regs_struct, PT_NULL};
use nix::sys::ptrace;
use nix::sys::ptrace::*;
use nix::unistd::*;
use std::ptr;
use std::mem;
use nix::sys::signal::Signal;

// Read string from user.
pub fn read_string(address: *mut c_void, pid: Pid) -> String {
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

pub fn ptrace_set_options(pid: Pid) -> nix::Result<()> {
    let options =
        Options::PTRACE_O_EXITKILL
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEEXEC
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACEEXIT
        | Options::PTRACE_O_TRACESYSGOOD;
    ptrace::setoptions(pid, options)
}

/// Nix does not yet have a way to fetch registers. We use our own instead.
/// Given the pid of a process that is currently being traced. Return the registers
/// for that process.
pub fn get_regs(pid: Pid) -> user_regs_struct {
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
            Ok(_) => regs,
            Err(e) => panic!("Get regs failed: {:?}", e),
        }
    }
}

pub fn ptrace_syscall(pid: Pid, signal_to_deliver: Option<Signal>) -> nix::Result<()>{
    let signal = match signal_to_deliver {
        None => 0 as *mut c_void,
        Some(s) => s as i64 as *mut c_void,
    };
    let res = unsafe {
        #[allow(deprecated)]
        ptrace::ptrace(
            Request::PTRACE_SYSCALL,
            pid,
            PT_NULL as *mut c_void,
            signal
        )
    };
    // Omit integer, not interesting.
    res.map(|_| ())
}
