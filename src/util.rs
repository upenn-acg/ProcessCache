use nix;
use libc::{c_void, PT_NULL};
use nix::sys::ptrace;
use nix::sys::ptrace::*;
use nix::unistd::*;
use nix::sys::signal::Signal;
use byteorder::LittleEndian;
use libc::c_char;
use std::ptr;
use byteorder::WriteBytesExt;

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

/// Nix's version doesn't take a signal as an argument. This one does.
pub fn ptrace_syscall(pid: Pid, signal_to_deliver: Option<Signal>) -> nix::Result<()>{
    let signal = match signal_to_deliver {
        None => 0 as *mut c_void,
        Some(s) => s as i64 as *mut c_void,
    };
    unsafe {
        #[allow(deprecated)]
        ptrace::ptrace(Request::PTRACE_SYSCALL, pid, PT_NULL as *mut c_void, signal)
        // Omit integer, not interesting.
            .map(|_| ())
    }
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
