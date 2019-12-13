use libc::user_regs_struct;
use std::marker::PhantomData;


/// Represents a register which has never been written to.
pub enum Unmodified {}
/// Represents a register which has been changed. Data must be written to tracee
/// for changes to take effect.
pub enum Modified {}
/// Data has been written to tracee.
pub enum Flushed {}

pub struct Regs<T> {
    pub regs: user_regs_struct,
    // TODO should not expose this.
    pub _type: PhantomData<T>,
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


    /// Nothing has been changed. Mark as flushed but do no not call set_regs.
    pub fn same(self) -> Regs<Flushed> {
        Regs {
            regs: self.regs,
            _type: PhantomData,
        }
    }

    /// Set registers as writeable. Changes will not be written to tracee until
    /// flush() is called.
    pub fn to_modified(self) -> Regs<Modified> {
        Regs {
            regs: self.regs,
            _type: PhantomData,
        }
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
}
