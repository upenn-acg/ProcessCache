use libc::user_regs_struct;
use std::marker::PhantomData;
use std::os::raw::c_char;

/// Represents a register which has never been written to.
pub enum Unmodified {}
/// Represents a register which has been changed. Data must be written to tracee
/// for changes to take effect.
#[allow(dead_code)]
pub enum Modified {}
/// Data has been written to tracee.
#[allow(dead_code)]
pub enum Flushed {}

pub struct Regs<T> {
    regs: user_regs_struct,
    // TODO should not expose this.
    _type: PhantomData<T>,
}

impl Regs<Unmodified> {
    pub fn new(regs: user_regs_struct) -> Regs<Unmodified> {
        Regs {
            regs,
            _type: PhantomData,
        }
    }
}

/// Create function with named $fname which returns register contents in $reg:
///
/// register_function!(arg1, rdi); =>
///     pub fn arg1(&self) -> u64 {
///         self.regs.rdi
///     }
macro_rules! read_regs_function {
    ($fname:ident, $reg:ident) => {
        #[allow(dead_code)]
        pub fn $fname<T: RegisterCast>(&self) -> T {
            T::cast(self.regs.$reg)
        }
    };
}

pub trait RegisterCast {
    fn cast(r: u64) -> Self;
}

macro_rules! implement_register_cast {
    ($t:ty) => {
        impl RegisterCast for $t {
            fn cast(r: u64) -> Self {
                r as Self
            }
        }
    };
}

implement_register_cast!(u64);
implement_register_cast!(usize);
implement_register_cast!(i32);
implement_register_cast!(*const c_char);
implement_register_cast!(*const char);
implement_register_cast!(*const *const c_char);
implement_register_cast!(*const libc::stat);

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
    #[allow(dead_code)]
    pub fn same(self) -> Regs<Flushed> {
        Regs {
            regs: self.regs,
            _type: PhantomData,
        }
    }

    /// Set registers as writeable. Changes will not be written to tracee until
    /// flush() is called.
    #[allow(dead_code)]
    pub fn make_modified(self) -> Regs<Modified> {
        Regs {
            regs: self.regs,
            _type: PhantomData,
        }
    }
}

/// Create function with named $fname which writes to register contents in $reg.
macro_rules! write_regs_function {
    ($fname:ident, $reg:ident) => {
        #[allow(dead_code)]
        pub fn $fname(&mut self, value: u64) {
            self.regs.$reg = value;
        }
    };
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

    #[allow(dead_code)]
    pub fn make_unmodified(self) -> Regs<Unmodified> {
        Regs::<Unmodified>::new(self.regs)
    }
}

#[allow(dead_code)]
pub fn empty_regs() -> user_regs_struct {
    user_regs_struct {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rax: 0,
        rcx: 0,
        rdx: 0,
        rsi: 0,
        rdi: 0,
        orig_rax: 0,
        rip: 0,
        cs: 0,
        eflags: 0,
        rsp: 0,
        ss: 0,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}
