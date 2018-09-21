use seccomp_sys::*;
use std::ptr::null_mut;
use std::u32;
use libc::c_int;
use std::env;

pub enum OnDebug { Intercept, LetPass }

pub struct RuleLoader{
    debug: bool,
    ctx: *mut scmp_filter_ctx,
}

// impl Drop for RuleLoader {
    // fn drop(&mut self){
        // unsafe{ seccomp_release(self.ctx) };
    // }
// }

impl RuleLoader {
    pub fn load_to_kernel(self){
        unsafe {
            if seccomp_load(self.ctx) < 0 {
                panic!("Unable to load seccomp filter context to kernel.");
            }
        }
    }
    pub fn intercept(&self, syscall: c_int){
        unsafe{
            // Send system call number as data to tracer to avoid a ptrace(GET_REGS).
            if seccomp_rule_add(self.ctx, SCMP_ACT_TRACE(syscall as u32), syscall, 0) < 0 {
                panic!("unnable to add intercept rule for {}", syscall);
            }
        }
    }

    /// Let syscall through.
    ///
    /// When OnDebug::Intercept is passed, if the debug flag is on, the system call will
    /// be intercepted.
    pub fn let_pass(&self, syscall: c_int, on_debug: OnDebug){
        match on_debug {
            OnDebug::Intercept if self.debug => self.intercept(syscall),
            _ => unsafe {
                // Send system call number as data to tracer to avoid a ptrace(GET_REGS).
                if seccomp_rule_add(self.ctx, SCMP_ACT_ALLOW, syscall, 0) < 0 {
                    panic!("unnable to add rule for {}", syscall);
                }
            }
        }
    }

    /// Create a new RuleLoader to pass rules to.
    pub fn new() -> RuleLoader {
        let ctx = unsafe { seccomp_init(/*SCMP_ACT_ALLOW*/ SCMP_ACT_TRACE(u32::MAX)) };
        if ctx == null_mut() {
            panic!("Unable to init seccomp filter.");
        }

        let debug =
            match env::var_os("RUST_LOG"){
                None => false,
                _ => true,
            };
        RuleLoader { debug, ctx }
    }

}
