use crate::system_call_names::SYSTEM_CALL_NAMES;
use anyhow::{bail, ensure, Context, Result};
use seccomp_sys::*;
use std::env;
use std::os::raw::c_long;
use std::u32;

#[allow(dead_code)]
pub enum OnDebug {
    Intercept,
    LetPass,
}

pub struct RuleLoader {
    // Flag specifying if we're running with RUST_LOG on.
    debug: bool,
    ctx: *mut scmp_filter_ctx,
}

impl RuleLoader {
    /// Loads rules to kernel and releases all memory uses "filtering context", that is, the memory
    /// taken by the libseccomp filtering structure. (Once memory is loaded into kernel we no longer
    /// need it in userspace.
    /// Note: This API does not allow for additional loads or changes to the seccomp filter created
    /// this is fine for now.
    pub fn load_to_kernel(self) -> Result<()> {
        unsafe {
            ensure!(
                seccomp_load(self.ctx) >= 0,
                "Unable to load seccomp filter context to kernel."
            );
            seccomp_release(self.ctx);
            Ok(())
        }
    }

    /// System call to intercept on execution.
    pub fn intercept(&mut self, syscall: c_long) -> Result<()> {
        unsafe {
            // Include system call number with data, this may save us some calls to
            // ptrace(GET_REGS).
            if seccomp_rule_add(self.ctx, SCMP_ACT_TRACE(syscall as u32), syscall as i32, 0) < 0 {
                bail!("Unable to add intercept rule for {}", syscall);
            }
            Ok(())
        }
    }

    /// When on_debug is OnDebug::Intercept, if the debugging is on, the system call will
    /// be intercepted.
    /// TODO: Currently we allow a conditional debug-based flag. Is this useful?
    #[allow(dead_code)]
    pub fn let_pass(&mut self, syscall: c_long, on_debug: OnDebug) -> Result<()> {
        match on_debug {
            OnDebug::Intercept if self.debug => self.intercept(syscall),
            _ => unsafe {
                // Send system call number as data to tracer to avoid a ptrace(GET_REGS).
                if seccomp_rule_add(self.ctx, SCMP_ACT_ALLOW, syscall as i32, 0) < 0 {
                    let syscall = SYSTEM_CALL_NAMES
                        .get(syscall as usize)
                        .with_context(|| format!("System call {} does not exist", syscall))?;
                    bail!("Unable to add rule for \"{}\"", syscall);
                }
                Ok(())
            },
        }
    }

    /// Create a new RuleLoader to pass rules to.
    pub fn new() -> Result<RuleLoader> {
        // Current default: Allow all system calls through:
        let ctx = unsafe {
            let res = seccomp_init(SCMP_ACT_ALLOW);
            if res.is_null() {
                bail!("Unable to seccomp_init");
            }
            res
        };

        let debug = !matches!(env::var_os("RUST_LOG"), None);
        Ok(RuleLoader { debug, ctx })
    }
}
