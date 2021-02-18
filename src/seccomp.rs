use crate::context;
use crate::system_call_names::get_syscall_name;
use anyhow::{bail, ensure, Context, Result};
use seccomp_sys::*;
use std::collections::HashSet;
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
    /// Ensure system call rules only exists once per syscall.
    rules_set: HashSet<c_long>,
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
        if !self.rules_set.insert(syscall) {
            bail!(context!(
                "Rule for system call already existed {:?}.",
                RuleLoader::syscall_name(syscall)?
            ));
        }

        unsafe {
            // Include system call number with data, this may save us some calls to
            // ptrace(GET_REGS).
            if seccomp_rule_add(self.ctx, SCMP_ACT_TRACE(syscall as u32), syscall as i32, 0) < 0 {
                bail!(context!("Unable to add intercept rule for {}", syscall));
            }
            Ok(())
        }
    }

    /// When on_debug is OnDebug::Intercept, if the debugging is on, the system call will
    /// be intercepted.
    /// TODO: This function is unused for now. Use `let_pass` isntead. Is this useful?
    #[allow(dead_code)]
    pub fn let_pass_debug(&mut self, syscall: c_long, on_debug: OnDebug) -> Result<()> {
        if !self.rules_set.insert(syscall) {
            bail!(context!(
                "Rule for system call already existed {:?}.",
                RuleLoader::syscall_name(syscall)?
            ));
        }
        match on_debug {
            OnDebug::Intercept if self.debug => self.intercept(syscall),
            _ => unsafe {
                // Send system call number as data to tracer to avoid a ptrace(GET_REGS).
                if seccomp_rule_add(self.ctx, SCMP_ACT_ALLOW, syscall as i32, 0) < 0 {
                    bail!(context!(
                        "Unable to add rule for \"{}\"",
                        RuleLoader::syscall_name(syscall)?
                    ));
                }
                Ok(())
            },
        }
    }

    /// Fetch syscall name for error handling.
    fn syscall_name(syscall: c_long) -> Result<&'static str> {
        get_syscall_name(syscall as usize)
            .with_context(|| context!("Cannot fetch name for syscall={}", syscall))
    }

    pub fn let_pass(&mut self, syscall: c_long) -> Result<()> {
        self.let_pass_debug(syscall, OnDebug::LetPass)
    }

    /// Create a new RuleLoader to pass rules to.
    pub fn new() -> Result<RuleLoader> {
        // Current default: Report u32::MAX for unspecified system calls.
        let ctx = unsafe {
            // SCMP_ACT_TRACE is wrong. It accepts a u32 but in reality the underlying system call
            // can only handle u16. So values higher than that will be silently truncated. So we
            // use a u16::MAX instead.
            let res = seccomp_init(SCMP_ACT_TRACE(u16::MAX as u32));
            if res.is_null() {
                bail!(context!("Unable to seccomp_init"));
            }
            res
        };

        let debug = !matches!(env::var_os("RUST_LOG"), None);
        Ok(RuleLoader {
            debug,
            ctx,
            rules_set: HashSet::new(),
        })
    }
}
