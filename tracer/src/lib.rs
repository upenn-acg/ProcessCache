//! Defines the Tracer trait and regs::Regs, awrapper around libc::user_regs_struct .
///
pub mod regs;
mod tracer;

pub use crate::tracer::TraceEvent;
pub use crate::tracer::Tracer;
