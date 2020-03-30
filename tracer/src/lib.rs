//! Defines the Tracer trait and wrapper around libc::user_regs_struct Regs.
///
pub mod regs;
mod tracer;

pub use tracer::TraceEvent;
pub use tracer::Tracer;
