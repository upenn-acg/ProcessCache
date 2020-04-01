//! Mock tracer implements the tracer::Trace trait by creating fake events the
//! conflict_tracer implementation can be tested against. This allows us to
//! test our code without us having write actual executable to ptrace against.
pub mod program;
pub mod events;
pub mod system_call;
pub mod blocking_event;
pub mod process;
