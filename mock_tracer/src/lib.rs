//! Mock tracer implements the tracer::Trace trait by creating fake events the
//! conflict_tracer implementation can be tested against. This allows us to
//! test our code without us having write actual executable to ptrace against.
pub mod blocking_event;
pub mod events;
pub mod process;
pub mod program;
pub mod system_call;
