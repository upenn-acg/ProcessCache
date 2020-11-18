// use conflict_tracer;
// use mock_tracer::events::Events;
// use mock_tracer::process::Process;
// use mock_tracer::program::Program;
// use mock_tracer::system_call::{ReadSyscall, WriteSyscall};
// use nix::unistd::Pid;
// use tracing_subscriber;
// use tracing_subscriber::EnvFilter;

// use conflict_tracer::run_program;

// #[test]
// fn blocking_syscall_test() {
//     tracing_subscriber::fmt::Subscriber::builder().
//         with_env_filter(EnvFilter::from_default_env()).
//     // with_target(false).
//         without_time().
//         init();

//     let starting_pid = Pid::from_raw(1);
//     let program = Program::new(starting_pid);

//     let (write, read) = program
//         .borrow_mut()
//         .new_blocking_pair(WriteSyscall {}, ReadSyscall {});

//     let child_events = Events::new().add_blocking(write).finished();

//     let events = Events::new()
//         .add_syscall(ReadSyscall {})
//         .add_process(child_events)
//         .add_blocked(read)
//         .finished();

//     let starting_process = Process::new(starting_pid, program.clone(), events);
//     run_program(starting_process);
// }

// #[test]
// fn couple_syscalls_test() {
//     use conflict_tracer::execution::run_program;
//     tracing_subscriber::fmt::Subscriber::builder().
//         with_env_filter(EnvFilter::from_default_env()).
//         without_time().
//         init();

//     let pid = Pid::from_raw(1);
//     let mut program = Program::new(pid);

//     let events = Events::new().
//         add_syscall(WriteSyscall {}).
//         add_syscall(ReadSyscall {});
//     program.add_events(events.finished(), pid);
//     run_program(program);
// }

// #[test]
// #[should_panic(expected = "No next available process. This is a deadlock!")]
// fn deadlocking_syscall_test() {
//     use conflict_tracer::execution::run_program;
//     tracing_subscriber::fmt::Subscriber::builder().
//         with_env_filter(EnvFilter::from_default_env()).
//     // with_target(false).
//         without_time().
//         init();

//     let pid = Pid::from_raw(1);
//     let mut program = Program::new(pid);

//     let (write, read) = program.new_blocking_pair(WriteSyscall{}, ReadSyscall{});
//     let events = Events::new().
//         // This read will block forever...
//         add_blocked(read).
//         add_blocking(write);

//     program.add_events(events.finished(), pid);
//     run_program(program);
// }
