extern crate byteorder;
extern crate env_logger;
extern crate libc;
extern crate nix;
extern crate seccomp_sys;
extern crate structopt;

mod args;
mod clocks;
mod execution;
mod ptracer;
pub mod regs;
pub mod seccomp;
mod system_call_names;
mod tracer;
mod MockReactor;

use crate::ptracer::Ptracer;
use tracing_subscriber::filter::EnvFilter;

use args::*;
use structopt::StructOpt;

#[derive(Clone)]
pub struct Command(String, Vec<String>);

impl Command {
    fn new(exe: String, args: Vec<String>) -> Self {
        Command(exe, args)
    }
}

/// Dettracer program written in Rust.
fn main() -> nix::Result<()> {
    tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();

    let opt = Opt::from_args();
    let command = Command::new(opt.exe, opt.args);

    Ptracer::run_tracer_and_tracee(command)?;
    Ok(())
}
