extern crate byteorder;
extern crate env_logger;
extern crate libc;
extern crate nix;
extern crate structopt;
extern crate seccomp_sys;

mod args;
mod execution;
mod ptracer;
pub mod seccomp;
mod clocks;
mod system_call_names;
pub mod regs;
mod tracer;

use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use crate::ptracer::Ptracer;

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
    tracing_subscriber::fmt::Subscriber::builder().
        with_env_filter(EnvFilter::from_default_env()).
        with_target(false).
        without_time().
        init();

    let opt = Opt::from_args();
    let command = Command::new(opt.exe, opt.args);

    Ptracer::run_tracer_and_tracee(command)?;
    Ok(())
}
