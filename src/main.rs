extern crate byteorder;
extern crate env_logger;
extern crate libc;
extern crate nix;
extern crate structopt;
#[macro_use]
extern crate log;
extern crate seccomp_sys;

mod args;
mod execution;
mod ptracer;
pub mod seccomp;
mod clocks;
mod system_call_names;
pub mod regs;
mod tracer;

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
    // Init logger with no timestamp data.
    env_logger::Builder::from_default_env()
        .default_format_timestamp(false)
        .default_format_module_path(false)
        .init();

    let opt = Opt::from_args();
    let command = Command::new(opt.exe, opt.args);

    Ptracer::run_tracer_and_tracee(command)?;
    Ok(())
}
