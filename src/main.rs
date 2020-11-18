use tracing_subscriber::filter::EnvFilter;

mod clocks;
mod execution;
mod ptracer;
mod tracer;
mod regs;
mod seccomp;
mod system_call_names;

pub use crate::execution::run_program;
pub use crate::ptracer::Command;
pub use crate::ptracer::Ptracer;

use structopt::StructOpt;

// Super annoying thing: I can't seem to put them in the order I want, instead,
// it is based on alphabetical order...
// This is even after using the correct flag through clap.
#[derive(StructOpt, Debug)]
#[structopt(
    name = "dettracer",
    about = "A parallel dsynamic determinism enforcement program written in Rust"
)]
pub struct Opt {
    pub exe: String,
    pub args: Vec<String>,
}

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
