use conflict_tracer;
use conflict_tracer::{Command, Ptracer};
use tracing_subscriber::filter::EnvFilter;

use structopt::StructOpt;

// Super annoying thing: I can't seem to put them in the order I want, instead,
// it is based on alphabetical order...
// This is even after using the correct flag through clap.
#[derive(StructOpt, Debug)]
#[structopt(
    name = "dettracer",
    about = "A parallel dynamic determinism enforcement program written in Rust"
)]
pub struct Opt {
    pub exe: String,
    pub args: Vec<String>,
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
