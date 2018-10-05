use std::str::FromStr;
use structopt::clap::AppSettings;
use structopt::StructOpt;

#[derive(PartialEq, Eq, Debug)]
pub enum RunType {
    All,
    None,
    Top20,
    Bottom20
}

// Super annoything: I can't seem to put them in the order I want, instead,
// it is based on alphabetical order...
#[derive(StructOpt, Debug)]
#[structopt(name = "dettracer", about = "A simple dettracer written in Rust")]
pub struct Opt {
    #[structopt(long = "run_type")]
    pub arg_type: String,
    #[structopt(long = "program")]
    pub prog: String,
    pub prog_args: Vec<String>,
}


