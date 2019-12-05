use structopt::StructOpt;


// Super annoying thing: I can't seem to put them in the order I want, instead,
// it is based on alphabetical order...
// This is even after using the correct flag through clap.
#[derive(StructOpt, Debug)]
#[structopt(name = "dettracer",
            about = "A parallel dynamic determinism enforcement program written in Rust")]
pub struct Opt {
    pub exe: String,
    pub args: Vec<String>,
}


