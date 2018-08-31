use structopt::StructOpt;


#[derive(StructOpt, Debug)]
#[structopt(name = "stracer", about = "A simple stracer written in Rust")]
pub struct Opt {
    #[structopt(short = "t", long = "to_trace")]
    pub to_trace: Vec<String>,

    #[structopt(
        short = "d",
        long = "dont_trace",
        conflicts_with = "to_trace"
    )]
    pub dont_trace: Vec<String>,

    pub exe: String,
    pub exe_args: Vec<String>,
}
