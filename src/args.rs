use structopt::StructOpt;


#[derive(StructOpt, Debug)]
#[structopt(name = "stracer", about = "A simple stracer written in Rust")]
pub struct Opt {
    pub exe: String,
    pub exe_args: Vec<String>,
}
