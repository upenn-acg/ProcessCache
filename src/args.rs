#[derive(StructOpt, Debug)]
#[structopt(name = "dettracer", about = "A simple dettracer written in Rust")]
pub struct Opt {
    pub exe: String,
    pub exe_args: Vec<String>,
}
