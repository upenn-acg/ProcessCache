use std::process::Command;

fn main() {
    let exec = String::from("./target/debug/simplest_ex_child");

    let mut job = Command::new(exec).spawn().expect("failed to run job");
    let _ = job.wait().expect("couldn't wait on job");
}
