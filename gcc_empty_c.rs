use std::process::Command;

fn main() {
    let exec = String::from("gcc");
    let args = vec![
        String::from("./c_examples/empty_c.c"),
        String::from("-o"),
        String::from("empty_c"),
    ];
    let mut job = Command::new(exec)
        .args(args)
        .spawn()
        .expect("failed to run gcc");
    let _ = job.wait().expect("couldn't wait on gcc job");
}
