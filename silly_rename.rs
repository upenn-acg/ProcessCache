use std::process::Command;

fn main() {
    let mut job = Command::new("mv")
        .args([
            "/home/kelly/research/IOTracker/kelly.txt",
            "/home/kelly/research/IOTracker/alex.txt",
        ])
        .spawn()
        .expect("failed");

    let _ = job.wait().expect("failed to wait");
}
