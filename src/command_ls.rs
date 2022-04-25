use std::process::Command;

fn main() {
    Command::new("/usr/bin/ls")
            .spawn()
            .expect("ls failed to start");
}
