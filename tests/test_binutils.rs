use std::process::Command;

// NB: cwd when running these tests is ProcessCache/

#[test]
fn pwd() {
    let mut cmd = Command::new("target/debug/conflict_tracer");
    cmd.arg("pwd"); 
    cmd.status().expect("error running pwd");
}

// TODO: sleep 1
// TODO: ls -lh /usr/lib
// TODO: time pwd
