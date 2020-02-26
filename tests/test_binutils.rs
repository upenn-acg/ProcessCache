use std::process::Command;
use std::io::{self, Write};

// NB: cwd when running these tests is ProcessCache/

// pwd test
#[test]
fn pwd() {
    let mut cmd = Command::new("target/debug/conflict_tracer");
    cmd.arg("pwd"); 
    assert!(cmd.status().expect("incorrect running pwd").success());
}

//sleep 1 test
#[test]
fn sleep1() {
    let mut cmd = Command::new("target/debug/conflict_tracer");
    cmd.args(&["sleep", "1"]); 
    let output = cmd.output().expect("incorrect running sleep 1");
    println!("status: {}", output.status);
    io::stdout().write_all(&output.stdout).unwrap();
    io::stderr().write_all(&output.stdout).unwrap();
    assert!(output.status.success());
}

//ls -lh /usr/lib
#[test]
fn usr_lib() {
    let output = Command::new("target/debug/conflict_tracer")
					.args(&["ls", "/usr/lib"])
    				.output()
    				.expect("error running usr_lib");

    println!("status: {}", output.status);
    io::stdout().write_all(&output.stdout).unwrap();
    io::stdout().write_all(&output.stderr).unwrap();
    assert!(output.status.success());
}

//time pwd
#[test]
fn time_pwd() {
    let mut cmd = Command::new("target/debug/conflict_tracer");
    cmd.arg("time"); 
    cmd.arg("pwd");
    assert!(cmd.status().expect("error running time & pwd").success());
}

//




