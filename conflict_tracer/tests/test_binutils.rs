use std::io::{self, Write};
use std::process::Command;

// NB: cwd when running these tests is ProcessCache/

// pwd test
#[test]
fn pwd() -> io::Result<()> {
    let mut cmd = Command::new("../target/debug/conflict_tracer");
    cmd.arg("pwd");
    assert!(cmd.status()?.success());
    Ok(())
}

//sleep 1 test
#[test]
fn sleep1() -> io::Result<()> {
    let mut cmd = Command::new("../target/debug/conflict_tracer");
    cmd.args(&["sleep", "1"]);
    let output = cmd.output()?;
    println!("status: {}", output.status);
    io::stdout().write_all(&output.stdout)?;
    io::stderr().write_all(&output.stdout)?;
    assert!(output.status.success());
    Ok(())
}

//ls -lh /usr/lib
#[test]
fn usr_lib() -> io::Result<()> {
    let output = Command::new("../target/debug/conflict_tracer")
        .args(&["ls", "/usr/lib"])
        .output()?;

    println!("status: {}", output.status);
    io::stdout().write_all(&output.stdout)?;
    io::stdout().write_all(&output.stderr)?;
    assert!(output.status.success());
    Ok(())
}

//time pwd
#[test]
fn time_pwd() -> io::Result<()> {
    let mut cmd = Command::new("../target/debug/conflict_tracer");
    cmd.arg("time");
    cmd.arg("pwd");
    assert!(cmd.status()?.success());
    Ok(())
}
