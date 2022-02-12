use crate::tracer::TraceEvent;
use crate::{context, Ptracer};
use anyhow::{bail, Context};
use libc::c_char;
use tracing::info;

/// Redirect the io stream on the tracee to the file specified by `file_name`.
pub async fn redirect_io_stream(
    file_name: &str,
    io_stream: u32,
    tracer: &mut Ptracer,
) -> anyhow::Result<()> {
    // Redirect stdout of this process file of our choosing.
    // 1) Write file name to red zone in tracee.
    // 2) Inject create system call.
    //    - Check retval of open call, use fd as argument for dup.
    // 3) Inject dup system call.
    //    - Check retval of dup call,
    // dup2(new_fd, stdout);

    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs."))?;
    let prev_regs1 = regs.clone();
    let prev_regs2 = regs.clone();

    // Write our string to the **red zone**.
    const RED_ZONE_SIZE: usize = 128;
    // - 1 because of the null terminator, which Rust does not include in `.len()`.
    let cstr_address = (regs.rsp::<usize>() - RED_ZONE_SIZE - file_name.len() - 1) as *const c_char;

    tracer
        .write_as_c_string(file_name, cstr_address)
        .with_context(|| context!("Cannot write string to red zone!"))?;

    // Inject creat call into tracee.
    let mut new_regs = regs.make_modified();
    new_regs.write_arg1(cstr_address as u64);
    new_regs.write_arg2((libc::S_IRWXU | libc::S_IRWXG) as u64);

    let injected = tracer
        .inject_system_call(libc::SYS_creat, prev_regs1, new_regs)
        .with_context(|| context!("Could not inject creat."))?;

    // Go to posthook and see what happened.
    let regs = tracer
        .posthook()
        .await
        .with_context(|| context!("Failed while injecting creat."))?;

    let new_fd = if regs.retval::<i32>() < 0 {
        bail!(context!(
            "Unable to creat file. Error code: {:?}",
            regs.retval::<i32>()
        ));
    } else {
        info!(
            "Output redirection file created. fd: {:?}",
            regs.retval::<i32>()
        );
        regs.retval::<u64>()
    };

    // restore registers and rewind IP.
    let regs = injected
        .restore_state(&tracer)
        .with_context(|| context!("Unable to restore register state."))?;

    // Tell ptrace to get us back to the pre-hook (same RIP as before) we are "replaying" this same
    // exact system call.
    let event = tracer
        .get_next_event(None)
        .await
        .with_context(|| context!("Cannot ptrace next event."))?;

    match event {
        TraceEvent::Prehook(_) => {}
        e => bail!(context!("Unexpected ptrace event: {:?}", e)),
    }

    // Inject dup2(new_file_we_created, stdout);
    let mut new_regs = regs.make_modified();
    new_regs.write_arg1(new_fd);
    new_regs.write_arg2(io_stream as u64);

    let injected = tracer
        .inject_system_call(libc::SYS_dup2, prev_regs2, new_regs)
        .with_context(|| context!("Could not inject dup2."))?;

    // Go to posthook and see what happened.
    let regs = tracer
        .posthook()
        .await
        .with_context(|| context!("Failed while injecting dup2"))?;

    if regs.retval::<i32>() < 0 {
        bail!(context!(
            "Unable to dup2. Reason: {:?}",
            regs.retval::<i32>()
        ));
    }

    injected
        .restore_state(&tracer)
        .with_context(|| context!("Unable to restore register state."))?;

    info!("Output redirected to file!");
    Ok(())
}