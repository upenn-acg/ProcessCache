use std::path::PathBuf;

use anyhow::Context;
use libc::{c_char, AT_FDCWD};
use nix::{
    fcntl::{readlink, OFlag},
    unistd::Pid,
};
use tracing::debug;

use crate::{
    cache_utils::generate_hash,
    context,
    recording::RcExecution,
    syscalls::{SyscallEvent, SyscallFailure, SyscallOutcome},
    Ptracer,
};

// "Create" designates that O_CREAT was used.
// This doesn't mean it succeeded to create, just
// that the flag was used.
pub fn generate_open_syscall_file_event(
    creat_flag: bool,
    excl_flag: bool,
    file_existed_at_start: bool,
    full_path: PathBuf,
    offset_mode: OFlag, // trunc, append, readonly. doesn't have to be a weird option anymore b/c
    open_mode: OFlag,
    syscall_outcome: Result<i32, i32>,
) -> Option<SyscallEvent> {
    if excl_flag && !creat_flag {
        panic!("Do not support for now. Also excl_flag but not creat_flag, baby what is you doin?");
    }

    if full_path.starts_with("/dev/null") {
        return None;
    }

    let starting_hash = if syscall_outcome.is_ok()
        && (offset_mode == OFlag::O_APPEND || offset_mode == OFlag::O_RDONLY)
    {
        Some(generate_hash(full_path))
    } else {
        None
    };
    if creat_flag {
        if excl_flag {
            match syscall_outcome {
                Ok(_) => Some(SyscallEvent::Create(
                    OFlag::O_CREAT,
                    SyscallOutcome::Success,
                )),
                Err(ret_val) => match ret_val {
                    -13 => Some(SyscallEvent::Create(
                        OFlag::O_CREAT,
                        // I know it's either WRITE or EXEC access denied.
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                    )),
                    -17 => Some(SyscallEvent::Create(
                        OFlag::O_CREAT,
                        SyscallOutcome::Fail(SyscallFailure::AlreadyExists),
                    )),
                    _ => panic!(
                        "O_CREAT + O_EXCL, syscall failed, but not for EACCES or EEXIST :{}",
                        ret_val
                    ),
                },
            }
        } else {
            match syscall_outcome {
                Ok(_) => {
                    if file_existed_at_start {
                        match (offset_mode, open_mode) {
                            (_, OFlag::O_RDONLY) => {
                                panic!("O_CREAT + O_RDONLY AND the system call succeeded????")
                            }
                            (_, OFlag::O_RDWR) => panic!("Do not support RW for now..."),
                            (OFlag::O_RDONLY, OFlag::O_WRONLY) => {
                                panic!("Do not support O_WRONLY without offset flag!")
                            }
                            (OFlag::O_APPEND, OFlag::O_WRONLY) => {
                                Some(SyscallEvent::Open(OFlag::O_APPEND, starting_hash, SyscallOutcome::Success))
                            }
                            (OFlag::O_TRUNC, OFlag::O_WRONLY) => {
                                Some(SyscallEvent::Open(OFlag::O_TRUNC, starting_hash, SyscallOutcome::Success))
                            }
                            (offset_flag, mode_flag) => panic!("Unexpected offset flag: {:?} and mode flag: {:?}", offset_flag, mode_flag),
                        }
                    } else {
                        Some(SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Success))
                    }
                }
                Err(ret_val) => match ret_val {
                    // More accurately, some "path component" doesn't exist, but they don't know that,
                    // and so we don't, and so y'all get a generic error. 
                    // Linux is NOT a generous god.
                    // And neither am I.
                    -2 => Some(SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Fail(SyscallFailure::FileDoesntExist))),
                    -13 => Some(SyscallEvent::Create(OFlag::O_CREAT, SyscallOutcome::Fail(SyscallFailure::PermissionDenied))),
                    _ => panic!("O_CREAT and failed but not because access denied or path component doesn't exist?"),
                }
            }
        }
    } else {
        // Only opens file, no need to worry about it creating a file.
        match syscall_outcome {
            Ok(_) => match (offset_mode, open_mode) {
                // TODO: Hmm. There should be a case for
                // (None, OpenOFlag::O_RDONLY)
                // Successfully opened a file for reading (NO O_CREAT FLAG), this means the
                // file existed.
                // Retval is pretty useless here but whatever.
                (OFlag::O_RDONLY, OFlag::O_RDONLY) => Some(SyscallEvent::Open(
                    OFlag::O_RDONLY,
                    starting_hash,
                    SyscallOutcome::Success,
                )),
                (OFlag::O_TRUNC | OFlag::O_APPEND, OFlag::O_RDONLY) => {
                    panic!("Undefined by POSIX/LINUX.")
                }
                (_, OFlag::O_RDWR) => panic!("Do not support RW for now..."),
                // "ReadOnly" is like my "None" offset flag. and it kinda makes sense
                (OFlag::O_RDONLY, OFlag::O_WRONLY) => {
                    panic!("Do not support O_WRONLY without offset flag!")
                }
                (OFlag::O_APPEND, OFlag::O_WRONLY) => Some(SyscallEvent::Open(
                    OFlag::O_APPEND,
                    starting_hash,
                    SyscallOutcome::Success,
                )),
                (OFlag::O_TRUNC, OFlag::O_WRONLY) => Some(SyscallEvent::Open(
                    OFlag::O_TRUNC,
                    starting_hash,
                    SyscallOutcome::Success,
                )),
                (offset_flag, mode_flag) => panic!(
                    "Unexpected offset flag: {:?} and mode flag: {:?}",
                    offset_flag, mode_flag
                ),
            },
            Err(ret_val) => match ret_val {
                // ENOENT
                -2 => Some(SyscallEvent::Open(
                    offset_mode,
                    starting_hash,
                    SyscallOutcome::Fail(SyscallFailure::FileDoesntExist),
                )),
                // EACCES
                -13 => match offset_mode {
                    OFlag::O_APPEND | OFlag::O_TRUNC => Some(SyscallEvent::Open(
                        offset_mode,
                        starting_hash,
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                    )),
                    _ => Some(SyscallEvent::Open(
                        offset_mode,
                        starting_hash,
                        SyscallOutcome::Fail(SyscallFailure::PermissionDenied),
                    )),
                },
                _ => panic!(
                    "Failed to open file NOT because ENOENT or EACCES, err num: {}",
                    ret_val
                ),
            },
        }
    }
}

// Currently: stat, fstat, newfstat64
// We consider these syscalls to be inputs.
// Well the files they are acting upon anyway!
pub fn get_full_path(
    curr_execution: &RcExecution,
    syscall_name: &str,
    tracer: &Ptracer,
) -> anyhow::Result<PathBuf> {
    let regs = tracer
        .get_registers()
        .with_context(|| context!("Failed to get regs in exec event"))?;

    let path_arg_bytes = match syscall_name {
        "access" | "creat" | "open" | "stat" | "unlink" => regs.arg1::<*const c_char>(),
        "openat" | "unlinkat" => regs.arg2::<*const c_char>(),
        _ => panic!("Not handling an appropriate system call in get_full_path!"),
    };

    let path_arg = tracer
        .read_c_string(path_arg_bytes)
        .with_context(|| context!("Cannot read `open` path."))?;
    let file_name_arg = PathBuf::from(path_arg);

    let full_path = if file_name_arg.starts_with("/") {
        file_name_arg
    } else {
        match syscall_name {
            "access" | "creat" | "open" | "stat" | "unlink" => {
                let cwd = curr_execution.starting_cwd();
                cwd.join(file_name_arg)
            }
            "openat" | "unlinkat" => {
                let dir_fd = regs.arg1::<i32>();
                let dir_path = if dir_fd == AT_FDCWD {
                    curr_execution.starting_cwd()
                } else {
                    path_from_fd(tracer.curr_proc, dir_fd)?
                };

                debug!("in get_full_path(), dir fd is: {}", dir_fd);
                dir_path.join(file_name_arg)
            }
            s => panic!("Unhandled syscall in get_full_path(): {}!", s),
        }
    };

    Ok(full_path)
}

pub fn path_from_fd(pid: Pid, fd: i32) -> anyhow::Result<PathBuf> {
    debug!("In path_from_fd()");
    let proc_path = format!("/proc/{}/fd/{}", pid, fd);
    let proc_path = readlink(proc_path.as_str())?;
    Ok(PathBuf::from(proc_path))
}
