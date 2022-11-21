use crossbeam::channel::Receiver;

use std::{
    fs::{self, metadata},
    os::linux::fs::MetadataExt,
    path::PathBuf,
    // sync::mpsc::Receiver,
};

use anyhow::Context;
use libc::{c_char, AT_FDCWD};
use nix::{
    fcntl::{readlink, OFlag},
    unistd::Pid,
};
use tracing::debug;

use crate::{
    cache_utils::{hash_command, Command},
    context,
    recording::{LinkType, RcExecution},
    syscalls::{
        AccessMode, CheckMechanism, OffsetMode, OpenFlags, SyscallEvent, SyscallFailure,
        SyscallOutcome,
    },
    Ptracer,
};

const DONT_HASH_FILES: bool = false;

pub fn background_thread_copying_outputs(recv_end: Receiver<(LinkType, PathBuf, PathBuf)>) {
    while let Ok((link_type, source, dest)) = recv_end.recv() {
        if link_type == LinkType::Copy {
            // fs::copy(source.clone(), dest).unwrap();
            match fs::copy(source.clone(), dest.clone()) {
                Ok(_) => (),
                Err(e) => panic!(
                    "Failed to copy source: {:?}, dest: {:?}, error: {:?}",
                    source, dest, e
                ),
            }
            let source_str = source.clone().into_os_string().into_string().unwrap();
            // The thread removes the old stdout files once they have been moved to the cache.
            // We don't want to do this if we are hardlinking the child's stdout file from
            // the child's cache to the parent's cache. Because then we are just deleting
            // from the child's cache -.-
            if source_str.contains("stdout") && source.exists() {
                fs::remove_file(source).unwrap();
            }
        } else {
            fs::hard_link(source.clone(), dest).unwrap();
        }
    }
}

// "Create" designates that O_CREAT was used.
// This doesn't mean it succeeded to create, just
// that the flag was used.
pub fn generate_open_syscall_file_event(
    curr_execution: &RcExecution,
    full_path: PathBuf,
    open_flags: OpenFlags,
    syscall_outcome: Result<i32, i32>,
) -> Option<SyscallEvent> {
    if open_flags.excl_flag && !open_flags.creat_flag {
        panic!("Do not support for now. Also excl_flag but not creat_flag, baby what is you doin?");
    }

    if full_path.starts_with("/dev/null") {
        return None;
    }

    if full_path.starts_with("/tmp")
        || full_path.starts_with("/temp")
        || full_path.starts_with("/proc")
        || full_path.starts_with("/usr")
        || full_path.starts_with("/etc")
    {
        return None;
    }

    // HERE!! THIS IS WHERE YOU DECIDE BETWEEN
    // - HASHING
    // - MTIME
    // - COPYING FILES
    let optional_checking_mech = if DONT_HASH_FILES {
        None
    } else if syscall_outcome.is_ok()
        && (open_flags.offset_mode == Some(OffsetMode::Append)
            || open_flags.access_mode == AccessMode::Read)
    {
        // DIFF FILES
        // Some(CheckMechanism::DiffFiles)
        // HASH
        // Some(CheckMechanism::Hash(generate_hash(full_path.clone())))
        // MTIME
        let curr_metadata = metadata(&full_path).unwrap();
        Some(CheckMechanism::Mtime(curr_metadata.st_mtime()))
    } else {
        None
    };

    if open_flags.creat_flag {
        if open_flags.excl_flag {
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
                    if open_flags.file_existed_at_start {
                        match (open_flags.offset_mode.clone(), open_flags.access_mode) {
                            (Some(mode), AccessMode::Read) => panic!("Offset mode {:?}, opened for reading!!", mode),
                            (offset_mode, access_mode) => Some(SyscallEvent::Open(access_mode, offset_mode, optional_checking_mech, SyscallOutcome::Success))
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
            Ok(_) => {
                // TODO: Hmm. There should be a case for
                // (None, OpenOFlag::O_RDONLY)
                // Successfully opened a file for reading (NO O_CREAT FLAG), this means the
                // file existed.
                // Retval is pretty useless here but whatever.

                // If access mode is read OR offset mode is append,
                // and if precondition checking mechanism is DiffFiles,
                // copy input file to the cache.
                if let Some(mech) = optional_checking_mech.clone() {
                    if (open_flags.offset_mode == Some(OffsetMode::Append)
                        || open_flags.access_mode == AccessMode::Read)
                        && mech == CheckMechanism::DiffFiles
                    {
                        copy_input_file_to_cache(curr_execution, full_path);
                    }
                }

                match (open_flags.offset_mode.clone(), open_flags.access_mode) {
                    (Some(mode), AccessMode::Read) => {
                        panic!("Offset mode {:?}, opened for reading!!", mode)
                    }
                    (offset_mode, access_mode) => Some(SyscallEvent::Open(
                        access_mode,
                        offset_mode,
                        optional_checking_mech,
                        SyscallOutcome::Success,
                    )),
                }
            }
            Err(ret_val) => {
                let syscall_failure = match ret_val {
                    // ENOENT
                    -2 => SyscallFailure::FileDoesntExist,
                    // EACCES
                    -13 => SyscallFailure::PermissionDenied,
                    _ => panic!(
                        "Failed to open file NOT because ENOENT or EACCES, err num: {}",
                        ret_val
                    ),
                };
                Some(SyscallEvent::Open(
                    open_flags.access_mode,
                    open_flags.offset_mode,
                    optional_checking_mech,
                    SyscallOutcome::Fail(syscall_failure),
                ))
            }
        }
    }
}

fn copy_input_file_to_cache(curr_execution: &RcExecution, input_file_path: PathBuf) {
    const CACHE_LOCATION: &str = "./cache";
    let cache_dir = PathBuf::from(CACHE_LOCATION);
    let input_str = PathBuf::from("input_files");

    let command = Command(curr_execution.executable(), curr_execution.args());
    let hashed_command = hash_command(command);
    let cache_subdir_hashed_command = cache_dir.join(hashed_command.to_string());
    let cache_subdir_hashed_command_inputs_dir = cache_subdir_hashed_command.join(input_str);

    if !cache_subdir_hashed_command_inputs_dir.exists() {
        fs::create_dir(cache_subdir_hashed_command_inputs_dir.clone()).unwrap();
    }

    let cache_input_file_path =
        cache_subdir_hashed_command_inputs_dir.join(input_file_path.file_name().unwrap());
    if input_file_path.exists() && !input_file_path.is_dir() {
        fs::copy(input_file_path, cache_input_file_path).unwrap();
    }
}

// TODO: clean this up
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
        "access" | "creat" | "lstat" | "mkdir" | "open" | "stat" | "statfs" | "unlink" => {
            regs.arg1::<*const c_char>()
        }
        "mkdirat" | "openat" | "unlinkat" => regs.arg2::<*const c_char>(),
        _ => panic!("Not handling an appropriate system call in get_full_path!"),
    };

    let path_arg = tracer
        .read_c_string(path_arg_bytes)
        .with_context(|| context!("Cannot read `open` path."))?;
    let file_name_arg = PathBuf::from(path_arg);

    let full_path =
        if file_name_arg.starts_with("/") && syscall_name != "mkdir" && syscall_name != "mkdirat" {
            file_name_arg
        } else {
            let cwd = curr_execution.cwd();
            match syscall_name {
                "access" | "creat" | "lstat" | "mkdir" | "open" | "stat" | "statfs" | "unlink" => {
                    cwd.join(file_name_arg)
                }
                // TODO: what the heck is this?
                // TODO: is ../ handled? no?
                "mkdirat" | "openat" | "unlinkat" => {
                    let file_name_arg_string = file_name_arg
                        .clone()
                        .into_os_string()
                        .into_string()
                        .unwrap();
                    if file_name_arg_string.starts_with('.') {
                        let idx = file_name_arg_string.chars().position(|c| c == '.').unwrap();
                        let file_name_without_dot = &file_name_arg_string[idx + 1..];
                        let path_buf = String::from(file_name_without_dot);
                        let mut str_cwd = cwd.into_os_string().into_string().unwrap();

                        str_cwd.push_str(&path_buf);
                        PathBuf::from(str_cwd)
                    } else {
                        let dir_fd = regs.arg1::<i32>();
                        let dir_path = if dir_fd == AT_FDCWD {
                            curr_execution.cwd()
                        } else {
                            path_from_fd(tracer.curr_proc, dir_fd)?
                        };

                        debug!("in get_full_path(), dir fd is: {}", dir_fd);
                        dir_path.join(file_name_arg)
                    }
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

pub fn get_umask(pid: &Pid) -> u32 {
    let status_file = format!("/proc/{}/status", pid.as_raw());
    let umask: u32 = fs::read_to_string(&status_file)
        .expect(&format!("error reading {}", status_file))
        .split("\n")
        .filter(|l| l.starts_with("Umask:"))
        .map(|l| u32::from_str_radix(l.split_once(":").unwrap().1.trim(), 8).unwrap())
        .collect::<Vec<u32>>()
        .pop()
        .unwrap();
    debug!("recording umask 0{:o}", umask);
    umask
}
