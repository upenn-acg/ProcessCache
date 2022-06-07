use nix::pty::SessionId;

use std::{
    collections::hash_map::DefaultHasher,
    fs::File,
    hash::{Hash, Hasher},
    io::Read,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CachedExecMetadata {
    caller_pid: SessionId,
    command: Command,
    env_vars: Vec<String>,
    // Currently this is just the first argument to execve
    // so I am not making sure it's the abosolute path.
    // May want to do that in the future?
    starting_cwd: PathBuf,
}

impl CachedExecMetadata {
    pub fn new(
        caller_pid: SessionId,
        command: Command,
        env_vars: Vec<String>,
        starting_cwd: PathBuf,
    ) -> CachedExecMetadata {
        CachedExecMetadata {
            caller_pid,
            command,
            env_vars,
            starting_cwd,
        }
    }

    pub fn caller_pid(&self) -> SessionId {
        self.caller_pid
    }

    pub fn command(&self) -> Command {
        self.command.clone()
    }

    pub fn starting_cwd(&self) -> PathBuf {
        self.starting_cwd.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Command(pub String, pub Vec<String>);

impl Command {
    pub fn new(exe: String, args: Vec<String>) -> Self {
        Command(exe, args)
    }
}

pub fn generate_hash(path: PathBuf) -> Vec<u8> {
    // let s = span!(Level::INFO, stringify!(generate_hash), pid=?caller_pid);
    // let _ = s.enter();
    // s.in_scope(|| info!("Made it to generate_hash for path: {}", path));
    if !path.is_dir() {
        let file = File::open(&path);
        if let Ok(mut f) = file {
            process::<Sha256, _>(&mut f)
        } else {
            panic!("Cannot open file for hashing: {:?}", path);
        }
    } else {
        Vec::new()
    }
}

pub fn hash_command(command: Command) -> u64 {
    let mut hasher = DefaultHasher::new();
    command.hash(&mut hasher);

    hasher.finish()
}

// ------ Hashing stuff ------
// Process the file and generate the hash.
fn process<D: Digest + Default, R: Read>(reader: &mut R) -> Vec<u8> {
    const BUFFER_SIZE: usize = 1024;
    let mut sh = D::default();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = reader
            .read(&mut buffer)
            .expect("Could not read buffer from reader processing hash!");
        sh.update(&buffer[..n]);
        if n == 0 || n < BUFFER_SIZE {
            break;
        }
    }
    let final_array = &sh.finalize();
    final_array.to_vec()
}
