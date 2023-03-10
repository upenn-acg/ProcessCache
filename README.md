# ProcessCache

This is the implementation of ProcessCache: a system for automatic caching of arbitrary Linux programs at the process level. It traces your process and its inputs and outputs for potential skipping later.

ProcessCache achieves multiple goals:
- **Easy to use.** Just pull it down and run `./process_cache your_program`
- **Agnostic / general.** Because ProcessCache works at the system call level caching processes, it can work with most programs.
- **Improves performance.** Skipping your process saves you on computation time, and caching your process doesn't introduce egregious overheads.

The cache unit in ProcessCache starts when a process calls `execve`, and ends when the process exits. This was chosen because: the inputs and outputs obvious and the computation easy to identify uniquely, and provides obvious start and end points.

ProcessCache can cache single process programs, multithreaded programs, and multiprocess programs. For multiprocess programs, it can even cache the nested executions of child progeny.

You don't have to worry about running ProcessCache in "caching" or "skipping" mode -- it is always doing both, automatically! At each `execve` barrier, ProcessCache decides whether to cache or skip this execution.

ProcessCache helps with _dependency hell_. Many build systems exist, but they require the user to specify their dependencies, which is fraught with user error. Process Cache works at a low-level (system calls), it learns the dependencies as it caches, no need to specify. But, ProcessCache is designed to be as program agnostic as possible, and works great for other types of programs, such as incremental or batch processing programs (like bash scripts) or highly parallel programs (like data processing workloads).

ProcessCache uses the traced information to generate what we call _preconditions_ and _postconditions_.

- Preconditions: the facts that must to be true to skip a process (i.e. the inputs)
- Postconditions: the facts that are true at the end of execution (i.e. the outputs)

Example: `open_file.c`
```
int main() {
    int fd = openat(AT_FDCWD, "file.txt", O_WRONLY | O_APPEND);
    printf("fd is: %d\n", fd);
}
```
Preconditions:
- `file.txt` exists
- `file.txt` has certain starting contents
- this process has write access to the file
- this process has executable (search) access to the parent directory

Postconditions:
- `file.txt` has certain final contents

## System Components
TODO: component diagram coming ASAP!

## Installation
Given a proper cargo set up. `cargo build` works using rustc 1.67.0. It should work for any newer version though.

## Usage
Note: examples use the `release` build of ProcessCache, to ensure its the fastest version of ProcessCache available.

Example: **ls**

To cache ls under ProcessCache:
```
cargo run ls
```
This will trace the program that runs ls. You should see a new `/cache` directory appear in your cwd. It will contain a file called `cache`; this is the serialized cache data structure. It will also contain another directory that is a long number (it's a hash, but you don't need to worry about that dear user!). This folder in the cache contains the outputs for the execution we just cached: ls! The outputs are just the contents of your cwd printed to stdout, because that's all ls does. If you look in your cache subdir (the number one), you should see a file called `stdout_pid` (where pid is a number, the process id that ran your ls, to be exact). If you call `cat stdout_pid`, you should see exactly what you would see if you ran ls.

If you run
```
cargo run ls
```
again, ProcessCache will skip the ls command, simply printing from the cached `stdout_pid` file.

To run something slightly more complicated, say with more command line arguments, run it under ProcessCache like so:

```
./target/release/process_cache -- ls -ahl
```

### Flags and Options
For most users, just ProcessCache main branch should work fine. For curious (determined?) users, ProcessCache has a built-in logging system, so you can see exactly what is happening when it caches and skips. The logging is built with the Rust tracing crate. Different levels of logging exist, like `debug` and `info`, see the Rust tracing documentation for more information about the different logging levels available. To log your program as it runs under ProcessCache:

```
RUST_LOG=debug ./target/release/process_cache -- ls
```

There are many in-code flags that can used to turn parts of the program on and off. _These are there strictly for benchmarking purposes, and changing them will result in ProcessCache not operating correctly and completely._ Examples include: `PTRACE_ONLY` and `FACT_GEN`. More information on these can be found in the in-code documentation.

Processes often use pipes to communicate. But, some processes even go so far as to close their own stdout fd, then create the pipe they are going to use to communicate with, leading to the pipe having fd stdout used to have. Because we redirect stdout in order to cache it as an output, this can lead to issues in the program. For programs like this, ProcessCache has a _no stdout_ option. It will eventually be merged into master with a flag option, but until then it is housed in the branch `master_no_stdout`.

## Limitations
ProcessCache strives to be as agnostic as possible, so that most programs can benefit from it. But, some problems are just way more challenging than others to solve.

#### Pipes / Signals (Between Processes)
ProcessCache caches multiprocess programs that use pipes to communicate as one big execution. If each process was cached separately, one process could be skipped, and another rerun, leading to broken pipes. If a program uses the `O_CLOEXEC` flag to create its pipes, this can be cached normally. ProcessCache also does not support sending signals between user processes as issues similar to pipes can occur.

#### Interactive Programs
If a user needs to input something in the middle of a program, ProcessCache cannot skip to that exact point in the program, and then resume correctly from there. ProcessCache makes cache/skip decisions at the boundary of `execve`. If ProcessCache detects a program is interactive, it stops tracing it and lets it run normally without caching it.

#### Networking
ProcessCache cannot cache processes that use sockets or otherwise perform networking. ProcessCache must check the inputs of process at the start of execution, but sockets are constantly receiving new inputs, and ProcessCache cannot jump to these points in the program and then continue easily and correctly.

## Benchmarks
We have run ProcessCache under a variety of benchmarks, which can be found in this repository.

## Contributing
Please see: [CONTRIBUTING.md](./CONTRIBUTING.md) for information on how to contribute to the project.
