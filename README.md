# ProcessCache

This is the implementation of ProcessCache: a system that tracks the inputs and outputs to automatically memoize Linux `exec` calls. This roughly translate to memoizing Linux processes.

## Installation
Given a proper cargo set up. `cargo build` works using rustc 1.47.0. It should work for any newer version though.

## Usage
Currently simple programs work:

```
cargo run pwd
```

## Contributing
Please see: [CONTRIBUTING.md](./CONTRIBUTING.md) for information on how to contribute to the project.
