# ProcessCache

This is the implementation of ProcessCache: a system for automatic caching of arbitrary Linux programs at the process level.

## Installation
Given a proper cargo set up, `cargo build` works using rustc 1.67.0. It should work for any newer version though.

## Usage
Process Cache is fairly robust. It should work with most programs that are not interactive and do not require networking.

To cache ls under Process Cache:
```
cargo run ls
```

This will cache the results in /cache. The next time this program is invoked with Process Cache, the system will determine whether
it can be skipped.

## Contributing
Please see: [CONTRIBUTING.md](./CONTRIBUTING.md) for information on how to contribute to the project.
