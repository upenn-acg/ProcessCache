## Contribution Guidelines

Please follow the following guidelines for contributing to ProcessCache.

### Git/Github Workflow
1) Every commit should represent a working, testable, version of ProcessCache, please squash commits as needed to have every commit represent a logical, working state of ProcessCache.
2) Please add tests for any change made to ProcessCache if possible. This will avoid future regressions, and ensure your modifications works as intended.
3) Please submit a pull request with your changes. We should all do a better job and hold each other accountable for reviews and quick pull request merges to keep things moving along.
5) Use rebase instead of merge when updating your branch with the latest ProcessCache changes. For more information see Servo's ["Beginner's guide to rebasing and squashing"](https://github.com/servo/servo/wiki/Beginner's-guide-to-rebasing-and-squashing)
6) Keep pull request commit numbers short when possible. It is hard/impossible to follow pull requests consisting of too many commits!

### Continuous Integration
On every commit and pull request, your changes will run on Azure Pipelines. The project page can be found [here](https://dev.azure.com/upenn-acg/ProcessCache). The pipelines steps are specified by [this yaml file](./azure-pipelines.yml). The following checks will run on every commit:

- Style: Runs Rust's `rustfmt` and `clippy`. Make sure both report no warnings locally before pushing to github.
- Compile and Test: Runs `cargo check` and `cargo test` for both the latest stable and nightly Rust. We expect no warnings and all tests to pass.
- Docs: Runs `cargo doc` to check the documentation for the project builds.

If any of the above fail, your code will be rejected. See below for more on `rustfmt` and `clippy`.

### Skipping CI for some commit.
Sometimes it is wasteful to run the CI on certain commits (any changes that don't affect the code, e.g. committing a markdown file like this one!). You can add `[skip ci]` in the body of the commit message!

### Clippy and Rust Format
Clippy is the Rust linter with many helpful lints to keep your code idiomatic. Rust format is an automatic formatter for your Rust code (never worry about formatting your code again!). You may install both for your current default Rust toolchain by doing:
```shell
> rustup install cargo-fmt
> rustup component add clippy
```

Inside the project repository you can run the following commands to run either tool (it is that easy!). The code probably needs to be compiling for the tools to work.
```shell
> cargo clippy
> cargo fmt
```

Please run both tools before doing a pull request.

### Branches
The following are useful branches for the project:
- master: :bow:
- azure-pipeliness: If you wanna update anything about the CI, please make changes and pushes to this branch for pull requesting!
- documentation: Please commit here for any changes to the project README.md or CONTRIBUTING.md.
