# cargo-remote

This is a fork of https://github.com/sgeisler/cargo-remote, adapted for use with nix-based rust projects.

## Concept

Using ssh + rsync, this cargo subcommand (`cargo remote build`, `cargo remote check`, ...) copies your git-tracked source files
to a remote build machine, uses `nix develop` to launch itself into a development environment with the appropriate compilers and
tools installed, and then copies the executable artifacts back to your local machine. The idea is to speed up builds by using a
powerful cloud server or something.

## Requirements

This code is specifically designed to work projects whose development environment can be activated with `nix develop` (i.e. [nix flakes](https://serokell.io/blog/practical-nix-flakes). It must be run from a git-tracked directory containing both a`flake.nix` and `Cargo.toml` file. It's also currently x86-64 only.

The remote server that you connect to must be accessible via ssh with passwordless login, and must have (flake-enabled) nix and rsync installed.

## Usage

```
$ cargo remote -h
cargo-remote 0.1.0
EXAMPLE
    cargo remote -r my.server.com build

USAGE:
    cargo-remote [OPTIONS] <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -r, --remote-host <remote-host>    Remote hostname or ssh alias

SUBCOMMANDS:
    build     Compile the current package (remotely)
    check     Analyze the current package and report errors, but don't build object files (remotely)
    clean     Remove the target directory (remotely)
    help      Prints this message or the help of the given subcommand(s)
    tunnel    Establish a persistent tunnel to the remote nix environment

```
