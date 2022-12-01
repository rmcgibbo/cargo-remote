{
  inputs = {
    nixpkgs.url = github:NixOS/nixpkgs/nixpkgs-unstable;
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    naersk.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.inputs.flake-utils.follows = "utils";
  };

  outputs = { self, nixpkgs, naersk, rust-overlay, utils }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" ];
          targets = [ "x86_64-unknown-linux-musl" ];
        };
        naersk-lib = naersk.lib."${system}".override {
          rustc = rust;
          cargo = rust;
        };
        # Utility for merging the common cargo configuration with the target
        # specific configuration.
        naerskBuildPackage = target: args: naersk-lib.buildPackage
          (args // { CARGO_BUILD_TARGET = target; } // cargoConfig);
        # All of the CARGO_* configurations which should be used for all
        # targets. Only use this for options which should be universally
        # applied or which can be applied to a specific target triple.
        # This is also merged into the devShell.
        cargoConfig = {
          # Enables static compilation.
          #
          # If the resulting executable is still considered dynamically
          # linked by ldd but doesn't have anything actually linked to it,
          # don't worry. It's still statically linked. It just has static
          # position independent execution enabled.
          # ref: https://doc.rust-lang.org/cargo/reference/config.html#targettriplerustflags
          CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C target-feature=+crt-static";
        };
      in
      rec {
        defaultPackage = packages.x86_64-unknown-linux-musl;

        # The rust compiler is internally a cross compiler, so a single
        # toolchain can be used to compile multiple targets. In a hermetic
        # build system like nix flakes, there's effectively one package for
        # every permutation of the supported hosts and targets.
        # i.e.: nix build .#packages.x86_64-linux.x86_64-pc-windows-gnu
        # where x86_64-linux is the host and x86_64-pc-windows-gnu is the
        # target
        packages.x86_64-unknown-linux-musl = naerskBuildPackage "x86_64-unknown-linux-musl" {
          src = ./.;
          nativeBuildInputs = with pkgs; [ pkgsStatic.stdenv.cc lld_13 ];
          buildInputs = with pkgs; [
            openssh
            rsync
            git
          ];
          preBuild = ''
            export CARGO_REMOTE_SSH=$(command -v ssh)
            export CARGO_REMOTE_RSYNC=$(command -v rsync)
            export CARGO_REMOTE_GIT=$(command -v git)
          '';
          doCheck = true;
        };


        checks = {
          cargo-check = naerskBuildPackage "x86_64-unknown-linux-musl" {
            src = ./.;
            cargoBuild = x: ''cargo $cargo_options check $cargo_build_options >> $cargo_build_output_json'';
          };
        };

        devShell = pkgs.mkShell (rec {
          name = "cargo-remote";
          shellHook = ''
            export PS1="\n(${name}) \[\033[1;32m\][\[\e]0;\u@\h: \w\a\]\u@\h:\w]\[\033[0m\]\n$ "
            ${packages.x86_64-unknown-linux-musl.preBuild}
          '';
          inputsFrom = [ packages.x86_64-unknown-linux-musl ];
          buildInputs = with pkgs; [
            openssh
            rsync
            git
          ];
          CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
        } // cargoConfig
        );
      }
    );
}
