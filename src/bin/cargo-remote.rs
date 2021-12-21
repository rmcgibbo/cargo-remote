use std::io::Write;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use futures::StreamExt;
use hyper::Body;

use structopt::StructOpt;

use cargo_remote::tunnel::CargoRemoteTunnel;
use tracing::info;

#[derive(StructOpt)]
#[structopt(setting = structopt::clap::AppSettings::NoBinaryName)]
struct CargoRemoteOptions {
    /// Remote hostname or ssh alias
    #[structopt(short, long)]
    remote_host: Option<String>,

    #[structopt(subcommand)]
    cmd: CargoRemoteCommand,
}

#[derive(StructOpt)]
#[structopt(verbatim_doc_comment)]
/// EXAMPLE
///     cargo remote -r my.server.com build
enum CargoRemoteCommand {
    /// Establish a persistent tunnel to the remote nix environment
    Tunnel {},

    ///  Compile the current package (remotely)
    #[structopt(
        name = "build",
        aliases = &["b"],
        setting = structopt::clap::AppSettings::TrailingVarArg,
        setting = structopt::clap::AppSettings::AllowLeadingHyphen
    )]
    Build {
        #[structopt(name = "args")]
        args: Vec<String>,
    },

    ///  Analyze the current package and report errors, but don't build object files (remotely)
    #[structopt(
        name = "check",
        aliases = &["c"],
        setting = structopt::clap::AppSettings::TrailingVarArg,
        setting = structopt::clap::AppSettings::AllowLeadingHyphen
    )]
    Check {
        #[structopt(name = "args")]
        args: Vec<String>,
    },

    ///  Remove the target directory (remotely)
    #[structopt(
        name = "clean",
        setting = structopt::clap::AppSettings::TrailingVarArg,
        setting = structopt::clap::AppSettings::AllowLeadingHyphen
    )]
    Clean {
        #[structopt(name = "args")]
        args: Vec<String>,
    },
}

async fn execute() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .pretty()
        .init();

    let opts = match args.get(1) {
        Some(x) if x == "remote-server" => {
            let unix_socket_path = args.get(2).ok_or(anyhow!(
                "usage: cargo-remote remote-server <unix-socket-path."
            ))?;
            cargo_remote::remote_process::main(unix_socket_path).await?;
            return Ok(());
        }
        Some(x) if x == "remote" => {
            // when run as a cargo subprocess, "cargo remote [...]" invokes
            // `cargo-remote remote [...]`, with the extra argument of "remote"
            // in position 1, so let's just parse the arguments shifted by 1
            CargoRemoteOptions::from_iter(&args[2..])
        }
        Some(_) | None=> {
            // parse normally. since we have structopt::clap::AppSettings::NoBinaryName
            // we strip off the first argument here
            CargoRemoteOptions::from_iter(&args[1..])
        }
    };

    let exit_code = match opts.cmd {
        CargoRemoteCommand::Tunnel {} => main_tunnel(opts.remote_host).await,
        CargoRemoteCommand::Build { args } => {
            let args = [&["build".to_owned()], &args as &[String]].concat();
            main_build(opts.remote_host, args, TransferBack::TargetsOnSuccess).await
        }
        CargoRemoteCommand::Check { args } => {
            let args = [&["check".to_owned()], &args as &[String]].concat();
            main_build(opts.remote_host, args, TransferBack::Never).await
        }
        CargoRemoteCommand::Clean { args } => {
            let args = [&["clean".to_owned()], &args as &[String]].concat();
            main_build(opts.remote_host, args, TransferBack::Never).await
        }
    };

    match exit_code {
        Ok(e) => std::process::exit(e),
        Err(e) => Err(e),
    }
}

/// Run the remote build
#[tracing::instrument]
async fn main_build(
    remote_host: Option<String>,
    args: Vec<String>,
    transfer: TransferBack,
) -> Result<i32> {
    bail_if_in_wrong_cwd().await?;

    let tunnel = CargoRemoteTunnel::new(std::env::current_dir()?, remote_host).await?;
    info!("Compiling...");
    let response = tunnel
        .http_request(
            "/shell",
            Body::from(format!(
                r#"{{"cmdline":"cargo {} --color always 2>&1"}}"#,
                args.join(" ")
            )),
        )
        .await
        .context("server not up yet")?;

    let mut stream =
        multipart_stream::parse(response.into_body(), cargo_remote::remote_process::BOUNDARY);
    let mut exit_code = None;
    while let Some(p) = stream.next().await {
        let p = p.unwrap();
        match bincode::deserialize(&p.body)? {
            cargo_remote::remote_process::ShellReplyPart::Stdout { s } => {
                std::io::stdout().write_all(&s)?;
            }
            cargo_remote::remote_process::ShellReplyPart::Stderr { s } => {
                std::io::stdout().write_all(&s)?;
            }

            cargo_remote::remote_process::ShellReplyPart::ExitCode(e) => {
                exit_code = Some(e);
            }
        }
    }
    if let (TransferBack::TargetsOnSuccess, Some(0)) = (transfer, exit_code) {
        let response = tunnel
            .http_request("/artifacts", Body::from(r#"{"root": "target/"}"#))
            .await
            .context("server failed")?
            .into_body();
        let artifacts: cargo_remote::remote_process::ArtifactsReply =
            serde_json::from_slice(&hyper::body::to_bytes(response).await?)?;
        assert!(!artifacts.paths.is_empty());
        tunnel.rsync_artifacts_back(artifacts.paths).await?;
    }

    match exit_code {
        Some(e) => Ok(e),
        None => Err(anyhow!("No valid exit code detected")),
    }
}

/// Establish a persistent tunnel
#[tracing::instrument]
async fn main_tunnel(remote_host: Option<String>) -> Result<i32> {
    bail_if_in_wrong_cwd().await?;
    let _tunnel = CargoRemoteTunnel::new(std::env::current_dir()?, remote_host).await?;
    println!("Tunnel established");
    tokio::signal::ctrl_c().await.expect("Cannot await signal");

    Ok(0)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = execute().await {
        // lol, i want colors
        eprintln!(
            "\u{001b}[0m\u{001b}[1m\u{001b}[38;5;9merror\u{001b}[0m: {}",
            e
        );
        std::process::exit(1);
    }
}

async fn bail_if_in_wrong_cwd() -> Result<()> {
    let (dot_got, cargo_toml, flake_nix) = futures::join!(
        tokio::fs::metadata(".git"),
        tokio::fs::metadata("Cargo.toml"),
        tokio::fs::metadata("flake.nix")
    );
    if dot_got.is_err() || cargo_toml.is_err() || flake_nix.is_err() {
        bail!("cargo-remote must be called from the root of a git repository containing a flake.nix and Cargo.toml file");
    }

    Ok(())
}

#[derive(Debug)]
enum TransferBack {
    TargetsOnSuccess,
    Never,
}
