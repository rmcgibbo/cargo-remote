use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;

use advisory_lock::{AdvisoryFileLock, FileLockMode};
use hyperlocal::{UnixClientExt, Uri};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::Write;
use std::os::unix::prelude::OsStrExt;
use std::os::unix::prelude::OsStringExt;
use std::path::Path;
use std::path::PathBuf;
use std::{process::Stdio, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};
use tracing::debug;
use tracing::{error, info};

const REMOTE_SERVER_BOOT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct CargoRemoteTunnel {
    inner: CargoRemoteTunnelImpl,
    #[allow(unused)]
    remote_server_cmd: Option<tokio::process::Child>,
}

impl CargoRemoteTunnel {
    #[tracing::instrument()]
    pub async fn new(
        local_project_dir: PathBuf,
        remote_host: Option<String>,
    ) -> Result<CargoRemoteTunnel> {
        // generate a unique build path by using the hashed project dir as
        // folder on the remote machine
        let local_project_dir: Box<Path> = local_project_dir.into();
        let mut hasher = DefaultHasher::new();
        local_project_dir.hash(&mut hasher);

        let remote_project_dir = PathBuf::from(format!("/tmp/cargo-remote-{}/", hasher.finish()));
        let local_socket_file = local_project_dir.join(".cargo-remote").join("tunnel.sock");
        let ssh_control_master = local_project_dir
            .join(".cargo-remote")
            .join("ssh-control-master.sock");

        // needs to be absolute path for ssh to work properly
        assert!(local_socket_file.is_absolute() && ssh_control_master.is_absolute());

        // Acquire a lock on a file called lock.txt that proves we either
        // currently have, or are in the process of constructing the tunnel.
        std::fs::create_dir_all(".cargo-remote")?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(".cargo-remote/lock-1.txt")
            .context("Creating lock-2")?;
        debug!("Locking lock-1");
        match file.try_lock(FileLockMode::Exclusive) {
            Ok(_) => {
                debug!("Acquired lock-1");
                let remote_host = match remote_host {
                    Some(r) => r,
                    None => {
                        return Err(anyhow!("-r/--remote-host is required"));
                    }
                };

                // Acquire a lock that proves we are are building the tunnel
                let file2 = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(".cargo-remote/lock-2.txt")
                    .context("Creating lock-2")?;
                debug!("Acquiring lock-2");
                file2.lock(FileLockMode::Exclusive)?;

                drop(std::fs::remove_file(&local_socket_file));
                drop(std::fs::remove_file(&ssh_control_master));

                serde_json::to_writer_pretty(
                    &file,
                    &CargoRemoteLogRecord {
                        remote_host: remote_host.clone(),
                        pid: std::process::id(),
                        time: std::time::SystemTime::now(),
                    },
                )
                .context("Unable to write host to file")?;
                file.flush()?;

                let inner = CargoRemoteTunnelImpl::new(
                    local_project_dir,
                    local_socket_file.into(),
                    remote_project_dir.into(),
                    &remote_host,
                    file,
                    ssh_control_master.into(),
                )?;

                // Do rsyncs in parallel. One of the rsyncs transfers this very executable,
                // which needs to be statically linked. The other transfers the source code.
                let (a, b) =
                    futures::join!(inner.rsync_sources(), inner.transfer_remote_server_exe());
                a?;
                b?;

                let tunnel = inner.run_remote_server().await;

                // drop the advisory file lock that proves we're stil building the tunnel,
                // because now the setup is complete.
                debug!("Releaseing lock-2");
                drop(file2);
                std::fs::remove_file(".cargo-remote/lock-2.txt")?;
                tunnel
            }
            Err(_) => {
                // try to acquire the second lock so that we wait until the tunnel
                // is fully built
                let file2 = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(".cargo-remote/lock-2.txt")
                    .context("Creating lock-2 (2)")?;

                debug!("Acquiring lock-2");
                match file2.try_lock(FileLockMode::Exclusive) {
                    Ok(_) => {}
                    Err(_) => {
                        println!("\x1b[1;36mBlocking\x1b[0m waiting for file lock on cargo-remote tunnel");
                        file2.lock(FileLockMode::Exclusive)?;
                    }
                }
                debug!("Releaseing lock-2");
                std::fs::remove_file(".cargo-remote/lock-2.txt")?;
                drop(file2);

                let log: CargoRemoteLogRecord =
                    serde_json::from_reader(std::fs::File::open(".cargo-remote/lock-1.txt")?)
                        .context("Loading .cargo-remote/lock-1.txt")?;

                let tunnel = CargoRemoteTunnel {
                    inner: CargoRemoteTunnelImpl {
                        local_project_dir,
                        local_socket_file: local_socket_file.into(),
                        remote_host: log.remote_host,
                        remote_socket_file: PathBuf::from("unused").into(),
                        remote_project_dir: remote_project_dir.into(),
                        ssh_cmd: None,
                        lockfile: None,
                        ssh_control_master: ssh_control_master.into(),
                    },
                    remote_server_cmd: None,
                };
                tunnel.rsync_sources_to_remote().await?;
                Ok(tunnel)
            }
        }
    }

    #[tracing::instrument]
    pub fn http_request(&self, path: &str, body: hyper::Body) -> hyper::client::ResponseFuture {
        let url = Uri::new(&self.inner.local_socket_file, path);
        let client = hyper::Client::unix();
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(url)
            .body(body)
            .expect("request builder");
        client.request(request)
    }

    #[tracing::instrument]
    pub async fn rsync_sources_to_remote(&self) -> Result<()> {
        self.inner.rsync_sources().await
    }

    #[tracing::instrument]
    pub async fn rsync_artifacts_back(&self, paths: Vec<PathBuf>) -> Result<()> {
        self.inner.rsync_artifacts_back(paths).await
    }
}

//--------------------

struct CargoRemoteTunnelImpl {
    local_project_dir: Box<Path>,
    local_socket_file: Box<Path>,
    remote_host: String,
    remote_project_dir: Box<Path>,
    remote_socket_file: Box<Path>,
    ssh_cmd: Option<tokio::process::Child>,
    ssh_control_master: Box<Path>,
    #[allow(unused)]
    lockfile: Option<std::fs::File>,
}

impl std::fmt::Debug for CargoRemoteTunnelImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CargoRemoteTunnelImpl").finish()
    }
}

impl CargoRemoteTunnelImpl {
    #[tracing::instrument()]
    fn new(
        local_project_dir: Box<Path>,
        local_socket_file: Box<Path>,
        remote_project_dir: Box<Path>,
        remote_host: &str,
        lockfile: std::fs::File,
        ssh_control_master: Box<Path>,
    ) -> Result<CargoRemoteTunnelImpl> {
        let remote_socket_file: Box<Path> = PathBuf::from(format!(
            "/tmp/cargo-remote-build-server.{}.sock",
            std::process::id()
        ))
        .into();

        //
        // 1. Create tunnel with muxed ssh and also a unix socket
        // that's being forwarded
        //
        info!("Establishing ssh tunnel");
        let ssh = Command::new(option_env!("CARGO_REMOTE_SSH").unwrap_or("ssh"))
            .arg("-t")
            .arg("-N")
            .arg("-n")
            // .arg("-vvv")
            .arg("-o")
            .arg("LogLevel=ERROR")
            .arg("-o")
            .arg("ControlMaster=yes")
            .arg("-o")
            .arg(format!(
                "ControlPath='{}'",
                ssh_control_master.to_str().expect("Invalid UTF-8")
            ))
            .arg("-o")
            .arg("ExitOnForwardFailure=yes")
            .arg(format!(
                "-L{}:{}",
                local_socket_file.to_str().expect("Invalid UTF-8"),
                remote_socket_file.to_str().expect("Invalid UTF-8")
            ))
            .arg(remote_host)
            .kill_on_drop(true)
            .stderr(Stdio::inherit())
            .spawn()?;
        debug!(
            "Spawned ssh tunnel with ControlPath={}",
            ssh_control_master.to_str().expect("Invalid UTF-8")
        );

        Ok(CargoRemoteTunnelImpl {
            local_project_dir,
            local_socket_file,
            remote_host: remote_host.to_string(),
            remote_project_dir,
            remote_socket_file,
            ssh_cmd: Some(ssh),
            ssh_control_master,
            lockfile: Some(lockfile),
        })
    }

    #[tracing::instrument]
    async fn transfer_remote_server_exe(&self) -> Result<()> {
        //
        // 2. Copy statically-linked server executable to remote
        //
        info!("Transfering remote server");
        let remote_process_exe = std::path::Path::new(&std::env::args().next().unwrap())
            .to_string_lossy()
            .to_string();
        Command::new(option_env!("CARGO_REMOTE_RSYNC").unwrap_or("rsync"))
            .arg("-a")
            .arg("--compress")
            .arg("--quiet")
            .arg("--rsync-path")
            .arg(format!(
                "mkdir -p '{}' && rsync",
                self.remote_project_dir.to_str().expect("Invalid UTF-8")
            ))
            .arg("-e")
            .arg(format!(
                "ssh -o ControlPath='{}'",
                self.ssh_control_master.to_str().expect("Invalid UTF-8")
            ))
            .arg(remote_process_exe)
            .arg(format!(
                "{}:{}",
                self.remote_host,
                self.remote_project_dir
                    .join("cargo-remote")
                    .to_str()
                    .expect("Invalid UTF-8")
            ))
            .kill_on_drop(true)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdin(Stdio::inherit())
            .spawn()?
            .wait()
            .await?;
        debug!("Finished transferring remote server");

        Ok(())
    }

    #[tracing::instrument]
    async fn rsync_sources(&self) -> Result<()> {
        println!("Transferring sources to {}", self.remote_host);
        //
        // 3. Copy the contents of local_project_dir to the remote
        //

        let mut ls_files =
            std::process::Command::new(option_env!("CARGO_REMOTE_GIT").unwrap_or("git"))
                .arg("ls-files")
                .arg("--exclude-standard")
                .arg("-z")
                .stdout(Stdio::piped())
                .spawn()
                .expect("failed git-ls command");

        Command::new(option_env!("CARGO_REMOTE_RSYNC").unwrap_or("rsync"))
            .arg("-a".to_owned())
            .arg("--delete")
            .arg("--compress")
            .arg("--info=progress2")
            .arg("--from0")
            .arg("--files-from")
            .arg("-")
            .arg("-e")
            .arg(format!(
                "ssh -o ControlPath='{}'",
                self.ssh_control_master.to_str().expect("Invalid UTF-8")
            ))
            .arg("--rsync-path")
            .arg(format!(
                "mkdir -p '{}' && rsync",
                self.remote_project_dir.to_str().expect("Invalid UTF-8")
            ))
            .arg(self.local_project_dir.as_os_str())
            .arg(format!(
                "{}:{}",
                self.remote_host,
                self.remote_source_dir().to_str().expect("Invalid UTF-8")
            ))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdin(ls_files.stdout.take().unwrap())
            .spawn()?
            .wait()
            .await
            .map_err(|e| anyhow!("Failed to transfer project to build server (error: {})", e))?;

        debug!("Finished transfering sources to build server");
        Ok(())
    }

    #[tracing::instrument]
    async fn run_remote_server(self) -> Result<CargoRemoteTunnel> {
        //
        // 4. Start up a server process on the remote side that we now should be able to
        // access via the ssh on the local (forwarded) socket unix socket
        //
        info!("Setting up remote nix environment");
        let mut remote_server = Command::new(option_env!("CARGO_REMOTE_SSH").unwrap_or("ssh"))
            .arg("-o")
            .arg(format!(
                "ControlPath='{}'",
                self.ssh_control_master.to_str().expect("Invalid UTF-8")
            ))
            .arg(&self.remote_host)
            .arg(format!(
                "cd '{}' && nix --print-build-logs develop -c ../cargo-remote remote-server {}",
                self.remote_source_dir().to_str().expect("Invalid UTF-8"),
                self.remote_socket_file.to_str().expect("Invalid UTF-8"),
            ))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        debug!("Spawned remote nix environment");

        //
        // 5. Wait for the remote process to print to stdout that it's ready to serve
        //
        let stdout = remote_server
            .stdout
            .take()
            .expect("child did not have a handle to stdout");

        match timeout(
            REMOTE_SERVER_BOOT_TIMEOUT,
            wait_for_line(stdout, self.remote_socket_file.to_str().expect("sdf")),
        )
        .await
        {
            Ok(Ok(_)) => {}
            _ => {
                error!("Unable to create ssh tunnel (timeout)");
                return Err(anyhow!("Unable to create ssh tunnel"));
            }
        };

        debug!("Created remote nix environment");
        Ok(CargoRemoteTunnel {
            inner: self,
            remote_server_cmd: Some(remote_server),
        })
    }

    #[tracing::instrument]
    pub async fn rsync_artifacts_back(&self, paths: Vec<PathBuf>) -> Result<()> {
        println!("Transferring {} artifact(s) back", paths.len());
        let paths = std::ffi::OsString::from_vec(
            paths
                .into_iter()
                .map(|x| x.into_os_string().into_vec())
                .fold(Vec::new(), |mut x, mut y| {
                    x.extend_from_slice(&[0u8; 1]);
                    x.append(&mut y);
                    x
                }),
        );

        let mut child = Command::new(option_env!("CARGO_REMOTE_RSYNC").unwrap_or("rsync"))
            .arg("-a")
            .arg("--delete")
            .arg("--compress")
            .arg("--info=progress2")
            .arg("-e")
            .arg(format!(
                "ssh -o ControlPath='{}'",
                self.ssh_control_master.to_str().expect("Invalid UTF-*")
            ))
            .arg("--rsync-path")
            .arg(format!(
                "cd '{}' && rsync",
                self.remote_source_dir().to_str().expect("Invalid UTF-8")
            ))
            .arg("--from0")
            .arg("--files-from")
            .arg("-")
            .arg(format!("{}:", self.remote_host))
            .arg(self.local_project_dir.as_os_str())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .stdin(Stdio::piped())
            .spawn()?;

        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        let jh = tokio::spawn(async move {
            debug!("Writing list of paths to stdin: {:#?}", paths);
            stdin
                .write_all(paths.as_bytes())
                .await
                .expect("Failed to write to stdin");
        });

        let (jh, child) = futures::join!(jh, child.wait());
        jh?;
        child.map_err(|e| {
            anyhow!(
                "Failed to transfer target back to local machine (error: {})",
                e
            )
        })?;

        Ok(())
    }

    fn remote_source_dir(&self) -> Box<Path> {
        self.remote_project_dir.join("build").into()
    }
}

impl Drop for CargoRemoteTunnelImpl {
    fn drop(&mut self) {
        if self.ssh_cmd.is_some() {
            debug!("Removing local socket file");
            drop(std::fs::remove_file(&self.local_socket_file));
        }
    }
}

async fn wait_for_line<X: tokio::io::AsyncRead + Unpin>(
    stream: X,
    remote_socket_file: &str,
) -> Result<()> {
    let mut reader = BufReader::new(stream).lines();
    while let Some(line) = reader.next_line().await? {
        if line.contains(remote_socket_file) {
            return Ok(());
        } else {
            println!("{}", line);
        }
    }
    return Err(anyhow!("Unexpected error with async read"));
}

#[derive(Serialize, Deserialize)]
struct CargoRemoteLogRecord {
    remote_host: String,
    pid: u32,
    time: std::time::SystemTime,
}
