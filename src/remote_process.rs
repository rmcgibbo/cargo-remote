use anyhow::anyhow;
use anyhow::Result;
use futures::FutureExt;
use futures::TryStreamExt;
use http::HeaderMap;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyperlocal::UnixServerExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::{fs, path::Path};
use tokio::process::Command;
use tokio_util::codec::{BytesCodec, FramedRead};
use tracing::error;

static NOTFOUND: &[u8] = b"Not Found";
pub const BOUNDARY: &str = "B";

pub async fn main(unix_socket_path: &str) -> Result<i32> {
    let path = Path::new(unix_socket_path);
    if path.exists() {
        fs::remove_file(path)?;
    }

    let make_service =
        make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(make_routing_table)) });

    let server = Server::bind_unix(path)?.serve(make_service);

    println!("Serving on {:#?}", path);
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            fs::remove_file(path)?;
        },
        o = server => {
            if let Err(e) = o {
                eprintln!("server error: {}", e);
            }
        },
    };

    Ok(0)
}

async fn make_routing_table(req: Request<Body>) -> Result<Response<Body>> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/shell") => shell(req).await,
        (&Method::POST, "/artifacts") => artifacts(req).await,
        _ => Ok(not_found()),
    }
}

/// HTTP status code 404
fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(NOTFOUND.into())
        .unwrap()
}

/// POST to /shell
///
/// $ curl  --no-buffer -XPOST --unix-socket ./foo http://localhost/shell -d '{"cmdline": "ls"}'
async fn shell(req: Request<Body>) -> Result<Response<Body>> {
    let request = get_json_body::<ShellRequest>(req).await?;

    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(request.cmdline)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn command");

    let stdout = child
        .stdout
        .take()
        .expect("child did not have a handle to stdout");

    let stderr = child
        .stderr
        .take()
        .expect("child did not have a handle to stderr");

    // Ensure the child process is spawned in the runtime so it can
    // make progress on its own while we await for any output.
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let status = child
            .wait()
            .await
            .expect("child process encountered an error");
        if tx.send(status).is_err() {
            error!("Unexpected error. Cound not send exit status to channel");
        }
    });

    let exit_status_stream = rx
        .into_stream()
        .map_ok(|x| multipart_stream::Part {
            headers: HeaderMap::new(),
            body: hyper::body::Bytes::from(
                bincode::serialize(&ShellReplyPart::ExitCode(x.code().unwrap())).unwrap(),
            ),
        })
        .map_err(anyhow::Error::from);

    let stdout_stream = FramedRead::new(stdout, BytesCodec::new())
        .map_ok(|x| multipart_stream::Part {
            headers: HeaderMap::new(),
            body: hyper::body::Bytes::from(
                bincode::serialize(&ShellReplyPart::Stdout { s: x.to_vec() }).unwrap(),
            ),
        })
        .map_err(anyhow::Error::from);

    let stderr_stream = FramedRead::new(stderr, BytesCodec::new())
        .map_ok(|x| multipart_stream::Part {
            headers: HeaderMap::new(),
            body: hyper::body::Bytes::from(
                bincode::serialize(&ShellReplyPart::Stderr { s: x.to_vec() }).unwrap(),
            ),
        })
        .map_err(anyhow::Error::from);

    let merged_stream = futures::stream::select(
        futures::stream::select(stdout_stream, exit_status_stream),
        stderr_stream,
    );

    Ok(hyper::Response::builder()
        .header(
            http::header::CONTENT_TYPE,
            format!("multipart/mixed; boundary={}", BOUNDARY),
        )
        .body(hyper::Body::wrap_stream(multipart_stream::serialize(
            merged_stream,
            BOUNDARY,
        )))?)
}

/// POST to /artifacts
/// curl --output - --no-buffer -XPOST --unix-socket ./unix.sock http://localhost/artifacts -d '{"root": "target"}'
async fn artifacts(req: Request<Body>) -> Result<Response<Body>> {
    let request = get_json_body::<ArtifactsRequest>(req).await?;
    let walker = walkdir::WalkDir::new(request.root).into_iter();

    fn skip_directory(entry: &walkdir::DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .map(|s| s == "build" || s == ".fingerprint" || s == "deps" || s == "incremental")
            .unwrap_or(false)
    }
    fn is_executable(e: &walkdir::DirEntry) -> Result<bool> {
        let m = e.metadata()?;
        let st_mode = m.permissions().mode();
        // check if any execute bits are set
        Ok(st_mode & 0o111 > 0)
    }

    let paths = walker
        .filter_entry(|e| !skip_directory(e))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && is_executable(e).unwrap_or(false))
        .map(|e| e.path().to_owned())
        .collect::<Vec<_>>();

    Ok(
        hyper::Response::builder().body(hyper::Body::from(serde_json::to_string(
            &ArtifactsReply { paths },
        )?))?,
    )
}

#[derive(Deserialize)]
struct ShellRequest {
    cmdline: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ShellReplyPart {
    Stdout { s: Vec<u8> },
    Stderr { s: Vec<u8> },
    ExitCode(i32),
}

#[derive(Deserialize)]
pub struct ArtifactsRequest {
    root: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ArtifactsReply {
    pub paths: Vec<PathBuf>,
}

async fn get_json_body<T: DeserializeOwned>(req: Request<Body>) -> Result<T> {
    let bytes = hyper::body::to_bytes(req.into_body()).await?;
    serde_json::from_slice(bytes.to_vec().as_slice()).map_err(|e| anyhow!("{}", e))
}
