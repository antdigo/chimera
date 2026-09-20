use super::DockerEndpoint;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const MAX_HEADER_BYTES: usize = 8192;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

pub struct EngineProbe {
    endpoint: DockerEndpoint,
    requests: Arc<Mutex<Vec<String>>>,
    listener_task: JoinHandle<()>,
    _temp_dir: TempDir,
}

impl EngineProbe {
    pub async fn start(marker: &'static str) -> Result<Self> {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            marker.len(),
            marker,
        );
        Self::start_with_response(response).await
    }

    pub async fn start_failing_images() -> Result<Self> {
        let body = r#"{"message":"synthetic endpoint probe failure"}"#;
        let response = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        Self::start_with_response(response).await
    }

    async fn start_with_response(response: String) -> Result<Self> {
        let temp_dir = tempfile::Builder::new()
            .prefix("ch-ep-")
            .tempdir_in("/tmp")
            .context("creating endpoint probe directory")?;
        let socket_path = temp_dir.path().join("docker.sock");
        let listener = UnixListener::bind(&socket_path).context("binding endpoint probe socket")?;
        let endpoint = DockerEndpoint::unix_socket(&socket_path)?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let listener_requests = Arc::clone(&requests);
        let listener_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                if serve_request(&mut stream, &response, &listener_requests)
                    .await
                    .is_err()
                {
                    continue;
                }
            }
        });

        Ok(Self {
            endpoint,
            requests,
            listener_task,
            _temp_dir: temp_dir,
        })
    }

    pub fn endpoint(&self) -> &DockerEndpoint {
        &self.endpoint
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for EngineProbe {
    fn drop(&mut self) {
        self.listener_task.abort();
    }
}

async fn serve_request(
    stream: &mut UnixStream,
    response: &str,
    requests: &Arc<Mutex<Vec<String>>>,
) -> Result<()> {
    let request_line = timeout(REQUEST_TIMEOUT, read_request_line(stream))
        .await
        .context("timed out reading endpoint probe request")??;
    requests.lock().unwrap().push(request_line);
    stream
        .write_all(response.as_bytes())
        .await
        .context("writing endpoint probe response")?;
    Ok(())
}

async fn read_request_line(stream: &mut UnixStream) -> Result<String> {
    let mut headers = Vec::with_capacity(512);
    let mut buffer = [0_u8; 512];

    loop {
        let remaining = MAX_HEADER_BYTES - headers.len();
        if remaining == 0 {
            bail!("endpoint probe request headers exceeded {MAX_HEADER_BYTES} bytes");
        }
        let read_capacity = remaining.min(buffer.len());
        let read = stream
            .read(&mut buffer[..read_capacity])
            .await
            .context("reading endpoint probe request")?;
        if read == 0 {
            bail!("endpoint probe request ended before headers completed");
        }
        headers.extend_from_slice(&buffer[..read]);
        if headers.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let line_end = headers
        .windows(2)
        .position(|window| window == b"\r\n")
        .context("endpoint probe request had no request line")?;
    String::from_utf8(headers[..line_end].to_vec())
        .context("endpoint probe request line was not UTF-8")
}
