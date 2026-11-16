//! Authenticated, connection-scoped stdio transport for editor navigation.
use super::*;
use anyhow::{Context, ensure};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

pub type Connections = Arc<Mutex<HashMap<String, mpsc::Sender<Value>>>>;
#[derive(Deserialize)]
pub struct Connection {
    id: String,
}

pub async fn messages(
    State(app): State<App>,
    Query(connection): Query<Connection>,
    Json(mut message): Json<Value>,
) -> ApiResult {
    if let Some(method) = message["method"].as_str() {
        if !matches!(
            method,
            "initialize"
                | "initialized"
                | "shutdown"
                | "exit"
                | "$/cancelRequest"
                | "textDocument/didOpen"
                | "textDocument/didChange"
                | "textDocument/didClose"
                | "textDocument/definition"
                | "textDocument/hover"
                | "workspace/didChangeConfiguration"
        ) {
            return Err(anyhow::anyhow!("unsupported language server operation").into());
        }
        if method == "initialize" {
            let root = app.session.lock().unwrap().root.clone();
            message["params"]["rootUri"] = json!(
                url::Url::from_directory_path(root)
                    .map_err(|_| anyhow::anyhow!("invalid workspace path"))?
                    .as_str()
            );
            message["params"]["workspaceFolders"] = Value::Null;
            message["params"]["processId"] = Value::Null;
            message["params"]["initializationOptions"] =
                json!({"checkOnSave":false,"check":{"enable":false}});
        }
        if let Some(uri) = message["params"]["textDocument"]["uri"].as_str() {
            let path = file_path(uri)?;
            app.session
                .lock()
                .unwrap()
                .buffer(&path.to_string_lossy())?;
        }
    }
    let sender = app
        .lsp
        .lock()
        .unwrap()
        .get(&connection.id)
        .cloned()
        .context("language server disconnected")?;
    sender
        .send(message)
        .await
        .context("language server disconnected")?;
    Ok(Json(json!({})))
}

fn file_path(uri: &str) -> anyhow::Result<std::path::PathBuf> {
    url::Url::parse(uri)?
        .to_file_path()
        .map_err(|_| anyhow::anyhow!("definition is not a local file"))
}

// Only the language server may extend the source allowlist, never an HTTP caller.
fn allow_destinations(session: &mut Session, value: &Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                allow_destinations(session, item);
            }
        }
        Value::Object(object) => {
            for key in ["uri", "targetUri"] {
                if let Some(uri) = object.get(key).and_then(Value::as_str)
                    && let Ok(path) = file_path(uri)
                {
                    session.allow_definition_source(&path);
                }
            }
            for value in object.values() {
                allow_destinations(session, value);
            }
        }
        _ => {}
    }
}

async fn read_message(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
) -> anyhow::Result<Value> {
    let mut length = None;
    loop {
        let mut line = String::new();
        ensure!(
            reader.read_line(&mut line).await? != 0,
            "rust-analyzer exited"
        );
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            length = Some(value.trim().parse::<usize>()?);
        }
        ensure!(line.len() < 8192, "invalid language server header");
    }
    let length = length.context("missing Content-Length")?;
    ensure!(
        length <= 16 * 1024 * 1024,
        "language server message too large"
    );
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn events(
    State(app): State<App>,
    Query(connection): Query<Connection>,
) -> Result<impl IntoResponse, ApiError> {
    if uuid::Uuid::parse_str(&connection.id).is_err() {
        return Err(anyhow::anyhow!("invalid connection id").into());
    }
    let root = app.session.lock().unwrap().root.clone();
    let mut child = tokio::process::Command::new("rust-analyzer")
        .current_dir(root).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null()).kill_on_drop(true).spawn()
        .context("Cannot start rust-analyzer. Run rustup component add rust-analyzer for the workspace toolchain.")?;
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let (input, mut incoming) = mpsc::channel::<Value>(64);
    {
        let mut connections = app.lsp.lock().unwrap();
        if connections.contains_key(&connection.id) {
            return Err(anyhow::anyhow!("language server connection already exists").into());
        }
        connections.insert(connection.id.clone(), input);
    }
    let (output, rx) = mpsc::channel::<Result<Event, Infallible>>(64);
    tokio::spawn(async move {
        let reader_output = output.clone();
        let session = app.session.clone();
        let mut reader = tokio::spawn(async move {
            loop {
                let message = read_message(&mut stdout).await?;
                if message.get("result").is_some() {
                    allow_destinations(&mut session.lock().unwrap(), &message["result"]);
                }
                reader_output
                    .send(Ok(Event::default().data(message.to_string())))
                    .await
                    .context("editor disconnected")?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });
        let result: anyhow::Result<()> = async {
            loop {
                tokio::select! {
                    _ = output.closed() => return Ok(()),
                    result = &mut reader => { result??; return Ok(()); },
                    message = incoming.recv() => {
                        let Some(message) = message else { return Ok(()); };
                        let body = message.to_string();
                        stdin.write_all(format!("Content-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()).await?;
                        stdin.flush().await?;
                    }
                }
            }
        }.await;
        if let Err(error) = result {
            let _ = output
                .send(Ok(Event::default().event("failure").data(format!(
                    "{error}. Check that rust-analyzer is installed for this workspace toolchain."
                ))))
                .await;
        }
        reader.abort();
        let _ = child.kill().await;
        let _ = child.wait().await;
        app.lsp.lock().unwrap().remove(&connection.id);
    });
    Ok(Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stdio_frames_preserve_unicode_and_message_boundaries() {
        let message = json!({"jsonrpc":"2.0","id":1,"result":{"uri":"file:///tmp/λ.rs"}});
        let body = message.to_string();
        let wire = format!(
            "Content-Length: {}\r\n\r\n{}Content-Length: 2\r\n\r\n{{}}",
            body.len(),
            body
        );
        let mut reader = BufReader::new(wire.as_bytes());
        assert_eq!(read_message(&mut reader).await.unwrap(), message);
        assert_eq!(read_message(&mut reader).await.unwrap(), json!({}));
        assert!(read_message(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn invalid_or_truncated_frames_fail_without_waiting_for_another_message() {
        for bytes in [
            "Content-Length: 100\r\n\r\n{}",
            "Content-Length: 999999999\r\n\r\n",
            "\r\n{}",
        ] {
            assert!(
                read_message(&mut BufReader::new(bytes.as_bytes()))
                    .await
                    .is_err()
            );
        }
        assert!(file_path("https://example.com/code.rs").is_err());
    }
}
