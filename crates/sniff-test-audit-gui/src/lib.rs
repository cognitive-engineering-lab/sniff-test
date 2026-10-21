//! Local HTTP adapter for the UI-independent audit bridge.
mod lsp;

use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sniff_test_audit_bridge::Session;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_stream::wrappers::ReceiverStream;

#[derive(rust_embed::RustEmbed)]
#[folder = "frontend/dist/"]
struct Assets;
#[derive(Clone)]
struct App {
    lsp: lsp::Connections,
    session: Arc<Mutex<Session>>,
    token: String,
    origin: String,
}
type ApiResult = Result<Json<Value>, ApiError>;
struct ApiError(anyhow::Error);
impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        Self(value)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::CONFLICT,
            Json(json!({"error": self.0.to_string()})),
        )
            .into_response()
    }
}

pub fn serve(session: Session) -> anyhow::Result<()> {
    tokio::runtime::Runtime::new()?.block_on(async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let app = App {
            lsp: Default::default(),
            session: Arc::new(Mutex::new(session)),
            token: uuid::Uuid::new_v4().to_string(),
            origin,
        };
        let url = format!("{}/#{}", app.origin, app.token);
        eprintln!(
            "Audit GUI: {url}\nPress Ctrl-C to stop. Drafts are saved separately from source files."
        );
        start_analysis(&app)?;
        let router = router(app);
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else if cfg!(target_os = "windows") {
            "explorer"
        } else {
            "xdg-open"
        };
        if std::env::var_os("SNIFF_TEST_AUDIT_NO_OPEN").is_none() {
            let _ = std::process::Command::new(opener).arg(&url).spawn();
        }
        axum::serve(listener, router).await?;
        Ok(())
    })
}
fn router(app: App) -> Router {
    let api = Router::new()
        .route("/workspace", get(workspace))
        .route("/lsp/events", get(lsp::events))
        .route("/lsp/messages", post(lsp::messages))
        .route("/analysis", get(analysis).post(analyze))
        .route("/events", get(events))
        .route("/findings", get(findings))
        .route("/finding", get(finding))
        .route("/buffer", get(buffer).post(update))
        .route("/drafts", get(drafts))
        .route("/diff", get(diff))
        .route("/propose", post(propose))
        .route("/template", post(template))
        .route("/apply", post(apply))
        .route("/discard", post(discard))
        .layer(middleware::from_fn_with_state(app.clone(), authorize));
    Router::new()
        .nest("/api/v1", api)
        .fallback(get(asset))
        .with_state(app)
        .layer(middleware::from_fn(headers))
}
async fn headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
async fn authorize(State(app): State<App>, request: Request, next: Next) -> Response {
    let token = request
        .headers()
        .get("x-audit-token")
        .and_then(|h| h.to_str().ok());
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok());
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    if token != Some(&app.token)
        || origin.is_some_and(|o| o != app.origin)
        || host != Some(app.origin.trim_start_matches("http://"))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    next.run(request).await
}
async fn asset(request: Request) -> Response {
    let path = request.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match Assets::get(path) {
        Some(asset) => (
            [(
                header::CONTENT_TYPE,
                mime_guess::from_path(path)
                    .first_or_octet_stream()
                    .to_string(),
            )],
            asset.data.into_owned(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
fn start_analysis(app: &App) -> anyhow::Result<()> {
    let config = app.session.lock().unwrap().begin_analysis()?;
    let session = app.session.clone();
    tokio::task::spawn_blocking(move || {
        let result = config.run();
        session.lock().unwrap().finish_analysis(result);
    });
    Ok(())
}
async fn workspace(State(app): State<App>) -> ApiResult {
    let session = app.session.lock().unwrap();
    Ok(Json(json!({"root":session.root,"api_version":1})))
}
fn status(session: &Session) -> Value {
    let a = &session.analysis;
    json!({"generation":a.generation,"running":a.running,"stale":a.stale,"status":a.status,"exit_code":a.exit_code,"log":a.log,"count":a.findings.len()})
}
async fn analysis(State(app): State<App>) -> ApiResult {
    Ok(Json(status(&app.session.lock().unwrap())))
}
async fn analyze(State(app): State<App>) -> ApiResult {
    start_analysis(&app)?;
    Ok(Json(json!({"started":true})))
}
async fn events(State(app): State<App>) -> impl IntoResponse {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(4);
    tokio::spawn(async move {
        let mut last = String::new();
        loop {
            let current = status(&app.session.lock().unwrap()).to_string();
            if last != current {
                last = current.clone();
                if tx.send(Ok(Event::default().data(current))).await.is_err() {
                    break;
                }
            }
            if tx.is_closed() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });
    Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default())
}
#[derive(Default, Deserialize)]
struct Filter {
    q: Option<String>,
    effect: Option<String>,
    level: Option<String>,
    class: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}
async fn findings(State(app): State<App>, Query(filter): Query<Filter>) -> ApiResult {
    let session = app.session.lock().unwrap();
    let matches: Vec<_> = session
        .analysis
        .findings
        .iter()
        .filter(|f| {
            filter.q.as_ref().is_none_or(|q| {
                format!(
                    "{} {} {} {:?}",
                    f.crate_name,
                    f.root.as_deref().unwrap_or_default(),
                    f.reason,
                    f.audit
                        .as_ref()
                        .and_then(|a| a.source.as_ref())
                        .map(|l| &l.path)
                )
                .to_lowercase()
                .contains(&q.to_lowercase())
            }) && filter
                .effect
                .as_ref()
                .is_none_or(|v| v.is_empty() || f.effect.as_deref() == Some(v.as_str()))
                && filter
                    .level
                    .as_ref()
                    .is_none_or(|v| v.is_empty() || f.level == *v)
                && filter
                    .class
                    .as_ref()
                    .is_none_or(|v| v.is_empty() || f.class.as_deref() == Some(v.as_str()))
        })
        .collect();
    let values: Vec<_> = matches.iter().skip(filter.offset.unwrap_or(0)).take(filter.limit.unwrap_or(100).min(500)).map(|f| json!({"id":f.id,"crate_name":f.crate_name,"root":f.root,"reason":f.reason,"level":f.level,"effect":f.effect,"class":f.class,"path":f.audit.as_ref().and_then(|a| a.source.as_ref()).map(|l| &l.path)})).collect();
    let effects: std::collections::BTreeSet<_> = session
        .analysis
        .findings
        .iter()
        .filter_map(|f| f.effect.as_deref())
        .collect();
    Ok(Json(
        json!({"total":matches.len(),"items":values,"effects":effects}),
    ))
}
#[derive(Deserialize)]
struct Id {
    id: String,
}
async fn finding(State(app): State<App>, Query(id): Query<Id>) -> ApiResult {
    let session = app.session.lock().unwrap();
    let f = session
        .analysis
        .findings
        .iter()
        .find(|f| f.id == id.id)
        .ok_or_else(|| anyhow::anyhow!("finding no longer exists"))?;
    let mut value = serde_json::to_value(f).map_err(anyhow::Error::from)?;
    drop(session);
    annotate_source_lines(&mut value, &mut std::collections::HashMap::new());
    Ok(Json(value))
}
// Presentation-only line numbers; reports retain their exact original-byte ranges.
fn annotate_source_lines(
    value: &mut Value,
    files: &mut std::collections::HashMap<String, Option<(String, String)>>,
) {
    match value {
        Value::Array(values) => {
            for value in values {
                annotate_source_lines(value, files);
            }
        }
        Value::Object(object) => {
            if object.get("available").and_then(Value::as_bool) == Some(true)
                && let (Some(path), Some(hash), Some(start)) = (
                    object.get("path").and_then(Value::as_str),
                    object.get("hash").and_then(Value::as_str),
                    object.get("start").and_then(Value::as_u64),
                )
            {
                let source = files.entry(path.to_owned()).or_insert_with(|| {
                    let text = std::fs::read_to_string(path).ok()?;
                    let hash = sniff_test_report::content_hash(text.as_bytes());
                    Some((text, hash))
                });
                if let Some((text, actual_hash)) = source
                    && actual_hash == hash
                    && let Some(prefix) = text.get(..start as usize)
                {
                    object.insert(
                        "line".into(),
                        json!(prefix.bytes().filter(|byte| *byte == b'\n').count() + 1),
                    );
                }
            }
            for child in object.values_mut() {
                annotate_source_lines(child, files);
            }
        }
        _ => {}
    }
}
#[derive(Deserialize)]
struct File {
    path: String,
}
async fn buffer(State(app): State<App>, Query(file): Query<File>) -> ApiResult {
    Ok(Json(json!(app.session.lock().unwrap().buffer(&file.path)?)))
}
async fn diff(State(app): State<App>, Query(file): Query<File>) -> ApiResult {
    Ok(Json(
        json!({"diff":app.session.lock().unwrap().diff(&file.path)?}),
    ))
}
async fn drafts(State(app): State<App>) -> ApiResult {
    Ok(Json(json!(app.session.lock().unwrap().drafts())))
}
#[derive(Deserialize)]
struct Update {
    path: String,
    revision: u64,
    content: String,
}
async fn update(State(app): State<App>, Json(edit): Json<Update>) -> ApiResult {
    Ok(Json(json!(app.session.lock().unwrap().update(
        &edit.path,
        edit.revision,
        edit.content
    )?)))
}
#[derive(Deserialize)]
struct Revision {
    path: String,
    revision: u64,
}
async fn apply(State(app): State<App>, Json(edit): Json<Revision>) -> ApiResult {
    app.session
        .lock()
        .unwrap()
        .apply(&edit.path, edit.revision)?;
    start_analysis(&app)?;
    Ok(Json(json!({"applied":true})))
}
async fn discard(State(app): State<App>, Json(edit): Json<Revision>) -> ApiResult {
    app.session
        .lock()
        .unwrap()
        .discard(&edit.path, edit.revision)?;
    Ok(Json(json!({"discarded":true})))
}
#[derive(Deserialize)]
struct TemplateRequest {
    id: String,
    action: String,
    revision: u64,
}
async fn template(State(app): State<App>, Json(edit): Json<TemplateRequest>) -> ApiResult {
    Ok(Json(json!(app.session.lock().unwrap().prepare_template(
        &edit.id,
        &edit.action,
        edit.revision
    )?)))
}

#[derive(Deserialize)]
struct Proposal {
    id: String,
    action: String,
    explanation: String,
    revision: u64,
}
async fn propose(State(app): State<App>, Json(edit): Json<Proposal>) -> ApiResult {
    Ok(Json(json!(app.session.lock().unwrap().propose(
        &edit.id,
        &edit.action,
        &edit.explanation,
        edit.revision
    )?)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn source_lines_require_matching_content_and_utf8_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.rs");
        let text = "\u{feff}// λ\r\nfn target() {}\r\n";
        std::fs::write(&path, text).unwrap();
        let mut location = serde_json::json!({"path":path,"available":true,"hash":sniff_test_report::content_hash(text.as_bytes()),"start":text.find("fn target").unwrap()});
        super::annotate_source_lines(&mut location, &mut Default::default());
        assert_eq!(location["line"], 2);
        location.as_object_mut().unwrap().remove("line");
        std::fs::write(path, "changed").unwrap();
        super::annotate_source_lines(&mut location, &mut Default::default());
        assert!(location.get("line").is_none());
    }

    use super::*;
    use tower::ServiceExt;
    #[tokio::test]
    async fn api_requires_token_origin_and_local_host() {
        let dir = tempfile::tempdir().unwrap();
        let config = sniff_test_audit_bridge::AnalysisConfig {
            executable: "false".into(),
            directory: dir.path().into(),
            arguments: vec![],
        };
        let session = Session::open(dir.path().into(), dir.path().join("target"), config).unwrap();
        let app = App {
            lsp: Default::default(),
            session: Arc::new(Mutex::new(session)),
            token: "secret".into(),
            origin: "http://127.0.0.1:1234".into(),
        };
        let router = router(app);
        for (token, origin, host, expected) in [
            (
                "",
                "http://127.0.0.1:1234",
                "127.0.0.1:1234",
                StatusCode::FORBIDDEN,
            ),
            (
                "secret",
                "https://elsewhere.example",
                "127.0.0.1:1234",
                StatusCode::FORBIDDEN,
            ),
            (
                "secret",
                "http://127.0.0.1:1234",
                "elsewhere.example",
                StatusCode::FORBIDDEN,
            ),
            (
                "secret",
                "http://127.0.0.1:1234",
                "127.0.0.1:1234",
                StatusCode::OK,
            ),
        ] {
            let request = Request::builder()
                .uri("/api/v1/workspace")
                .header("x-audit-token", token)
                .header("origin", origin)
                .header("host", host)
                .body(axum::body::Body::empty())
                .unwrap();
            assert_eq!(
                router.clone().oneshot(request).await.unwrap().status(),
                expected
            );
        }
        let asset = router
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(asset.status(), StatusCode::OK);
        assert!(
            asset
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );
    }
}
