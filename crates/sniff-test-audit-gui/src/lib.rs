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
use sniff_test_audit_bridge::{OverrideEditorTarget, Session};
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
        .route("/buffer", get(buffer))
        .route("/source/save", post(save_source))
        .route("/template", post(template))
        .route("/override/editor", post(override_editor))
        .route("/override/commit", post(override_commit))
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
    json!({"generation":a.generation,"running":a.running,"stale":a.stale,"overrides_changed":a.overrides_changed,"override_revision":a.override_revision,"override_error":a.override_error,"status":a.status,"exit_code":a.exit_code,"log":a.log,"count":a.findings.len()})
}
async fn analysis(State(app): State<App>) -> ApiResult {
    Ok(Json(status(&app.session.lock().unwrap())))
}
async fn analyze(State(app): State<App>) -> ApiResult {
    start_analysis(&app)?;
    Ok(Json(json!({"status":status(&app.session.lock().unwrap())})))
}
async fn events(State(app): State<App>) -> impl IntoResponse {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(4);
    tokio::spawn(async move {
        let mut last = String::new();
        loop {
            let current = {
                let mut session = app.session.lock().unwrap();
                session.reconcile_overrides();
                status(&session).to_string()
            };
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
#[derive(Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum GroupBy {
    #[default]
    File,
    EffectSource,
}
#[derive(Default, Deserialize)]
struct Filter {
    #[serde(default)]
    group_by: GroupBy,
    q: Option<String>,
    effect: Option<String>,
    level: Option<String>,
    class: Option<String>,
    grouped: Option<bool>,
    offset: Option<usize>,
    limit: Option<usize>,
}
async fn findings(State(app): State<App>, Query(filter): Query<Filter>) -> ApiResult {
    let session = app.session.lock().unwrap();
    let inverted = filter.group_by == GroupBy::EffectSource;
    let matches: Vec<_> = session
        .analysis
        .findings
        .iter()
        .filter(|f| {
            (inverted
                || filter.q.as_ref().is_none_or(|q| {
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
                }))
                && filter
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
    let values: Vec<_> = if inverted {
        Vec::new()
    } else {
        matches.iter().map(|f| finding_summary(f)).collect()
    };
    let effects: std::collections::BTreeSet<_> = session
        .analysis
        .findings
        .iter()
        .filter_map(|f| f.effect.as_deref())
        .collect();
    let offset = filter.offset.unwrap_or(0);
    let limit = filter.limit.unwrap_or(100).min(500);
    if filter.grouped == Some(true) || inverted {
        let groups = if inverted {
            group_effect_sources(&matches, filter.q.as_deref().unwrap_or_default())
        } else {
            group_findings(values)
        };
        let total: usize = groups
            .iter()
            .map(|g| g["count"].as_u64().unwrap() as usize)
            .sum();
        return Ok(Json(json!({
            "total": total, "total_groups": groups.len(), "effects": effects,
            "groups": groups.into_iter().skip(offset).take(limit).collect::<Vec<_>>()
        })));
    }
    Ok(Json(json!({"total":matches.len(),
        "items":values.into_iter().skip(offset).take(limit).collect::<Vec<_>>(),"effects":effects})))
}
fn finding_summary(f: &sniff_test_audit_bridge::Finding) -> serde_json::Value {
    json!({"id":f.id,"crate_name":f.crate_name,"root":f.root,"reason":f.reason,"level":f.level,"effect":f.effect,"class":f.class,"path":f.audit.as_ref().and_then(|a| a.source.as_ref()).map(|l| &l.path)})
}

fn group_effect_sources(
    findings: &[&sniff_test_audit_bridge::Finding],
    query: &str,
) -> Vec<serde_json::Value> {
    use sniff_test_report::{DirectSourceKey, justification_impact_rank};
    use std::collections::{BTreeMap, BTreeSet};
    let mut sites: BTreeMap<&DirectSourceKey, Vec<&sniff_test_audit_bridge::Finding>> =
        BTreeMap::new();
    let mut fallback = Vec::new();
    for &finding in findings {
        if let Some(source) = &finding.direct_source {
            sites.entry(source).or_default().push(finding);
        } else {
            fallback.push(finding);
        }
    }
    let mut sites: Vec<_> = sites.into_iter().collect();
    sites.sort_by_cached_key(|(source, reports)| {
        let roots: BTreeSet<_> = reports.iter().filter_map(|f| f.root.as_deref()).collect();
        justification_impact_rank(reports.len(), roots.len(), *source)
    });
    let query = query.to_lowercase();
    let mut files = std::collections::HashMap::new();
    let query = query.as_str();
    let sources = sites.into_iter().filter_map(|(source, reports)| {
        let first = reports[0];
        let mut location =
            serde_json::to_value(first.audit.as_ref().and_then(|a| a.source.as_ref())).unwrap();
        annotate_source_lines(&mut location, &mut files);
        let path = location["path"].as_str().unwrap_or(&source.source.0);
        let position = location["line"]
            .as_u64()
            .map(|line| line.to_string())
            .unwrap_or_else(|| format!("byte {}", source.source.2));
        let description = source
            .function
            .as_deref()
            .or(source.target.as_deref())
            .or(source.kind.2.as_deref())
            .or(first.class.as_deref())
            .unwrap_or("effect source");
        let requirements = if source.missing_requirements.is_empty() {
            &source.requirements
        } else {
            &source.missing_requirements
        };
        let mut label = format!("{} · {path}:{position} · {description}", source.kind.0);
        if !requirements.is_empty() {
            label.push_str(&format!(" · {}", requirements.join(", ")));
        }
        let search = format!(
            "{label} {} {}",
            source.kind.2.as_deref().unwrap_or_default(),
            source.target.as_deref().unwrap_or_default()
        );
        if !search.to_lowercase().contains(query) {
            return None;
        }
        Some(json!({
            "key":serde_json::to_string(source).unwrap(),"label":label,"path":path,
            "count":reports.len(),
            "items":reports.iter().map(|f| finding_summary(f)).collect::<Vec<_>>()
        }))
    });
    let fallback = fallback.into_iter().filter_map(|finding| {
        // Findings without direct-source identity must never inflate a source's impact.
        let path = finding
            .audit
            .as_ref()
            .and_then(|a| a.source.as_ref())
            .map(|l| l.path.as_str())
            .unwrap_or("Unknown source");
        let label = format!(
            "{} · {path} · {}",
            finding.effect.as_deref().unwrap_or("Diagnostic"),
            finding.class.as_deref().unwrap_or(&finding.kind)
        );
        label.to_lowercase().contains(query).then(|| {
            json!({
                "key":format!("finding:{}",finding.id),"label":label,"path":path,
                "count":1,"items":[finding_summary(finding)]
            })
        })
    });
    sources.chain(fallback).collect()
}

// Preserve first-occurrence order while keeping each file complete.
fn group_findings(values: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    let mut indices = std::collections::HashMap::new();
    let mut groups: Vec<serde_json::Value> = Vec::new();
    for value in values {
        let key = ["path", "root", "crate_name"]
            .iter()
            .find_map(|field| value[*field].as_str().filter(|v| !v.is_empty()))
            .unwrap_or("Unknown source")
            .to_owned();
        let index = *indices.entry(key.clone()).or_insert_with(|| {
            groups.push(json!({"key":key,"items":[],"count":0}));
            groups.len() - 1
        });
        let group = &mut groups[index];
        group["items"].as_array_mut().unwrap().push(value);
        group["count"] = json!(group["items"].as_array().unwrap().len());
    }
    groups
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
#[derive(Deserialize)]
struct Update {
    finding: Option<String>,
    path: String,
    revision: u64,
    content: String,
}
async fn save_source(State(app): State<App>, Json(edit): Json<Update>) -> ApiResult {
    let mut session = app.session.lock().unwrap();
    let buffer = session.save_source(&edit.path, edit.revision, edit.content)?;
    let targets = edit
        .finding
        .as_ref()
        .and_then(|id| {
            session
                .analysis
                .findings
                .iter()
                .find(|finding| &finding.id == id)
        })
        .and_then(|finding| finding.audit.as_ref())
        .map(|audit| &audit.targets);
    Ok(Json(
        json!({"buffer":buffer,"status":status(&session),"finding":edit.finding,"targets":targets}),
    ))
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

async fn override_editor(
    State(app): State<App>,
    Json(target): Json<OverrideEditorTarget>,
) -> ApiResult {
    Ok(Json(json!(
        app.session.lock().unwrap().open_override_editor(target)?
    )))
}

#[derive(Deserialize)]
struct OverrideCommit {
    token: String,
    destination: String,
    filename: Option<String>,
    document: String,
}
async fn override_commit(State(app): State<App>, Json(edit): Json<OverrideCommit>) -> ApiResult {
    let mut session = app.session.lock().unwrap();
    let (buffer, destination) = session.commit_override(
        &edit.token,
        &edit.destination,
        edit.filename.as_deref(),
        edit.document,
    )?;
    Ok(Json(
        json!({"buffer": buffer, "destination": destination, "status": status(&session)}),
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn file_groups_keep_all_findings_in_order_and_support_missing_paths() {
        let mut values = vec![json!({"path":"first.rs","id":"first"})];
        values.extend((0..101).map(|i| json!({"path":format!("file{i}.rs"),"id":i})));
        values.extend((0..150).map(|i| json!({"path":"first.rs","id":i})));
        values.push(json!({"root":"root-only","crate_name":"crate"}));
        values.push(json!({"crate_name":"crate"}));
        let groups = group_findings(values);
        assert_eq!(groups.len(), 104);
        assert_eq!(groups[0]["key"], "first.rs");
        assert_eq!(groups[0]["count"], 151);
        assert_eq!(groups[0]["items"][0]["id"], "first");
        assert_eq!(groups[100]["key"], "file99.rs");
        assert_eq!(groups[102]["key"], "root-only");
        assert_eq!(groups[103]["key"], "crate");
    }

    fn source_finding(id: &str, source: u64, root: &str) -> sniff_test_audit_bridge::Finding {
        let mut finding: sniff_test_audit_bridge::Finding = serde_json::from_value(json!({
            "id":id,"crate_name":"crate","root":root,"effect":"custom","kind":"effect",
            "class":"concrete-operation","level":"warn","reason":format!("reachable from {root}"),
            "requirements":[],"missing_requirements":[],"display_trace":[]
        }))
        .unwrap();
        finding.direct_source = Some(sniff_test_report::DirectSourceKey {
            source: ("shared.rs".into(), "source".into(), source, source + 1),
            kind: ("custom".into(), 0, Some("request".into())),
            function: Some("origin".into()),
            target: None,
            owner: None,
            missing_requirements: vec![],
            requirements: vec![],
        });
        finding
    }

    #[test]
    fn source_groups_rank_by_reports_then_roots_then_source_and_keep_all_reports() {
        let values = vec![
            source_finding("a1", 10, "caller_a"),
            source_finding("b1", 20, "caller_b"),
            source_finding("c1", 30, "caller_c"),
            source_finding("a2", 10, "caller_a"),
            source_finding("b2", 20, "caller_d"),
            source_finding("c2", 30, "caller_c"),
            source_finding("c3", 30, "caller_c"),
            source_finding("d1", 40, "caller_e"),
            source_finding("d2", 40, "caller_e"),
        ];
        let refs = values.iter().collect::<Vec<_>>();
        let groups = group_effect_sources(&refs, "");
        assert_eq!(
            groups
                .iter()
                .map(|g| g["items"][0]["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["c1", "b1", "a1", "d1"]
        );
        assert_eq!(groups[0]["count"], 3);
        assert_eq!(groups[0]["items"][2]["id"], "c3");
        assert_eq!(group_effect_sources(&refs, "SHARED.RS"), groups);
        assert_eq!(group_effect_sources(&refs, "origin"), groups);
        assert_eq!(group_effect_sources(&refs, "request"), groups);
        assert!(group_effect_sources(&refs, "caller_c").is_empty());
        assert!(group_effect_sources(&refs, "reachable from").is_empty());
        assert_eq!(
            group_effect_sources(&refs, "byte 30"),
            vec![groups[0].clone()]
        );
    }

    #[test]
    fn source_groups_separate_obligations_effects_and_missing_identity() {
        let first = source_finding("a", 10, "root");
        let mut obligation = first.clone();
        obligation.id = "b".into();
        obligation
            .direct_source
            .as_mut()
            .unwrap()
            .missing_requirements
            .push("bounds".into());
        let mut effect = first.clone();
        effect.id = "c".into();
        effect.direct_source.as_mut().unwrap().kind.0 = "other".into();
        let mut fallback = first.clone();
        fallback.id = "d".into();
        fallback.direct_source = None;
        let values = [fallback.clone(), first, obligation, effect, fallback];
        let refs = values.iter().collect::<Vec<_>>();
        let groups = group_effect_sources(&refs, "");
        assert_eq!(groups.len(), 5);
        assert!(groups.iter().all(|g| g["count"] == 1));
        assert_eq!(groups[3]["items"][0]["id"], "d");
        let filtered = group_effect_sources(&refs, "bounds");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["items"][0]["id"], "b");
    }

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
    async fn grouped_api_paginates_whole_groups_after_filtering() {
        let dir = tempfile::tempdir().unwrap();
        let config = sniff_test_audit_bridge::AnalysisConfig {
            executable: "false".into(),
            directory: dir.path().into(),
            arguments: vec![],
        };
        let mut session =
            Session::open(dir.path().into(), dir.path().join("target"), config).unwrap();
        for i in 0..252 {
            session.analysis.findings.push(serde_json::from_value(json!({
                "id":i.to_string(), "crate_name":"crate", "root":if i<151 {"large".to_owned()} else {format!("root{i}")},
                "effect":if i<151 {"panic"} else {"safety"}, "kind":"operation",
                "class":"concrete-operation", "level":"warn", "reason":"test",
                "requirements":[], "missing_requirements":[], "display_trace":[]
            })).unwrap());
        }
        let app = App {
            lsp: Default::default(),
            session: Arc::new(Mutex::new(session)),
            token: "secret".into(),
            origin: "http://127.0.0.1:1234".into(),
        };
        let query = |s: &str| {
            Query::<Filter>::try_from_uri(&format!("/findings?{s}").parse().unwrap()).unwrap()
        };
        let first = findings(State(app.clone()), query("grouped=true"))
            .await
            .ok()
            .unwrap()
            .0;
        assert_eq!(first["total"], 252);
        assert_eq!(first["total_groups"], 102);
        assert_eq!(first["groups"].as_array().unwrap().len(), 100);
        assert_eq!(first["groups"][0]["count"], 151);
        let second = findings(State(app.clone()), query("grouped=true&offset=100"))
            .await
            .ok()
            .unwrap()
            .0;
        assert_eq!(second["groups"].as_array().unwrap().len(), 2);
        assert_eq!(second["groups"][0]["key"], "root250");
        let filtered = findings(
            State(app.clone()),
            query("grouped=true&effect=panic&level=warn&class=concrete-operation&q=large"),
        )
        .await
        .ok()
        .unwrap()
        .0;
        assert_eq!(filtered["total"], 151);
        assert_eq!(filtered["total_groups"], 1);
        assert_eq!(
            filtered["groups"][0]["items"].as_array().unwrap().len(),
            151
        );
        {
            let mut session = app.session.lock().unwrap();
            for (index, finding) in session.analysis.findings.iter_mut().enumerate() {
                let source = if index < 151 { 0 } else { index as u64 };
                finding.direct_source = source_finding("", source, "").direct_source;
            }
        }
        let inverted = findings(
            State(app.clone()),
            query("group_by=effect-source&q=shared.rs"),
        )
        .await
        .ok()
        .unwrap()
        .0;
        assert_eq!(inverted["total"], 252);
        assert_eq!(inverted["total_groups"], 102);
        assert_eq!(inverted["groups"].as_array().unwrap().len(), 100);
        assert_eq!(inverted["groups"][0]["count"], 151);
        let second = findings(
            State(app.clone()),
            query("group_by=effect-source&offset=100&q=shared.rs"),
        )
        .await
        .ok()
        .unwrap()
        .0;
        assert_eq!(second["groups"].as_array().unwrap().len(), 2);
        let narrowed = findings(
            State(app.clone()),
            query("group_by=effect-source&q=shared.rs&effect=panic"),
        )
        .await
        .ok()
        .unwrap()
        .0;
        assert_eq!(narrowed["total_groups"], 1);
        assert_eq!(narrowed["groups"][0]["count"], 151);
        let root_search = findings(State(app.clone()), query("group_by=effect-source&q=large"))
            .await
            .ok()
            .unwrap()
            .0;
        assert_eq!(root_search["total_groups"], 0);
        let flat = findings(State(app), query("")).await.ok().unwrap().0;
        assert_eq!(flat["items"].as_array().unwrap().len(), 100);
        assert!(flat.get("groups").is_none());
    }

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
