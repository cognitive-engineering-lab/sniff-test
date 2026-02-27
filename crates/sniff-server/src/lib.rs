#![feature(mpmc_channel)]
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        mpmc::{Receiver, Sender, channel},
    },
};

use axum::{
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};

const PORT_NUM: &str = "3000";

#[must_use]
/// # Panics
/// Panics if the axum sever panics.
pub fn run_server() -> ServerHandle {
    let (client_handle, server_handle) = build_handles();
    let app = build_app(Arc::new(Mutex::new(client_handle)));

    std::thread::spawn(|| {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{PORT_NUM}"))
                .await
                .unwrap();
            let addr = format!("http://{}", listener.local_addr().unwrap());
            println!("listening on {addr}");
            open::that(&addr).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });

    server_handle
}

fn build_handles() -> (ClientHandle, ServerHandle) {
    let (give_request, get_request) = channel();
    let (give_response, get_response) = channel();
    (
        ClientHandle {
            give_request,
            get_response,
        },
        ServerHandle {
            give_response,
            get_request,
        },
    )
}

fn build_app(analysis: Arc<Mutex<ClientHandle>>) -> Router {
    Router::new()
        .route("/", get(handle_index))
        .route("/api/crate-name", get(handle_crate_name))
        .route("/api/analyze", get(handle_analyze))
        .with_state(analysis)
}

async fn handle_analyze(
    State(ref handle): State<Arc<Mutex<ClientHandle>>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let property = params.get("property").cloned().unwrap_or_default();

    let Response::AnalysisResult { stats } =
        send_get_response(handle, Request::DoAnalysis { property }).await
    else {
        panic!("bad response");
    };

    println!("got analysis response");

    axum::Json(stats)
}

async fn handle_crate_name(State(handle): State<Arc<Mutex<ClientHandle>>>) -> impl IntoResponse {
    let Response::CrateName(name) = send_get_response(&handle, Request::GetCrateName).await else {
        panic!("incorrect response");
    };
    axum::Json(name)
}

async fn send_get_response(handle: &Arc<Mutex<ClientHandle>>, request: Request) -> Response {
    let handle = handle.clone();
    tokio::task::spawn_blocking(move || {
        let handle = handle.lock().unwrap();
        println!("sending stats request");
        handle.give_request.send(request).unwrap();
        println!("done sending stats request");
        handle.get_response.recv().unwrap()
    })
    .await
    .unwrap()
}

async fn handle_index(State(handle): State<Arc<Mutex<ClientHandle>>>) -> String {
    let Response::CrateName(crate_name) = send_get_response(&handle, Request::GetCrateName).await
    else {
        panic!("incorrect response");
    };

    format!("looking at {crate_name} crate")
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct CheckStats {
    pub entrypoints: usize,
    pub total_fns_checked: usize,
    pub w_obligation: usize,
    pub w_no_obligation: usize,
    pub calls_checked: usize,
    pub analysis_time_ms: usize,
}

pub enum Request {
    GetCrateName,
    DoAnalysis { property: String },
}

#[derive(Debug)]
pub enum Response {
    CrateName(String),
    AnalysisResult { stats: CheckStats },
    Err(axum::response::Response<String>),
}

pub struct ServerHandle {
    pub give_response: Sender<Response>,
    pub get_request: Receiver<Request>,
}

pub struct ClientHandle {
    pub give_request: Sender<Request>,
    pub get_response: Receiver<Response>,
}
