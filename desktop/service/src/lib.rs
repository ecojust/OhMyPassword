//! Local browser bridge and authenticated, encrypted peer synchronization.
//! Discovery never grants access. Only paired peers can exchange vault records.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod discovery;
mod manual;
mod protocol;
pub use manual::MergeSession;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ohmypassword_core::{EntryInput, Vault};
use protocol::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use tokio::sync::{watch, Notify, Semaphore};
use zeroize::Zeroize;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Authentication,
    Locked,
    ForbiddenOrigin,
    InvalidHost,
    InvalidRequest,
    InvalidEndpoint,
    Expired,
    Replay,
    Busy,
    TooLarge,
    Unavailable,
    Vault(String),
    Io(std::io::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Authentication => "此合并会话无效或尚未获双方确认",
                Self::Locked => "密码库已锁定，请先在客户端解锁",
                Self::ForbiddenOrigin => "仅允许 OhMyPassword 官方浏览器插件访问",
                Self::InvalidHost => "无效的本地服务地址",
                Self::InvalidRequest => "请求格式无效",
                Self::InvalidEndpoint => "请使用局域网 IP 地址和有效端口",
                Self::Expired => "合并会话或消息已过期，请重新发起",
                Self::Replay => "重复消息已拒绝",
                Self::Busy => "服务繁忙，请稍后重试",
                Self::TooLarge => "密码库已达到同步容量上限",
                Self::Unavailable => "设备暂不可达，请确认双方已解锁且位于同一局域网",
                Self::Vault(e) => e,
                Self::Io(_) => "无法启动服务，请检查端口是否已被占用",
            }
        )
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ohmypassword_core::Error> for Error {
    fn from(e: ohmypassword_core::Error) -> Self {
        if e.is_capacity_limit() {
            Self::TooLarge
        } else {
            Self::Vault(e.to_string())
        }
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Authentication => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Locked => (StatusCode::LOCKED, "locked"),
            Self::ForbiddenOrigin => (StatusCode::FORBIDDEN, "forbidden_origin"),
            Self::InvalidHost => (StatusCode::FORBIDDEN, "invalid_host"),
            Self::Expired => (StatusCode::GONE, "expired"),
            Self::Replay => (StatusCode::CONFLICT, "replay"),
            Self::Busy => (StatusCode::TOO_MANY_REQUESTS, "busy"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
            Self::Unavailable | Self::Io(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            _ => (StatusCode::BAD_REQUEST, "invalid_request"),
        };
        let message = self.to_string();
        let mut r = (
            status,
            Json(serde_json::json!({"error":code,"message":message})),
        )
            .into_response();
        secure_headers(&mut r);
        r
    }
}
fn secure_headers(response: &mut Response) {
    let h = response.headers_mut();
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    h.insert("pragma", HeaderValue::from_static("no-cache"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
}
fn lock<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    mutex.lock().map_err(|_| Error::Unavailable)
}

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub local_port: u16,
    pub lan_port: u16,
    pub enable_discovery: bool,
    pub discovery_interval_secs: u64,
}
impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            local_port: 17841,
            lan_port: 17842,
            enable_discovery: true,
            discovery_interval_secs: 300,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub last_seen: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub local_endpoint: String,
    pub lan_port: u16,
    pub running: bool,
    pub discovery_generation: u64,
    pub last_discovery_at: Option<u64>,
    pub next_discovery_at: Option<u64>,
    pub discovering: bool,
    pub merges: Vec<MergeSession>,
    pub last_error: Option<String>,
    pub discovered: Vec<DiscoveredPeer>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    protocol: u32,
    device_id: String,
    name: String,
    epoch: String,
}
struct Inner {
    vault: Arc<Mutex<Vault>>,
    local_port: u16,
    lan_port: u16,
    discovery_interval_secs: u64,
    active: AtomicBool,
    shutdown: watch::Sender<bool>,
    detect_trigger: Notify,
    epoch: Mutex<String>,
    sessions: Mutex<HashMap<String, manual::Session>>,
    runtime: tokio::runtime::Handle,
    replay: Mutex<ReplayGuard>,
    status: Mutex<ServiceStatus>,
    discovered: Mutex<HashMap<String, DiscoveredPeer>>,
    capacity: Arc<Semaphore>,
    rates: Mutex<HashMap<IpAddr, (u64, u32)>>,
    client: reqwest::Client,
}
pub struct Service {
    inner: Arc<Inner>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}
impl Service {
    pub fn start(vault: Arc<Mutex<Vault>>, config: ServiceConfig) -> Result<Self> {
        let local = TcpListener::bind((Ipv4Addr::LOCALHOST, config.local_port))?;
        let lan = TcpListener::bind((Ipv4Addr::UNSPECIFIED, config.lan_port))?;
        local.set_nonblocking(true)?;
        lan.set_nonblocking(true)?;
        let local_port = local.local_addr()?.port();
        let lan_port = lan.local_addr()?.port();
        let (shutdown, _) = watch::channel(false);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| Error::Unavailable)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let inner = Arc::new(Inner {
            vault,
            local_port,
            lan_port,
            discovery_interval_secs: config.discovery_interval_secs.max(1),
            active: AtomicBool::new(true),
            shutdown,
            detect_trigger: Notify::new(),
            epoch: Mutex::new(random_id()),
            sessions: Mutex::new(HashMap::new()),
            runtime: runtime.handle().clone(),
            replay: Mutex::new(ReplayGuard::new()),
            status: Mutex::new(ServiceStatus {
                local_endpoint: format!("http://127.0.0.1:{local_port}"),
                lan_port,
                running: true,
                discovery_generation: 0,
                last_discovery_at: None,
                next_discovery_at: None,
                discovering: false,
                merges: vec![],
                last_error: None,
                discovered: vec![],
            }),
            discovered: Mutex::new(HashMap::new()),
            capacity: Arc::new(Semaphore::new(8)),
            rates: Mutex::new(HashMap::new()),
            client,
        });
        let state = inner.clone();
        let handle = thread::Builder::new()
            .name("ohmypassword-service".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let Ok(local) = tokio::net::TcpListener::from_std(local) else {
                        return;
                    };
                    let Ok(lan) = tokio::net::TcpListener::from_std(lan) else {
                        return;
                    };
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    let discovery = if config.enable_discovery {
                        discovery::Discovery::start(state.clone()).ok()
                    } else {
                        None
                    };
                    let local_app = Router::new()
                        .route("/v1/status", get(local_status))
                        .route("/v1/browser/connect", post(browser_connect))
                        .route(
                            "/v1/credentials",
                            get(get_credentials).post(put_credentials),
                        )
                        .route("/v1/credentials/search", post(search_credentials))
                        .fallback(local_fallback)
                        .layer(axum::middleware::from_fn_with_state(
                            state.clone(),
                            local_middleware,
                        ))
                        .layer(DefaultBodyLimit::max(MAX_BODY))
                        .with_state(state.clone());
                    let lan_app = Router::new()
                        .route("/v2/info", get(challenge))
                        .route("/v2/merge/request", post(manual::request))
                        .route("/v2/merge/reveal", post(manual::reveal))
                        .route("/v2/merge/{id}/status", post(manual::session_status))
                        .route("/v2/merge/{id}/exchange", post(manual::exchange))
                        .route("/v2/merge/{id}/ack", post(manual::ack))
                        .route("/v2/merge/{id}/cancel", post(manual::cancel))
                        .fallback(|| async { Error::InvalidRequest })
                        .layer(axum::middleware::from_fn_with_state(
                            state.clone(),
                            lan_middleware,
                        ))
                        .layer(DefaultBodyLimit::max(MAX_BODY))
                        .with_state(state.clone());
                    let local_stop = state.shutdown.subscribe();
                    let lan_stop = state.shutdown.subscribe();
                    let local_server = axum::serve(
                        local,
                        local_app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(wait_shutdown(local_stop));
                    let lan_server = axum::serve(
                        lan,
                        lan_app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(wait_shutdown(lan_stop));
                    let mut local_task = tokio::spawn(async move {
                        let _ = local_server.await;
                    });
                    let mut lan_task = tokio::spawn(async move {
                        let _ = lan_server.await;
                    });
                    let mut worker = tokio::spawn(discovery_worker(
                        state.clone(),
                        config.discovery_interval_secs.max(1),
                    ));
                    wait_shutdown(state.shutdown.subscribe()).await;
                    if tokio::time::timeout(Duration::from_secs(2), async {
                        let _ = tokio::join!(&mut local_task, &mut lan_task, &mut worker);
                    })
                    .await
                    .is_err()
                    {
                        local_task.abort();
                        lan_task.abort();
                        worker.abort();
                    }
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    drop(discovery);
                })
            })?;
        Ok(Self {
            inner,
            thread: Mutex::new(Some(handle)),
        })
    }
    pub fn status(&self) -> ServiceStatus {
        let mut status = lock(&self.inner.status)
            .map(|s| s.clone())
            .unwrap_or(ServiceStatus {
                local_endpoint: String::new(),
                lan_port: 0,
                running: false,
                last_error: Some("服务不可用".into()),
                discovery_generation: 0,
                last_discovery_at: None,
                next_discovery_at: None,
                discovering: false,
                discovered: vec![],
                merges: vec![],
            });
        status.running =
            self.inner.active.load(Ordering::Acquire) && !*self.inner.shutdown.borrow();
        status.discovering =
            status.running && status.last_discovery_at.is_some_and(|at| now() < at + 20);
        if let Ok(mut found) = self.inner.discovered.lock() {
            found.retain(|_, p| now().saturating_sub(p.last_seen) < 660);
            status.discovered = found.values().cloned().collect();
            status.discovered.sort_by(|a, b| a.id.cmp(&b.id));
        }
        status.merges = manual::views(&self.inner);
        status
    }
    pub fn detect_devices(&self) -> Result<()> {
        self.inner.ensure_active()?;
        if lock(&self.inner.vault)?.status().locked {
            return Err(Error::Locked);
        }
        self.inner.request_detection();
        Ok(())
    }
    pub fn pause(&self) {
        self.inner.active.store(false, Ordering::Release);
        if let Ok(mut epoch) = self.inner.epoch.lock() {
            *epoch = random_id();
        }
        manual::abort_sessions(&self.inner, "密码库已锁定，合并已取消");
        if let Ok(mut status) = self.inner.status.lock() {
            status.discovering = false;
            status.last_discovery_at = None;
            status.next_discovery_at = None;
            status.last_error = None;
        }
        if let Ok(mut found) = self.inner.discovered.lock() {
            found.clear();
        }
    }
    pub fn resume(&self) {
        self.inner.active.store(true, Ordering::Release);
        self.inner.request_detection();
    }
    pub fn discovered_peer(&self, id: &str, endpoint: SocketAddr) {
        self.inner.discovered_peer(id, "", endpoint);
    }
    pub fn discovered_peer_named(&self, id: &str, name: &str, endpoint: SocketAddr) {
        self.inner.discovered_peer(id, name, endpoint);
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.inner.shutdown.send_replace(true);
        self.inner.active.store(false, Ordering::Release);
        manual::abort_sessions(&self.inner, "服务已停止");
        if let Ok(mut join) = self.thread.lock() {
            if let Some(join) = join.take() {
                let _ = join.join();
            }
        }
    }
}
impl Inner {
    fn ensure_active(&self) -> Result<()> {
        if !self.active.load(Ordering::Acquire) || *self.shutdown.borrow() {
            Err(Error::Locked)
        } else {
            Ok(())
        }
    }
    fn discovered_peer(&self, id: &str, name: &str, address: SocketAddr) {
        if !valid_id(id) || !address.is_ipv4() || !local_ip(address.ip()) || address.port() == 0 {
            return;
        }
        if lock(&self.vault).is_ok_and(|vault| vault.status().device_id == id) {
            return;
        }
        if let Ok(mut found) = self.discovered.lock() {
            found.retain(|_, p| now().saturating_sub(p.last_seen) < 660);
            if found.len() < 128 || found.contains_key(id) {
                let name = if name.is_empty() {
                    format!("OhMyPassword {}", &id[..8])
                } else {
                    name.chars().take(64).collect()
                };
                found.insert(
                    id.into(),
                    DiscoveredPeer {
                        id: id.into(),
                        name,
                        endpoint: endpoint(address),
                        last_seen: now(),
                    },
                );
            }
        }
    }
    fn request_detection(&self) {
        if self.ensure_active().is_err() {
            return;
        }
        if let Ok(mut status) = self.status.lock() {
            status.discovery_generation = status.discovery_generation.saturating_add(1);
            status.last_discovery_at = Some(now());
            status.next_discovery_at = Some(now() + self.discovery_interval_secs);
            status.discovering = true;
        }
        self.detect_trigger.notify_one();
    }
}
async fn wait_shutdown(mut receiver: watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}
fn source_endpoint(remote: SocketAddr, port: u16) -> Result<String> {
    let bind = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(remote)?;
    let ip = socket.local_addr()?.ip();
    if !local_ip(ip) {
        return Err(Error::InvalidEndpoint);
    }
    Ok(endpoint(SocketAddr::new(ip, port)))
}

fn extension_origin(value: &str) -> bool {
    value == include_str!("browser-origin.txt").trim()
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str> {
    if headers.get_all(name).iter().count() != 1 {
        return Err(Error::InvalidRequest);
    }
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or(Error::InvalidRequest)
}
fn local_origin(state: &Inner, headers: &HeaderMap, public: bool) -> Result<Option<String>> {
    let host = header(headers, "host").map_err(|_| Error::InvalidHost)?;
    if host != format!("127.0.0.1:{}", state.local_port)
        && host != format!("localhost:{}", state.local_port)
    {
        return Err(Error::InvalidHost);
    }
    let origin = match headers.get("origin") {
        Some(_) => header(headers, "origin").map_err(|_| Error::ForbiddenOrigin)?,
        None if public => return Ok(None),
        None => return Err(Error::ForbiddenOrigin),
    };
    if !extension_origin(origin) {
        return Err(Error::ForbiddenOrigin);
    }
    if !public {
        state.ensure_active()?;
        let vault = lock(&state.vault)?;
        if vault.status().locked {
            return Err(Error::Locked);
        }
    }
    Ok(Some(origin.into()))
}
fn cors(response: &mut Response, origin: &str) {
    if let Ok(value) = HeaderValue::from_str(origin) {
        response
            .headers_mut()
            .insert("access-control-allow-origin", value);
        response
            .headers_mut()
            .insert("vary", HeaderValue::from_static("Origin"));
    }
}
async fn local_middleware(
    State(state): State<Arc<Inner>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let public = request.uri().path() == "/v1/status";
    let origin = match local_origin(&state, request.headers(), public) {
        Ok(origin) => origin,
        Err(error) => {
            let mut response = error.into_response();
            if let Some(origin) = request
                .headers()
                .get("origin")
                .and_then(|o| o.to_str().ok())
                .filter(|o| extension_origin(o))
            {
                cors(&mut response, origin);
            }
            return response;
        }
    };
    let mut response = if request.method() == Method::OPTIONS {
        let method = request
            .headers()
            .get("access-control-request-method")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let headers = request
            .headers()
            .get("access-control-request-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !["GET", "POST"].contains(&method)
            || !headers
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .all(|s| s.eq_ignore_ascii_case("content-type"))
        {
            Error::ForbiddenOrigin.into_response()
        } else {
            let mut r = StatusCode::NO_CONTENT.into_response();
            r.headers_mut().insert(
                "access-control-allow-methods",
                HeaderValue::from_static("GET, POST"),
            );
            r.headers_mut().insert(
                "access-control-allow-headers",
                HeaderValue::from_static("Content-Type"),
            );
            r.headers_mut()
                .insert("access-control-max-age", HeaderValue::from_static("60"));
            r.headers_mut().insert(
                "access-control-allow-private-network",
                HeaderValue::from_static("true"),
            );
            r
        }
    } else {
        match state.capacity.clone().try_acquire_owned() {
            Ok(_permit) => {
                match tokio::time::timeout(Duration::from_secs(10), next.run(request)).await {
                    Ok(response) => response,
                    Err(_) => Error::Busy.into_response(),
                }
            }
            Err(_) => Error::Busy.into_response(),
        }
    };
    if let Some(origin) = origin {
        cors(&mut response, &origin);
    }
    secure_headers(&mut response);
    response
}
async fn lan_middleware(
    State(state): State<Arc<Inner>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // LAN traffic is a native-only protocol. Browser requests have no role here.
    if request.headers().contains_key("origin") {
        return Error::ForbiddenOrigin.into_response();
    }
    let source = match request.extensions().get::<ConnectInfo<SocketAddr>>() {
        Some(source) => source.0.ip(),
        None => return Error::InvalidEndpoint.into_response(),
    };
    if !local_ip(source) {
        return Error::InvalidEndpoint.into_response();
    }
    {
        let Ok(mut rates) = state.rates.lock() else {
            return Error::Unavailable.into_response();
        };
        let current = now();
        rates.retain(|_, (started, _)| current.saturating_sub(*started) < 60);
        if rates.len() >= 128 && !rates.contains_key(&source) {
            return Error::Busy.into_response();
        }
        let (_, count) = rates.entry(source).or_insert((current, 0));
        if *count >= 64 {
            return Error::Busy.into_response();
        }
        *count += 1;
    }
    let mut response = match state.capacity.clone().try_acquire_owned() {
        Ok(_permit) => match tokio::time::timeout(Duration::from_secs(10), next.run(request)).await
        {
            Ok(r) => r,
            Err(_) => Error::Busy.into_response(),
        },
        Err(_) => Error::Busy.into_response(),
    };
    secure_headers(&mut response);
    response
}
fn authorize<'a>(
    state: &'a Inner,
    headers: &HeaderMap,
) -> Result<std::sync::MutexGuard<'a, Vault>> {
    state.ensure_active()?;
    let origin = header(headers, "origin").map_err(|_| Error::ForbiddenOrigin)?;
    if !extension_origin(origin) {
        return Err(Error::ForbiddenOrigin);
    }
    let vault = lock(&state.vault)?;
    if vault.status().locked {
        return Err(Error::Locked);
    }
    state.ensure_active()?;
    Ok(vault)
}

async fn local_status(State(state): State<Arc<Inner>>) -> Result<Json<serde_json::Value>> {
    let vault = lock(&state.vault)?;
    let status = vault.status();
    Ok(Json(
        serde_json::json!({"protocol":2,"initialized":status.initialized,"locked":status.locked||state.ensure_active().is_err()}),
    ))
}
async fn browser_connect(
    State(state): State<Arc<Inner>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let _vault = authorize(&state, &headers)?;
    Ok(Json(serde_json::json!({"connected":true,"protocol":2})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    hostname: String,
}
fn read_credentials(
    state: &Inner,
    headers: &HeaderMap,
    search: Search,
) -> Result<Json<serde_json::Value>> {
    let vault = authorize(state, headers)?;
    if search.hostname.len() > 253 || search.hostname.trim().is_empty() {
        return Err(Error::InvalidRequest);
    }
    let summaries = vault.list(Some(&search.hostname))?;
    let entries: std::result::Result<Vec<_>, _> =
        summaries.iter().map(|e| vault.get(&e.id)).collect();
    Ok(Json(serde_json::json!({"entries":entries?})))
}
async fn get_credentials(
    State(state): State<Arc<Inner>>,
    headers: HeaderMap,
    Query(search): Query<Search>,
) -> Result<Json<serde_json::Value>> {
    read_credentials(&state, &headers, search)
}
async fn search_credentials(
    State(state): State<Arc<Inner>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>> {
    require_json(&headers)?;
    let search = serde_json::from_slice(&body).map_err(|_| Error::InvalidRequest)?;
    read_credentials(&state, &headers, search)
}
fn require_json(headers: &HeaderMap) -> Result<()> {
    let content = header(headers, "content-type")?;
    if content.split(';').next().map(str::trim) != Some("application/json") {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}
async fn put_credentials(
    State(state): State<Arc<Inner>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>> {
    let mut vault = authorize(&state, &headers)?;
    require_json(&headers)?;
    let input: EntryInput = serde_json::from_slice(&body).map_err(|_| Error::InvalidRequest)?;
    let entry = vault.upsert(input)?;
    Ok(Json(serde_json::json!({"entry":entry})))
}
async fn local_fallback() -> Error {
    Error::InvalidRequest
}
async fn challenge(State(state): State<Arc<Inner>>) -> Result<Json<Challenge>> {
    state.ensure_active()?;
    let vault = lock(&state.vault)?;
    let own = vault.status();
    Ok(Json(Challenge {
        protocol: 2,
        device_id: own.device_id,
        name: own.device_name,
        epoch: lock(&state.epoch)?.clone(),
    }))
}

async fn response_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T> {
    if !response.status().is_success() {
        return Err(match response.status().as_u16() {
            401 | 403 => Error::Authentication,
            423 => Error::Locked,
            410 => Error::Expired,
            409 => Error::Replay,
            413 => Error::TooLarge,
            429 => Error::Busy,
            _ => Error::Unavailable,
        });
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_BODY as u64)
    {
        return Err(Error::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
        if bytes.len() + chunk.len() > MAX_BODY {
            return Err(Error::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    let data = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest);
    bytes.zeroize();
    data
}
async fn fetch_challenge(state: &Inner, address: SocketAddr, id: &str) -> Result<Challenge> {
    let response = state
        .client
        .get(format!("{}/v2/info", endpoint(address)))
        .send()
        .await
        .map_err(|_| Error::Unavailable)?;
    let info: Challenge = response_json(response).await?;
    if info.protocol != 2 || info.device_id != id || !valid_id(&info.epoch) || info.name.len() > 128
    {
        return Err(Error::Authentication);
    }
    Ok(info)
}
async fn discovery_worker(state: Arc<Inner>, interval_secs: u64) {
    let delay = Duration::from_secs(interval_secs.max(1));
    let mut deadline = tokio::time::Instant::now();
    let mut shutdown = state.shutdown.subscribe();
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _=tokio::time::sleep_until(deadline)=>{state.request_detection();deadline=tokio::time::Instant::now()+delay;},
            _=state.detect_trigger.notified()=>{deadline=tokio::time::Instant::now()+delay;},
            _=shutdown.changed()=>{if *shutdown.borrow(){break}},
        }
        manual::expire_sessions(&state);
    }
}

#[cfg(test)]
mod tests;
