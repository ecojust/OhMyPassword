//! Local browser bridge and authenticated, encrypted peer synchronization.
//! Discovery never grants access. Only paired peers can exchange vault records.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod discovery;
mod protocol;

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ohmypassword_core::{EntryInput, Peer, SyncPayload, Vault};
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
    time::{Duration, Instant},
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
                Self::Authentication => "未授权，请在客户端重新授权浏览器或配对设备",
                Self::Locked => "密码库已锁定，请先在客户端解锁",
                Self::ForbiddenOrigin => "此浏览器扩展未获授权",
                Self::InvalidHost => "无效的本地服务地址",
                Self::InvalidRequest => "请求格式无效",
                Self::InvalidEndpoint => "请使用局域网 IP 地址和有效端口",
                Self::Expired => "邀请或消息已过期，请检查设备时间并重试",
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
    pub sync_interval_secs: u64,
}
impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            local_port: 17841,
            lan_port: 17842,
            enable_discovery: true,
            sync_interval_secs: 30,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    pub id: String,
    pub name: String,
    pub endpoint: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub local_endpoint: String,
    pub lan_port: u16,
    pub running: bool,
    pub last_sync: Option<u64>,
    pub last_error: Option<String>,
    pub discovered: Vec<DiscoveredPeer>,
}
#[derive(Serialize, Deserialize)]
pub struct Invitation {
    pub code: String,
    pub expires_at: u64,
    pub endpoint: String,
}
impl Drop for Invitation {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub device_id: String,
    pub name: String,
    pub endpoint: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteData {
    version: u32,
    device_id: String,
    endpoint: String,
    secret: String,
    expires_at: u64,
}
impl Drop for InviteData {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
struct PendingInvite {
    key: [u8; 32],
    expires_at: u64,
    endpoint: String,
}
impl Drop for PendingInvite {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairRequest {
    name: String,
    endpoint: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairReply {
    device_id: String,
    name: String,
    endpoint: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncRequest {
    data: SyncPayload,
    endpoint: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncReply {
    data: SyncPayload,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    protocol: u32,
    device_id: String,
    epoch: String,
}
struct Inner {
    vault: Arc<Mutex<Vault>>,
    local_port: u16,
    lan_port: u16,
    active: AtomicBool,
    shutdown: watch::Sender<bool>,
    trigger: Notify,
    epoch: Mutex<String>,
    pending: Mutex<Option<PendingInvite>>,
    replay: Mutex<ReplayGuard>,
    status: Mutex<ServiceStatus>,
    discovered: Mutex<HashMap<String, (SocketAddr, u64)>>,
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
        let inner = Arc::new(Inner {
            vault,
            local_port,
            lan_port,
            active: AtomicBool::new(true),
            shutdown,
            trigger: Notify::new(),
            epoch: Mutex::new(random_id()),
            pending: Mutex::new(None),
            replay: Mutex::new(ReplayGuard::new()),
            status: Mutex::new(ServiceStatus {
                local_endpoint: format!("http://127.0.0.1:{local_port}"),
                lan_port,
                running: true,
                last_sync: None,
                last_error: None,
                discovered: vec![],
            }),
            discovered: Mutex::new(HashMap::new()),
            capacity: Arc::new(Semaphore::new(8)),
            rates: Mutex::new(HashMap::new()),
            client,
        });
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
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
                        .route("/v1/challenge", get(challenge))
                        .route("/v1/pair", post(pair))
                        .route("/v1/sync", post(sync))
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
                    let mut worker =
                        tokio::spawn(sync_worker(state.clone(), config.sync_interval_secs.max(1)));
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
                last_sync: None,
                last_error: Some("服务不可用".into()),
                discovered: vec![],
            });
        status.running =
            self.inner.active.load(Ordering::Acquire) && !*self.inner.shutdown.borrow();
        if let Ok(mut discovered) = lock(&self.inner.discovered) {
            discovered.retain(|_, (_, time)| now().saturating_sub(*time) < 180);
            status.discovered = discovered
                .iter()
                .map(|(id, (addr, _))| DiscoveredPeer {
                    id: id.clone(),
                    name: format!("OhMyPassword {}", &id[..id.len().min(8)]),
                    endpoint: endpoint(*addr),
                })
                .collect();
        }
        status
    }
    pub fn create_invitation(&self, advertised_ip: IpAddr) -> Result<Invitation> {
        self.inner.ensure_active()?;
        if !advertised_ip.is_ipv4() || !local_ip(advertised_ip) {
            return Err(Error::InvalidEndpoint);
        }
        let status = lock(&self.inner.vault)?.status();
        if status.locked {
            return Err(Error::Locked);
        }
        let key = random_key();
        let expires_at = now() + 300;
        let endpoint = endpoint(SocketAddr::new(advertised_ip, self.inner.lan_port));
        let data = InviteData {
            version: 1,
            device_id: status.device_id,
            endpoint: endpoint.clone(),
            secret: encode(key),
            expires_at,
        };
        let mut json = serde_json::to_vec(&data).map_err(|_| Error::InvalidRequest)?;
        let code = format!("omp1.{}", encode(&json));
        json.zeroize();
        *lock(&self.inner.pending)? = Some(PendingInvite {
            key,
            expires_at,
            endpoint: endpoint.clone(),
        });
        Ok(Invitation {
            code,
            expires_at,
            endpoint,
        })
    }
    pub fn accept_invitation(&self, code: &str) -> Result<PeerInfo> {
        self.inner.ensure_active()?;
        if code.len() > 4096 {
            return Err(Error::InvalidRequest);
        }
        let mut bytes = decode(
            code.trim()
                .strip_prefix("omp1.")
                .ok_or(Error::InvalidRequest)?,
        )?;
        let data = serde_json::from_slice::<InviteData>(&bytes).map_err(|_| Error::InvalidRequest);
        bytes.zeroize();
        let data = data?;
        if data.version != 1 || !valid_id(&data.device_id) {
            return Err(Error::InvalidRequest);
        }
        if data.expires_at < now() || data.expires_at > now() + 300 + CLOCK_WINDOW {
            return Err(Error::Expired);
        }
        let remote = parse_endpoint(&data.endpoint)?;
        let own = lock(&self.inner.vault)?.status();
        if own.locked {
            return Err(Error::Locked);
        }
        if own.device_id == data.device_id {
            return Err(Error::InvalidRequest);
        }
        let advertised = source_endpoint(remote, self.inner.lan_port)?;
        let mut invitation_key = key_from(&data.secret)?;
        let state = self.inner.clone();
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let challenge = fetch_challenge(&state, remote, &data.device_id).await?;
                let id = random_id();
                let env = seal(
                    &invitation_key,
                    "pair",
                    false,
                    &own.device_id,
                    &data.device_id,
                    &id,
                    &challenge.epoch,
                    &PairRequest {
                        name: own.device_name.clone(),
                        endpoint: advertised.clone(),
                    },
                )?;
                state.ensure_active()?;
                if lock(&state.vault)?.status().locked {
                    return Err(Error::Locked);
                }
                let response = post_envelope(&state, remote, "pair", &env).await?;
                validate_response(&response, &env)?;
                let reply: PairReply = open(&invitation_key, "pair", true, &response)?;
                if reply.device_id != data.device_id
                    || parse_endpoint(&reply.endpoint)? != remote
                    || reply.name.len() > 128
                {
                    return Err(Error::Authentication);
                }
                state.ensure_active()?;
                let shared_key = paired_key(&invitation_key, &own.device_id, &data.device_id);
                lock(&state.vault)?.add_peer(Peer {
                    device_id: reply.device_id.clone(),
                    name: reply.name.clone(),
                    endpoint: reply.endpoint.clone(),
                    shared_key,
                })?;
                Ok(PeerInfo {
                    device_id: reply.device_id,
                    name: reply.name,
                    endpoint: reply.endpoint,
                })
            });
        invitation_key.zeroize();
        if result.is_ok() {
            self.trigger_sync()
        }
        result
    }
    pub fn trigger_sync(&self) {
        self.inner.trigger.notify_one();
    }
    pub fn pause(&self) {
        self.inner.active.store(false, Ordering::Release);
        if let Ok(mut invite) = self.inner.pending.lock() {
            *invite = None;
        }
        if let Ok(mut epoch) = self.inner.epoch.lock() {
            *epoch = random_id();
        }
    }
    pub fn resume(&self) {
        self.inner.active.store(true, Ordering::Release);
        self.trigger_sync();
    }
    pub fn discovered_peer(&self, id: &str, endpoint: SocketAddr) {
        self.inner.discovered_peer(id, endpoint);
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.inner.shutdown.send_replace(true);
        self.inner.active.store(false, Ordering::Release);
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
    fn discovered_peer(&self, id: &str, address: SocketAddr) {
        if !valid_id(id) || !address.is_ipv4() || !local_ip(address.ip()) || address.port() == 0 {
            return;
        }
        let paired = self
            .vault
            .lock()
            .ok()
            .and_then(|vault| vault.peers().ok())
            .is_some_and(|peers| peers.iter().any(|p| p.device_id == id));
        if let Ok(mut found) = self.discovered.lock() {
            found.retain(|_, (_, seen)| now().saturating_sub(*seen) < 180);
            if found.len() < 128 || found.contains_key(id) {
                let changed = found
                    .get(id)
                    .is_none_or(|(previous, _)| *previous != address);
                found.insert(id.into(), (address, now()));
                if paired && changed {
                    self.trigger.notify_one();
                }
            }
        }
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
    if let Some(id) = value.strip_prefix("chrome-extension://") {
        return id.len() == 32 && id.bytes().all(|c| (b'a'..=b'p').contains(&c));
    }
    if let Some(id) = value.strip_prefix("moz-extension://") {
        return valid_id(id);
    }
    false
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
        if !vault
            .clients()?
            .iter()
            .any(|client| client.origin == origin)
        {
            return Err(Error::ForbiddenOrigin);
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
                .all(|s| {
                    s.eq_ignore_ascii_case("authorization")
                        || s.eq_ignore_ascii_case("content-type")
                })
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
                HeaderValue::from_static("Authorization, Content-Type"),
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
    let token = header(headers, "authorization")
        .map_err(|_| Error::Authentication)?
        .strip_prefix("Bearer ")
        .ok_or(Error::Authentication)?;
    if token.len() > 128 {
        return Err(Error::Authentication);
    }
    let vault = lock(&state.vault)?;
    if vault.status().locked {
        return Err(Error::Locked);
    }
    if !vault.authorize_client(token, origin)? {
        return Err(Error::Authentication);
    }
    state.ensure_active()?;
    Ok(vault)
}
async fn local_status(State(state): State<Arc<Inner>>) -> Result<Json<serde_json::Value>> {
    let vault = lock(&state.vault)?;
    let status = vault.status();
    Ok(Json(
        serde_json::json!({"protocol":1,"initialized":status.initialized,"locked":status.locked||state.ensure_active().is_err()}),
    ))
}
async fn browser_connect(
    State(state): State<Arc<Inner>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let _vault = authorize(&state, &headers)?;
    Ok(Json(serde_json::json!({"connected":true,"protocol":1})))
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
    state.trigger.notify_one();
    Ok(Json(serde_json::json!({"entry":entry})))
}
async fn local_fallback() -> Error {
    Error::InvalidRequest
}
async fn challenge(State(state): State<Arc<Inner>>) -> Result<Json<Challenge>> {
    state.ensure_active()?;
    Ok(Json(Challenge {
        protocol: 1,
        device_id: lock(&state.vault)?.status().device_id,
        epoch: lock(&state.epoch)?.clone(),
    }))
}
fn request_envelope(state: &Inner, headers: &HeaderMap, body: &Bytes) -> Result<Envelope> {
    state.ensure_active()?;
    require_json(headers)?;
    let env: Envelope = serde_json::from_slice(body).map_err(|_| Error::InvalidRequest)?;
    if env.epoch != *lock(&state.epoch)? || env.to != lock(&state.vault)?.status().device_id {
        return Err(Error::Authentication);
    }
    Ok(env)
}
async fn pair(
    State(state): State<Arc<Inner>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Envelope>> {
    if !local_ip(source.ip()) {
        return Err(Error::InvalidEndpoint);
    }
    let env = request_envelope(&state, &headers, &body)?;
    let mut pending = lock(&state.pending)?;
    let invite = pending.as_ref().ok_or(Error::Expired)?;
    if invite.expires_at < now() {
        *pending = None;
        return Err(Error::Expired);
    }
    let input: PairRequest = open(&invite.key, "pair", false, &env)?;
    let address = parse_endpoint(&input.endpoint)?;
    if address.ip() != source.ip() || input.name.len() > 128 || input.name.trim().is_empty() {
        return Err(Error::InvalidRequest);
    }
    lock(&state.replay)?.accept(&env.from, &env.request_id)?;
    let mut vault = lock(&state.vault)?;
    state.ensure_active()?;
    let own = vault.status();
    if own.locked {
        return Err(Error::Locked);
    }
    if env.from == own.device_id {
        return Err(Error::InvalidRequest);
    }
    let reply = PairReply {
        device_id: own.device_id.clone(),
        name: own.device_name,
        endpoint: invite.endpoint.clone(),
    };
    let response = seal(
        &invite.key,
        "pair",
        true,
        &own.device_id,
        &env.from,
        &env.request_id,
        &env.epoch,
        &reply,
    )?;
    let shared_key = paired_key(&invite.key, &own.device_id, &env.from);
    vault.add_peer(Peer {
        device_id: env.from,
        name: input.name,
        endpoint: input.endpoint,
        shared_key,
    })?;
    // Persist first; only successful pairing consumes the invitation.
    *pending = None;
    state.trigger.notify_one();
    Ok(Json(response))
}
async fn sync(
    State(state): State<Arc<Inner>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Envelope>> {
    if !local_ip(source.ip()) {
        return Err(Error::InvalidEndpoint);
    }
    let env = request_envelope(&state, &headers, &body)?;
    let peer = {
        let vault = lock(&state.vault)?;
        if vault.status().locked {
            return Err(Error::Locked);
        }
        vault
            .peers()?
            .into_iter()
            .find(|p| p.device_id == env.from)
            .ok_or(Error::Authentication)?
    };
    let request: SyncRequest = open(&peer.shared_key, "sync", false, &env)?;
    let address = parse_endpoint(&request.endpoint)?;
    if address.ip() != source.ip() {
        return Err(Error::InvalidEndpoint);
    }
    lock(&state.replay)?.accept(&env.from, &env.request_id)?;
    let mut vault = lock(&state.vault)?;
    state.ensure_active()?;
    let current = vault
        .peers()?
        .into_iter()
        .find(|p| p.device_id == peer.device_id)
        .ok_or(Error::Authentication)?;
    if current.shared_key != peer.shared_key {
        return Err(Error::Authentication);
    }
    vault.merge_sync(request.data)?;
    let output = vault.export_sync()?;
    // Only an authenticated peer can update its persisted address.
    if peer.endpoint != request.endpoint {
        vault.add_peer(Peer {
            device_id: peer.device_id.clone(),
            name: peer.name.clone(),
            endpoint: request.endpoint,
            shared_key: peer.shared_key,
        })?;
    }
    let response = seal(
        &peer.shared_key,
        "sync",
        true,
        &env.to,
        &env.from,
        &env.request_id,
        &env.epoch,
        &SyncReply { data: output },
    )?;
    drop(vault);
    if let Ok(mut status) = state.status.lock() {
        status.last_sync = Some(now());
        status.last_error = None;
    }
    Ok(Json(response))
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
        .get(format!("{}/v1/challenge", endpoint(address)))
        .send()
        .await
        .map_err(|_| Error::Unavailable)?;
    let challenge: Challenge = response_json(response).await?;
    if challenge.protocol != 1 || challenge.device_id != id || !valid_id(&challenge.epoch) {
        return Err(Error::Authentication);
    }
    Ok(challenge)
}
async fn post_envelope(
    state: &Inner,
    address: SocketAddr,
    route: &str,
    env: &Envelope,
) -> Result<Envelope> {
    let response = state
        .client
        .post(format!("{}/v1/{route}", endpoint(address)))
        .json(env)
        .send()
        .await
        .map_err(|_| Error::Unavailable)?;
    response_json(response).await
}
fn validate_response(response: &Envelope, request: &Envelope) -> Result<()> {
    if response.from != request.to
        || response.to != request.from
        || response.request_id != request.request_id
        || response.epoch != request.epoch
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn current_peer(vault: &Vault, peer: &Peer) -> Result<()> {
    if vault.status().locked {
        return Err(Error::Locked);
    }
    let current = vault
        .peers()?
        .into_iter()
        .find(|p| p.device_id == peer.device_id)
        .ok_or(Error::Authentication)?;
    if current.shared_key != peer.shared_key {
        return Err(Error::Authentication);
    }
    Ok(())
}
async fn sync_peer(state: &Arc<Inner>, peer: &Peer, address: SocketAddr) -> Result<()> {
    state.ensure_active()?;
    {
        let vault = lock(&state.vault)?;
        current_peer(&vault, peer)?;
    }
    let advertised = source_endpoint(address, state.lan_port)?;
    let challenge = fetch_challenge(state, address, &peer.device_id).await?;
    // Do not export a new snapshot for a stale worker copy of a revoked peer.
    let (own, data) = {
        let vault = lock(&state.vault)?;
        state.ensure_active()?;
        current_peer(&vault, peer)?;
        (vault.status(), vault.export_sync()?)
    };
    let id = random_id();
    let request = seal(
        &peer.shared_key,
        "sync",
        false,
        &own.device_id,
        &peer.device_id,
        &id,
        &challenge.epoch,
        &SyncRequest {
            data,
            endpoint: advertised,
        },
    )?;
    state.ensure_active()?;
    {
        let vault = lock(&state.vault)?;
        current_peer(&vault, peer)?;
    }
    let response = post_envelope(state, address, "sync", &request).await?;
    validate_response(&response, &request)?;
    let reply: SyncReply = open(&peer.shared_key, "sync", true, &response)?;
    state.ensure_active()?;
    let mut vault = lock(&state.vault)?;
    // Revocation or locking while an RPC was in flight takes effect immediately.
    let current = vault
        .peers()?
        .into_iter()
        .find(|p| p.device_id == peer.device_id)
        .ok_or(Error::Authentication)?;
    if current.shared_key != peer.shared_key {
        return Err(Error::Authentication);
    }
    vault.merge_sync(reply.data)?;
    let address = endpoint(address);
    if current.endpoint != address {
        vault.add_peer(Peer {
            device_id: current.device_id.clone(),
            name: current.name.clone(),
            endpoint: address,
            shared_key: current.shared_key,
        })?;
    }
    drop(vault);
    let mut status = lock(&state.status)?;
    status.last_sync = Some(now());
    status.last_error = None;
    Ok(())
}
async fn sync_worker(state: Arc<Inner>, interval_secs: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut shutdown = state.shutdown.subscribe();
    let mut last_cycle = Instant::now() - Duration::from_secs(2);
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! { _=interval.tick()=>{},_=state.trigger.notified()=>{},_=shutdown.changed()=>{if *shutdown.borrow(){break}} }
        if state.ensure_active().is_err() {
            continue;
        }
        if let Some(delay) = Duration::from_secs(2).checked_sub(last_cycle.elapsed()) {
            tokio::select! {_=tokio::time::sleep(delay)=>{},_=shutdown.changed()=>{if *shutdown.borrow(){break}}}
        }
        last_cycle = Instant::now();
        let peers = match lock(&state.vault).and_then(|vault| vault.peers().map_err(Into::into)) {
            Ok(peers) => peers,
            Err(_) => continue,
        };
        for peer in peers {
            if *shutdown.borrow() {
                return;
            }
            let mut candidates = Vec::new();
            if let Ok(found) = state.discovered.lock() {
                if let Some((address, seen)) = found.get(&peer.device_id) {
                    if now().saturating_sub(*seen) < 180 {
                        candidates.push(*address);
                    }
                }
            }
            if let Ok(address) = parse_endpoint(&peer.endpoint) {
                if !candidates.contains(&address) {
                    candidates.push(address);
                }
            }
            let mut success = false;
            let mut last_error = Error::Unavailable.to_string();
            for address in candidates {
                match sync_peer(&state, &peer, address).await {
                    Ok(()) => {
                        success = true;
                        break;
                    }
                    Err(error) => last_error = error.to_string(),
                }
            }
            if !success {
                if let Ok(mut status) = state.status.lock() {
                    status.last_error = Some(last_error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
