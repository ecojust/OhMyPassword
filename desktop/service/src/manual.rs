use super::*;
use axum::extract::Path;
use hkdf::Hkdf;
use ohmypassword_core::SyncPayload;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const LIFETIME: u64 = 300;
#[derive(Clone, Serialize, Deserialize)]
pub struct MergeSession {
    pub id: String,
    pub peer_id: String,
    pub peer_name: String,
    pub endpoint: String,
    pub direction: String,
    pub state: String,
    pub verification_code: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub completed_at: Option<u64>,
    pub error: Option<String>,
    pub received_count: Option<usize>,
    pub changed_count: Option<usize>,
    pub source_count: Option<usize>,
}
pub(super) struct Session {
    pub view: MergeSession,
    own_id: String,
    own_epoch: String,
    peer_epoch: String,
    secret: Option<StaticSecret>,
    public: String,
    nonce: Zeroizing<[u8; 32]>,
    peer_commit: String,
    key: Option<Zeroizing<[u8; 32]>>,
    approved: bool,
    cached: HashMap<String, (String, Envelope)>,
    prepared_hash: Option<String>,
    completed_hash: Option<String>,
}
impl Session {
    fn clear_keys(&mut self) {
        self.secret = None;
        self.key = None;
        self.nonce.zeroize();
        self.cached.clear();
    }
    fn fail(&mut self, state: &str, message: &str) {
        self.view.state = state.into();
        self.view.error = Some(message.into());
        self.clear_keys();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    protocol: u32,
    id: String,
    from: String,
    to: String,
    name: String,
    endpoint: String,
    from_epoch: String,
    to_epoch: String,
    commitment: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Begun {
    protocol: u32,
    id: String,
    from: String,
    to: String,
    commitment: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reveal {
    id: String,
    from: String,
    to: String,
    public: String,
    nonce: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Revealed {
    id: String,
    from: String,
    to: String,
    public: String,
    nonce: String,
}
#[derive(Serialize)]
struct Transcript<'a> {
    id: &'a str,
    from: &'a str,
    to: &'a str,
    from_epoch: &'a str,
    to_epoch: &'a str,
    from_public: &'a str,
    to_public: &'a str,
    from_nonce: &'a str,
    to_nonce: &'a str,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteState {
    approved: bool,
    state: String,
    completed_hash: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    data: SyncPayload,
    digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledged {
    completed: bool,
    digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cancellation {
    failed: bool,
}
struct WriteLease {
    vault: Arc<Mutex<Vault>>,
    id: String,
}
impl Drop for WriteLease {
    fn drop(&mut self) {
        if let Ok(mut vault) = self.vault.lock() {
            let _ = vault.end_merge_write(&self.id);
        }
    }
}
struct Access {
    key: Zeroizing<[u8; 32]>,
    own_id: String,
    peer_id: String,
    peer_epoch: String,
    own_epoch: String,
    endpoint: SocketAddr,
}

fn terminal(state: &str) -> bool {
    matches!(state, "completed" | "rejected" | "failed" | "expired")
}
fn new_session(
    id: String,
    own_id: String,
    own_epoch: String,
    peer_epoch: String,
    peer_id: String,
    peer_name: String,
    endpoint: String,
    direction: &str,
) -> Session {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = encode(PublicKey::from(&secret).as_bytes());
    Session {
        view: MergeSession {
            id,
            peer_id,
            peer_name,
            endpoint,
            direction: direction.into(),
            state: "waiting".into(),
            verification_code: String::new(),
            created_at: now(),
            expires_at: now() + LIFETIME,
            completed_at: None,
            error: None,
            received_count: None,
            changed_count: None,
            source_count: None,
        },
        own_id,
        own_epoch,
        peer_epoch,
        secret: Some(secret),
        public,
        nonce: Zeroizing::new(random_key()),
        peer_commit: String::new(),
        key: None,
        approved: false,
        cached: HashMap::new(),
        prepared_hash: None,
        completed_hash: None,
    }
}
fn commitment(
    id: &str,
    from: &str,
    to: &str,
    own_epoch: &str,
    peer_epoch: &str,
    role: &str,
    public: &str,
    nonce: &str,
) -> String {
    let data = serde_json::json!([
        "OhMyPassword manual pull commitment v3",
        id,
        from,
        to,
        own_epoch,
        peer_epoch,
        role,
        public,
        nonce
    ]);
    encode(Sha256::digest(
        serde_json::to_vec(&data).expect("serializable transcript"),
    ))
}
fn own_commit(session: &Session) -> String {
    commitment(
        &session.view.id,
        &session.own_id,
        &session.view.peer_id,
        &session.own_epoch,
        &session.peer_epoch,
        &session.view.direction,
        &session.public,
        &encode(session.nonce.as_ref()),
    )
}
fn derive(session: &mut Session, peer_public: &str, peer_nonce: &str) -> Result<()> {
    let peer_public_bytes = key_from(peer_public)?;
    let peer_nonce_bytes = key_from(peer_nonce)?;
    let expected = commitment(
        &session.view.id,
        &session.view.peer_id,
        &session.own_id,
        &session.peer_epoch,
        &session.own_epoch,
        if session.view.direction == "incoming" {
            "outgoing"
        } else {
            "incoming"
        },
        peer_public,
        peer_nonce,
    );
    if session.peer_commit != expected {
        return Err(Error::Authentication);
    }
    let secret = session.secret.take().ok_or(Error::Authentication)?;
    let shared = secret.diffie_hellman(&PublicKey::from(peer_public_bytes));
    if !shared.was_contributory() {
        return Err(Error::Authentication);
    }
    let own_nonce = encode(session.nonce.as_ref());
    let transcript = if session.view.direction == "outgoing" {
        Transcript {
            id: &session.view.id,
            from: &session.own_id,
            to: &session.view.peer_id,
            from_epoch: &session.own_epoch,
            to_epoch: &session.peer_epoch,
            from_public: &session.public,
            to_public: peer_public,
            from_nonce: &own_nonce,
            to_nonce: peer_nonce,
        }
    } else {
        Transcript {
            id: &session.view.id,
            from: &session.view.peer_id,
            to: &session.own_id,
            from_epoch: &session.peer_epoch,
            to_epoch: &session.own_epoch,
            from_public: peer_public,
            to_public: &session.public,
            from_nonce: peer_nonce,
            to_nonce: &own_nonce,
        }
    };
    let salt = Sha256::digest(serde_json::to_vec(&transcript).map_err(|_| Error::InvalidRequest)?);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut key = Zeroizing::new([0; 32]);
    let mut sas = Zeroizing::new([0; 4]);
    hkdf.expand(b"OhMyPassword manual pull encryption v3", key.as_mut())
        .map_err(|_| Error::Authentication)?;
    hkdf.expand(b"OhMyPassword manual pull verification v3", sas.as_mut())
        .map_err(|_| Error::Authentication)?;
    session.key = Some(key);
    session.view.verification_code = format!("{:06}", u32::from_be_bytes(*sas) % 1_000_000);
    session.view.state = "awaiting_confirmation".into();
    let _ = peer_nonce_bytes;
    Ok(())
}
fn expire(session: &mut Session) {
    if session.view.expires_at <= now() {
        if !terminal(&session.view.state) {
            session.fail("expired", "合并请求已过期，请重新发起");
        } else {
            session.clear_keys();
        }
    }
}
pub(super) fn expire_sessions(state: &Inner) {
    if let Ok(mut sessions) = state.sessions.lock() {
        for session in sessions.values_mut() {
            expire(session);
            if session.view.expires_at <= now() {
                if let Ok(mut vault) = state.vault.lock() {
                    let _ = vault.end_merge_write(&session.view.id);
                }
            }
        }
        sessions.retain(|_, session| now().saturating_sub(session.view.created_at) < 3600);
    }
}
pub(super) fn abort_sessions(state: &Inner, message: &str) {
    if let Ok(mut sessions) = state.sessions.lock() {
        for session in sessions.values_mut() {
            if let Ok(mut vault) = state.vault.lock() {
                let _ = vault.end_merge_write(&session.view.id);
            }
            session.fail("failed", message);
        }
        sessions.clear();
    }
}
pub(super) fn views(state: &Inner) -> Vec<MergeSession> {
    expire_sessions(state);
    let mut views = state
        .sessions
        .lock()
        .map(|s| s.values().map(|s| s.view.clone()).collect::<Vec<_>>())
        .unwrap_or_default();
    views.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    views
}
fn room(sessions: &mut HashMap<String, Session>) -> Result<()> {
    for session in sessions.values_mut() {
        expire(session);
    }
    if sessions.len() >= 16 {
        if let Some(oldest) = sessions
            .iter()
            .filter(|(_, s)| terminal(&s.view.state))
            .min_by_key(|(_, s)| s.view.created_at)
            .map(|(id, _)| id.clone())
        {
            sessions.remove(&oldest);
        }
    }
    if sessions.len() >= 16
        || sessions
            .values()
            .filter(|s| !terminal(&s.view.state))
            .count()
            >= 4
    {
        return Err(Error::Busy);
    }
    Ok(())
}
fn access(state: &Inner, id: &str, allow_terminal: bool) -> Result<Access> {
    state.ensure_active()?;
    let mut sessions = lock(&state.sessions)?;
    let session = sessions.get_mut(id).ok_or(Error::Expired)?;
    expire(session);
    if session.own_epoch != *lock(&state.epoch)?
        || (!allow_terminal && terminal(&session.view.state))
    {
        return Err(Error::Expired);
    }
    if lock(&state.vault)?.status().locked {
        return Err(Error::Locked);
    }
    Ok(Access {
        key: session.key.as_ref().ok_or(Error::Authentication)?.clone(),
        own_id: session.own_id.clone(),
        peer_id: session.view.peer_id.clone(),
        peer_epoch: session.peer_epoch.clone(),
        own_epoch: session.own_epoch.clone(),
        endpoint: parse_endpoint(&session.view.endpoint)?,
    })
}
fn route(id: &str, operation: &str) -> String {
    format!("merge/{id}/{operation}")
}
fn digest(data: &SyncPayload) -> Result<String> {
    let mut bytes = serde_json::to_vec(data).map_err(|_| Error::InvalidRequest)?;
    let hash = encode(Sha256::digest(&bytes));
    bytes.zeroize();
    Ok(hash)
}
fn live<'a>(
    state: &Inner,
    sessions: &'a mut HashMap<String, Session>,
    id: &str,
    approved: bool,
) -> Result<&'a mut Session> {
    state.ensure_active()?;
    let session = sessions.get_mut(id).ok_or(Error::Expired)?;
    expire(session);
    if session.own_epoch != *lock(&state.epoch)?
        || session.key.is_none()
        || terminal(&session.view.state)
        || (approved && !session.approved)
    {
        return Err(Error::Authentication);
    }
    Ok(session)
}

impl Service {
    pub fn request_merge(&self, device_id: &str) -> Result<MergeSession> {
        self.inner.ensure_active()?;
        let own = lock(&self.inner.vault)?.status();
        if own.locked {
            return Err(Error::Locked);
        }
        let peer = lock(&self.inner.discovered)?
            .get(device_id)
            .filter(|p| now().saturating_sub(p.last_seen) < 660)
            .cloned()
            .ok_or(Error::InvalidEndpoint)?;
        if peer.id == own.device_id {
            return Err(Error::InvalidRequest);
        }
        let mut sessions = lock(&self.inner.sessions)?;
        room(&mut sessions)?;
        if sessions
            .values()
            .any(|s| s.view.peer_id == device_id && !terminal(&s.view.state))
        {
            return Err(Error::Busy);
        }
        let id = random_id();
        let session = new_session(
            id.clone(),
            own.device_id,
            lock(&self.inner.epoch)?.clone(),
            String::new(),
            peer.id,
            peer.name,
            peer.endpoint,
            "outgoing",
        );
        let view = session.view.clone();
        sessions.insert(id.clone(), session);
        drop(sessions);
        let state = self.inner.clone();
        self.inner.runtime.spawn(async move {
            if let Err(error) = outgoing(&state, &id).await {
                let _ =
                    rpc::<_, Empty>(&state, &id, "cancel", &Cancellation { failed: true }, true)
                        .await;
                if let Ok(mut sessions) = state.sessions.lock() {
                    if let Some(session) = sessions.get_mut(&id) {
                        if !terminal(&session.view.state) {
                            session.fail(
                                if matches!(error, Error::Expired) {
                                    "expired"
                                } else {
                                    "failed"
                                },
                                &error.to_string(),
                            );
                        }
                    }
                }
            }
        });
        Ok(view)
    }
    pub fn respond_merge(&self, session_id: &str, accept: bool) -> Result<()> {
        self.inner.ensure_active()?;
        if lock(&self.inner.vault)?.status().locked {
            return Err(Error::Locked);
        }
        let mut sessions = lock(&self.inner.sessions)?;
        let session = sessions.get_mut(session_id).ok_or(Error::Expired)?;
        expire(session);
        if terminal(&session.view.state) {
            return Err(Error::Expired);
        }
        if accept {
            if session.approved {
                return Ok(());
            }
            if session.view.state != "awaiting_confirmation"
                || session.view.verification_code.len() != 6
                || session.key.is_none()
            {
                return Err(Error::Authentication);
            }
            session.approved = true;
            session.view.state = "waiting".into();
        } else {
            session.view.state = "rejected".into();
            session.view.error = Some("合并请求已拒绝或取消".into());
            session.cached.clear();
            let _ = lock(&self.inner.vault)?.end_merge_write(session_id);
        }
        Ok(())
    }
}

pub(super) async fn request(
    State(state): State<Arc<Inner>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Begun>> {
    state.ensure_active()?;
    require_json(&headers)?;
    if body.len() > 4096 {
        return Err(Error::TooLarge);
    }
    let input: Begin = serde_json::from_slice(&body).map_err(|_| Error::InvalidRequest)?;
    if input.protocol != 3
        || !valid_id(&input.id)
        || !valid_id(&input.from)
        || !valid_id(&input.from_epoch)
        || input.name.is_empty()
        || input.name.len() > 128
        || key_from(&input.commitment).is_err()
    {
        return Err(Error::InvalidRequest);
    }
    let address = parse_endpoint(&input.endpoint)?;
    if address.ip() != source.ip() {
        return Err(Error::InvalidEndpoint);
    }
    let own = lock(&state.vault)?.status();
    let epoch = lock(&state.epoch)?.clone();
    if own.locked {
        return Err(Error::Locked);
    }
    if input.to != own.device_id || input.to_epoch != epoch || input.from == own.device_id {
        return Err(Error::Authentication);
    }
    let mut sessions = lock(&state.sessions)?;
    state.ensure_active()?;
    if epoch != *lock(&state.epoch)? {
        return Err(Error::Expired);
    }
    room(&mut sessions)?;
    if sessions.contains_key(&input.id)
        || sessions
            .values()
            .any(|s| s.view.peer_id == input.from && !terminal(&s.view.state))
    {
        return Err(Error::Busy);
    }
    let mut session = new_session(
        input.id.clone(),
        own.device_id.clone(),
        epoch,
        input.from_epoch,
        input.from.clone(),
        input.name,
        input.endpoint,
        "incoming",
    );
    session.peer_commit = input.commitment;
    let reply = Begun {
        protocol: 3,
        id: input.id.clone(),
        from: own.device_id,
        to: input.from,
        commitment: own_commit(&session),
    };
    sessions.insert(input.id, session);
    Ok(Json(reply))
}
pub(super) async fn reveal(
    State(state): State<Arc<Inner>>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Revealed>> {
    state.ensure_active()?;
    require_json(&headers)?;
    if body.len() > 4096 {
        return Err(Error::TooLarge);
    }
    let input: Reveal = serde_json::from_slice(&body).map_err(|_| Error::InvalidRequest)?;
    let mut sessions = lock(&state.sessions)?;
    let session = sessions.get_mut(&input.id).ok_or(Error::Expired)?;
    expire(session);
    if session.view.direction != "incoming"
        || session.view.state != "waiting"
        || session.approved
        || session.key.is_some()
        || session.own_epoch != *lock(&state.epoch)?
        || session.own_id != input.to
        || session.view.peer_id != input.from
        || parse_endpoint(&session.view.endpoint)?.ip() != source.ip()
    {
        return Err(Error::Authentication);
    }
    if lock(&state.vault)?.status().locked {
        return Err(Error::Locked);
    }
    let reply = Revealed {
        id: input.id,
        from: session.own_id.clone(),
        to: session.view.peer_id.clone(),
        public: session.public.clone(),
        nonce: encode(session.nonce.as_ref()),
    };
    if let Err(error) = derive(session, &input.public, &input.nonce) {
        session.fail("failed", &error.to_string());
        return Err(error);
    }
    Ok(Json(reply))
}

fn incoming_access(
    state: &Inner,
    id: &str,
    source: SocketAddr,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(Access, Envelope)> {
    require_json(headers)?;
    let env: Envelope = serde_json::from_slice(body).map_err(|_| Error::InvalidRequest)?;
    let access = access(state, id, true)?;
    if access.endpoint.ip() != source.ip()
        || env.from != access.peer_id
        || env.to != access.own_id
        || env.epoch != access.own_epoch
    {
        return Err(Error::Authentication);
    }
    Ok((access, env))
}
fn response<T: Serialize>(
    access: &Access,
    id: &str,
    operation: &str,
    request: &Envelope,
    data: &T,
) -> Result<Envelope> {
    seal(
        &access.key,
        &route(id, operation),
        true,
        &access.own_id,
        &access.peer_id,
        &request.request_id,
        &request.epoch,
        data,
    )
}
fn replay_cached(state: &Inner, id: &str, env: &Envelope) -> Result<Option<Envelope>> {
    let hash = encode(Sha256::digest(
        serde_json::to_vec(env).map_err(|_| Error::InvalidRequest)?,
    ));
    let sessions = lock(&state.sessions)?;
    let session = sessions.get(id).ok_or(Error::Expired)?;
    if let Some((original, response)) = session.cached.get(&env.request_id) {
        if original != &hash {
            return Err(Error::Replay);
        }
        return Ok(Some(response.clone()));
    }
    Ok(None)
}
fn remember(session: &mut Session, request: &Envelope, response: Envelope) -> Result<Envelope> {
    let hash = encode(Sha256::digest(
        serde_json::to_vec(request).map_err(|_| Error::InvalidRequest)?,
    ));
    // At most one large snapshot and one small acknowledgement are retained.
    if session.cached.len() >= 2 {
        session.cached.clear();
    }
    session
        .cached
        .insert(request.request_id.clone(), (hash, response.clone()));
    Ok(response)
}
pub(super) async fn session_status(
    State(state): State<Arc<Inner>>,
    Path(id): Path<String>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Envelope>> {
    let (a, env) = incoming_access(&state, &id, source, &headers, &body)?;
    let _: Empty = open(&a.key, &route(&id, "status"), false, &env)?;
    lock(&state.replay)?.accept(&env.from, &env.request_id)?;
    let sessions = lock(&state.sessions)?;
    let session = sessions.get(&id).ok_or(Error::Expired)?;
    Ok(Json(response(
        &a,
        &id,
        "status",
        &env,
        &RemoteState {
            approved: session.approved,
            state: session.view.state.clone(),
            completed_hash: session.completed_hash.clone(),
        },
    )?))
}
pub(super) async fn pull(
    State(state): State<Arc<Inner>>,
    Path(id): Path<String>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Envelope>> {
    let (a, env) = incoming_access(&state, &id, source, &headers, &body)?;
    let _: Empty = open(&a.key, &route(&id, "pull"), false, &env)?;
    if let Some(cached) = replay_cached(&state, &id, &env)? {
        return Ok(Json(cached));
    }
    lock(&state.replay)?.accept(&env.from, &env.request_id)?;
    let mut sessions = lock(&state.sessions)?;
    let session = live(&state, &mut sessions, &id, true)?;
    if session.view.direction != "incoming" || session.prepared_hash.is_some() {
        return Err(Error::Authentication);
    }
    // The provider exports one approved snapshot and never accepts records.
    // Only an exact retry can replay this cached snapshot.
    let vault = lock(&state.vault)?;
    let data = vault.export_pull()?;
    session.view.source_count = Some(data.records.len());
    let hash = digest(&data)?;
    let reply = response(
        &a,
        &id,
        "pull",
        &env,
        &Snapshot {
            data,
            digest: hash.clone(),
        },
    )?;
    session.prepared_hash = Some(hash);
    session.view.state = "merging".into();
    Ok(Json(remember(session, &env, reply)?))
}
pub(super) async fn ack(
    State(state): State<Arc<Inner>>,
    Path(id): Path<String>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Envelope>> {
    let (a, env) = incoming_access(&state, &id, source, &headers, &body)?;
    let input: Ack = open(&a.key, &route(&id, "ack"), false, &env)?;
    if let Some(cached) = replay_cached(&state, &id, &env)? {
        return Ok(Json(cached));
    }
    lock(&state.replay)?.accept(&env.from, &env.request_id)?;
    let mut sessions = lock(&state.sessions)?;
    let session = live(&state, &mut sessions, &id, true)?;
    if session.view.direction != "incoming"
        || session.prepared_hash.as_deref() != Some(input.digest.as_str())
    {
        return Err(Error::Authentication);
    }
    // A receipt confirms the approved snapshot was saved by the requester.
    // The provider may continue editing; its current vault is never compared,
    // locked for writes, or overwritten by the requester.
    let current = input.digest;
    let completed = true;
    let reply = response(
        &a,
        &id,
        "ack",
        &env,
        &Acknowledged {
            completed,
            digest: current.clone(),
        },
    )?;
    if completed {
        session.view.state = "completed".into();
        session.view.completed_at = Some(now());
        session.completed_hash = Some(current);
        session.cached.clear();
    }
    Ok(Json(remember(session, &env, reply)?))
}
pub(super) async fn cancel(
    State(state): State<Arc<Inner>>,
    Path(id): Path<String>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Envelope>> {
    let (a, env) = incoming_access(&state, &id, source, &headers, &body)?;
    let cancellation: Cancellation = open(&a.key, &route(&id, "cancel"), false, &env)?;
    lock(&state.replay)?.accept(&env.from, &env.request_id)?;
    let mut sessions = lock(&state.sessions)?;
    let session = sessions.get_mut(&id).ok_or(Error::Expired)?;
    if !terminal(&session.view.state) {
        session.view.state = if cancellation.failed {
            "failed"
        } else {
            "rejected"
        }
        .into();
        session.view.error = Some(
            if session.view.direction == "incoming" {
                "对方已取消或未完成接收；本机密码未修改"
            } else {
                "本次接收未确认完成；已保存到本机的记录会保留"
            }
            .into(),
        );
        session.cached.clear();
        let _ = lock(&state.vault)?.end_merge_write(&id);
    }
    Ok(Json(response(&a, &id, "cancel", &env, &Empty {})?))
}
async fn post<T: Serialize, R: serde::de::DeserializeOwned>(
    state: &Inner,
    address: SocketAddr,
    path: &str,
    body: &T,
) -> Result<R> {
    state.ensure_active()?;
    let result = state
        .client
        .post(format!("{}{path}", endpoint(address)))
        .json(body)
        .send()
        .await
        .map_err(|_| Error::Unavailable)?;
    response_json(result).await
}
async fn rpc<T: Serialize, R: serde::de::DeserializeOwned>(
    state: &Inner,
    id: &str,
    operation: &str,
    body: &T,
    allow_terminal: bool,
) -> Result<R> {
    let a = access(state, id, allow_terminal)?;
    let env = seal(
        &a.key,
        &route(id, operation),
        false,
        &a.own_id,
        &a.peer_id,
        &random_id(),
        &a.peer_epoch,
        body,
    )?;
    let path = format!("/v3/merge/{id}/{operation}");
    let mut last_error = Error::Unavailable;
    let attempts = if operation == "pull" || operation == "ack" {
        2
    } else {
        1
    };
    for _ in 0..attempts {
        let _current = access(state, id, allow_terminal)?;
        match post::<_, Envelope>(state, a.endpoint, &path, &env).await {
            Ok(reply) => {
                if reply.from != env.to
                    || reply.to != env.from
                    || reply.request_id != env.request_id
                    || reply.epoch != env.epoch
                {
                    return Err(Error::Authentication);
                }
                return open(&a.key, &route(id, operation), true, &reply);
            }
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}
async fn outgoing(state: &Arc<Inner>, id: &str) -> Result<()> {
    let (remote, peer_id) = {
        let sessions = lock(&state.sessions)?;
        let session = sessions.get(id).ok_or(Error::Expired)?;
        (
            parse_endpoint(&session.view.endpoint)?,
            session.view.peer_id.clone(),
        )
    };
    let info = fetch_challenge(state, remote, &peer_id).await?;
    let begin = {
        let mut sessions = lock(&state.sessions)?;
        let session = sessions.get_mut(id).ok_or(Error::Expired)?;
        state.ensure_active()?;
        if terminal(&session.view.state) {
            return Err(Error::Expired);
        }
        let own = lock(&state.vault)?.status();
        if own.locked {
            return Err(Error::Locked);
        }
        session.peer_epoch = info.epoch;
        session.view.peer_name = info.name;
        Begin {
            protocol: 3,
            id: id.into(),
            from: session.own_id.clone(),
            to: session.view.peer_id.clone(),
            name: own.device_name,
            endpoint: source_endpoint(remote, state.lan_port)?,
            from_epoch: session.own_epoch.clone(),
            to_epoch: session.peer_epoch.clone(),
            commitment: own_commit(session),
        }
    };
    let reply: Begun = post(state, remote, "/v3/merge/request", &begin).await?;
    if reply.protocol != 3
        || reply.id != id
        || reply.from != begin.to
        || reply.to != begin.from
        || key_from(&reply.commitment).is_err()
    {
        return Err(Error::Authentication);
    }
    let reveal = {
        let mut sessions = lock(&state.sessions)?;
        let session = sessions.get_mut(id).ok_or(Error::Expired)?;
        state.ensure_active()?;
        if (terminal(&session.view.state) && session.view.state != "rejected")
            || session.own_epoch != *lock(&state.epoch)?
        {
            return Err(Error::Expired);
        }
        session.peer_commit = reply.commitment;
        Reveal {
            id: id.into(),
            from: session.own_id.clone(),
            to: session.view.peer_id.clone(),
            public: session.public.clone(),
            nonce: encode(session.nonce.as_ref()),
        }
    };
    let reply: Revealed = post(state, remote, "/v3/merge/reveal", &reveal).await?;
    if reply.id != id || reply.from != begin.to || reply.to != begin.from {
        return Err(Error::Authentication);
    }
    {
        let mut sessions = lock(&state.sessions)?;
        let session = sessions.get_mut(id).ok_or(Error::Expired)?;
        state.ensure_active()?;
        if (terminal(&session.view.state) && session.view.state != "rejected")
            || session.own_epoch != *lock(&state.epoch)?
        {
            return Err(Error::Expired);
        }
        let cancelled = session.view.state == "rejected";
        derive(session, &reply.public, &reply.nonce)?;
        if cancelled {
            session.view.state = "rejected".into();
        }
    }
    loop {
        let (approved, local_state) = {
            let sessions = lock(&state.sessions)?;
            let session = sessions.get(id).ok_or(Error::Expired)?;
            (session.approved, session.view.state.clone())
        };
        if local_state == "rejected" {
            let _ =
                rpc::<_, Empty>(state, id, "cancel", &Cancellation { failed: false }, true).await;
            return Ok(());
        }
        let remote: RemoteState = rpc(state, id, "status", &Empty {}, false).await?;
        if matches!(remote.state.as_str(), "rejected" | "failed" | "expired") {
            let mut sessions = lock(&state.sessions)?;
            let session = sessions.get_mut(id).ok_or(Error::Expired)?;
            session.fail(&remote.state, "对方未同意或未完成合并");
            return Ok(());
        }
        if approved && remote.approved {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    {
        let mut sessions = lock(&state.sessions)?;
        live(state, &mut sessions, id, true)?.view.state = "merging".into();
    }
    // No account data leaves the requesting device. The only record-bearing
    // message is the provider's response to this empty, authenticated request.
    let snapshot: Snapshot = rpc(state, id, "pull", &Empty {}, false).await?;
    if digest(&snapshot.data)? != snapshot.digest {
        return Err(Error::Authentication);
    }
    let saved_digest = snapshot.digest;
    let received_count = snapshot.data.records.len();
    let _write_lease = {
        let mut sessions = lock(&state.sessions)?;
        let session = live(state, &mut sessions, id, true)?;
        let mut vault = lock(&state.vault)?;
        let merged = vault.import_pull(snapshot.data)?;
        // Hold the requester's write lease through its receipt so completion
        // cannot race a local deletion after the durable import.
        vault.begin_merge_write(id)?;
        session.view.received_count = Some(received_count);
        session.view.changed_count = Some(merged.changed);
        WriteLease {
            vault: state.vault.clone(),
            id: id.into(),
        }
    };
    let acknowledgement: Result<Acknowledged> = rpc(
        state,
        id,
        "ack",
        &Ack {
            digest: saved_digest.clone(),
        },
        false,
    )
    .await;
    let acknowledgement = match acknowledgement {
        Ok(reply) => reply,
        Err(error) => {
            // A lost ACK is recovered using an authenticated receipt of this
            // exact snapshot, never by sending local records back to the source.
            let status: Result<RemoteState> = rpc(state, id, "status", &Empty {}, false).await;
            match status {
                Ok(status)
                    if status.state == "completed"
                        && status.completed_hash.as_deref() == Some(&saved_digest) =>
                {
                    Acknowledged {
                        completed: true,
                        digest: saved_digest.clone(),
                    }
                }
                _ => return Err(error),
            }
        }
    };
    if !acknowledgement.completed || acknowledgement.digest != saved_digest {
        return Err(Error::Authentication);
    }
    let mut sessions = lock(&state.sessions)?;
    let session = live(state, &mut sessions, id, true)?;
    if lock(&state.vault)?.status().locked {
        return Err(Error::Locked);
    }
    session.completed_hash = Some(saved_digest);
    session.view.state = "completed".into();
    session.view.completed_at = Some(now());
    session.cached.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{begin, client, discover, entry, eventually, fixture, runtime, session};
    #[test]
    fn commitment_reveal_binds_public_keys_and_rejects_low_order_keys() {
        let id = random_id();
        let a = random_id();
        let b = random_id();
        let ae = random_id();
        let be = random_id();
        let mut sa = new_session(
            id.clone(),
            a.clone(),
            ae.clone(),
            be.clone(),
            b.clone(),
            "B".into(),
            "http://127.0.0.1:17842".into(),
            "outgoing",
        );
        let mut sb = new_session(
            id.clone(),
            b.clone(),
            be.clone(),
            ae.clone(),
            a.clone(),
            "A".into(),
            "http://127.0.0.1:17842".into(),
            "incoming",
        );
        sa.peer_commit = own_commit(&sb);
        sb.peer_commit = own_commit(&sa);
        let ap = sa.public.clone();
        let an = encode(sa.nonce.as_ref());
        let bp = sb.public.clone();
        let bn = encode(sb.nonce.as_ref());
        assert!(
            derive(&mut sa, &bp, &encode(random_key())).is_err(),
            "reveal must match the earlier commitment"
        );
        derive(&mut sa, &bp, &bn).unwrap();
        derive(&mut sb, &ap, &an).unwrap();
        assert_eq!(sa.view.verification_code, sb.view.verification_code);
        assert_eq!(sa.key.as_deref(), sb.key.as_deref());
        assert!(sa.secret.is_none());
        let mut low = new_session(
            id.clone(),
            a.clone(),
            ae.clone(),
            be.clone(),
            b.clone(),
            "B".into(),
            "http://127.0.0.1:17842".into(),
            "outgoing",
        );
        let zero = encode([0; 32]);
        let nonce = encode(random_key());
        low.peer_commit = commitment(&id, &b, &a, &be, &ae, "incoming", &zero, &nonce);
        assert!(derive(&mut low, &zero, &nonce).is_err());
    }
    #[test]
    fn pending_and_expired_sessions_cannot_be_approved_or_pull() {
        let (_dir, vault, service) = fixture("A");
        let own = vault.lock().unwrap().status();
        let id = random_id();
        let peer = random_id();
        let pending = new_session(
            id.clone(),
            own.device_id,
            lock(&service.inner.epoch).unwrap().clone(),
            random_id(),
            peer,
            "B".into(),
            "http://127.0.0.1:17842".into(),
            "incoming",
        );
        service
            .inner
            .sessions
            .lock()
            .unwrap()
            .insert(id.clone(), pending);
        assert!(service.respond_merge(&id, true).is_err());
        {
            let mut sessions = service.inner.sessions.lock().unwrap();
            let pending = sessions.get_mut(&id).unwrap();
            pending.view.expires_at = now() - 1;
            pending.key = Some(Zeroizing::new(random_key()));
        }
        assert!(service.respond_merge(&id, true).is_err());
        assert_eq!(session(&service, &id).state, "expired");
        assert!(service.inner.sessions.lock().unwrap()[&id].key.is_none());
    }
    #[test]
    fn completed_session_cannot_read_new_passwords_and_ack_is_idempotent() {
        let (_ad, a, sa) = fixture("A");
        let (_bd, b, sb) = fixture("B");
        discover(&a, &sa, &b, &sb);
        b.lock()
            .unwrap()
            .upsert(entry("example.com", "before-merge"))
            .unwrap();
        let id = begin(&sa, &b, &sb);
        // Drive the wire explicitly while only the receiver is approved, so the
        // normal sender task cannot race these duplicate-ACK assertions.
        sb.respond_merge(&id, true).unwrap();
        runtime().block_on(async {
            let before = serde_json::to_vec(&b.lock().unwrap().export_sync().unwrap()).unwrap();
            // A legacy-shaped encrypted upload cannot be interpreted as a pull.
            let rejected: Result<Snapshot> = rpc(
                &sa.inner,
                &id,
                "pull",
                &serde_json::json!({
                    "data": { "records": [] }
                }),
                false,
            )
            .await;
            assert!(rejected.is_err());
            assert_eq!(
                serde_json::to_vec(&b.lock().unwrap().export_sync().unwrap()).unwrap(),
                before
            );
            let snapshot: Snapshot = rpc(&sa.inner, &id, "pull", &Empty {}, false).await.unwrap();
            let hash = snapshot.digest;
            a.lock().unwrap().import_pull(snapshot.data).unwrap();
            let access = access(&sa.inner, &id, false).unwrap();
            let env = seal(
                &access.key,
                &route(&id, "ack"),
                false,
                &access.own_id,
                &access.peer_id,
                &random_id(),
                &access.peer_epoch,
                &Ack { digest: hash },
            )
            .unwrap();
            let path = format!("/v3/merge/{id}/ack");
            let first: Envelope = post(&sa.inner, access.endpoint, &path, &env).await.unwrap();
            let ack: Acknowledged = open(&access.key, &route(&id, "ack"), true, &first).unwrap();
            assert!(ack.completed);
            b.lock()
                .unwrap()
                .upsert(entry("new.example", "never-granted-by-old-session"))
                .unwrap();
            let repeated: Envelope = post(&sa.inner, access.endpoint, &path, &env).await.unwrap();
            assert_eq!(first.ciphertext, repeated.ciphertext);
            let result: Result<Snapshot> = rpc(&sa.inner, &id, "pull", &Empty {}, true).await;
            assert!(result.is_err());
            assert!(a
                .lock()
                .unwrap()
                .list(Some("new.example"))
                .unwrap()
                .is_empty());
            let mut changed = env.clone();
            changed.ciphertext.push('A');
            let result: Result<Envelope> = post(&sa.inner, access.endpoint, &path, &changed).await;
            assert!(result.is_err());
            sb.pause();
            b.lock().unwrap().lock();
            b.lock()
                .unwrap()
                .unlock("test vault passphrase 123")
                .unwrap();
            sb.resume();
            assert!(sb.respond_merge(&id, true).is_err());
            let result: Result<Envelope> = post(&sa.inner, access.endpoint, &path, &env).await;
            assert!(result.is_err());
        });
    }
    #[test]
    fn final_ack_blocks_concurrent_writes_and_recovers_a_lost_reply() {
        #[derive(Clone)]
        struct Proxy {
            target: u16,
            client: reqwest::Client,
            count: Arc<std::sync::atomic::AtomicUsize>,
            blocked: std::sync::mpsc::Sender<()>,
            release: Arc<Notify>,
        }
        async fn forward(State(proxy): State<Proxy>, request: axum::extract::Request) -> Response {
            let method = request.method().clone();
            let path = request.uri().path().to_string();
            let body = axum::body::to_bytes(request.into_body(), MAX_BODY)
                .await
                .unwrap();
            let attempt = if path.ends_with("/ack") {
                Some(proxy.count.fetch_add(1, Ordering::SeqCst))
            } else {
                None
            };
            if attempt == Some(0) {
                proxy.blocked.send(()).unwrap();
                proxy.release.notified().await;
            }
            let result = proxy
                .client
                .request(method, format!("http://127.0.0.1:{}{path}", proxy.target))
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .unwrap();
            let status = result.status();
            let body = result.bytes().await.unwrap();
            // Both ACK replies are lost; the authenticated status receipt must
            // recover completion without sending a second password snapshot.
            if attempt.is_some() {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            (status, [("content-type", "application/json")], body).into_response()
        }
        let (_ad, a, sa) = fixture("A");
        let (_bd, b, sb) = fixture("B");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
        let release = Arc::new(Notify::new());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let proxy = Proxy {
            target: sb.status().lan_port,
            client: client(),
            count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            blocked: blocked_tx,
            release: release.clone(),
        };
        let proxy_thread = thread::spawn(move || {
            runtime().block_on(async move{let listener=tokio::net::TcpListener::from_std(listener).unwrap();let router=Router::new().fallback(forward).with_state(proxy);tokio::select!{_=async{let _=axum::serve(listener,router).await;}=>{},_=stop_rx=>{}}})
        });
        sa.discovered_peer(&b.lock().unwrap().status().device_id, address);
        sb.discovered_peer(
            &a.lock().unwrap().status().device_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), sa.status().lan_port),
        );
        b.lock()
            .unwrap()
            .upsert(entry("example.com", "merge-me"))
            .unwrap();
        let id = begin(&sa, &b, &sb);
        sa.respond_merge(&id, true).unwrap();
        sb.respond_merge(&id, true).unwrap();
        blocked_rx.recv_timeout(Duration::from_secs(12)).unwrap();
        assert!(a
            .lock()
            .unwrap()
            .upsert(entry("during-ack.example", "must-not-save-yet"))
            .is_err());
        assert!(a
            .lock()
            .unwrap()
            .list(Some("during-ack.example"))
            .unwrap()
            .is_empty());
        // Provider edits are independent of the requester's receipt. They
        // remain local and do not require comparing the two entire vaults.
        let new_source = b
            .lock()
            .unwrap()
            .upsert(entry("source-during-ack.example", "source-keeps-editing"))
            .unwrap();
        release.notify_one();
        eventually(|| {
            session(&sa, &id).state == "completed" && session(&sb, &id).state == "completed"
        });
        assert_eq!(
            b.lock().unwrap().get(&new_source.id).unwrap().password,
            "source-keeps-editing"
        );
        assert!(a.lock().unwrap().get(&new_source.id).is_err());
        a.lock()
            .unwrap()
            .upsert(entry("after-merge.example", "new-local-edit"))
            .unwrap();
        assert!(b
            .lock()
            .unwrap()
            .list(Some("after-merge.example"))
            .unwrap()
            .is_empty());
        let _ = stop_tx.send(());
        proxy_thread.join().unwrap();
    }
}
