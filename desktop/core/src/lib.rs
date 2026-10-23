//! Local encrypted password vault. Network access belongs to the service crate.
//!
//! All mutations are persisted before becoming visible. `list` never includes
//! passwords, sync exports require an unlocked vault, and peer/client secrets
//! live inside the encrypted file. Callers should clear their password input
//! after `create` / `unlock`; borrowed strings cannot be erased by this API.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Block, Params, Version as ArgonVersion};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const FORMAT: u32 = 1;
const MAX_FILE: usize = 16 * 1024 * 1024;
/// Maximum encoded record/history payload, also used by the LAN service.
pub const MAX_SYNC_BYTES: usize = 1024 * 1024;
const MAX_RECORDS: usize = 20_000;
const MAX_FUTURE_MS: u64 = 5 * 60 * 1000;
const MAX_COUNTER_JUMP: u64 = 1_000_000;
const EARLIEST_MS: u64 = 946_684_800_000; // 2000-01-01 UTC
const MAX_PEERS: usize = 64;
const MAX_CLIENTS: usize = 64;
const AAD: &[u8] = b"OhMyPassword vault v1; Argon2id m=65536,t=3,p=1; AES-256-GCM";

#[derive(Debug)]
pub struct Error {
    message: String,
    capacity_limit: bool,
}

impl Error {
    /// Transports can classify capacity without matching translated messages.
    pub fn is_capacity_limit(&self) -> bool {
        self.capacity_limit
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

fn error(message: &str) -> Error {
    Error {
        message: message.to_owned(),
        capacity_limit: false,
    }
}
fn capacity_error(message: &str) -> Error {
    Error {
        message: message.to_owned(),
        capacity_limit: true,
    }
}
fn io_error(_: std::io::Error) -> Error {
    error("无法读写密码库，请检查存储空间和文件权限")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub initialized: bool,
    pub locked: bool,
    pub device_id: String,
    pub device_name: String,
    pub entry_count: usize,
    pub peer_count: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Version {
    /// Hybrid logical physical component in UTC milliseconds. This field is
    /// first deliberately: newest edit wins before the counter tie-breaker.
    pub modified_at: u64,
    pub counter: u64,
    pub device_id: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub hostname: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub version: Version,
    pub deleted: bool,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.notes.zeroize();
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryInput {
    #[serde(default)]
    pub id: Option<String>,
    pub hostname: String,
    #[serde(default)]
    pub title: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub notes: String,
}

impl Drop for EntryInput {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.notes.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntrySummary {
    pub id: String,
    pub hostname: String,
    pub title: String,
    pub username: String,
    pub version: Version,
    pub deleted: bool,
    pub conflict_count: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Peer {
    pub device_id: String,
    pub name: String,
    pub endpoint: String,
    pub shared_key: [u8; 32],
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.shared_key.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    pub id: String,
    pub name: String,
    pub origin: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientGrant {
    pub client: ClientInfo,
    pub token: String,
}

impl Drop for ClientGrant {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncPayload {
    pub version: u32,
    pub records: Vec<Entry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MergeResult {
    pub changed: usize,
    pub conflicts: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredClient {
    info: ClientInfo,
    token_hash: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultData {
    version: u32,
    device_name: String,
    clock: u64,
    modified_at: u64,
    // Every revision is immutable. Old values remain available as history;
    // deleted records retain their tombstone, so offline peers cannot revive
    // an older password merely by reconnecting.
    records: BTreeMap<String, Vec<Entry>>,
    peers: BTreeMap<String, Peer>,
    clients: BTreeMap<String, StoredClient>,
}

struct Unlocked {
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
    data: VaultData,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u32,
    device_id: String,
}

pub struct Vault {
    directory: PathBuf,
    device_id: String,
    initialized: bool,
    unlocked: Option<Unlocked>,
    _lock: File,
}

impl Vault {
    pub fn open(directory: PathBuf) -> Result<Self> {
        fs::create_dir_all(&directory).map_err(io_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
        }
        let lock = private_file(&directory.join("vault.lock"), false)?;
        lock.try_lock_exclusive()
            .map_err(|_| error("密码库已由另一进程打开"))?;
        let identity_path = directory.join("identity.json");
        let identity = if identity_path.exists() {
            let bytes = read_bounded(&identity_path, 1024)?;
            let identity: Identity =
                serde_json::from_slice(&bytes).map_err(|_| error("设备标识文件已损坏"))?;
            if identity.version != FORMAT || !valid_id(&identity.device_id) {
                return Err(error("设备标识文件无效"));
            }
            identity
        } else {
            if directory.join("vault.json").exists() {
                return Err(error("密码库缺少设备标识，请恢复完整备份"));
            }
            let identity = Identity {
                version: FORMAT,
                device_id: Uuid::new_v4().to_string(),
            };
            let bytes = serde_json::to_vec(&identity).map_err(|_| error("无法创建设备标识"))?;
            atomic_write(&directory, "identity.json", &bytes)?;
            identity
        };
        let initialized = directory.join("vault.json").exists();
        Ok(Self {
            directory,
            device_id: identity.device_id,
            initialized,
            unlocked: None,
            _lock: lock,
        })
    }

    pub fn status(&self) -> Status {
        Status {
            initialized: self.initialized,
            locked: self.unlocked.is_none(),
            device_id: self.device_id.clone(),
            device_name: self
                .unlocked
                .as_ref()
                .map(|u| u.data.device_name.clone())
                .unwrap_or_else(|| "此设备".to_owned()),
            entry_count: self
                .unlocked
                .as_ref()
                .map(|u| {
                    u.data
                        .records
                        .values()
                        .filter(|r| r.last().is_some_and(|e| !e.deleted))
                        .count()
                })
                .unwrap_or(0),
            peer_count: self
                .unlocked
                .as_ref()
                .map(|u| u.data.peers.len())
                .unwrap_or(0),
        }
    }

    pub fn create(&mut self, master_password: &str, device_name: &str) -> Result<Status> {
        if self.initialized {
            return Err(error("密码库已存在，请解锁"));
        }
        if master_password.chars().count() < 10 || master_password.len() > 1024 {
            return Err(error("主密码需至少 10 个字符，且不超过 1024 字节"));
        }
        validate_label(device_name)?;
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(master_password, &salt)?;
        let data = VaultData {
            version: FORMAT,
            device_name: device_name.trim().to_owned(),
            clock: 0,
            modified_at: 0,
            records: BTreeMap::new(),
            peers: BTreeMap::new(),
            clients: BTreeMap::new(),
        };
        let unlocked = Unlocked { key, salt, data };
        persist(
            &self.directory,
            &unlocked.key,
            &unlocked.salt,
            &unlocked.data,
        )?;
        self.unlocked = Some(unlocked);
        self.initialized = true;
        Ok(self.status())
    }

    pub fn unlock(&mut self, master_password: &str) -> Result<Status> {
        if !self.initialized {
            return Err(error("请先创建密码库"));
        }
        if master_password.len() > 1024 {
            return Err(error("主密码过长"));
        }
        // A failed unlock never leaves a previously unlocked instance active.
        self.lock();
        let bytes = read_bounded(&self.directory.join("vault.json"), MAX_FILE)?;
        let envelope: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| error("密码库文件格式无效"))?;
        if envelope.version != FORMAT {
            return Err(error("不支持此密码库版本"));
        }
        let salt = decode_array::<16>(&envelope.salt)?;
        let nonce = decode_array::<12>(&envelope.nonce)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&envelope.ciphertext)
            .map_err(|_| error("密码库文件格式无效"))?;
        let key = derive_key(master_password, &salt)?;
        let cipher =
            Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| error("加密初始化失败"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: AAD,
                    },
                )
                .map_err(|_| error("主密码错误或密码库已损坏"))?,
        );
        let data: VaultData =
            serde_json::from_slice(&plaintext).map_err(|_| error("密码库内容无效"))?;
        validate_data(&data, &self.device_id)?;
        self.unlocked = Some(Unlocked { key, salt, data });
        Ok(self.status())
    }

    pub fn lock(&mut self) -> Status {
        self.unlocked = None;
        self.status()
    }

    pub fn list(&self, hostname: Option<&str>) -> Result<Vec<EntrySummary>> {
        let data = &self.current()?.data;
        let hostname = hostname.map(normalize_hostname).transpose()?;
        let mut entries = Vec::new();
        for revisions in data.records.values() {
            if let Some(entry) = revisions.last() {
                if !entry.deleted && hostname.as_ref().is_none_or(|h| h == &entry.hostname) {
                    entries.push(EntrySummary {
                        id: entry.id.clone(),
                        hostname: entry.hostname.clone(),
                        title: entry.title.clone(),
                        username: entry.username.clone(),
                        version: entry.version.clone(),
                        deleted: false,
                        conflict_count: revisions.len().saturating_sub(1),
                    });
                }
            }
        }
        entries.sort_by(|a, b| {
            (&a.hostname, &a.username, &a.id).cmp(&(&b.hostname, &b.username, &b.id))
        });
        Ok(entries)
    }

    pub fn get(&self, id: &str) -> Result<Entry> {
        self.current()?
            .data
            .records
            .get(id)
            .and_then(|r| r.last())
            .filter(|e| !e.deleted)
            .cloned()
            .ok_or_else(|| error("账号不存在或已删除"))
    }

    pub fn get_conflicts(&self, id: &str) -> Result<Vec<Entry>> {
        let records = self
            .current()?
            .data
            .records
            .get(id)
            .ok_or_else(|| error("账号不存在"))?;
        Ok(records
            .iter()
            .take(records.len().saturating_sub(1))
            .filter(|e| !e.deleted)
            .cloned()
            .collect())
    }

    pub fn upsert(&mut self, input: EntryInput) -> Result<Entry> {
        let mut next = self.current()?.data.clone();
        let id = match &input.id {
            Some(id) if valid_id(id) && next.records.contains_key(id) => id.clone(),
            Some(_) => return Err(error("要修改的账号不存在")),
            None => Uuid::new_v4().to_string(),
        };
        next.clock = next
            .clock
            .checked_add(1)
            .ok_or_else(|| error("修订计数已达上限"))?;
        next.modified_at = next_timestamp(next.modified_at)?;
        let entry = Entry {
            id: id.clone(),
            hostname: normalize_hostname(&input.hostname)?,
            title: input.title.trim().to_owned(),
            username: input.username.clone(),
            password: input.password.clone(),
            notes: input.notes.clone(),
            version: Version {
                modified_at: next.modified_at,
                counter: next.clock,
                device_id: self.device_id.clone(),
            },
            deleted: false,
        };
        validate_entry(&entry)?;
        next.records.entry(id).or_default().push(entry.clone());
        self.commit(next)?;
        Ok(entry)
    }

    pub fn delete(&mut self, id: &str) -> Result<()> {
        let previous = self.get(id)?;
        let mut next = self.current()?.data.clone();
        next.clock = next
            .clock
            .checked_add(1)
            .ok_or_else(|| error("修订计数已达上限"))?;
        next.modified_at = next_timestamp(next.modified_at)?;
        let tombstone = Entry {
            id: id.to_owned(),
            hostname: previous.hostname.clone(),
            title: String::new(),
            username: String::new(),
            password: String::new(),
            notes: String::new(),
            version: Version {
                modified_at: next.modified_at,
                counter: next.clock,
                device_id: self.device_id.clone(),
            },
            deleted: true,
        };
        next.records
            .get_mut(id)
            .ok_or_else(|| error("账号不存在"))?
            .push(tombstone);
        self.commit(next)
    }

    pub fn export_sync(&self) -> Result<SyncPayload> {
        Ok(SyncPayload {
            version: FORMAT,
            records: self
                .current()?
                .data
                .records
                .values()
                .flatten()
                .cloned()
                .collect(),
        })
    }

    pub fn merge_sync(&mut self, payload: SyncPayload) -> Result<MergeResult> {
        if payload.version != FORMAT || payload.records.len() > MAX_RECORDS {
            return Err(error("同步数据版本或大小无效"));
        }
        let mut next = self.current()?.data.clone();
        // A genuine complete-history vault under the 1 MiB limit cannot
        // produce a million edits. Bound a single peer's counter jump so a
        // malformed authenticated message cannot exhaust the local counter.
        let max_counter = next.clock.saturating_add(MAX_COUNTER_JUMP);
        let mut result = MergeResult::default();
        for entry in &payload.records {
            validate_entry(entry)?;
            validate_remote_time(entry.version.modified_at)?;
            if entry.version.counter > max_counter {
                return Err(error("远端修订计数异常，已拒绝此次同步"));
            }
            next.clock = next.clock.max(entry.version.counter);
            next.modified_at = next.modified_at.max(entry.version.modified_at);
            let revisions = next.records.entry(entry.id.clone()).or_default();
            if let Some(existing) = revisions.iter().find(|r| r.version == entry.version) {
                if existing != entry {
                    return Err(error("相同修订包含不同内容，已拒绝同步"));
                }
                continue;
            }
            revisions.push(entry.clone());
            revisions.sort_by(|a, b| a.version.cmp(&b.version));
            result.changed += 1;
        }
        result.conflicts = next
            .records
            .values()
            .map(|r| r.len().saturating_sub(1))
            .sum();
        if result.changed > 0 {
            self.commit(next)?;
        }
        Ok(result)
    }

    pub fn peers(&self) -> Result<Vec<Peer>> {
        Ok(self.current()?.data.peers.values().cloned().collect())
    }

    pub fn add_peer(&mut self, peer: Peer) -> Result<()> {
        validate_peer(&peer, &self.device_id)?;
        let mut next = self.current()?.data.clone();
        if !next.peers.contains_key(&peer.device_id) && next.peers.len() >= MAX_PEERS {
            return Err(error("配对设备数量已达上限"));
        }
        next.peers.insert(peer.device_id.clone(), peer);
        self.commit(next)
    }

    pub fn remove_peer(&mut self, device_id: &str) -> Result<()> {
        let mut next = self.current()?.data.clone();
        next.peers.remove(device_id);
        self.commit(next)
    }

    pub fn create_client(&mut self, name: &str, origin: &str) -> Result<ClientGrant> {
        validate_label(name)?;
        validate_origin(origin)?;
        let mut next = self.current()?.data.clone();
        if next.clients.len() >= MAX_CLIENTS {
            return Err(error("浏览器授权数量已达上限"));
        }
        let mut random = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(random.as_mut());
        let token = format!("omp_{}", URL_SAFE_NO_PAD.encode(random.as_ref()));
        let client = ClientInfo {
            id: Uuid::new_v4().to_string(),
            name: name.trim().to_owned(),
            origin: origin.to_owned(),
        };
        let stored = StoredClient {
            info: client.clone(),
            token_hash: Sha256::digest(token.as_bytes()).into(),
        };
        next.clients.insert(client.id.clone(), stored);
        self.commit(next)?;
        Ok(ClientGrant { client, token })
    }

    pub fn clients(&self) -> Result<Vec<ClientInfo>> {
        Ok(self
            .current()?
            .data
            .clients
            .values()
            .map(|c| c.info.clone())
            .collect())
    }

    pub fn revoke_client(&mut self, id: &str) -> Result<()> {
        let mut next = self.current()?.data.clone();
        next.clients.remove(id);
        self.commit(next)
    }

    pub fn authorize_client(&self, token: &str, origin: &str) -> Result<bool> {
        let data = &self.current()?.data;
        if token.len() != 47 || !token.starts_with("omp_") || validate_origin(origin).is_err() {
            return Ok(false);
        }
        let supplied: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        Ok(data
            .clients
            .values()
            .any(|c| c.info.origin == origin && bool::from(c.token_hash.ct_eq(&supplied))))
    }

    fn current(&self) -> Result<&Unlocked> {
        self.unlocked.as_ref().ok_or_else(|| error("密码库已锁定"))
    }

    fn commit(&mut self, data: VaultData) -> Result<()> {
        validate_data(&data, &self.device_id)?;
        let current = self.current()?;
        persist(&self.directory, &current.key, &current.salt, &data)?;
        self.unlocked
            .as_mut()
            .ok_or_else(|| error("密码库已锁定"))?
            .data = data;
        Ok(())
    }
}

/// Normalize an exact hostname. No suffix or registrable-domain matching.
pub fn normalize_hostname(input: &str) -> Result<String> {
    if input.chars().any(char::is_control) {
        return Err(error("网站地址不能包含控制字符"));
    }
    let input = input.trim();
    if input.is_empty() || input.len() > 2048 {
        return Err(error("请输入有效网站域名或 HTTP(S) 地址"));
    }
    let has_scheme = input.contains("://");
    let url = Url::parse(if has_scheme { input } else { "" })
        .or_else(|_| Url::parse(&format!("https://{input}")))
        .map_err(|_| error("网站地址无效"))?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(error("网站地址仅支持 HTTP(S)，不能包含账号信息"));
    }
    if !has_scheme && (url.path() != "/" || url.query().is_some() || url.fragment().is_some()) {
        return Err(error("请输入域名，或包含 http(s):// 的完整地址"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| error("网站地址缺少域名"))?
        .trim_end_matches('.')
        .to_lowercase();
    if host.is_empty() || host.len() > 253 || host.contains('*') {
        return Err(error("网站域名无效"));
    }
    // The URL crate accepts unusual DNS labels; reject empty internal labels
    // and labels containing spaces or separators rather than widening matches.
    if !host.starts_with('[')
        && host.split('.').any(|p| {
            p.is_empty()
                || p.len() > 63
                || !p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                || p.starts_with('-')
                || p.ends_with('-')
        })
    {
        return Err(error("网站域名无效"));
    }
    Ok(host)
}

fn valid_id(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| error("系统时间无效，请先校准系统时间"))?
        .as_millis()
        .try_into()
        .map_err(|_| error("系统时间超出范围"))
}

fn next_timestamp(previous: u64) -> Result<u64> {
    let next = now_ms()?.max(
        previous
            .checked_add(1)
            .ok_or_else(|| error("修订时间已达上限"))?,
    );
    validate_remote_time(next)?;
    Ok(next)
}

fn validate_remote_time(timestamp: u64) -> Result<()> {
    if timestamp < EARLIEST_MS
        || timestamp
            > now_ms()?
                .checked_add(MAX_FUTURE_MS)
                .ok_or_else(|| error("系统时间无效"))?
    {
        return Err(error(
            "修订时间无效或设备时钟相差超过 5 分钟，请校准设备时间",
        ));
    }
    Ok(())
}

fn validate_label(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err(error("名称不能为空，且不超过 128 字节"))
    } else {
        Ok(())
    }
}

fn validate_entry(entry: &Entry) -> Result<()> {
    if !valid_id(&entry.id)
        || !valid_id(&entry.version.device_id)
        || entry.version.counter == 0
        || entry.version.counter > (1u64 << 53) - 1
        || entry.version.modified_at < EARLIEST_MS
        || entry.version.modified_at > (1u64 << 53) - 1
    {
        return Err(error("账号修订标识无效"));
    }
    if normalize_hostname(&entry.hostname)? != entry.hostname {
        return Err(error("同步域名未规范化"));
    }
    if entry.title.len() > 512
        || entry.username.len() > 1024
        || entry.password.len() > 16 * 1024
        || entry.notes.len() > 32 * 1024
    {
        return Err(error("账号字段超过大小限制"));
    }
    if entry.deleted {
        if !entry.password.is_empty()
            || !entry.username.is_empty()
            || !entry.notes.is_empty()
            || !entry.title.is_empty()
        {
            return Err(error("删除标记不能包含账号内容"));
        }
    } else if entry.password.is_empty() {
        return Err(error("密码不能为空"));
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<()> {
    let url = Url::parse(origin).map_err(|_| error("扩展来源无效"))?;
    let host = url.host_str().ok_or_else(|| error("扩展来源无效"))?;
    let valid_host = match url.scheme() {
        "chrome-extension" => host.len() == 32 && host.bytes().all(|c| (b'a'..=b'p').contains(&c)),
        "moz-extension" => valid_id(host),
        _ => false,
    };
    if !valid_host || origin != format!("{}://{}", url.scheme(), host) {
        return Err(error(
            "请填写完整扩展来源 chrome-extension://扩展ID 或 moz-extension://UUID",
        ));
    }
    Ok(())
}

fn validate_peer(peer: &Peer, local_id: &str) -> Result<()> {
    if !valid_id(&peer.device_id) || peer.device_id == local_id || peer.shared_key == [0; 32] {
        return Err(error("配对设备标识或密钥无效"));
    }
    validate_label(&peer.name)?;
    // The service enforces LAN-only destination addresses and routes. Core
    // stores a bounded endpoint rather than performing DNS/network requests.
    if peer.endpoint.len() > 512 || peer.endpoint.chars().any(char::is_control) {
        return Err(error("配对设备地址无效"));
    }
    Ok(())
}

fn validate_data(data: &VaultData, local_id: &str) -> Result<()> {
    if data.version != FORMAT
        || data.records.values().map(Vec::len).sum::<usize>() > MAX_RECORDS
        || data.peers.len() > MAX_PEERS
        || data.clients.len() > MAX_CLIENTS
    {
        return Err(error("密码库版本或大小无效"));
    }
    validate_label(&data.device_name)?;
    for (id, entries) in &data.records {
        if entries.is_empty() {
            return Err(error("密码库修订记录无效"));
        }
        let mut previous = None;
        for entry in entries {
            validate_entry(entry)?;
            if &entry.id != id
                || entry.version.counter > data.clock
                || entry.version.modified_at > data.modified_at
                || previous.is_some_and(|p: &Version| p >= &entry.version)
            {
                return Err(error("密码库修订顺序无效"));
            }
            previous = Some(&entry.version);
        }
    }
    for (id, peer) in &data.peers {
        if id != &peer.device_id {
            return Err(error("配对记录无效"));
        }
        validate_peer(peer, local_id)?;
    }
    for (id, client) in &data.clients {
        if id != &client.info.id || !valid_id(id) {
            return Err(error("扩展授权记录无效"));
        }
        validate_label(&client.info.name)?;
        validate_origin(&client.info.origin)?;
    }
    let payload = SyncPayload {
        version: FORMAT,
        records: data.records.values().flatten().cloned().collect(),
    };
    let encoded =
        Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| error("同步数据编码失败"))?);
    if encoded.len() > MAX_SYNC_BYTES {
        return Err(capacity_error(
            "密码及历史版本已超过 1 MiB 同步容量，未保存此次修改",
        ));
    }
    Ok(())
}

fn derive_key(password: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(65_536, 3, 1, Some(32)).map_err(|_| error("密钥参数无效"))?;
    let block_count = params.block_count();
    let algorithm = Argon2::new(Algorithm::Argon2id, ArgonVersion::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    // Argon2's convenience API owns an ordinary Vec<Block>; its zeroize
    // feature clears intermediate hashes but does not erase that whole Vec.
    // Supplying zeroizing storage also clears the 64 MiB working arena.
    let mut memory = Zeroizing::new(Vec::<Block>::new());
    memory
        .try_reserve_exact(block_count)
        .map_err(|_| error("可用内存不足，无法解锁密码库"))?;
    memory.resize(block_count, Block::default());
    algorithm
        .hash_password_into_with_memory(password.as_bytes(), salt, key.as_mut(), &mut *memory)
        .map_err(|_| error("无法派生密码库密钥"))?;
    Ok(key)
}

fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| error("密码库文件格式无效"))?
        .try_into()
        .map_err(|_| error("密码库文件格式无效"))
}

fn persist(directory: &Path, key: &[u8; 32], salt: &[u8; 16], data: &VaultData) -> Result<()> {
    let plaintext = Zeroizing::new(serde_json::to_vec(data).map_err(|_| error("无法编码密码库"))?);
    if plaintext.len() > MAX_FILE * 3 / 4 - 1024 {
        return Err(capacity_error("密码库超过 16 MiB 存储限制"));
    }
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| error("加密初始化失败"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| error("密码库加密失败"))?;
    let envelope = Envelope {
        version: FORMAT,
        salt: URL_SAFE_NO_PAD.encode(salt),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| error("无法编码密码库"))?;
    atomic_write(directory, "vault.json", &bytes)
}

fn private_file(path: &Path, create_new: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(io_error)
}

fn atomic_write(directory: &Path, filename: &str, bytes: &[u8]) -> Result<()> {
    // Fixed temp name under the process-wide file lock. Never truncate a
    // pre-existing path (including a symlink). An interrupted write may leave
    // a temp file; remove only a regular file before the next attempt.
    let temporary = directory.join(format!(".{filename}.new"));
    if let Ok(metadata) = fs::symlink_metadata(&temporary) {
        if !metadata.file_type().is_file() {
            return Err(error("临时文件路径异常，未修改密码库"));
        }
        fs::remove_file(&temporary).map_err(io_error)?;
    }
    let result = (|| {
        let mut file = private_file(&temporary, true)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        fs::rename(&temporary, directory.join(filename)).map_err(io_error)?;
        // A failed directory fsync after rename cannot roll the rename back.
        // Best effort here preserves the durable-before-visible ordering.
        #[cfg(unix)]
        {
            if let Ok(directory) = File::open(directory) {
                let _ = directory.sync_all();
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(io_error)?;
    if file.metadata().map_err(io_error)?.len() > limit as u64 {
        return Err(error("密码库文件超过大小限制"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > limit {
        return Err(error("密码库文件超过大小限制"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
