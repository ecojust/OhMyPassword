use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroize;

pub(crate) const MAX_BODY: usize = 2 * 1024 * 1024;
pub(crate) const CLOCK_WINDOW: u64 = 120;
pub(crate) const REPLAY_CAPACITY: usize = 4096;

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(crate) fn random_key() -> [u8; 32] {
    let mut key = [0; 32];
    OsRng.fill_bytes(&mut key);
    key
}
pub(crate) fn random_id() -> String {
    Uuid::new_v4().to_string()
}
pub(crate) fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub(crate) fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::InvalidRequest)
}
pub(crate) fn key_from(value: &str) -> Result<[u8; 32]> {
    let mut bytes = decode(value)?;
    let result = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidRequest);
    bytes.zeroize();
    result
}
pub(crate) fn valid_id(value: &str) -> bool {
    Uuid::parse_str(value).is_ok() && value.len() == 36
}
pub(crate) fn local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        IpAddr::V6(v) => {
            v.is_loopback()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}
pub(crate) fn parse_endpoint(value: &str) -> Result<SocketAddr> {
    // Only literal LAN addresses: no DNS, credentials, redirects or arbitrary paths.
    let value = value
        .strip_prefix("http://")
        .ok_or(Error::InvalidEndpoint)?;
    let addr: SocketAddr = value.parse().map_err(|_| Error::InvalidEndpoint)?;
    if addr.port() == 0 || !addr.is_ipv4() || !local_ip(addr.ip()) {
        return Err(Error::InvalidEndpoint);
    }
    Ok(addr)
}
pub(crate) fn endpoint(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    pub version: u32,
    pub from: String,
    pub to: String,
    pub request_id: String,
    pub epoch: String,
    pub nonce: String,
    pub ciphertext: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plain<T> {
    sent_at: u64,
    data: T,
}

fn aad(route: &str, response: bool, env: &Envelope) -> Vec<u8> {
    format!(
        "ohmypassword/2|{}|{}|{}|{}|{}|{}",
        if response { "response" } else { "request" },
        route,
        env.from,
        env.to,
        env.request_id,
        env.epoch
    )
    .into_bytes()
}
pub(crate) fn seal<T: Serialize>(
    key: &[u8; 32],
    route: &str,
    response: bool,
    from: &str,
    to: &str,
    request_id: &str,
    epoch: &str,
    data: &T,
) -> Result<Envelope> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut env = Envelope {
        version: 2,
        from: from.into(),
        to: to.into(),
        request_id: request_id.into(),
        epoch: epoch.into(),
        nonce: encode(nonce),
        ciphertext: String::new(),
    };
    let mut plain = serde_json::to_vec(&Plain {
        sent_at: now(),
        data,
    })
    .map_err(|_| Error::InvalidRequest)?;
    if plain.len() > ohmypassword_core::MAX_SYNC_BYTES + 16 * 1024 {
        plain.zeroize();
        return Err(Error::TooLarge);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidRequest)?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &aad(route, response, &env),
            },
        )
        .map_err(|_| Error::Authentication);
    plain.zeroize();
    env.ciphertext = encode(encrypted?);
    Ok(env)
}
pub(crate) fn open<T: DeserializeOwned>(
    key: &[u8; 32],
    route: &str,
    response: bool,
    env: &Envelope,
) -> Result<T> {
    if env.version != 2
        || !valid_id(&env.from)
        || !valid_id(&env.to)
        || !valid_id(&env.request_id)
        || !valid_id(&env.epoch)
        || env.ciphertext.len() > MAX_BODY
    {
        return Err(Error::InvalidRequest);
    }
    let nonce = decode(&env.nonce)?;
    if nonce.len() != 12 {
        return Err(Error::InvalidRequest);
    }
    let ciphertext = decode(&env.ciphertext)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidRequest)?;
    let mut bytes = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad(route, response, env),
            },
        )
        .map_err(|_| Error::Authentication)?;
    let result = serde_json::from_slice::<Plain<T>>(&bytes).map_err(|_| Error::InvalidRequest);
    bytes.zeroize();
    let plain = result?;
    if now().abs_diff(plain.sent_at) > CLOCK_WINDOW {
        return Err(Error::Expired);
    }
    Ok(plain.data)
}
pub(crate) struct ReplayGuard {
    seen: HashMap<(String, String), u64>,
}
impl ReplayGuard {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }
    pub fn accept(&mut self, sender: &str, id: &str) -> Result<()> {
        let current = now();
        self.seen
            .retain(|_, time| current.saturating_sub(*time) <= CLOCK_WINDOW * 2 + 1);
        let key = (sender.into(), id.into());
        if self.seen.contains_key(&key) {
            return Err(Error::Replay);
        }
        // Never evict a valid entry to make room: an attacker could replay it.
        if self.seen.len() >= REPLAY_CAPACITY {
            return Err(Error::Busy);
        }
        self.seen.insert(key, current);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_messages_bind_direction_route_identity_and_epoch() {
        let key = random_key();
        let a = random_id();
        let b = random_id();
        let id = random_id();
        let epoch = random_id();
        let env = seal(&key, "sync", false, &a, &b, &id, &epoch, &"secret").unwrap();
        assert_eq!(open::<String>(&key, "sync", false, &env).unwrap(), "secret");
        assert!(open::<String>(&key, "pair", false, &env).is_err());
        assert!(open::<String>(&key, "sync", true, &env).is_err());
        let mut changed = env.clone();
        changed.to = random_id();
        assert!(open::<String>(&key, "sync", false, &changed).is_err());
        let mut changed = env.clone();
        changed.epoch = random_id();
        assert!(open::<String>(&key, "sync", false, &changed).is_err());
        let mut changed = env.clone();
        changed.ciphertext.push('A');
        assert!(open::<String>(&key, "sync", false, &changed).is_err());
        assert!(open::<String>(&random_key(), "sync", false, &env).is_err());
    }
    #[test]
    fn replay_cache_rejects_duplicates_and_does_not_evict_live_entries() {
        let mut replay = ReplayGuard::new();
        replay.accept("a", "first").unwrap();
        assert!(matches!(replay.accept("a", "first"), Err(Error::Replay)));
        for i in 1..REPLAY_CAPACITY {
            replay.accept("a", &i.to_string()).unwrap();
        }
        assert!(matches!(replay.accept("b", "new"), Err(Error::Busy)));
        assert!(matches!(replay.accept("a", "first"), Err(Error::Replay)));
    }
    #[test]
    fn endpoints_are_literal_lan_addresses_without_paths_or_credentials() {
        for value in ["http://127.0.0.1:17842", "http://192.168.1.2:17842"] {
            assert!(parse_endpoint(value).is_ok(), "{value}");
        }
        for value in [
            "http://[::1]:17842",
            "https://192.168.1.2:443",
            "http://example.com:17842",
            "http://8.8.8.8:17842",
            "http://192.168.1.2:0",
            "http://user:pass@192.168.1.2:80",
            "http://192.168.1.2:80/path",
            "http://0.0.0.0:80",
        ] {
            assert!(parse_endpoint(value).is_err(), "{value}");
        }
    }
}
