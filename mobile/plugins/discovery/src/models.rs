use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartRequest {
    pub device_id: String,
    pub name: String,
    pub port: u16,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct DiscoveredPeer {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    /// Unix milliseconds of the most recent native resolution, not a poll time.
    pub last_seen: u64,
}
#[derive(Default, Deserialize, Serialize)]
pub struct PeersResponse {
    pub peers: Vec<DiscoveredPeer>,
}
