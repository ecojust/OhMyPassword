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
}
#[derive(Default, Deserialize, Serialize)]
pub struct PeersResponse {
    pub peers: Vec<DiscoveredPeer>,
}
