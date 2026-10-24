//! Bounded, read-only discovery of peers on directly attached IPv4 networks.
//! Only the public information endpoint is queried; discovery grants no access.
use crate::{
    lock, protocol::*, AppVersionInfo, Challenge, DiscoveredPeer, IncompatiblePeer, Inner,
};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::task::JoinSet;

pub(super) const PORT: u16 = 17842;
const MAX_TARGETS: usize = 1024;
const CONCURRENCY: usize = 32;
const MAX_INFO_BYTES: usize = 8192;
const PROBE_TIMEOUT: Duration = Duration::from_millis(1000);

struct Plan {
    targets: Vec<SocketAddr>,
    ranges: Vec<String>,
    limited: bool,
}

fn private_address(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

fn plan(networks: &[(Ipv4Addr, Ipv4Addr)]) -> Plan {
    let own: BTreeSet<_> = networks.iter().map(|(ip, _)| u32::from(*ip)).collect();
    let mut subnets = BTreeSet::new();
    let mut limited = false;
    for (ip, netmask) in networks {
        if !private_address(*ip) {
            continue;
        }
        let mask = u32::from(*netmask);
        let prefix = mask.leading_ones();
        if prefix == 0 || mask != u32::MAX << (32 - prefix) {
            continue;
        }
        // A large corporate/VPN network is not a reason to scan thousands of
        // unrelated hosts. Declare the exact smaller range in the status.
        let effective = if prefix < 22 {
            limited = true;
            24
        } else {
            prefix
        };
        let effective_mask = u32::MAX << (32 - effective);
        subnets.insert((u32::from(*ip) & effective_mask, effective));
    }
    let mut selected = BTreeSet::new();
    let mut ranges = Vec::new();
    for (network, prefix) in subnets {
        // /31 and /32 have no ordinary LAN hosts after excluding network and
        // broadcast, so do not guess point-to-point destinations.
        if prefix >= 31 {
            continue;
        }
        let broadcast = network | (u32::MAX >> prefix);
        let candidates: Vec<_> = (network + 1..broadcast)
            .filter(|ip| {
                !own.contains(ip) && private_address(Ipv4Addr::from(*ip)) && !selected.contains(ip)
            })
            .collect();
        if selected.len() + candidates.len() > MAX_TARGETS {
            limited = true;
            continue;
        }
        if !candidates.is_empty() {
            selected.extend(candidates);
            ranges.push(format!("{}/{}", Ipv4Addr::from(network), prefix));
        }
    }
    Plan {
        targets: selected
            .into_iter()
            .map(|ip| SocketAddr::from((Ipv4Addr::from(ip), PORT)))
            .collect(),
        ranges,
        limited,
    }
}

fn local_plan() -> std::io::Result<Plan> {
    let networks = if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|interface| {
            // Cellular interfaces and point-to-point tunnels are not the local
            // Wi-Fi/Ethernet LAN the user is asking to inspect.
            let name = interface.name.to_ascii_lowercase();
            if ["rmnet", "ccmni", "pdp_ip", "tun", "utun", "wg", "tailscale"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                return None;
            }
            match interface.addr {
                if_addrs::IfAddr::V4(address) => Some((address.ip, address.netmask)),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    Ok(plan(&networks))
}

fn client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT)
        .pool_max_idle_per_host(0)
        .build()
        .ok()
}

async fn bounded_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Option<T> {
    if response.status().as_u16() != 200
        || response
            .content_length()
            .is_some_and(|n| n > MAX_INFO_BYTES as u64)
    {
        return None;
    }
    let media_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)?
        .to_str()
        .ok()?
        .split(';')
        .next()?
        .trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return None;
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > MAX_INFO_BYTES {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).ok()
}

async fn decode_info(response: reqwest::Response, expected_protocol: u32) -> Option<Challenge> {
    let info: Challenge = bounded_json(response).await?;
    if info.protocol != expected_protocol
        || !valid_id(&info.device_id)
        || !valid_id(&info.epoch)
        || info.name.trim().is_empty()
        || info.name.len() > 128
        || info.name.chars().any(char::is_control)
    {
        return None;
    }
    Some(info)
}

struct Found {
    info: Challenge,
    app_version: Option<String>,
}
async fn probe(client: &reqwest::Client, address: SocketAddr) -> Option<Found> {
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
    let info = tokio::time::timeout_at(deadline, async {
        let response = client
            .get(format!("{}/v3/info", endpoint(address)))
            .send()
            .await
            .ok()?;
        if matches!(response.status().as_u16(), 400 | 404) {
            // Compatibility diagnosis only. Old peers never enter the usable
            // discovered list and cannot trigger a protocol downgrade.
            let legacy = client
                .get(format!("{}/v2/info", endpoint(address)))
                .send()
                .await
                .ok()?;
            decode_info(legacy, 2).await
        } else {
            decode_info(response, 3).await
        }
    })
    .await
    .ok()
    .flatten()?;
    // Keep /v3/info byte-schema compatible with released 0.2.3 clients.
    // Version metadata is optional; failure cannot discard an identified peer.
    let app_version = if info.protocol == 3 {
        tokio::time::timeout_at(deadline, async {
            let response = client
                .get(format!("{}/v3/version", endpoint(address)))
                .send()
                .await
                .ok()?;
            let version: AppVersionInfo = bounded_json(response).await?;
            if version.protocol == 3
                && version.device_id == info.device_id
                && version.epoch == info.epoch
                && !version.app_version.is_empty()
                && version.app_version.len() <= 32
                && version
                    .app_version
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-+".contains(&c))
            {
                Some(version.app_version)
            } else {
                None
            }
        })
        .await
        .ok()
        .flatten()
    } else {
        None
    };
    Some(Found { info, app_version })
}

fn current(state: &Inner, generation: u64, status: &crate::ServiceStatus) -> bool {
    state.ensure_active().is_ok() && status.discovery_generation == generation
}

pub(super) async fn run(state: Arc<Inner>, generation: u64) {
    let plan = match local_plan() {
        Ok(plan) => plan,
        Err(_) => {
            if let Ok(mut status) = state.status.lock() {
                if current(&state, generation, &status) {
                    status.scan_state = "failed".into();
                    status.scan_error = Some("无法读取本机网卡，请检查网络权限后重试".into());
                }
            }
            return;
        }
    };
    scan_plan(state, generation, plan).await;
}

async fn scan_plan(state: Arc<Inner>, generation: u64, plan: Plan) {
    let own_id = match lock(&state.vault) {
        Ok(vault) if !vault.status().locked => vault.status().device_id,
        _ => return,
    };
    let Some(client) = client() else {
        if let Ok(mut status) = state.status.lock() {
            if current(&state, generation, &status) {
                status.scan_state = "failed".into();
                status.scan_error = Some("无法启动局域网探测，请稍后重试".into());
            }
        }
        return;
    };
    {
        let Ok(mut status) = state.status.lock() else {
            return;
        };
        if !current(&state, generation, &status) {
            return;
        }
        status.scan_total = plan.targets.len();
        status.scan_checked = 0;
        status.scan_ranges = plan.ranges;
        status.scan_limited = plan.limited;
        status.scan_state = "scanning".into();
        status.scan_error = if plan.targets.is_empty() {
            Some("没有可探测的局域网 IPv4 地址，请连接 Wi-Fi 或有线网络".into())
        } else {
            None
        };
    }
    let mut targets = plan.targets.into_iter();
    let mut pending = JoinSet::new();
    loop {
        {
            let Ok(status) = state.status.lock() else {
                return;
            };
            if !current(&state, generation, &status) {
                return;
            }
        }
        while pending.len() < CONCURRENCY {
            let Some(address) = targets.next() else {
                break;
            };
            let client = client.clone();
            pending.spawn(async move { (address, probe(&client, address).await) });
        }
        let Some(result) = pending.join_next().await else {
            break;
        };
        let Ok(mut status) = state.status.lock() else {
            return;
        };
        if !current(&state, generation, &status) {
            return;
        }
        status.scan_checked = (status.scan_checked + 1).min(status.scan_total);
        if let Ok((address, Some(found_peer))) = result {
            let info = found_peer.info;
            if info.device_id == own_id {
                continue;
            }
            if info.protocol == 3 {
                if let Ok(mut found) = state.discovered.lock() {
                    if found.len() < 128 || found.contains_key(&info.device_id) {
                        found.insert(
                            info.device_id.clone(),
                            DiscoveredPeer {
                                id: info.device_id.clone(),
                                name: info.name,
                                endpoint: endpoint(address),
                                last_seen: now(),
                                app_version: found_peer.app_version,
                            },
                        );
                    }
                }
                if let Ok(mut old) = state.incompatible_discovered.lock() {
                    old.remove(&info.device_id);
                }
            } else {
                if let Ok(mut found) = state.discovered.lock() {
                    found.remove(&info.device_id);
                }
                if let Ok(mut old) = state.incompatible_discovered.lock() {
                    if old.len() < 128 || old.contains_key(&info.device_id) {
                        old.insert(
                            info.device_id.clone(),
                            IncompatiblePeer {
                                id: info.device_id,
                                name: info.name,
                                endpoint: endpoint(address),
                                last_seen: now(),
                                protocol: 2,
                            },
                        );
                    }
                }
            }
        }
    }
    if let Ok(mut status) = state.status.lock() {
        if current(&state, generation, &status) {
            status.scan_state = "completed".into();
        }
    }
}

#[cfg(test)]
#[path = "lan_scan_tests.rs"]
mod tests;
