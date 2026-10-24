use super::*;
use axum::{
    http::{header, StatusCode},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use std::{
    net::TcpListener,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Server {
    address: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
async fn server(router: Router) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Server { address, handle }
}
async fn raw_server(response: Vec<u8>, pause: Duration) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let _ = stream.read(&mut request).await;
        let _ = stream.write_all(&response).await;
        tokio::time::sleep(pause).await;
    });
    Server { address, handle }
}
fn info(protocol: u32) -> Value {
    json!({"protocol":protocol,"device_id":random_id(),"epoch":random_id(),"name":"LAN test peer"})
}
fn fixed(path: &str, data: Value) -> Router {
    Router::new().route(
        path,
        get(move || {
            let data = data.clone();
            async move { Json(data) }
        }),
    )
}
fn prepare(service: &crate::Service) -> u64 {
    crate::tests::eventually(|| service.status().discovery_generation > 0);
    let mut status = service.inner.status.lock().unwrap();
    status.discovery_generation += 1;
    status.scan_state = "planning".into();
    status.scan_checked = 0;
    status.scan_total = 0;
    status.discovery_generation
}
fn test_plan(targets: Vec<SocketAddr>) -> Plan {
    Plan {
        targets,
        ranges: vec!["loopback-test-only".into()],
        limited: false,
    }
}

#[test]
fn plans_use_real_masks_deduplicate_and_bound_large_networks() {
    let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
    let p = plan(&[
        (ip("192.168.7.10"), ip("255.255.255.0")),
        (ip("192.168.7.20"), ip("255.255.255.0")),
    ]);
    assert_eq!(p.targets.len(), 252);
    assert_eq!(p.ranges, ["192.168.7.0/24"]);
    assert!(!p.limited);
    assert!(p.targets.iter().all(|a| a.port() == 17842
        && a.ip() != ip("192.168.7.10")
        && a.ip() != ip("192.168.7.20")));
    assert!(!p
        .targets
        .iter()
        .any(|a| a.ip() == ip("192.168.7.0") || a.ip() == ip("192.168.7.255")));
    let p = plan(&[(ip("10.4.8.130"), ip("255.255.255.128"))]);
    assert_eq!(p.targets.len(), 125);
    assert_eq!(p.ranges, ["10.4.8.128/25"]);
    let p = plan(&[(ip("10.2.7.3"), ip("255.0.0.0"))]);
    assert_eq!(p.targets.len(), 253);
    assert_eq!(p.ranges, ["10.2.7.0/24"]);
    assert!(p.limited);
    let many = (0..10)
        .map(|n| (Ipv4Addr::new(192, 168, n, 2), ip("255.255.255.0")))
        .collect::<Vec<_>>();
    let p = plan(&many);
    assert!(p.targets.len() <= MAX_TARGETS);
    assert!(p.limited);
    assert_eq!(p.ranges.len(), 4);
    let p = plan(&[
        (ip("8.8.8.8"), ip("255.255.255.0")),
        (ip("127.0.0.1"), ip("255.0.0.0")),
        (ip("192.168.7.2"), ip("255.0.255.0")),
    ]);
    assert!(p.targets.is_empty());
    let p = plan(&[
        (ip("192.168.7.2"), ip("255.255.255.254")),
        (ip("192.168.8.3"), ip("255.255.255.255")),
    ]);
    assert!(p.targets.is_empty());
}

#[test]
fn probes_identify_only_valid_info_and_optional_bound_version() {
    crate::tests::runtime().block_on(async {
        let client=client().unwrap();
        let current=info(3);
        let version=json!({"protocol":3,"device_id":current["device_id"],"epoch":current["epoch"],"app_version":"0.2.4"});
        let available=server(fixed("/v3/info",current.clone()).merge(fixed("/v3/version",version))).await;
        let found=probe(&client,available.address).await.unwrap();assert_eq!(found.app_version.as_deref(),Some("0.2.4"));
        let old_v3=server(fixed("/v3/info",current.clone())).await;
        assert!(probe(&client,old_v3.address).await.unwrap().app_version.is_none());
        let bad_version=json!({"protocol":3,"device_id":random_id(),"epoch":current["epoch"],"app_version":"0.2.4"});
        let changed=server(fixed("/v3/info",current.clone()).merge(fixed("/v3/version",bad_version))).await;
        assert!(probe(&client,changed.address).await.unwrap().app_version.is_none());
        let delayed=server(fixed("/v3/info",current.clone()).route("/v3/version",get(||async {tokio::time::sleep(Duration::from_secs(3)).await;Json(json!({}))}))).await;
        let started=Instant::now();assert!(probe(&client,delayed.address).await.is_some());assert!(started.elapsed()<Duration::from_millis(1800));
        let legacy=server(fixed("/v2/info",info(2))).await;
        assert_eq!(probe(&client,legacy.address).await.unwrap().info.protocol,2);
        for bad in [json!({"ok":true}),info(2),json!({"protocol":3,"device_id":"invalid","epoch":random_id(),"name":"Other"})] {
            let unknown=server(fixed("/v3/info",bad)).await;assert!(probe(&client,unknown.address).await.is_none());
        }
        let closed=TcpListener::bind("127.0.0.1:0").unwrap();let address=closed.local_addr().unwrap();drop(closed);
        assert!(probe(&client,address).await.is_none());
    });
}

#[test]
fn probes_do_not_redirect_and_bound_chunked_or_slow_responses() {
    crate::tests::runtime().block_on(async {
        let client=client().unwrap();let hits=Arc::new(AtomicUsize::new(0));let counted=hits.clone();
        let target=server(Router::new().route("/v3/info",get(move||{counted.fetch_add(1,Ordering::SeqCst);async{Json(info(3))}}))).await;
        let location=format!("http://{}/v3/info",target.address);
        let redirect=server(Router::new().route("/v3/info",get(move||{let location=location.clone();async{(StatusCode::FOUND,[(header::LOCATION,location)])}}))).await;
        assert!(probe(&client,redirect.address).await.is_none());assert_eq!(hits.load(Ordering::SeqCst),0);
        let mut huge=b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2001\r\n".to_vec();
        huge.extend(vec![b' ';8193]);huge.extend_from_slice(b"\r\n0\r\n\r\n");
        let oversized=raw_server(huge,Duration::from_secs(2)).await;assert!(probe(&client,oversized.address).await.is_none());
        let slow=raw_server(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n{\"protocol\":3,".to_vec(),Duration::from_secs(3)).await;
        let started=Instant::now();assert!(probe(&client,slow.address).await.is_none());assert!(started.elapsed()<Duration::from_millis(1800));
    });
}

#[test]
fn actual_scan_counts_results_without_modifying_or_merging_passwords() {
    let (dir, vault, service) = crate::tests::fixture("scanner");
    let before = std::fs::read(dir.path().join("vault.json")).unwrap();
    crate::tests::runtime().block_on(async {
        let compatible = info(3);
        let id = compatible["device_id"].as_str().unwrap().to_owned();
        let old = info(2);
        let old_id = old["device_id"].as_str().unwrap().to_owned();
        let valid = server(fixed("/v3/info", compatible.clone()).merge(fixed(
            "/v3/version",
            json!({"protocol":3,"device_id":id,"epoch":compatible["epoch"],"app_version":"0.2.4"}),
        )))
        .await;
        let legacy = server(fixed("/v2/info", old)).await;
        let other = server(fixed("/v3/info", json!({"ok":true}))).await;
        let generation = prepare(&service);
        scan_plan(
            service.inner.clone(),
            generation,
            test_plan(vec![valid.address, legacy.address, other.address]),
        )
        .await;
        let status = service.status();
        assert_eq!(status.scan_state, "completed");
        assert_eq!(status.scan_checked, 3);
        assert_eq!(status.scan_total, 3);
        assert_eq!(status.discovered.len(), 1);
        assert_eq!(status.discovered[0].id, id);
        assert_eq!(status.discovered[0].app_version.as_deref(), Some("0.2.4"));
        assert_eq!(status.incompatible_discovered.len(), 1);
        assert_eq!(status.incompatible_discovered[0].id, old_id);
        assert!(service.request_merge(&old_id).is_err());
        assert!(service.status().merges.is_empty());
        // A later mDNS observation preserves verified display information.
        service.discovered_peer(&id, valid.address);
        let status = service.status();
        assert_eq!(status.discovered[0].name, "LAN test peer");
        assert_eq!(status.discovered[0].app_version.as_deref(), Some("0.2.4"));
        // Previously compatible peers downgrade only to the diagnostic list.
        let old_same_id =
            json!({"protocol":2,"device_id":id,"epoch":random_id(),"name":"Old installation"});
        let downgraded = server(fixed("/v2/info", old_same_id)).await;
        scan_plan(
            service.inner.clone(),
            prepare(&service),
            test_plan(vec![downgraded.address]),
        )
        .await;
        assert!(!service.status().discovered.iter().any(|p| p.id == id));
        assert!(service.request_merge(&id).is_err());
        service.discovered_peer(&id, downgraded.address);
        assert!(!service.status().discovered.iter().any(|peer| peer.id == id));
        assert!(service
            .status()
            .incompatible_discovered
            .iter()
            .any(|peer| peer.id == id));
        scan_plan(
            service.inner.clone(),
            prepare(&service),
            test_plan(vec![valid.address]),
        )
        .await;
        assert!(!service
            .status()
            .incompatible_discovered
            .iter()
            .any(|p| p.id == id));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let running = active.clone();
        let highest = peak.clone();
        let record = info(3);
        let bounded = server(Router::new().route(
            "/v3/info",
            get(move || {
                let active = running.clone();
                let peak = highest.clone();
                let record = record.clone();
                async move {
                    let n = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(n, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Json(record)
                }
            }),
        ))
        .await;
        scan_plan(
            service.inner.clone(),
            prepare(&service),
            test_plan(vec![bounded.address; 70]),
        )
        .await;
        let status = service.status();
        assert_eq!(status.scan_checked, 70);
        assert_eq!(status.scan_total, 70);
        assert!(peak.load(Ordering::SeqCst) > 1);
        assert!(peak.load(Ordering::SeqCst) <= CONCURRENCY);
    });
    assert!(vault.lock().unwrap().list(None).unwrap().is_empty());
    assert_eq!(
        std::fs::read(dir.path().join("vault.json")).unwrap(),
        before
    );
}

#[test]
fn paused_or_replaced_scans_cannot_publish_late_peers_or_counts() {
    let (_dir, _vault, service) = crate::tests::fixture("scanner cancellation");
    crate::tests::runtime().block_on(async {
        let entered = Arc::new(AtomicUsize::new(0));
        let observed = entered.clone();
        let slow = server(Router::new().route(
            "/v3/info",
            get(move || {
                observed.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    Json(info(3))
                }
            }),
        ))
        .await;
        let generation = prepare(&service);
        let state = service.inner.clone();
        let address = slow.address;
        let task =
            tokio::spawn(
                async move { scan_plan(state, generation, test_plan(vec![address])).await },
            );
        while entered.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        service.pause();
        task.await.unwrap();
        let status = service.status();
        assert_eq!(status.scan_state, "cancelled");
        assert!(status.discovered.is_empty());
        assert_eq!(status.scan_checked, 0);
        service.resume();
        let generation = prepare(&service);
        let state = service.inner.clone();
        let task =
            tokio::spawn(
                async move { scan_plan(state, generation, test_plan(vec![address])).await },
            );
        while entered.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let replacement = prepare(&service);
        task.await.unwrap();
        let status = service.status();
        assert_eq!(status.discovery_generation, replacement);
        assert_eq!(status.scan_checked, 0);
        assert_eq!(status.scan_state, "planning");
        assert!(status.discovered.is_empty());
        scan_plan(service.inner.clone(), replacement, test_plan(vec![])).await;
        let status = service.status();
        assert_eq!(status.scan_state, "completed");
        assert_eq!(status.scan_total, 0);
        assert!(status.scan_error.is_some());
    });
}
