use super::*;
use std::{io::Write, net::TcpStream, time::Instant};
const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
const PASSWORD: &str = "test vault passphrase 123";
fn fixture(name: &str) -> (tempfile::TempDir, Arc<Mutex<Vault>>, Service) {
    let dir = tempfile::tempdir().unwrap();
    let mut vault = Vault::open(dir.path().into()).unwrap();
    vault.create(PASSWORD, name).unwrap();
    let vault = Arc::new(Mutex::new(vault));
    let service = Service::start(
        vault.clone(),
        ServiceConfig {
            local_port: 0,
            lan_port: 0,
            enable_discovery: false,
            sync_interval_secs: 3600,
        },
    )
    .unwrap();
    (dir, vault, service)
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .no_proxy()
        .build()
        .unwrap()
}
fn entry(host: &str, password: &str) -> EntryInput {
    EntryInput {
        id: None,
        hostname: host.into(),
        title: "Example".into(),
        username: "alice".into(),
        password: password.into(),
        notes: String::new(),
    }
}
fn eventually(check: impl Fn() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "condition timed out"
        );
        thread::sleep(Duration::from_millis(40));
    }
}

#[test]
fn browser_bridge_requires_exact_origin_token_host_and_unlocked_vault() {
    let (_dir, vault, service) = fixture("desktop");
    let grant = vault
        .lock()
        .unwrap()
        .create_client("Browser", ORIGIN)
        .unwrap();
    let rt = runtime();
    rt.block_on(async {
        let c = client();
        let base = service.status().local_endpoint;
        let search = format!("{base}/v1/credentials?hostname=example.com");
        let r = c.get(&search).send().await.unwrap();
        assert_eq!(r.status(), 403);
        let r = c
            .get(&search)
            .header("Origin", "https://evil.example")
            .bearer_auth(&grant.token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        assert!(!r.headers().contains_key("access-control-allow-origin"));
        let r = c
            .get(&search)
            .header("Origin", ORIGIN)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
        let r = c
            .get(&search)
            .header("Origin", ORIGIN)
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
        let r = c
            .get(&search)
            .header("Origin", ORIGIN)
            .header("Host", "evil.example")
            .bearer_auth(&grant.token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        let r = c
            .request(reqwest::Method::OPTIONS, &search)
            .header("Origin", ORIGIN)
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Headers", "Authorization")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204);
        assert_eq!(r.headers()["access-control-allow-origin"], ORIGIN);
        let r = c
            .post(format!("{base}/v1/browser/connect"))
            .header("Origin", ORIGIN)
            .bearer_auth(&grant.token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let r = c
            .post(format!("{base}/v1/credentials"))
            .header("Origin", ORIGIN)
            .bearer_auth(&grant.token)
            .json(&entry("example.com", "private-value"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["cache-control"], "no-store");
        let r = c
            .get(&search)
            .header("Origin", ORIGIN)
            .bearer_auth(&grant.token)
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["entries"][0]["password"], "private-value");
        let r = c
            .post(format!("{base}/v1/credentials/search"))
            .header("Origin", ORIGIN)
            .bearer_auth(&grant.token)
            .json(&serde_json::json!({"hostname":"sub.example.com"}))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["entries"].as_array().unwrap().len(), 0);
        vault
            .lock()
            .unwrap()
            .revoke_client(&grant.client.id)
            .unwrap();
        let r = c
            .get(&search)
            .header("Origin", ORIGIN)
            .bearer_auth(&grant.token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        vault.lock().unwrap().lock();
        let r = c
            .get(&search)
            .header("Origin", ORIGIN)
            .bearer_auth(&grant.token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 423);
    });
}

#[test]
fn paired_devices_sync_newest_password_and_tombstones_over_real_http() {
    let (_ad, a, sa) = fixture("Desktop A");
    let (_bd, b, sb) = fixture("Phone B");
    let original = a
        .lock()
        .unwrap()
        .upsert(entry("example.com", "old-secret"))
        .unwrap();
    let invitation = sa
        .create_invitation(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap();
    let paired = sb.accept_invitation(&invitation.code).unwrap();
    assert_eq!(paired.device_id, a.lock().unwrap().status().device_id);
    eventually(|| b.lock().unwrap().get(&original.id).is_ok());
    let mut updated = entry("example.com", "newest-secret");
    updated.id = Some(original.id.clone());
    b.lock().unwrap().upsert(updated).unwrap();
    sb.trigger_sync();
    eventually(|| a.lock().unwrap().get(&original.id).unwrap().password == "newest-secret");
    assert!(sa.status().last_sync.is_some());
    assert!(sb.status().last_sync.is_some());
    a.lock().unwrap().delete(&original.id).unwrap();
    sa.trigger_sync();
    eventually(|| b.lock().unwrap().list(None).unwrap().is_empty());
    assert!(
        sb.accept_invitation(&invitation.code).is_err(),
        "single-use invitation must not be reused"
    );
}

#[test]
fn lan_rejects_tampering_replay_old_epoch_unpaired_and_locked_requests() {
    let (_ad, a, sa) = fixture("A");
    let (_bd, b, sb) = fixture("B");
    let invite = sa
        .create_invitation(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap();
    sb.accept_invitation(&invite.code).unwrap();
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), sa.status().lan_port);
    let own = b.lock().unwrap().status();
    let peer = b.lock().unwrap().peers().unwrap().pop().unwrap();
    let payload = b.lock().unwrap().export_sync().unwrap();
    let rt = runtime();
    rt.block_on(async {
        let challenge = fetch_challenge(&sb.inner, remote, &peer.device_id)
            .await
            .unwrap();
        let request = seal(
            &peer.shared_key,
            "sync",
            false,
            &own.device_id,
            &peer.device_id,
            &random_id(),
            &challenge.epoch,
            &SyncRequest {
                data: payload,
                endpoint: format!("http://127.0.0.1:{}", sb.status().lan_port),
            },
        )
        .unwrap();
        let c = client();
        let url = format!("{}/v1/sync", endpoint(remote));
        let mut corrupted = request.clone();
        corrupted.ciphertext.push('A');
        let r = c.post(&url).json(&corrupted).send().await.unwrap();
        assert!(!r.status().is_success());
        let r = c
            .post(&url)
            .header("Origin", "https://evil.example")
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        let r = c.post(&url).json(&request).send().await.unwrap();
        assert_eq!(r.status(), 200);
        let envelope: Envelope = r.json().await.unwrap();
        let _: SyncReply = open(&peer.shared_key, "sync", true, &envelope).unwrap();
        let r = c.post(&url).json(&request).send().await.unwrap();
        assert_eq!(r.status(), 409);
        sa.pause();
        sa.resume();
        let r = c.post(&url).json(&request).send().await.unwrap();
        assert_eq!(r.status(), 401, "old service epoch must not be accepted");
        let challenge = fetch_challenge(&sb.inner, remote, &peer.device_id)
            .await
            .unwrap();
        let req = seal(
            &peer.shared_key,
            "sync",
            false,
            &own.device_id,
            &peer.device_id,
            &random_id(),
            &challenge.epoch,
            &SyncRequest {
                data: b.lock().unwrap().export_sync().unwrap(),
                endpoint: format!("http://127.0.0.1:{}", sb.status().lan_port),
            },
        )
        .unwrap();
        a.lock().unwrap().remove_peer(&own.device_id).unwrap();
        let r = c.post(&url).json(&req).send().await.unwrap();
        assert_eq!(r.status(), 401);
        a.lock().unwrap().lock();
        let r = c.post(&url).json(&req).send().await.unwrap();
        assert_eq!(r.status(), 423);
    });
}

#[test]
fn malicious_discovery_cannot_grant_trust_and_shutdown_is_bounded() {
    let (_dir, vault, service) = fixture("A");
    let forged = random_id();
    service.discovered_peer(&forged, "127.0.0.1:19001".parse().unwrap());
    assert!(vault.lock().unwrap().peers().unwrap().is_empty());
    assert_eq!(service.status().discovered.len(), 1);
    service.discovered_peer(&random_id(), "8.8.8.8:19001".parse().unwrap());
    assert_eq!(service.status().discovered.len(), 1);
    let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, service.status().lan_port)).unwrap();
    socket.write_all(b"POST /v1/sync HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999\r\nContent-Type: application/json\r\n\r\n{").unwrap();
    thread::sleep(Duration::from_millis(80));
    let started = Instant::now();
    drop(service);
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
fn stale_worker_peer_is_rejected_before_export_or_any_network_request() {
    let (_dir, vault, service) = fixture("A");
    let id = random_id();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let remote = listener.local_addr().unwrap();
    let peer = Peer {
        device_id: id.clone(),
        name: "B".into(),
        endpoint: endpoint(remote),
        shared_key: random_key(),
    };
    vault.lock().unwrap().add_peer(peer.clone()).unwrap();
    vault.lock().unwrap().remove_peer(&id).unwrap();
    vault
        .lock()
        .unwrap()
        .upsert(entry("example.com", "created-after-revocation"))
        .unwrap();
    let result = runtime().block_on(sync_peer(&service.inner, &peer, remote));
    assert!(matches!(result, Err(Error::Authentication)));
    assert!(matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
}

#[test]
fn immediate_shutdown_before_runtime_subscription_does_not_hang() {
    // A successful send must not depend on whether the service thread has
    // subscribed yet. Repeating immediate shutdown exercises startup ordering.
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Mutex::new(Vault::open(dir.path().into()).unwrap()));
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for _ in 0..10 {
            let service = Service::start(
                vault.clone(),
                ServiceConfig {
                    local_port: 0,
                    lan_port: 0,
                    enable_discovery: false,
                    sync_interval_secs: 3600,
                },
            )
            .unwrap();
            drop(service);
        }
        done_tx.send(()).unwrap();
    });
    done_rx
        .recv_timeout(Duration::from_secs(6))
        .expect("immediate shutdown must be bounded");
}

#[test]
fn full_vault_merge_reports_capacity_without_partial_writes() {
    let (_ad, a, sa) = fixture("A");
    let (_bd, b, sb) = fixture("B");
    for i in 0..18 {
        let mut left = entry(&format!("a-{i}.example"), "left");
        left.notes = "x".repeat(32 * 1024);
        a.lock().unwrap().upsert(left).unwrap();
        let mut right = entry(&format!("b-{i}.example"), "right");
        right.notes = "y".repeat(32 * 1024);
        b.lock().unwrap().upsert(right).unwrap();
    }
    let invite = sa
        .create_invitation(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap();
    sb.accept_invitation(&invite.code).unwrap();
    let peer = b.lock().unwrap().peers().unwrap().pop().unwrap();
    let result = runtime().block_on(sync_peer(
        &sb.inner,
        &peer,
        parse_endpoint(&peer.endpoint).unwrap(),
    ));
    assert!(matches!(result, Err(Error::TooLarge)));
    assert_eq!(a.lock().unwrap().list(None).unwrap().len(), 18);
    assert_eq!(b.lock().unwrap().list(None).unwrap().len(), 18);
}
