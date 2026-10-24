use super::*;
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Instant,
};
const PASSWORD: &str = "test vault passphrase 123";
pub(super) fn fixture(name: &str) -> (tempfile::TempDir, Arc<Mutex<Vault>>, Service) {
    fixture_interval(name, 300)
}
fn fixture_interval(name: &str, interval: u64) -> (tempfile::TempDir, Arc<Mutex<Vault>>, Service) {
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
            enable_lan_scan: false,
            discovery_interval_secs: interval,
        },
    )
    .unwrap();
    (dir, vault, service)
}
pub(super) fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
pub(super) fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .no_proxy()
        .build()
        .unwrap()
}
pub(super) fn entry(host: &str, password: &str) -> EntryInput {
    EntryInput {
        id: None,
        hostname: host.into(),
        title: "Example".into(),
        username: "alice".into(),
        password: password.into(),
        notes: String::new(),
    }
}
pub(super) fn eventually(check: impl Fn() -> bool) {
    let start = Instant::now();
    while !check() {
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "condition timed out"
        );
        thread::sleep(Duration::from_millis(35));
    }
}
pub(super) fn discover(a: &Arc<Mutex<Vault>>, sa: &Service, b: &Arc<Mutex<Vault>>, sb: &Service) {
    sa.discovered_peer(
        &b.lock().unwrap().status().device_id,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), sb.status().lan_port),
    );
    sb.discovered_peer(
        &a.lock().unwrap().status().device_id,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), sa.status().lan_port),
    );
}
pub(super) fn session(service: &Service, id: &str) -> MergeSession {
    service
        .status()
        .merges
        .into_iter()
        .find(|s| s.id == id)
        .unwrap()
}
pub(super) fn begin(sa: &Service, b: &Arc<Mutex<Vault>>, sb: &Service) -> String {
    let first = sa
        .request_merge(&b.lock().unwrap().status().device_id)
        .unwrap();
    let id = first.id;
    eventually(|| {
        sa.status()
            .merges
            .iter()
            .any(|s| s.id == id && s.state == "awaiting_confirmation")
            && sb
                .status()
                .merges
                .iter()
                .any(|s| s.id == id && s.state == "awaiting_confirmation")
    });
    assert_eq!(
        session(sa, &id).verification_code,
        session(sb, &id).verification_code
    );
    assert_eq!(session(sa, &id).verification_code.len(), 6);
    id
}
pub(super) fn complete(sa: &Service, sb: &Service, id: &str) {
    sa.respond_merge(id, true).unwrap();
    sb.respond_merge(id, true).unwrap();
    eventually(|| session(sa, id).state == "completed" && session(sb, id).state == "completed");
}

#[test]
fn official_extension_needs_no_token_and_other_origins_remain_blocked() {
    let (_dir, vault, service) = fixture("Desktop");
    let rt = runtime();
    let origin = include_str!("browser-origin.txt").trim();
    assert!(vault.lock().unwrap().clients().unwrap().is_empty());
    rt.block_on(async {
        let c = client();
        let base = service.status().local_endpoint;
        let search = format!("{base}/v1/credentials/search");
        let query = serde_json::json!({"hostname":"example.com"});
        let r = c
            .post(format!("{base}/v1/browser/connect"))
            .header("Origin", origin)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["protocol"], 2);
        let r = c
            .post(format!("{base}/v1/credentials"))
            .header("Origin", origin)
            .json(&entry("example.com", "private-value"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let r = c
            .post(&search)
            .header("Origin", origin)
            .json(&query)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["cache-control"], "no-store");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["entries"][0]["password"], "private-value");
        let r = c
            .post(&search)
            .header("Origin", origin)
            .json(&serde_json::json!({"hostname":"sub.example.com"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["entries"].as_array().unwrap().len(), 1);
        assert_eq!(body["entries"][0]["hostname"], "example.com");
        assert_eq!(body["entries"][0]["password"], "private-value");
        for other in [
            None,
            Some("https://evil.example"),
            Some("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ] {
            let mut req = c.post(&search).json(&query);
            if let Some(origin) = other {
                req = req.header("Origin", origin)
            }
            let r = req.send().await.unwrap();
            assert_eq!(r.status(), 403);
            assert!(!r.text().await.unwrap().contains("private-value"));
        }
        let r = c
            .post(&search)
            .header("Origin", origin)
            .header("Host", "evil.example")
            .json(&query)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        let r = c
            .request(reqwest::Method::OPTIONS, &search)
            .header("Origin", origin)
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "Content-Type")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204);
        let r = c
            .post(&search)
            .header("Origin", origin)
            .header("Content-Type", "text/plain")
            .body(query.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
        vault.lock().unwrap().lock();
        let r = c
            .post(&search)
            .header("Origin", origin)
            .json(&query)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 423);
    });
}

#[test]
fn lan_pause_keeps_browser_access_but_full_pause_and_locked_vault_block_it() {
    let (_ad, a, sa) = fixture("Browser bridge");
    let (_bd, b, sb) = fixture("LAN peer");
    a.lock()
        .unwrap()
        .upsert(entry("example.com", "saved-before-lock"))
        .unwrap();
    discover(&a, &sa, &b, &sb);
    let merge_id = begin(&sa, &b, &sb);
    let peer_id = b.lock().unwrap().status().device_id;
    sa.pause_lan();
    assert!(sa.browser_available());
    assert!(!sa.status().running);
    assert!(sa.status().merges.is_empty());
    assert!(sa.status().discovered.is_empty());
    assert!(matches!(sa.detect_devices(), Err(Error::Locked)));
    assert!(matches!(sa.request_merge(&peer_id), Err(Error::Locked)));
    assert!(sa.respond_merge(&merge_id, true).is_err());
    sa.discovered_peer(
        &peer_id,
        format!("127.0.0.1:{}", sb.status().lan_port)
            .parse()
            .unwrap(),
    );
    assert!(sa.status().discovered.is_empty());

    runtime().block_on(async {
        let c = client();
        let origin = include_str!("browser-origin.txt").trim();
        let base = sa.status().local_endpoint;
        let search = format!("{base}/v1/credentials/search");
        let query = serde_json::json!({"hostname":"example.com"});
        let status: serde_json::Value = c
            .get(format!("{base}/v1/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status["locked"], false);
        let response = c
            .post(format!("{base}/v1/browser/connect"))
            .header("Origin", origin)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let response = c
            .post(&search)
            .header("Origin", origin)
            .json(&query)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let data: serde_json::Value = response.json().await.unwrap();
        assert_eq!(data["entries"][0]["password"], "saved-before-lock");
        let response = c
            .post(format!("{base}/v1/credentials"))
            .header("Origin", origin)
            .json(&entry("new.example", "saved-while-ui-locked"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        for other in [
            None,
            Some("https://evil.example"),
            Some("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ] {
            let mut request = c.post(&search).json(&query);
            if let Some(origin) = other {
                request = request.header("Origin", origin);
            }
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), 403);
            assert!(!response.text().await.unwrap().contains("saved-before-lock"));
        }
        let response = c
            .post(&search)
            .header("Origin", origin)
            .header("Host", "evil.example")
            .json(&query)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let response = c
            .post(format!("{base}/v1/credentials"))
            .header("Origin", origin)
            .header("Content-Type", "application/json")
            .body("x".repeat(MAX_BODY + 1))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 413);
        let lan = format!("http://127.0.0.1:{}", sa.status().lan_port);
        for route in ["/v3/info", "/v3/version"] {
            assert_eq!(
                c.get(format!("{lan}{route}"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                423
            );
        }
        assert_eq!(
            c.post(format!("{lan}/v3/merge/request"))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap()
                .status(),
            423
        );

        sa.pause();
        assert!(!sa.browser_available());
        sa.pause_lan();
        assert!(
            !sa.browser_available(),
            "LAN pause must not reactivate a fully paused bridge"
        );
        let status: serde_json::Value = c
            .get(format!("{base}/v1/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status["locked"], true);
        for route in [
            "/v1/browser/connect",
            "/v1/credentials",
            "/v1/credentials/search",
        ] {
            assert_eq!(
                c.post(format!("{base}{route}"))
                    .header("Origin", origin)
                    .json(&query)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                423
            );
        }
        sa.resume();
        assert!(sa.browser_available());
        assert_eq!(
            c.post(&search)
                .header("Origin", origin)
                .json(&query)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(
            c.get(format!("{lan}/v3/info"))
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
        a.lock().unwrap().lock();
        assert!(!sa.browser_available());
        assert_eq!(
            c.post(&search)
                .header("Origin", origin)
                .json(&query)
                .send()
                .await
                .unwrap()
                .status(),
            423
        );
        let status: serde_json::Value = c
            .get(format!("{base}/v1/status"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status["locked"], true);
        a.lock().unwrap().unlock(PASSWORD).unwrap();
        assert!(sa.browser_available());
    });
    assert_eq!(a.lock().unwrap().list(None).unwrap().len(), 2);
    assert!(b.lock().unwrap().list(None).unwrap().is_empty());
    sa.inner.shutdown.send_replace(true);
    assert!(!sa.browser_available());
    sa.resume();
    assert!(
        !sa.browser_available(),
        "resume must not revive a stopped service"
    );
}

#[test]
fn full_pause_invalidates_http_waiting_for_vault_even_after_resume() {
    let (dir, vault, service) = fixture("HTTP lifecycle");
    vault
        .lock()
        .unwrap()
        .upsert(entry("example.com", "keep-secret"))
        .unwrap();
    for route in ["/v1/credentials/search", "/v1/credentials"] {
        let before = std::fs::read(dir.path().join("vault.json")).unwrap();
        let guard = vault.lock().unwrap();
        let url = format!("{}{route}", service.status().local_endpoint);
        let pending = thread::spawn(move || {
            runtime().block_on(async {
                let body = if route.ends_with("search") {
                    serde_json::json!({"hostname":"example.com"})
                } else {
                    serde_json::to_value(entry("never.example", "must-not-save")).unwrap()
                };
                let response = client()
                    .post(url)
                    .header("Origin", include_str!("browser-origin.txt").trim())
                    .json(&body)
                    .send()
                    .await
                    .unwrap();
                (response.status(), response.text().await.unwrap())
            })
        });
        // Observe the actual HTTP middleware blocked on the vault, without timing
        // guesses or a real network scan.
        eventually(|| service.inner.browser_waiters.load(Ordering::Acquire) > 0);
        service.pause();
        service.resume();
        drop(guard);
        let (status, body) = pending.join().unwrap();
        assert_eq!(status, 423);
        assert!(!body.contains("keep-secret"));
        assert_eq!(
            std::fs::read(dir.path().join("vault.json")).unwrap(),
            before
        );
    }
    assert!(service.browser_available());
}

#[test]
fn full_pause_invalidates_http_waiting_for_body_while_lan_pause_preserves_it() {
    let (dir, vault, service) = fixture("Slow browser request");
    for full_pause in [false, true] {
        service.resume();
        let before = std::fs::read(dir.path().join("vault.json")).unwrap();
        let body = serde_json::to_string(&entry(
            if full_pause {
                "blocked.example"
            } else {
                "allowed.example"
            },
            "browser-save",
        ))
        .unwrap();
        let mut socket =
            TcpStream::connect((Ipv4Addr::LOCALHOST, service.inner.local_port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        socket.write_all(format!("POST /v1/credentials HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", service.inner.local_port, include_str!("browser-origin.txt").trim(), body.len()).as_bytes()).unwrap();
        eventually(|| service.inner.capacity.available_permits() < 8);
        if full_pause {
            service.pause();
            service.resume();
        } else {
            service.pause_lan();
        }
        socket.write_all(body.as_bytes()).unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
        if full_pause {
            assert!(response.starts_with("HTTP/1.1 423"), "{response}");
            assert_eq!(
                std::fs::read(dir.path().join("vault.json")).unwrap(),
                before
            );
        } else {
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }
    }
    assert_eq!(vault.lock().unwrap().list(None).unwrap().len(), 1);
}

#[test]
fn browser_search_groups_registrable_domains_and_keeps_private_hosts_isolated() {
    let (_dir, vault, service) = fixture("Domain matching");
    let origin = include_str!("browser-origin.txt").trim();
    runtime().block_on(async {
        let c = client();
        let base = service.status().local_endpoint;
        let search = format!("{base}/v1/credentials/search");
        for (hostname, password) in [
            ("example.com", "com-root"),
            ("login.example.com", "com-login"),
            ("unrelated.com", "other-com"),
            ("example.co.uk", "uk-root"),
            ("login.example.co.uk", "uk-login"),
            ("unrelated.co.uk", "other-uk"),
            ("alice.github.io", "alice-root"),
            ("blog.alice.github.io", "alice-blog"),
            ("bob.github.io", "bob-root"),
            ("127.0.0.1", "ipv4-one"),
            ("127.0.0.2", "ipv4-two"),
            ("[::1]", "ipv6-one"),
            ("[::2]", "ipv6-two"),
            ("localhost", "local-root"),
            ("app.localhost", "local-app"),
        ] {
            let r = c
                .post(format!("{base}/v1/credentials"))
                .header("Origin", origin)
                .json(&entry(hostname, password))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200, "could not save {hostname}");
        }

        let cases: &[(&str, &[&str])] = &[
            ("example.com", &["com-root", "com-login"]),
            ("login.example.com", &["com-root", "com-login"]),
            ("shop.example.com", &["com-root", "com-login"]),
            ("unrelated.com", &["other-com"]),
            ("example.co.uk", &["uk-root", "uk-login"]),
            ("shop.example.co.uk", &["uk-root", "uk-login"]),
            ("unrelated.co.uk", &["other-uk"]),
            ("co.uk", &[]),
            ("alice.github.io", &["alice-root", "alice-blog"]),
            ("shop.alice.github.io", &["alice-root", "alice-blog"]),
            ("bob.github.io", &["bob-root"]),
            ("github.io", &[]),
            ("127.0.0.1", &["ipv4-one"]),
            ("127.0.0.2", &["ipv4-two"]),
            ("127.0.0.3", &[]),
            ("[::1]", &["ipv6-one"]),
            ("[::2]", &["ipv6-two"]),
            ("[::3]", &[]),
            ("localhost", &["local-root"]),
            ("app.localhost", &["local-app"]),
            ("other.localhost", &[]),
        ];
        for (hostname, expected) in cases {
            let r = c
                .post(&search)
                .header("Origin", origin)
                .json(&serde_json::json!({"hostname":hostname}))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200, "could not search {hostname}");
            let body: serde_json::Value = r.json().await.unwrap();
            let mut actual: Vec<_> = body["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["password"].as_str().unwrap())
                .collect();
            let mut expected = expected.to_vec();
            actual.sort_unstable();
            expected.sort_unstable();
            assert_eq!(actual, expected, "unexpected matches for {hostname}");
        }

        // Broadening hostname lookup must not broaden browser authorization.
        let query = serde_json::json!({"hostname":"shop.example.com"});
        let r = c
            .post(&search)
            .header("Origin", "https://shop.example.com")
            .json(&query)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        assert!(!r.text().await.unwrap().contains("com-root"));
        vault.lock().unwrap().lock();
        let r = c
            .post(&search)
            .header("Origin", origin)
            .json(&query)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 423);
        assert!(!r.text().await.unwrap().contains("com-root"));
    });
}

#[test]
fn discovery_resume_timer_and_browser_save_never_merge_passwords() {
    assert_eq!(ServiceConfig::default().discovery_interval_secs, 300);
    let (_ad, a, sa) = fixture_interval("A", 1);
    let (_bd, b, sb) = fixture("B");
    discover(&a, &sa, &b, &sb);
    a.lock()
        .unwrap()
        .upsert(entry("example.com", "local-only"))
        .unwrap();
    let initial = sa.status().discovery_generation;
    sa.detect_devices().unwrap();
    sa.resume();
    eventually(|| sa.status().discovery_generation > initial + 2);
    assert!(b.lock().unwrap().list(None).unwrap().is_empty());
    assert!(sa.status().merges.is_empty());
    assert!(sb.status().merges.is_empty());
    let origin = include_str!("browser-origin.txt").trim();
    runtime().block_on(async {
        let r = client()
            .post(format!("{}/v1/credentials", sa.status().local_endpoint))
            .header("Origin", origin)
            .json(&entry("second.example", "also-local"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    });
    thread::sleep(Duration::from_millis(1300));
    assert!(b.lock().unwrap().list(None).unwrap().is_empty());
    runtime().block_on(async {
        for route in ["/v1/pair", "/v1/sync", "/v1/challenge"] {
            let r = client()
                .post(format!("http://127.0.0.1:{}{route}", sa.status().lan_port))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap();
            assert!(!r.status().is_success());
        }
    });
}

#[test]
fn empty_requester_pulls_passwords_without_changing_the_provider() {
    let (_ad, a, sa) = fixture("New device");
    let (bd, b, sb) = fixture("Existing device");
    discover(&a, &sa, &b, &sb);
    let original = b
        .lock()
        .unwrap()
        .upsert(entry("example.com", "old-secret"))
        .unwrap();
    b.lock()
        .unwrap()
        .upsert(entry("second.example", "second-secret"))
        .unwrap();
    let provider_file = std::fs::read(bd.path().join("vault.json")).unwrap();
    let provider_identity = std::fs::read(bd.path().join("identity.json")).unwrap();
    let provider_records = serde_json::to_vec(&b.lock().unwrap().export_sync().unwrap()).unwrap();
    let id = begin(&sa, &b, &sb);
    thread::sleep(Duration::from_millis(300));
    assert!(a.lock().unwrap().list(None).unwrap().is_empty());
    sa.respond_merge(&id, true).unwrap();
    thread::sleep(Duration::from_millis(300));
    assert!(a.lock().unwrap().list(None).unwrap().is_empty());
    sb.respond_merge(&id, true).unwrap();
    eventually(|| session(&sa, &id).state == "completed" && session(&sb, &id).state == "completed");
    assert_eq!(a.lock().unwrap().list(None).unwrap().len(), 2);
    assert_eq!(
        a.lock().unwrap().get(&original.id).unwrap().password,
        "old-secret"
    );
    assert_eq!(
        std::fs::read(bd.path().join("vault.json")).unwrap(),
        provider_file
    );
    assert_eq!(
        std::fs::read(bd.path().join("identity.json")).unwrap(),
        provider_identity
    );
    assert_eq!(
        serde_json::to_vec(&b.lock().unwrap().export_sync().unwrap()).unwrap(),
        provider_records
    );
    assert_eq!(session(&sa, &id).received_count, Some(2));
    assert_eq!(session(&sa, &id).changed_count, Some(2));
    assert_eq!(session(&sb, &id).source_count, Some(2));
    assert_eq!(session(&sb, &id).received_count, None);
    assert_eq!(
        std::fs::read_dir(bd.path()).unwrap().count(),
        3,
        "Provider must not even create a backup or write sidecar."
    );

    let mut input = entry("example.com", "newest-secret");
    input.id = Some(original.id.clone());
    b.lock().unwrap().upsert(input).unwrap();
    sa.detect_devices().unwrap();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        a.lock().unwrap().get(&original.id).unwrap().password,
        "old-secret"
    );
    let second = begin(&sa, &b, &sb);
    complete(&sa, &sb, &second);
    assert_eq!(
        a.lock().unwrap().get(&original.id).unwrap().password,
        "newest-secret"
    );
    b.lock().unwrap().delete(&original.id).unwrap();
    let third = begin(&sa, &b, &sb);
    complete(&sa, &sb, &third);
    assert_eq!(
        a.lock().unwrap().get(&original.id).unwrap().password,
        "newest-secret",
        "Source deletion is never imported."
    );
    assert_eq!(a.lock().unwrap().list(None).unwrap().len(), 2);
    assert_eq!(b.lock().unwrap().list(None).unwrap().len(), 1);
    assert!(sa.respond_merge(&id, true).is_err());
}

#[test]
fn requester_records_and_deletions_never_reach_the_provider() {
    let (_ad, a, sa) = fixture("Requester");
    let (bd, b, sb) = fixture("Provider");
    discover(&a, &sa, &b, &sb);
    let from_provider = b
        .lock()
        .unwrap()
        .upsert(entry("source.example", "source-secret"))
        .unwrap();
    let first = begin(&sa, &b, &sb);
    complete(&sa, &sb, &first);
    a.lock().unwrap().delete(&from_provider.id).unwrap();
    let local = a
        .lock()
        .unwrap()
        .upsert(entry("local.example", "never-send-back"))
        .unwrap();
    let before = std::fs::read(bd.path().join("vault.json")).unwrap();
    let second = begin(&sa, &b, &sb);
    complete(&sa, &sb, &second);
    assert_eq!(
        a.lock().unwrap().get(&local.id).unwrap().password,
        "never-send-back"
    );
    assert_eq!(
        b.lock().unwrap().get(&from_provider.id).unwrap().password,
        "source-secret"
    );
    assert!(b.lock().unwrap().get(&local.id).is_err());
    assert_eq!(std::fs::read(bd.path().join("vault.json")).unwrap(), before);
    let source = b.lock().unwrap().export_sync().unwrap();
    assert!(!source
        .records
        .iter()
        .any(|record| record.deleted || record.id == local.id));
}

#[test]
fn empty_provider_and_failed_local_save_cannot_clear_either_vault_or_report_completion() {
    let (ad, a, sa) = fixture("Requester");
    let (bd, b, sb) = fixture("Provider");
    discover(&a, &sa, &b, &sb);
    let local = a
        .lock()
        .unwrap()
        .upsert(entry("local.example", "keep-local"))
        .unwrap();
    let local_before = std::fs::read(ad.path().join("vault.json")).unwrap();
    let source_before = std::fs::read(bd.path().join("vault.json")).unwrap();
    let empty = begin(&sa, &b, &sb);
    complete(&sa, &sb, &empty);
    assert_eq!(session(&sa, &empty).received_count, Some(0));
    assert_eq!(session(&sa, &empty).changed_count, Some(0));
    assert_eq!(
        std::fs::read(ad.path().join("vault.json")).unwrap(),
        local_before
    );
    assert_eq!(
        std::fs::read(bd.path().join("vault.json")).unwrap(),
        source_before
    );
    b.lock()
        .unwrap()
        .upsert(entry("source.example", "keep-source"))
        .unwrap();
    let source_before = std::fs::read(bd.path().join("vault.json")).unwrap();
    std::fs::rename(
        ad.path().join("vault.json"),
        ad.path().join("saved-vault.json"),
    )
    .unwrap();
    std::fs::create_dir(ad.path().join("vault.json")).unwrap();
    let failed = begin(&sa, &b, &sb);
    sa.respond_merge(&failed, true).unwrap();
    sb.respond_merge(&failed, true).unwrap();
    eventually(|| session(&sa, &failed).state == "failed");
    assert_ne!(session(&sb, &failed).state, "completed");
    assert_eq!(
        a.lock().unwrap().get(&local.id).unwrap().password,
        "keep-local"
    );
    assert_eq!(a.lock().unwrap().list(None).unwrap().len(), 1);
    assert_eq!(
        std::fs::read(bd.path().join("vault.json")).unwrap(),
        source_before
    );
    assert_eq!(
        std::fs::read(ad.path().join("saved-vault.json")).unwrap(),
        local_before
    );
}

#[test]
fn legacy_bidirectional_routes_and_protocols_are_rejected() {
    let (dir, vault, service) = fixture("V3 provider");
    let before = std::fs::read(dir.path().join("vault.json")).unwrap();
    runtime().block_on(async {
        let c = client();
        let base = format!("http://127.0.0.1:{}", service.status().lan_port);
        for path in ["/v2/info", "/v2/merge/request", "/v2/merge/example/exchange"] {
            let response = c.post(format!("{base}{path}")).json(&serde_json::json!({})).send().await.unwrap();
            assert!(!response.status().is_success());
        }
        let info: serde_json::Value = c.get(format!("{base}/v3/info")).send().await.unwrap().json().await.unwrap();
        assert_eq!(info["protocol"], 3);
        let response = c.post(format!("{base}/v3/merge/request")).json(&serde_json::json!({
            "protocol": 2, "id":random_id(), "from":random_id(), "to":vault.lock().unwrap().status().device_id,
            "name":"Old client", "endpoint":"http://127.0.0.1:17842", "from_epoch":random_id(),
            "to_epoch":info["epoch"], "commitment":encode(random_key())
        })).send().await.unwrap();
        assert_eq!(response.status(), 400);
    });
    assert!(service.status().merges.is_empty());
    assert_eq!(
        std::fs::read(dir.path().join("vault.json")).unwrap(),
        before
    );
}

#[test]
fn rejecting_or_locking_cannot_export_or_complete_a_session() {
    let (_ad, a, sa) = fixture("A");
    let (_bd, b, sb) = fixture("B");
    discover(&a, &sa, &b, &sb);
    a.lock()
        .unwrap()
        .upsert(entry("example.com", "private-value"))
        .unwrap();
    let id = begin(&sa, &b, &sb);
    sb.respond_merge(&id, false).unwrap();
    eventually(|| session(&sa, &id).state == "rejected");
    assert!(b.lock().unwrap().list(None).unwrap().is_empty());
    let id = begin(&sa, &b, &sb);
    sa.respond_merge(&id, false).unwrap();
    eventually(|| session(&sb, &id).state == "rejected");
    assert!(b.lock().unwrap().list(None).unwrap().is_empty());
    let id = begin(&sa, &b, &sb);
    sa.pause();
    a.lock().unwrap().lock();
    assert!(sa.respond_merge(&id, true).is_err());
    assert!(sa.status().merges.is_empty());
    assert!(b.lock().unwrap().list(None).unwrap().is_empty());
}

#[test]
fn unknown_devices_and_oversized_union_do_not_merge() {
    let (_ad, a, sa) = fixture("A");
    let (_bd, b, sb) = fixture("B");
    assert!(sa
        .request_merge(&b.lock().unwrap().status().device_id)
        .is_err());
    discover(&a, &sa, &b, &sb);
    for i in 0..18 {
        let mut x = entry(&format!("a-{i}.example"), "left");
        x.notes = "x".repeat(32 * 1024);
        a.lock().unwrap().upsert(x).unwrap();
        let mut y = entry(&format!("b-{i}.example"), "right");
        y.notes = "y".repeat(32 * 1024);
        b.lock().unwrap().upsert(y).unwrap();
    }
    let id = begin(&sa, &b, &sb);
    sa.respond_merge(&id, true).unwrap();
    sb.respond_merge(&id, true).unwrap();
    eventually(|| session(&sa, &id).state == "failed");
    assert_eq!(a.lock().unwrap().list(None).unwrap().len(), 18);
    assert_eq!(b.lock().unwrap().list(None).unwrap().len(), 18);
    assert_ne!(session(&sb, &id).state, "completed");
}

#[test]
fn discovery_does_not_grant_access_and_shutdown_remains_bounded() {
    let (_dir, vault, service) = fixture("A");
    service.discovered_peer(&random_id(), "127.0.0.1:19001".parse().unwrap());
    assert!(vault.lock().unwrap().peers().unwrap().is_empty());
    assert_eq!(service.status().discovered.len(), 1);
    service.discovered_peer(&random_id(), "8.8.8.8:19001".parse().unwrap());
    assert_eq!(service.status().discovered.len(), 1);
    let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, service.status().lan_port)).unwrap();
    socket.write_all(b"POST /v3/merge/request HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999\r\nContent-Type: application/json\r\n\r\n{").unwrap();
    thread::sleep(Duration::from_millis(60));
    let time = Instant::now();
    drop(service);
    assert!(time.elapsed() < Duration::from_secs(4));
}
#[test]
fn immediate_shutdown_before_runtime_subscription_does_not_hang() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Mutex::new(Vault::open(dir.path().into()).unwrap()));
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for _ in 0..10 {
            drop(
                Service::start(
                    vault.clone(),
                    ServiceConfig {
                        local_port: 0,
                        lan_port: 0,
                        enable_discovery: false,
                        enable_lan_scan: false,
                        discovery_interval_secs: 300,
                    },
                )
                .unwrap(),
            );
        }
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(6)).unwrap();
}
