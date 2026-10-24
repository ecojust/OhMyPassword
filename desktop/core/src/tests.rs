use super::*;
use tempfile::TempDir;

const PASSWORD: &str = "correct horse vault secret";
const ORIGIN: &str = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

fn ready() -> (TempDir, Vault) {
    let dir = TempDir::new().unwrap();
    let mut vault = Vault::open(dir.path().to_path_buf()).unwrap();
    vault.create(PASSWORD, "测试设备").unwrap();
    (dir, vault)
}

fn input(hostname: &str, password: &str) -> EntryInput {
    EntryInput {
        hostname: hostname.to_owned(),
        username: "alice@example.test".to_owned(),
        password: password.to_owned(),
        title: "测试账号".to_owned(),
        id: None,
        notes: String::new(),
    }
}

fn revised(entry: &Entry, password: &str) -> EntryInput {
    EntryInput {
        id: Some(entry.id.clone()),
        hostname: entry.hostname.clone(),
        username: entry.username.clone(),
        password: password.to_owned(),
        title: entry.title.clone(),
        notes: entry.notes.clone(),
    }
}

#[test]
fn password_reverification_preserves_live_records_key_and_ciphertext() {
    let (dir, mut vault) = ready();
    let original = vault
        .upsert(input("verify.example", "first-value"))
        .unwrap();
    let updated = vault
        .upsert(revised(&original, "browser-saved-new-value"))
        .unwrap();
    let before = fs::read(dir.path().join("vault.json")).unwrap();
    let history = vault.export_sync().unwrap().records;

    assert!(vault.verify_password("wrong interface password").is_err());
    assert!(vault.verify_password(&"x".repeat(1025)).is_err());
    assert!(!vault.status().locked);
    assert_eq!(
        vault.get(&updated.id).unwrap().password,
        "browser-saved-new-value"
    );
    vault.verify_password(PASSWORD).unwrap();
    assert!(vault.export_sync().unwrap().records == history);
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);

    // This method cannot turn a complete lock into an interface-only lock.
    vault.lock();
    assert!(vault.verify_password(PASSWORD).is_err());
    assert!(vault.status().locked);
    vault.unlock(PASSWORD).unwrap();
    assert_eq!(
        vault.get(&updated.id).unwrap().password,
        "browser-saved-new-value"
    );
}

#[test]
fn encrypted_roundtrip_random_nonce_and_private_permissions() {
    let (dir, mut vault) = ready();
    let entry = vault
        .upsert(input(
            "https://EXAMPLE.com/login",
            "unique-secret-never-plaintext",
        ))
        .unwrap();
    let bytes = fs::read(dir.path().join("vault.json")).unwrap();
    let disk = String::from_utf8(bytes.clone()).unwrap();
    assert!(!disk.contains("unique-secret"));
    assert!(!disk.contains("alice"));
    assert!(!disk.contains("example.com"));
    let envelope: Envelope = serde_json::from_slice(&bytes).unwrap();
    let identity = vault.status().device_id;
    vault
        .upsert(revised(&entry, "unique-secret-updated"))
        .unwrap();
    let next: Envelope =
        serde_json::from_slice(&fs::read(dir.path().join("vault.json")).unwrap()).unwrap();
    assert_ne!(envelope.nonce, next.nonce);
    assert_eq!(envelope.salt, next.salt);
    drop(vault);
    let mut reopened = Vault::open(dir.path().to_path_buf()).unwrap();
    assert_eq!(reopened.status().device_id, identity);
    assert!(reopened.status().locked);
    reopened.unlock(PASSWORD).unwrap();
    assert_eq!(
        reopened.get(&entry.id).unwrap().password,
        "unique-secret-updated"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(dir.path().join("vault.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[test]
fn wrong_password_tampering_and_unknown_kdf_fields_are_rejected() {
    let (dir, mut vault) = ready();
    vault.upsert(input("example.com", "real-secret")).unwrap();
    assert!(vault.unlock("incorrect password").is_err());
    assert!(vault.status().locked);
    let file = dir.path().join("vault.json");
    let original = fs::read(&file).unwrap();
    let mut envelope: serde_json::Value = serde_json::from_slice(&original).unwrap();
    envelope["memory_kib"] = serde_json::json!(u64::MAX);
    fs::write(&file, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(vault.unlock(PASSWORD).is_err());
    let mut envelope: Envelope = serde_json::from_slice(&original).unwrap();
    let mut ciphertext = URL_SAFE_NO_PAD.decode(&envelope.ciphertext).unwrap();
    ciphertext[0] ^= 1;
    envelope.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
    fs::write(&file, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(vault.unlock(PASSWORD).is_err());
    assert!(vault.status().locked);
    fs::write(&file, &original).unwrap();
    vault.unlock(PASSWORD).unwrap();
    assert_eq!(vault.list(None).unwrap().len(), 1);
}

#[test]
fn locking_rejects_all_secret_access_and_sync() {
    let (_dir, mut vault) = ready();
    let entry = vault.upsert(input("example.com", "locked-secret")).unwrap();
    let grant = vault.create_client("浏览器", ORIGIN).unwrap();
    let exported = vault.export_sync().unwrap();
    let identity = vault.status().device_id;
    vault.lock();
    assert_eq!(vault.status().device_id, identity);
    assert!(vault.get(&entry.id).is_err());
    assert!(vault.get_conflicts(&entry.id).is_err());
    assert!(vault.list(None).is_err());
    assert!(vault.export_sync().is_err());
    assert!(vault.merge_sync(exported).is_err());
    assert!(vault.peers().is_err());
    assert!(vault.authorize_client(&grant.token, ORIGIN).is_err());
    assert!(vault.upsert(input("example.com", "other")).is_err());
}

#[test]
fn hostname_normalization_retains_full_host_and_rejects_ambiguous_inputs() {
    assert_eq!(
        normalize_hostname("https://EXAMPLE.com.:443/path?a=b").unwrap(),
        "example.com"
    );
    assert_eq!(
        normalize_hostname("BÜCHER.example").unwrap(),
        "xn--bcher-kva.example"
    );
    assert_eq!(normalize_hostname("localhost:3000").unwrap(), "localhost");
    assert_eq!(
        normalize_hostname("http://[::1]:3000/login").unwrap(),
        "[::1]"
    );
    for invalid in [
        "",
        "*.example.com",
        "javascript://example.com",
        "https://user:pass@example.com",
        "example.com/path",
        "example..com",
        "example.com\n",
        "example.com.evil/login",
        "-bad.example",
        "exa mple.com",
    ] {
        assert!(
            normalize_hostname(invalid).is_err(),
            "accepted invalid hostname: {invalid}"
        );
    }
    let (_dir, mut vault) = ready();
    vault.upsert(input("example.com", "one")).unwrap();
    vault.upsert(input("login.example.com", "two")).unwrap();
    vault
        .upsert(input("example.com.evil.test", "three"))
        .unwrap();
    assert_eq!(
        vault.list(Some("https://example.com/login")).unwrap().len(),
        2
    );
    assert_eq!(vault.list(Some("example.com.evil.test")).unwrap().len(), 1);
    assert_eq!(vault.list(Some("other.example.com")).unwrap().len(), 2);
    let summaries = serde_json::to_string(&vault.list(None).unwrap()).unwrap();
    assert!(!summaries.contains("\"password\""));
    assert!(!summaries.contains("\"notes\""));
}

#[test]
fn matching_domain_agrees_with_shared_browser_fixtures() {
    #[derive(Deserialize)]
    struct Case {
        hostname: String,
        key: Option<String>,
    }
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../testdata/domain-matches.json")).unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        assert_eq!(
            matching_domain(&case.hostname).ok(),
            case.key,
            "shared hostname: {}",
            case.hostname
        );
    }
}

#[test]
fn matching_domain_respects_icann_private_wildcard_and_exception_rules() {
    for (host, expected) in [
        ("login.account.example.com", "example.com"),
        (
            "https://LOGIN.example.co.uk.:8443/auth?x=1",
            "example.co.uk",
        ),
        ("api.example.com.cn", "example.com.cn"),
        ("alice.github.io", "alice.github.io"),
        ("login.alice.github.io", "alice.github.io"),
        ("bob.github.io", "bob.github.io"),
        ("login.one.appspot.com", "one.appspot.com"),
        ("two.appspot.com", "two.appspot.com"),
        ("a.b.ck", "a.b.ck"),
        ("sub.a.b.ck", "a.b.ck"),
        ("b.ck", "b.ck"),
        ("www.ck", "www.ck"),
        ("login.www.ck", "www.ck"),
        ("foo.city.kawasaki.jp", "city.kawasaki.jp"),
        ("LOGIN.BÜCHER.DE.", "xn--bcher-kva.de"),
        ("www.食狮.公司.cn", "xn--85x722f.xn--55qx5d.cn"),
    ] {
        assert_eq!(matching_domain(host).unwrap(), expected, "host: {host}");
    }
}

#[test]
fn matching_domain_keeps_ip_local_unknown_and_suffix_only_hosts_exact() {
    for (host, expected) in [
        ("localhost", "localhost"),
        ("https://localhost:3000/login", "localhost"),
        ("app.localhost", "app.localhost"),
        ("printer", "printer"),
        ("https://127.0.0.1:8443/path", "127.0.0.1"),
        ("127.0.0.2", "127.0.0.2"),
        ("https://[2001:db8::1]:443/login", "[2001:db8::1]"),
        ("[2001:db8::2]", "[2001:db8::2]"),
        ("account.example.invalid", "account.example.invalid"),
        ("example.invalid", "example.invalid"),
        ("foo.corp", "foo.corp"),
        ("login.foo.corp", "login.foo.corp"),
        ("com", "com"),
        ("co.uk", "co.uk"),
        ("github.io", "github.io"),
        ("appspot.com", "appspot.com"),
        ("公司.cn", "xn--55qx5d.cn"),
    ] {
        assert_eq!(matching_domain(host).unwrap(), expected, "host: {host}");
    }
    for invalid in [
        "",
        "*.example.com",
        "javascript://example.com",
        "https://user:pass@example.com",
        "example.com/path",
        "example..com",
        "example.com\n",
        "-bad.example",
        "exa mple.com",
    ] {
        assert!(matching_domain(invalid).is_err(), "invalid host: {invalid}");
    }
}

#[test]
fn domain_lookup_preserves_stored_hosts_ids_and_keeps_tenants_isolated() {
    let (dir, mut vault) = ready();
    let mut ids = BTreeMap::new();
    for host in [
        "login.example.com",
        "accounts.example.com",
        "example.com.evil.com",
        "alice.github.io",
        "www.alice.github.io",
        "bob.github.io",
        "127.0.0.1",
        "127.0.0.2",
        "localhost",
        "app.localhost",
        "foo.corp",
        "login.foo.corp",
    ] {
        let entry = vault.upsert(input(host, "test-password")).unwrap();
        ids.insert(host.to_owned(), entry.id.clone());
    }
    let before = fs::read(dir.path().join("vault.json")).unwrap();
    assert_eq!(vault.list(None).unwrap().len(), ids.len());
    for (query, expected) in [
        (
            "https://api.example.com/profile",
            vec!["accounts.example.com", "login.example.com"],
        ),
        (
            "example.com",
            vec!["accounts.example.com", "login.example.com"],
        ),
        (
            "assets.alice.github.io",
            vec!["alice.github.io", "www.alice.github.io"],
        ),
        ("bob.github.io", vec!["bob.github.io"]),
        ("github.io", Vec::new()),
        ("com", Vec::new()),
        ("127.0.0.1", vec!["127.0.0.1"]),
        ("localhost", vec!["localhost"]),
        ("app.localhost", vec!["app.localhost"]),
        ("foo.corp", vec!["foo.corp"]),
        ("login.foo.corp", vec!["login.foo.corp"]),
    ] {
        let results = vault.list(Some(query)).unwrap();
        assert_eq!(
            results
                .iter()
                .map(|entry| entry.hostname.as_str())
                .collect::<Vec<_>>(),
            expected,
            "query: {query}"
        );
        for entry in results {
            assert_eq!(&entry.id, ids.get(&entry.hostname).unwrap());
        }
    }
    for (host, id) in &ids {
        let entry = vault.get(id).unwrap();
        assert_eq!(&entry.hostname, host);
        assert_eq!(&entry.id, id);
    }
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
}

#[test]
fn token_is_bound_to_exact_extension_origin_and_revocable() {
    let (dir, mut vault) = ready();
    let grant = vault.create_client("Chrome", ORIGIN).unwrap();
    assert!(vault.authorize_client(&grant.token, ORIGIN).unwrap());
    assert!(!vault.authorize_client("omp_not-a-token", ORIGIN).unwrap());
    assert!(!vault
        .authorize_client(&grant.token, "https://example.com")
        .unwrap());
    assert!(!vault
        .authorize_client(
            &grant.token,
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .unwrap());
    assert!(!vault
        .authorize_client(&grant.token, &format!("{ORIGIN}/"))
        .unwrap());
    for invalid in [
        "*",
        "null",
        "https://example.com",
        "chrome-extension://abc",
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/path",
    ] {
        assert!(vault.create_client("bad", invalid).is_err());
    }
    assert!(
        !String::from_utf8(fs::read(dir.path().join("vault.json")).unwrap())
            .unwrap()
            .contains(&grant.token)
    );
    let token = grant.token.clone();
    let id = grant.client.id.clone();
    vault.lock();
    vault.unlock(PASSWORD).unwrap();
    assert!(vault.authorize_client(&token, ORIGIN).unwrap());
    vault.revoke_client(&id).unwrap();
    assert!(!vault.authorize_client(&token, ORIGIN).unwrap());
    assert!(vault.clients().unwrap().is_empty());
}

#[test]
fn peer_and_browser_secrets_never_leave_in_sync_payload() {
    let (_dir, mut vault) = ready();
    vault
        .upsert(input("example.com", "password-for-peer"))
        .unwrap();
    let peer = Peer {
        device_id: Uuid::new_v4().to_string(),
        name: "Private phone label".to_owned(),
        endpoint: "http://192.168.1.9:17842".to_owned(),
        shared_key: [13; 32],
    };
    vault.add_peer(peer.clone()).unwrap();
    let grant = vault
        .create_client("Private browser label", ORIGIN)
        .unwrap();
    let payload = serde_json::to_string(&vault.export_sync().unwrap()).unwrap();
    assert!(payload.contains("password-for-peer"));
    assert!(!payload.contains("shared_key"));
    assert!(!payload.contains("Private phone"));
    assert!(!payload.contains("Private browser"));
    assert!(!payload.contains(&grant.token));
    assert!(!payload.contains("token_hash"));
    vault.lock();
    vault.unlock(PASSWORD).unwrap();
    assert_eq!(vault.peers().unwrap()[0].shared_key, [13; 32]);
    vault.remove_peer(&peer.device_id).unwrap();
    assert!(vault.peers().unwrap().is_empty());
}

#[test]
fn newest_edit_wins_not_larger_old_counter_and_history_survives() {
    let (_dir, mut vault) = ready();
    let original = vault.upsert(input("example.com", "original")).unwrap();
    let mut older = original.clone();
    older.version.counter = 100_000;
    older.version.device_id = Uuid::new_v4().to_string();
    older.password = "old high-counter password".to_owned();
    let mut newer = original.clone();
    newer.version.modified_at += 10;
    newer.version.counter = 2;
    newer.version.device_id = Uuid::new_v4().to_string();
    newer.password = "newest offline password".to_owned();
    let payload = SyncPayload {
        version: FORMAT,
        records: vec![newer.clone(), older.clone()],
    };
    assert_eq!(vault.merge_sync(payload.clone()).unwrap().changed, 2);
    assert_eq!(
        vault.get(&original.id).unwrap().password,
        "newest offline password"
    );
    assert_eq!(vault.merge_sync(payload).unwrap().changed, 0);
    assert_eq!(
        vault.get(&original.id).unwrap().version.modified_at,
        newer.version.modified_at
    );
    assert_eq!(vault.get_conflicts(&original.id).unwrap().len(), 2);
    let edited = vault
        .upsert(revised(&original, "edited after sync"))
        .unwrap();
    assert!(edited.version.modified_at > newer.version.modified_at);
    assert!(edited.version.counter > older.version.counter);
    assert_eq!(
        vault.get(&original.id).unwrap().password,
        "edited after sync"
    );
}

#[test]
fn reordered_and_duplicate_edits_converge_with_deterministic_ties() {
    let (_dir_a, mut a) = ready();
    let (_dir_b, mut b) = ready();
    let original = a.upsert(input("example.com", "baseline")).unwrap();
    b.merge_sync(a.export_sync().unwrap()).unwrap();
    let mut first = original.clone();
    first.version.modified_at += 20;
    first.version.counter = 42;
    first.version.device_id = "11111111-1111-4111-8111-111111111111".to_owned();
    first.password = "first value".to_owned();
    let mut second = first.clone();
    second.version.device_id = "22222222-2222-4222-8222-222222222222".to_owned();
    second.password = "second value".to_owned();
    a.merge_sync(SyncPayload {
        version: FORMAT,
        records: vec![first.clone(), second.clone()],
    })
    .unwrap();
    b.merge_sync(SyncPayload {
        version: FORMAT,
        records: vec![second, first],
    })
    .unwrap();
    assert_eq!(a.get(&original.id).unwrap().password, "second value");
    assert!(a.get(&original.id).unwrap() == b.get(&original.id).unwrap());
    assert_eq!(
        serde_json::to_vec(&a.export_sync().unwrap()).unwrap(),
        serde_json::to_vec(&b.export_sync().unwrap()).unwrap()
    );
    assert_eq!(a.merge_sync(b.export_sync().unwrap()).unwrap().changed, 0);
}

#[test]
fn deletion_tombstone_blocks_older_offline_payload_and_survives_restart() {
    let (dir, mut vault) = ready();
    let entry = vault.upsert(input("example.com", "old-password")).unwrap();
    let stale = vault.export_sync().unwrap();
    vault.delete(&entry.id).unwrap();
    assert!(vault.get(&entry.id).is_err());
    assert_eq!(vault.merge_sync(stale.clone()).unwrap().changed, 0);
    assert!(vault.list(None).unwrap().is_empty());
    let payload = vault.export_sync().unwrap();
    assert!(payload.records.iter().any(|entry| entry.deleted));
    drop(vault);
    let mut reopened = Vault::open(dir.path().to_path_buf()).unwrap();
    reopened.unlock(PASSWORD).unwrap();
    reopened.merge_sync(stale).unwrap();
    assert!(reopened.list(None).unwrap().is_empty());
}

#[test]
fn malformed_or_future_remote_revisions_reject_whole_batch() {
    let (dir, mut vault) = ready();
    let original = vault.upsert(input("example.com", "baseline")).unwrap();
    let before = fs::read(dir.path().join("vault.json")).unwrap();
    let mut valid = original.clone();
    valid.version.modified_at += 20;
    valid.version.counter += 1;
    valid.password = "valid but not committed".to_owned();
    let mut invalid = valid.clone();
    invalid.version.modified_at = now_ms().unwrap() + MAX_FUTURE_MS + 60_000;
    invalid.version.counter += 1;
    assert!(vault
        .merge_sync(SyncPayload {
            version: FORMAT,
            records: vec![valid, invalid]
        })
        .is_err());
    assert_eq!(vault.get(&original.id).unwrap().password, "baseline");
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
    let mut excessive_counter = original.clone();
    excessive_counter.version.counter += MAX_COUNTER_JUMP + 1;
    excessive_counter.version.modified_at += 1;
    assert!(vault
        .merge_sync(SyncPayload {
            version: FORMAT,
            records: vec![excessive_counter]
        })
        .is_err());
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
    let mut collision = original.clone();
    collision.password = "tampered revision".to_owned();
    assert!(vault
        .merge_sync(SyncPayload {
            version: FORMAT,
            records: vec![collision]
        })
        .is_err());
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
    let mut unknown = serde_json::to_value(vault.export_sync().unwrap()).unwrap();
    unknown["algorithm"] = serde_json::json!("accept-anything");
    assert!(serde_json::from_value::<SyncPayload>(unknown).is_err());
}

#[test]
fn failed_persistence_retains_previous_memory_and_disk() {
    let (dir, mut vault) = ready();
    let entry = vault
        .upsert(input("example.com", "persisted-value"))
        .unwrap();
    let before = fs::read(dir.path().join("vault.json")).unwrap();
    let temp = dir.path().join(".vault.json.new");
    fs::create_dir(&temp).unwrap();
    assert!(vault
        .upsert(revised(&entry, "must-not-be-visible"))
        .is_err());
    assert!(vault.delete(&entry.id).is_err());
    assert_eq!(vault.get(&entry.id).unwrap().password, "persisted-value");
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
    fs::remove_dir(&temp).unwrap();
    vault
        .upsert(revised(&entry, "success-after-retry"))
        .unwrap();
    assert_eq!(
        vault.get(&entry.id).unwrap().password,
        "success-after-retry"
    );
}

#[test]
fn sync_capacity_is_enforced_before_a_successful_write() {
    let (dir, mut vault) = ready();
    let first = vault.upsert(input("example.com", "secret")).unwrap();
    let mut records = Vec::new();
    for index in 0..40 {
        let mut entry = first.clone();
        entry.id = Uuid::new_v4().to_string();
        entry.version.counter += index;
        entry.notes = "x".repeat(32 * 1024);
        records.push(entry);
    }
    let before = fs::read(dir.path().join("vault.json")).unwrap();
    let result = vault.merge_sync(SyncPayload {
        version: FORMAT,
        records,
    });
    let error = result.unwrap_err();
    assert!(error.is_capacity_limit());
    assert!(error.to_string().contains("1 MiB"));
    assert!(!super::error("其他错误").is_capacity_limit());
    assert_eq!(vault.list(None).unwrap().len(), 1);
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
}

#[test]
fn process_lock_prevents_two_writers_and_releases_on_drop() {
    let dir = TempDir::new().unwrap();
    let first = Vault::open(dir.path().to_path_buf()).unwrap();
    assert!(Vault::open(dir.path().to_path_buf()).is_err());
    let identity = first.status().device_id;
    drop(first);
    let second = Vault::open(dir.path().to_path_buf()).unwrap();
    assert_eq!(second.status().device_id, identity);
}

#[test]
fn weak_password_and_oversized_fields_do_not_change_vault() {
    let dir = TempDir::new().unwrap();
    let mut vault = Vault::open(dir.path().to_path_buf()).unwrap();
    assert!(vault.create("short", "测试").is_err());
    assert!(!vault.status().initialized);
    vault.create(PASSWORD, "测试").unwrap();
    let before = fs::read(dir.path().join("vault.json")).unwrap();
    assert!(vault.upsert(input("example.com", "")).is_err());
    assert!(vault
        .upsert(input("example.com", &"x".repeat(16 * 1024 + 1)))
        .is_err());
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
    assert!(vault.list(None).unwrap().is_empty());
}

#[test]
fn merge_write_lease_blocks_record_mutations_but_keeps_reads_available() {
    let (dir, mut vault) = ready();
    let entry = vault.upsert(input("example.com", "before-ack")).unwrap();
    let mut incoming = entry.clone();
    incoming.version.counter += 1;
    incoming.version.modified_at += 10;
    incoming.password = "remote-update-during-ack".to_owned();
    let payload = SyncPayload {
        version: FORMAT,
        records: vec![incoming],
    };
    let disk_before = fs::read(dir.path().join("vault.json")).unwrap();
    let snapshot_before = serde_json::to_vec(&vault.export_sync().unwrap()).unwrap();

    vault.begin_merge_write("merge-flight-1").unwrap();
    vault.begin_merge_write("merge-flight-1").unwrap();
    assert!(vault.begin_merge_write("merge-flight-2").is_err());
    assert!(vault.end_merge_write("merge-flight-2").is_err());
    assert!(vault
        .upsert(revised(&entry, "local-update-during-ack"))
        .is_err());
    assert!(vault.delete(&entry.id).is_err());
    assert!(vault.merge_sync(payload.clone()).is_err());
    assert_eq!(vault.get(&entry.id).unwrap().password, "before-ack");
    assert_eq!(vault.list(Some("example.com")).unwrap().len(), 1);
    assert_eq!(
        serde_json::to_vec(&vault.export_sync().unwrap()).unwrap(),
        snapshot_before
    );
    assert_eq!(
        fs::read(dir.path().join("vault.json")).unwrap(),
        disk_before
    );

    vault.end_merge_write("merge-flight-1").unwrap();
    vault.end_merge_write("merge-flight-1").unwrap();
    assert_eq!(vault.merge_sync(payload).unwrap().changed, 1);
    assert_eq!(
        vault.get(&entry.id).unwrap().password,
        "remote-update-during-ack"
    );
    vault
        .upsert(revised(&entry, "local-update-after-ack"))
        .unwrap();
    assert_eq!(
        vault.get(&entry.id).unwrap().password,
        "local-update-after-ack"
    );
    vault.delete(&entry.id).unwrap();
    assert!(vault.get(&entry.id).is_err());
}

#[test]
fn merge_write_lease_validates_ids_and_lock_clears_the_previous_session() {
    let (_dir, mut vault) = ready();
    let entry = vault.upsert(input("example.com", "before-lock")).unwrap();
    vault.begin_merge_write("previous-session").unwrap();
    for invalid in [
        "",
        " ",
        " padded",
        "padded ",
        "line\nbreak",
        &"x".repeat(129),
    ] {
        assert!(vault.begin_merge_write(invalid).is_err());
        assert!(vault.end_merge_write(invalid).is_err());
    }
    assert!(vault.delete(&entry.id).is_err());
    vault.lock();
    assert!(vault.begin_merge_write("while-locked").is_err());
    vault.end_merge_write("previous-session").unwrap();
    vault.unlock(PASSWORD).unwrap();
    vault.upsert(revised(&entry, "after-unlock")).unwrap();
    vault.begin_merge_write("new-session").unwrap();
    assert!(vault.end_merge_write("previous-session").is_err());
    assert!(vault.delete(&entry.id).is_err());
    vault.end_merge_write("new-session").unwrap();
    vault.delete(&entry.id).unwrap();
}

#[test]
fn merge_write_lease_is_not_persisted_across_process_restarts() {
    let (dir, mut vault) = ready();
    let entry = vault
        .upsert(input("example.com", "before-restart"))
        .unwrap();
    let disk_before = fs::read(dir.path().join("vault.json")).unwrap();
    vault.begin_merge_write("interrupted-ack").unwrap();
    assert_eq!(
        fs::read(dir.path().join("vault.json")).unwrap(),
        disk_before
    );
    drop(vault);
    let mut reopened = Vault::open(dir.path().to_path_buf()).unwrap();
    reopened.unlock(PASSWORD).unwrap();
    reopened.upsert(revised(&entry, "after-restart")).unwrap();
    assert_eq!(reopened.get(&entry.id).unwrap().password, "after-restart");
}

fn backup_paths(dir: &Path) -> Vec<PathBuf> {
    match fs::read_dir(dir.join("backups")) {
        Ok(entries) => entries.map(|entry| entry.unwrap().path()).collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => vec![],
        Err(err) => panic!("cannot list recovery snapshots: {err}"),
    }
}

#[test]
fn empty_requester_pulls_live_accounts_without_modifying_provider() {
    let (source_dir, mut source) = ready();
    let first = source.upsert(input("one.example", "first-private-password")).unwrap();
    source.upsert(revised(&first, "updated-private-password")).unwrap();
    source.upsert(input("two.example", "second-private-password")).unwrap();
    let deleted = source.upsert(input("deleted.example", "deleted-private-password")).unwrap();
    source.delete(&deleted.id).unwrap();
    let (target_dir, mut target) = ready();
    let source_before = fs::read(source_dir.path().join("vault.json")).unwrap();
    let target_before = fs::read(target_dir.path().join("vault.json")).unwrap();
    let payload = source.export_pull().unwrap();
    assert_eq!(payload.records.len(), 2);
    assert!(payload.records.iter().all(|entry| !entry.deleted));
    assert!(!serde_json::to_string(&payload).unwrap().contains("first-private-password"));
    assert_eq!(target.import_pull(payload).unwrap().changed, 2);
    assert_eq!(source.list(None).unwrap().len(), 2);
    assert_eq!(target.list(None).unwrap().len(), 2);
    assert_eq!(source.get(&first.id).unwrap().password, "updated-private-password");
    assert_eq!(target.get(&first.id).unwrap().password, "updated-private-password");
    assert_eq!(fs::read(source_dir.path().join("vault.json")).unwrap(), source_before);
    assert!(backup_paths(source_dir.path()).is_empty());
    let backups = backup_paths(target_dir.path());
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(backups[0].join("vault.json")).unwrap(), target_before);
    assert_eq!(fs::read(backups[0].join("identity.json")).unwrap(), fs::read(target_dir.path().join("identity.json")).unwrap());
    let mut snapshot = Vault::open(backups[0].clone()).unwrap();
    snapshot.unlock(PASSWORD).unwrap();
    assert!(snapshot.list(None).unwrap().is_empty());
    let after = fs::read(target_dir.path().join("vault.json")).unwrap();
    assert_eq!(target.import_pull(source.export_pull().unwrap()).unwrap().changed, 0);
    assert_eq!(target.import_pull(SyncPayload { version: FORMAT, records: vec![] }).unwrap().changed, 0);
    assert_eq!(fs::read(target_dir.path().join("vault.json")).unwrap(), after);
    assert_eq!(backup_paths(target_dir.path()).len(), 1);
}

#[test]
fn pulling_keeps_unrelated_local_records_and_newer_local_passwords() {
    let (dir, mut vault) = ready();
    let local = vault.upsert(input("local.example", "keep-this-local-password")).unwrap();
    let first = vault.upsert(input("shared.example", "old-shared-password")).unwrap();
    let latest = vault.upsert(revised(&first, "newer-local-password")).unwrap();
    let mut older_remote = first.clone();
    older_remote.version.device_id = Uuid::new_v4().to_string();
    older_remote.password = "older-remote-password".to_owned();
    let result = vault.import_pull(SyncPayload { version: FORMAT, records: vec![older_remote] }).unwrap();
    assert_eq!(result.changed, 1);
    assert_eq!(vault.list(None).unwrap().len(), 2);
    assert_eq!(vault.get(&local.id).unwrap().password, "keep-this-local-password");
    assert_eq!(vault.get(&first.id).unwrap().password, "newer-local-password");
    assert_eq!(vault.recovery_history(&first.id).unwrap().len(), 3);
    let mut newer_remote = latest.clone();
    newer_remote.version.modified_at += 10;
    newer_remote.version.counter += 1;
    newer_remote.version.device_id = Uuid::new_v4().to_string();
    newer_remote.password = "newer-remote-password".to_owned();
    assert_eq!(vault.import_pull(SyncPayload { version: FORMAT, records: vec![newer_remote] }).unwrap().changed, 1);
    assert_eq!(vault.get(&first.id).unwrap().password, "newer-remote-password");
    assert_eq!(vault.get(&local.id).unwrap().password, "keep-this-local-password");
    assert_eq!(backup_paths(dir.path()).len(), 2);
}

#[test]
fn pull_rejects_remote_deletions_duplicates_and_invalid_batches_atomically() {
    let (dir, mut vault) = ready();
    let original = vault.upsert(input("example.com", "must-survive-pull")).unwrap();
    let mut valid = original.clone();
    valid.id = Uuid::new_v4().to_string();
    let mut deleted = original.clone();
    deleted.deleted = true;
    deleted.title.clear(); deleted.username.clear(); deleted.password.clear(); deleted.notes.clear();
    deleted.version.modified_at += 10;
    let mut future = valid.clone();
    future.version.modified_at = now_ms().unwrap() + MAX_FUTURE_MS + 60_000;
    let before = fs::read(dir.path().join("vault.json")).unwrap();
    for records in [vec![valid.clone(), deleted], vec![valid.clone(), valid.clone()], vec![future]] {
        assert!(vault.import_pull(SyncPayload { version: FORMAT, records }).is_err());
        assert_eq!(vault.get(&original.id).unwrap().password, "must-survive-pull");
        assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
        assert!(backup_paths(dir.path()).is_empty());
    }
    let mut oversized = Vec::new();
    for _ in 0..40 {
        let mut entry = valid.clone();
        entry.id = Uuid::new_v4().to_string();
        entry.notes = "x".repeat(32 * 1024);
        oversized.push(entry);
    }
    assert!(vault.import_pull(SyncPayload { version: FORMAT, records: oversized }).unwrap_err().is_capacity_limit());
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
    assert!(backup_paths(dir.path()).is_empty());
}

#[test]
fn deleted_records_remain_globally_recoverable_and_restore_as_new_local_edits() {
    let (dir, mut vault) = ready();
    let first = vault.upsert(input("example.com", "original-recoverable-password")).unwrap();
    let second = vault.upsert(revised(&first, "second-recoverable-password")).unwrap();
    vault.delete(&first.id).unwrap();
    let deleted_version = vault.export_sync().unwrap().records.last().unwrap().version.clone();
    assert!(vault.list(None).unwrap().is_empty());
    let recoverable = vault.list_recovery_entries().unwrap();
    assert_eq!(recoverable.len(), 1);
    assert!(recoverable[0].deleted);
    assert_eq!(recoverable[0].username, first.username);
    assert!(!serde_json::to_string(&recoverable).unwrap().contains("recoverable-password"));
    let history = vault.recovery_history(&first.id).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].version, second.version);
    assert_eq!(history[1].version, first.version);
    let before = fs::read(dir.path().join("vault.json")).unwrap();
    assert!(vault.restore_entry(&first.id, deleted_version.clone()).is_err());
    assert!(vault.restore_entry("missing", first.version.clone()).is_err());
    assert!(backup_paths(dir.path()).is_empty());
    let restored = vault.restore_entry(&first.id, first.version.clone()).unwrap();
    assert_eq!(restored.password, "original-recoverable-password");
    assert_eq!(restored.id, first.id);
    assert_eq!(restored.version.device_id, vault.status().device_id);
    assert!(restored.version > deleted_version);
    assert_eq!(vault.recovery_history(&first.id).unwrap().len(), 3);
    let backups = backup_paths(dir.path());
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(backups[0].join("vault.json")).unwrap(), before);
    assert!(!String::from_utf8(before).unwrap().contains("recoverable-password"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&backups[0]).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(backups[0].join("vault.json")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(backups[0].join("identity.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    drop(vault);
    let mut reopened = Vault::open(dir.path().to_path_buf()).unwrap();
    reopened.unlock(PASSWORD).unwrap();
    assert_eq!(reopened.get(&first.id).unwrap().password, "original-recoverable-password");
    let mut snapshot = Vault::open(backups[0].clone()).unwrap();
    snapshot.unlock(PASSWORD).unwrap();
    assert!(snapshot.list(None).unwrap().is_empty());
    assert_eq!(snapshot.recovery_history(&first.id).unwrap().len(), 2);
}

#[test]
fn newer_local_deletion_requires_explicit_restore_even_after_pull() {
    let (_dir, mut vault) = ready();
    let entry = vault.upsert(input("example.com", "locally-deleted-password")).unwrap();
    vault.delete(&entry.id).unwrap();
    let mut remote = entry.clone();
    remote.version.device_id = Uuid::new_v4().to_string();
    remote.password = "recover-only-on-request".to_owned();
    assert_eq!(vault.import_pull(SyncPayload { version: FORMAT, records: vec![remote.clone()] }).unwrap().changed, 1);
    assert!(vault.list(None).unwrap().is_empty());
    assert!(vault.list_recovery_entries().unwrap()[0].deleted);
    let restored = vault.restore_entry(&entry.id, remote.version.clone()).unwrap();
    assert_eq!(restored.password, "recover-only-on-request");
    assert_eq!(vault.list(None).unwrap().len(), 1);
}

#[test]
fn backup_or_persist_failure_leaves_import_and_restore_unchanged() {
    let (dir, mut vault) = ready();
    let entry = vault.upsert(input("example.com", "original-safe-password")).unwrap();
    vault.delete(&entry.id).unwrap();
    let before = fs::read(dir.path().join("vault.json")).unwrap();
    let mut incoming = entry.clone();
    incoming.id = Uuid::new_v4().to_string();
    let payload = SyncPayload { version: FORMAT, records: vec![incoming] };
    fs::write(dir.path().join("backups"), b"not-a-directory").unwrap();
    assert!(vault.import_pull(payload.clone()).is_err());
    assert!(vault.restore_entry(&entry.id, entry.version.clone()).is_err());
    assert!(vault.list(None).unwrap().is_empty());
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
    fs::remove_file(dir.path().join("backups")).unwrap();
    fs::create_dir(dir.path().join(".vault.json.new")).unwrap();
    assert!(vault.import_pull(payload).is_err());
    assert!(vault.restore_entry(&entry.id, entry.version.clone()).is_err());
    assert!(vault.list(None).unwrap().is_empty());
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
    let backups = backup_paths(dir.path());
    assert_eq!(backups.len(), 2);
    assert!(backups.iter().all(|backup| fs::read(backup.join("vault.json")).unwrap() == before));
}

#[test]
fn backup_limit_preserves_first_snapshot_and_lock_blocks_recovery() {
    let (dir, mut vault) = ready();
    let entry = vault.upsert(input("example.com", "recovery-secret")).unwrap();
    vault.delete(&entry.id).unwrap();
    fs::create_dir(dir.path().join("backups")).unwrap();
    for index in 0..MAX_RECOVERY_BACKUPS {
        fs::write(dir.path().join("backups").join(format!("preserved-{index}")), b"preserved").unwrap();
    }
    let before = fs::read(dir.path().join("vault.json")).unwrap();
    assert!(vault.restore_entry(&entry.id, entry.version.clone()).err().unwrap().to_string().contains("64"));
    assert_eq!(fs::read(dir.path().join("vault.json")).unwrap(), before);
    assert_eq!(fs::read(dir.path().join("backups/preserved-0")).unwrap(), b"preserved");
    vault.begin_merge_write("waiting-receipt").unwrap();
    assert!(vault.restore_entry(&entry.id, entry.version.clone()).is_err());
    assert!(vault.import_pull(SyncPayload { version: FORMAT, records: vec![entry.clone()] }).is_err());
    assert_eq!(vault.recovery_history(&entry.id).unwrap().len(), 1);
    vault.lock();
    assert!(vault.list_recovery_entries().is_err());
    assert!(vault.recovery_history(&entry.id).is_err());
    assert!(vault.restore_entry(&entry.id, entry.version.clone()).is_err());
    assert!(vault.export_pull().is_err());
    assert!(vault.import_pull(SyncPayload { version: FORMAT, records: vec![] }).is_err());
}
