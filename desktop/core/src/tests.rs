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
fn hostname_normalization_is_exact_and_rejects_ambiguous_inputs() {
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
        1
    );
    assert_eq!(vault.list(Some("example.com.evil.test")).unwrap().len(), 1);
    assert!(vault.list(Some("other.example.com")).unwrap().is_empty());
    let summaries = serde_json::to_string(&vault.list(None).unwrap()).unwrap();
    assert!(!summaries.contains("\"password\""));
    assert!(!summaries.contains("\"notes\""));
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
