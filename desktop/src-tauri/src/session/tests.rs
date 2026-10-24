use super::*;
use ohmypassword_core::EntryInput;
use ohmypassword_service::ServiceConfig;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PASSWORD: &str = "synthetic native session password";

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Fixture {
    state: Arc<AppState>,
    directory: Directory,
    id: String,
}
fn input(id: Option<String>, password: &str) -> EntryInput {
    EntryInput {
        id,
        hostname: "native-session.invalid".into(),
        title: "Synthetic native session".into(),
        username: "native@example.invalid".into(),
        password: password.into(),
        notes: String::new(),
    }
}
fn fixture() -> Fixture {
    fixture_state(true)
}
fn fixture_state(initialized: bool) -> Fixture {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let directory = Directory(std::env::temp_dir().join(format!(
            "omp-native-session-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )));
    fs::create_dir(&directory.0).unwrap();
    let mut vault = Vault::open(directory.0.clone()).unwrap();
    let id = if initialized {
        vault
            .create(PASSWORD, "Private fixture device name")
            .unwrap();
        vault
            .upsert(input(None, "before-ui-lock"))
            .unwrap()
            .id
            .clone()
    } else {
        String::new()
    };
    vault.lock();
    let vault = Arc::new(Mutex::new(vault));
    // Both discovery transports are disabled. These tests never enumerate or
    // probe a real LAN; the ephemeral listeners receive no external requests.
    let service = Arc::new(
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
    service.pause();
    Fixture {
        state: Arc::new(AppState::new(vault, Some(service), None)),
        directory,
        id,
    }
}
fn current_generation(state: &AppState) -> u64 {
    state.generation.load(Ordering::SeqCst)
}
fn unlock(state: &AppState) {
    let generation = state
        .authentication_ticket(current_generation(state))
        .unwrap();
    state.authenticate(generation, PASSWORD, None).unwrap();
    assert!(!state.interface_locked());
    assert!(state.service.as_ref().unwrap().browser_available());
}

#[test]
fn startup_is_fully_locked_and_soft_lock_preserves_browser_but_denies_ui() {
    let f = fixture();
    let initial = f.state.snapshot().unwrap();
    assert!(initial.interface_locked && initial.vault.locked);
    assert!(!initial.browser_available);
    assert!(f
        .state
        .interface_ticket(current_generation(&f.state))
        .is_err());
    unlock(&f.state);
    let ticket = f
        .state
        .interface_ticket(current_generation(&f.state))
        .unwrap();
    assert_eq!(
        f.state
            .ui_operation(ticket, |vault| vault.list(None))
            .unwrap()
            .len(),
        1
    );
    let locked = f.state.lock_interface().unwrap();
    assert!(!locked.locked);
    assert_eq!(locked.entry_count, 0);
    assert_eq!(locked.device_name, "此设备");
    assert!(f
        .state
        .interface_ticket(current_generation(&f.state))
        .is_err());
    assert!(f
        .state
        .ui_operation(ticket, |vault| vault.list(None))
        .is_err());
    assert!(f
        .state
        .with_service(current_generation(&f.state), |service| service
            .detect_devices())
        .is_err());
    assert!(f
        .state
        .with_service(current_generation(&f.state), |service| service
            .request_merge("not-a-device"))
        .is_err());
    assert!(f
        .state
        .with_service(current_generation(&f.state), |service| service
            .respond_merge("not-a-session", true))
        .is_err());
    let snapshot = f.state.snapshot().unwrap();
    assert!(snapshot.interface_locked && snapshot.browser_available);
    assert!(!snapshot.vault.locked);
    assert_eq!(snapshot.vault.entry_count, 0);
    assert!(snapshot.service.is_none());
    assert_eq!(f.state.vault.lock().unwrap().list(None).unwrap().len(), 1);
}

#[test]
fn incorrect_soft_unlock_keeps_shared_browser_updates_and_success_never_reloads() {
    let f = fixture();
    unlock(&f.state);
    f.state.lock_interface().unwrap();
    // Use exactly the same shared Vault the browser HTTP service holds.
    f.state
        .vault
        .lock()
        .unwrap()
        .upsert(input(Some(f.id.clone()), "browser-updated-while-ui-locked"))
        .unwrap();
    let ciphertext = fs::read(f.directory.0.join("vault.json")).unwrap();
    let generation = f
        .state
        .authentication_ticket(current_generation(&f.state))
        .unwrap();
    assert!(f
        .state
        .authenticate(generation, "incorrect interface password", None)
        .is_err());
    assert!(f.state.interface_locked());
    assert!(f.state.service.as_ref().unwrap().browser_available());
    assert!(!f.state.vault.lock().unwrap().status().locked);
    assert_eq!(
        f.state.vault.lock().unwrap().get(&f.id).unwrap().password,
        "browser-updated-while-ui-locked"
    );
    assert_eq!(
        fs::read(f.directory.0.join("vault.json")).unwrap(),
        ciphertext
    );
    unlock(&f.state);
    let ticket = f
        .state
        .interface_ticket(current_generation(&f.state))
        .unwrap();
    assert_eq!(
        f.state
            .ui_operation(ticket, |vault| vault.get(&f.id))
            .unwrap()
            .password,
        "browser-updated-while-ui-locked"
    );
    assert_eq!(
        fs::read(f.directory.0.join("vault.json")).unwrap(),
        ciphertext
    );
}

#[test]
fn full_lock_disables_browser_and_rejects_queued_authentication() {
    let f = fixture();
    unlock(&f.state);
    let pending = f
        .state
        .authentication_ticket(current_generation(&f.state))
        .unwrap();
    f.state.fully_lock().unwrap();
    assert!(f.state.authenticate(pending, PASSWORD, None).is_err());
    let snapshot = f.state.snapshot().unwrap();
    assert!(snapshot.interface_locked && snapshot.vault.locked);
    assert!(!snapshot.browser_available);
    f.state.lock_interface().unwrap();
    assert!(!f.state.service.as_ref().unwrap().browser_available());
}

#[test]
fn cold_authentication_cannot_resume_after_a_later_lock_at_the_commit_boundary() {
    for fully in [false, true] {
        let f = fixture();
        let _authentication = f.state.authentication.lock().unwrap();
        let generation = f
            .state
            .authentication_ticket(current_generation(&f.state))
            .unwrap();
        // Exercise the exact boundary between KDF work and lifecycle commit.
        f.state.vault.lock().unwrap().unlock(PASSWORD).unwrap();
        if fully {
            f.state.fully_lock().unwrap();
        } else {
            f.state.lock_interface().unwrap();
        }
        assert!(f.state.finish_authentication(generation, true).is_err());
        assert!(f.state.interface_locked());
        assert!(f.state.vault.lock().unwrap().status().locked);
        assert!(!f.state.service.as_ref().unwrap().browser_available());
    }
}

#[test]
fn stale_warm_authentication_and_inflight_ui_result_never_erase_the_browser_key() {
    let f = fixture();
    unlock(&f.state);
    {
        let _authentication = f.state.authentication.lock().unwrap();
        let generation = f
            .state
            .authentication_ticket(current_generation(&f.state))
            .unwrap();
        f.state
            .vault
            .lock()
            .unwrap()
            .verify_password(PASSWORD)
            .unwrap();
        f.state.lock_interface().unwrap();
        assert!(f.state.finish_authentication(generation, false).is_err());
        assert!(f.state.service.as_ref().unwrap().browser_available());
    }
    unlock(&f.state);
    let ticket = f
        .state
        .interface_ticket(current_generation(&f.state))
        .unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let state = f.state.clone();
    let operation = std::thread::spawn(move || {
        state.ui_operation(ticket, |vault| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            vault.list(None)
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let state = f.state.clone();
    let locking = std::thread::spawn(move || state.lock_interface());
    let until = Instant::now() + Duration::from_secs(2);
    while !f.state.interface_locked() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    let lock_started = f.state.interface_locked();
    release_tx.send(()).unwrap();
    let result = operation.join().unwrap();
    locking.join().unwrap().unwrap();
    assert!(lock_started && result.is_err());
    assert!(f.state.service.as_ref().unwrap().browser_available());
    assert!(!f.state.vault.lock().unwrap().status().locked);
}

#[test]
fn mobile_suspension_and_exit_block_new_and_late_unlocks() {
    let f = fixture();
    unlock(&f.state);
    let pending = f
        .state
        .authentication_ticket(current_generation(&f.state))
        .unwrap();
    f.state.suspend().unwrap();
    assert!(f
        .state
        .authentication_ticket(current_generation(&f.state))
        .is_err());
    assert!(f.state.authenticate(pending, PASSWORD, None).is_err());
    assert!(f.state.vault.lock().unwrap().status().locked);
    assert!(!f.state.service.as_ref().unwrap().browser_available());
    f.state.resume_foreground();
    assert!(f.state.interface_locked());
    assert!(!f.state.service.as_ref().unwrap().browser_available());
    unlock(&f.state);
    f.state.stop().unwrap();
    f.state.resume_foreground();
    assert!(f
        .state
        .authentication_ticket(current_generation(&f.state))
        .is_err());
    assert!(!f.state.service.as_ref().unwrap().browser_available());
}

#[test]
fn invocations_first_received_after_relock_cannot_adopt_the_new_session() {
    let f = fixture();
    unlock(&f.state);
    // These expected generations were captured when the UI dispatched an IPC,
    // before its async Rust handler was first polled by the runtime.
    let dispatched = f.state.snapshot().unwrap().session_generation;
    f.state.fully_lock().unwrap();
    assert!(f.state.authentication_ticket(dispatched).is_err());
    assert!(f.state.authenticate(dispatched, PASSWORD, None).is_err());
    assert!(!f.state.service.as_ref().unwrap().browser_available());
    unlock(&f.state);
    assert!(f.state.interface_ticket(dispatched).is_err());
    assert!(f
        .state
        .ui_operation(dispatched, |vault| vault.delete(&f.id))
        .is_err());
    assert!(f
        .state
        .with_service(dispatched, |service| service.detect_devices())
        .is_err());
    assert!(f
        .state
        .with_service(dispatched, |service| service.request_merge("late-request"))
        .is_err());
    assert!(f
        .state
        .with_service(dispatched, |service| service
            .respond_merge("late-response", true))
        .is_err());
    assert_eq!(f.state.vault.lock().unwrap().list(None).unwrap().len(), 1);
    assert!(f.state.service.as_ref().unwrap().browser_available());
}

#[test]
fn create_uses_a_current_authentication_ticket_and_never_runs_while_suspended() {
    let f = fixture_state(false);
    assert!(!f.state.snapshot().unwrap().vault.initialized);
    let dispatched = f
        .state
        .authentication_ticket(current_generation(&f.state))
        .unwrap();
    f.state.suspend().unwrap();
    assert!(f
        .state
        .authenticate(dispatched, PASSWORD, Some("new fixture"))
        .is_err());
    assert!(!f.state.vault.lock().unwrap().status().initialized);
    f.state.resume_foreground();
    assert!(f
        .state
        .authenticate(dispatched, PASSWORD, Some("new fixture"))
        .is_err());
    let current = f
        .state
        .authentication_ticket(current_generation(&f.state))
        .unwrap();
    f.state
        .authenticate(current, PASSWORD, Some("new fixture"))
        .unwrap();
    assert!(!f.state.interface_locked());
    assert!(f.state.vault.lock().unwrap().status().initialized);
    assert!(f.state.service.as_ref().unwrap().browser_available());
}
