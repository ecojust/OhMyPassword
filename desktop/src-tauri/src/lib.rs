//! The shared native shell for desktop, Android and iOS. Passwords only cross
//! this local IPC bridge after an explicit action in the bundled UI.
use ohmypassword_core::{Entry, EntryInput, EntrySummary, Status, Vault, Version};
use ohmypassword_service::{MergeSession, Service, ServiceConfig, ServiceStatus};
use serde::Serialize;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{Emitter, Manager, State};
use zeroize::Zeroizing;

const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
mod session;
use session::{AppState, NativeResult};
#[derive(Serialize)]
struct AppStatus {
    app_version: &'static str,
    session_generation: u64,
    interface_locked: bool,
    browser_available: bool,
    vault: Status,
    service: Option<ServiceStatus>,
    service_error: Option<String>,
    local_addresses: Vec<String>,
    mobile: bool,
}
fn local_addresses() -> Vec<String> {
    let mut addresses: Vec<_> = local_ip_address::list_afinet_netifas()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, ip)| match ip {
            IpAddr::V4(value) if value.is_private() && !value.is_loopback() => {
                Some(value.to_string())
            }
            _ => None,
        })
        .collect();
    addresses.sort();
    addresses.dedup();
    addresses
}
#[tauri::command]
fn app_status(state: State<'_, Arc<AppState>>) -> NativeResult<AppStatus> {
    let snapshot = state.snapshot()?;
    Ok(AppStatus {
        app_version: env!("CARGO_PKG_VERSION"),
        session_generation: snapshot.session_generation,
        interface_locked: snapshot.interface_locked,
        browser_available: snapshot.browser_available,
        vault: snapshot.vault,
        service: snapshot.service,
        service_error: state.service_error.clone(),
        local_addresses: if snapshot.interface_locked {
            vec![]
        } else {
            local_addresses()
        },
        mobile: cfg!(any(target_os = "android", target_os = "ios")),
    })
}
async fn with_vault<T: Send + 'static>(
    state: Arc<AppState>,
    expected_generation: u64,
    operation: impl FnOnce(&mut Vault) -> ohmypassword_core::Result<T> + Send + 'static,
) -> NativeResult<T> {
    let generation = state.interface_ticket(expected_generation)?;
    tauri::async_runtime::spawn_blocking(move || state.ui_operation(generation, operation))
        .await
        .map_err(|_| "密码库操作未完成".to_owned())?
}

#[tauri::command]
async fn create_vault(
    expected_generation: u64,
    password: String,
    device_name: String,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<Status> {
    let password = Zeroizing::new(password);
    let generation = state.authentication_ticket(expected_generation)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        state.authenticate(generation, &password, Some(&device_name))
    })
    .await
    .map_err(|_| "密码库操作未完成".to_owned())?
}
#[tauri::command]
async fn unlock_vault(
    expected_generation: u64,
    password: String,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<Status> {
    let password = Zeroizing::new(password);
    let generation = state.authentication_ticket(expected_generation)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || state.authenticate(generation, &password, None))
        .await
        .map_err(|_| "密码库操作未完成".to_owned())?
}
#[tauri::command]
fn lock_vault(state: State<'_, Arc<AppState>>, app: tauri::AppHandle) -> NativeResult<Status> {
    let result = state.lock_interface()?;
    let _ = app.emit("vault-locked", ());
    Ok(result)
}
#[tauri::command]
fn fully_lock_vault(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
) -> NativeResult<Status> {
    let result = state.fully_lock()?;
    let _ = app.emit("vault-locked", ());
    Ok(result)
}

#[tauri::command]
fn user_activity(state: State<'_, Arc<AppState>>) {
    state.touch();
}
#[tauri::command]
async fn list_entries(
    expected_generation: u64,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<Vec<EntrySummary>> {
    with_vault(state.inner().clone(), expected_generation, |vault| {
        vault.list(None)
    })
    .await
}
#[tauri::command]
async fn get_entry(
    expected_generation: u64,
    id: String,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<Entry> {
    state.touch();
    with_vault(state.inner().clone(), expected_generation, move |vault| {
        vault.get(&id)
    })
    .await
}
#[tauri::command]
async fn save_entry(
    expected_generation: u64,
    input: EntryInput,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<()> {
    with_vault(state.inner().clone(), expected_generation, move |vault| {
        vault.upsert(input).map(|_| ())
    })
    .await?;
    state.touch();
    Ok(())
}
#[tauri::command]
async fn delete_entry(
    expected_generation: u64,
    id: String,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<()> {
    with_vault(state.inner().clone(), expected_generation, move |vault| {
        vault.delete(&id)
    })
    .await?;
    state.touch();
    Ok(())
}
#[tauri::command]
async fn entry_history(
    expected_generation: u64,
    id: String,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<Vec<Entry>> {
    state.touch();
    with_vault(state.inner().clone(), expected_generation, move |vault| {
        vault.get_conflicts(&id)
    })
    .await
}
#[tauri::command]
async fn list_recovery_entries(
    expected_generation: u64,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<Vec<EntrySummary>> {
    state.touch();
    with_vault(state.inner().clone(), expected_generation, |vault| {
        vault.list_recovery_entries()
    })
    .await
}
#[tauri::command]
async fn recovery_history(
    expected_generation: u64,
    id: String,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<Vec<Entry>> {
    state.touch();
    with_vault(state.inner().clone(), expected_generation, move |vault| {
        vault.recovery_history(&id)
    })
    .await
}
#[tauri::command]
async fn restore_entry(
    expected_generation: u64,
    id: String,
    version: Version,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<Entry> {
    let restored = with_vault(state.inner().clone(), expected_generation, move |vault| {
        vault.restore_entry(&id, version)
    })
    .await?;
    state.touch();
    Ok(restored)
}
#[tauri::command]
fn detect_devices(expected_generation: u64, state: State<'_, Arc<AppState>>) -> NativeResult<()> {
    state.touch();
    state.with_service(expected_generation, |service| service.detect_devices())
}
#[tauri::command]
fn request_merge(
    expected_generation: u64,
    device_id: String,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<MergeSession> {
    state.touch();
    state.with_service(expected_generation, |service| {
        service.request_merge(&device_id)
    })
}
#[tauri::command]
fn respond_merge(
    expected_generation: u64,
    session_id: String,
    accept: bool,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<()> {
    state.touch();
    state.with_service(expected_generation, |service| {
        service.respond_merge(&session_id, accept)
    })
}

/// Both native wrappers supply their own generated Tauri context.
pub fn run(context: tauri::Context<tauri::Wry>) {
    let builder = tauri::Builder::default().plugin(tauri_plugin_clipboard_manager::init());
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder.plugin(tauri_plugin_discovery::init());
    let app = builder
        .setup(|app| {
            let directory = app.path().app_data_dir()?;
            let vault = Arc::new(Mutex::new(Vault::open(directory)?));
            let config = ServiceConfig {
                enable_discovery: !cfg!(any(target_os = "android", target_os = "ios")),
                ..ServiceConfig::default()
            };
            let (service, service_error) = match Service::start(vault.clone(), config) {
                Ok(service) => {
                    service.pause();
                    (Some(Arc::new(service)), None)
                }
                Err(error) => (None, Some(error.to_string())),
            };
            let state = Arc::new(AppState::new(vault, service, service_error));
            app.manage(state.clone());
            let handle = app.handle().clone();
            std::thread::spawn(move || monitor(handle, state));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_status,
            create_vault,
            unlock_vault,
            lock_vault,
            fully_lock_vault,
            user_activity,
            list_entries,
            get_entry,
            save_entry,
            delete_entry,
            entry_history,
            list_recovery_entries,
            recovery_history,
            restore_entry,
            detect_devices,
            request_merge,
            respond_merge
        ])
        .build(context)
        .expect("Could not initialize OhMyPassword");
    app.run(|app, event| match event {
        tauri::RunEvent::Exit => {
            if let Some(state) = app.try_state::<Arc<AppState>>() {
                let _ = state.stop();
            }
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        tauri::RunEvent::WindowEvent {
            event: tauri::WindowEvent::Suspended,
            ..
        } => {
            if let Some(state) = app.try_state::<Arc<AppState>>() {
                let _ = state.suspend();
                let _ = app.emit("vault-locked", ());
            }
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        tauri::RunEvent::WindowEvent {
            event: tauri::WindowEvent::Resumed,
            ..
        } => {
            if let Some(state) = app.try_state::<Arc<AppState>>() {
                state.resume_foreground();
            }
        }
        // iOS can become active after a temporary interruption without entering
        // the background. Focus only permits re-authentication; it never unlocks.
        #[cfg(target_os = "ios")]
        tauri::RunEvent::WindowEvent {
            event: tauri::WindowEvent::Focused(true),
            ..
        } => {
            if let Some(state) = app.try_state::<Arc<AppState>>() {
                state.resume_foreground();
            }
        }
        _ => {}
    });
}
fn monitor(app: tauri::AppHandle, state: Arc<AppState>) {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let mut discovery_started = false;
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let mut discovery_generation = 0;
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let mut scan_generation = None;
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let mut seen = std::collections::HashMap::<String, (String, u64)>::new();
    while !state.stopping.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(3));
        let idle = state
            .activity
            .lock()
            .map(|time| time.elapsed() >= IDLE_TIMEOUT)
            .unwrap_or(true);
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let status = match state.vault.lock() {
            Ok(vault) => vault.status(),
            Err(_) => continue,
        };
        if idle && !state.interface_locked() {
            let _ = state.lock_interface();
            let _ = app.emit("vault-locked", ());
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            use tauri_plugin_discovery::DiscoveryExt;
            let generation = state.generation.load(Ordering::SeqCst);
            if generation != discovery_generation {
                let _ = app.discovery().stop();
                discovery_started = false;
                discovery_generation = generation;
                scan_generation = None;
                seen.clear();
            }
            let locked = idle || state.interface_locked() || status.locked;
            if locked && discovery_started {
                let _ = app.discovery().stop();
                discovery_started = false;
                scan_generation = None;
                seen.clear();
            }
            if !locked {
                if let Some(service) = &state.service {
                    // Mobile plugin calls synchronously wait for platform UI
                    // callbacks. Never hold lifecycle/vault locks across them:
                    // a main-thread Suspended event must be able to fully lock.
                    if state.interface_ticket(generation).is_err() {
                        continue;
                    }
                    if !discovery_started {
                        discovery_started = app
                            .discovery()
                            .start(tauri_plugin_discovery::StartRequest {
                                device_id: status.device_id.clone(),
                                name: status.device_name.clone(),
                                port: service.status().lan_port,
                            })
                            .is_ok();
                        if state.interface_ticket(generation).is_err() {
                            stop_native_discovery(
                                &app,
                                &mut discovery_started,
                                &mut scan_generation,
                                &mut seen,
                            );
                            continue;
                        }
                    }
                    if discovery_started {
                        let discovery_status = service.status();
                        if discovery_status.discovering
                            && scan_generation != Some(discovery_status.discovery_generation)
                            && state.interface_ticket(generation).is_ok()
                        {
                            let scanned = app.discovery().scan().is_ok();
                            if state.interface_ticket(generation).is_err() {
                                stop_native_discovery(
                                    &app,
                                    &mut discovery_started,
                                    &mut scan_generation,
                                    &mut seen,
                                );
                                continue;
                            }
                            if scanned {
                                scan_generation = Some(discovery_status.discovery_generation);
                            }
                        }
                        if state.interface_ticket(generation).is_err() {
                            stop_native_discovery(
                                &app,
                                &mut discovery_started,
                                &mut scan_generation,
                                &mut seen,
                            );
                            continue;
                        }
                        let peers = app.discovery().peers();
                        if state.interface_ticket(generation).is_err() {
                            stop_native_discovery(
                                &app,
                                &mut discovery_started,
                                &mut scan_generation,
                                &mut seen,
                            );
                            continue;
                        }
                        if let Ok(result) = peers {
                            // Only the pure-Rust publication is serialized with
                            // locking, preventing stale callbacks from entering
                            // a newly unlocked session. No platform call occurs
                            // while this gate is held.
                            let published = state.with_service(generation, |service| {
                                let mut present = std::collections::HashSet::new();
                                for peer in result.peers {
                                    present.insert(peer.id.clone());
                                    let observation = (peer.endpoint.clone(), peer.last_seen);
                                    if seen.get(&peer.id) != Some(&observation) {
                                        if let Ok(endpoint) = peer.endpoint.parse() {
                                            service.discovered_peer(&peer.id, endpoint);
                                            seen.insert(peer.id, observation);
                                        }
                                    }
                                }
                                seen.retain(|id, _| present.contains(id));
                                Ok(())
                            });
                            if published.is_err() {
                                stop_native_discovery(
                                    &app,
                                    &mut discovery_started,
                                    &mut scan_generation,
                                    &mut seen,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn stop_native_discovery(
    app: &tauri::AppHandle,
    started: &mut bool,
    scan_generation: &mut Option<u64>,
    seen: &mut std::collections::HashMap<String, (String, u64)>,
) {
    use tauri_plugin_discovery::DiscoveryExt;
    let _ = app.discovery().stop();
    *started = false;
    *scan_generation = None;
    seen.clear();
}
