//! The shared native shell for desktop, Android and iOS. Passwords only cross
//! this local IPC bridge after an explicit action in the bundled UI.
use ohmypassword_core::{Entry, EntryInput, EntrySummary, Status, Vault, Version};
use ohmypassword_service::{MergeSession, Service, ServiceConfig, ServiceStatus};
use serde::Serialize;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager, State};
use zeroize::Zeroizing;

const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
type NativeResult<T> = std::result::Result<T, String>;
struct AppState {
    vault: Arc<Mutex<Vault>>,
    service: Option<Arc<Service>>,
    service_error: Option<String>,
    activity: Mutex<Instant>,
    generation: AtomicU64,
    stopping: AtomicBool,
}
impl AppState {
    fn touch(&self) {
        if let Ok(mut time) = self.activity.lock() {
            *time = Instant::now();
        }
    }
    fn lock(&self) -> NativeResult<Status> {
        self.generation.fetch_add(1, Ordering::SeqCst);
        if let Some(service) = &self.service {
            service.pause();
        }
        self.vault
            .lock()
            .map(|mut vault| vault.lock())
            .map_err(|_| "密码库暂不可用".into())
    }
    fn unlocked(&self) {
        self.touch();
        if let Some(service) = &self.service {
            service.resume();
        }
    }
}
#[derive(Serialize)]
struct AppStatus {
    app_version: &'static str,
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
    let vault = state.vault.lock().map_err(|_| "密码库暂不可用")?.status();
    Ok(AppStatus {
        app_version: env!("CARGO_PKG_VERSION"),
        vault,
        service: state.service.as_ref().map(|service| service.status()),
        service_error: state.service_error.clone(),
        local_addresses: local_addresses(),
        mobile: cfg!(any(target_os = "android", target_os = "ios")),
    })
}
async fn with_vault<T: Send + 'static>(
    state: Arc<AppState>,
    operation: impl FnOnce(&mut Vault) -> ohmypassword_core::Result<T> + Send + 'static,
) -> NativeResult<T> {
    let generation = state.generation.load(Ordering::SeqCst);
    tauri::async_runtime::spawn_blocking(move || {
        let mut vault = state
            .vault
            .lock()
            .map_err(|_| "密码库暂不可用".to_owned())?;
        if state.generation.load(Ordering::SeqCst) != generation {
            return Err("密码库会话已结束，请重新解锁".into());
        }
        let value = operation(&mut vault).map_err(|error| error.to_string())?;
        if state.generation.load(Ordering::SeqCst) != generation {
            vault.lock();
            return Err("密码库会话已结束，请重新解锁".into());
        }
        Ok(value)
    })
    .await
    .map_err(|_| "密码库操作未完成".to_owned())?
}
#[tauri::command]
async fn create_vault(
    password: String,
    device_name: String,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<Status> {
    let password = Zeroizing::new(password);
    let result = with_vault(state.inner().clone(), move |vault| {
        vault.create(&password, &device_name)
    })
    .await?;
    state.unlocked();
    Ok(result)
}
#[tauri::command]
async fn unlock_vault(password: String, state: State<'_, Arc<AppState>>) -> NativeResult<Status> {
    let password = Zeroizing::new(password);
    let result = with_vault(state.inner().clone(), move |vault| vault.unlock(&password)).await?;
    state.unlocked();
    Ok(result)
}
#[tauri::command]
fn lock_vault(state: State<'_, Arc<AppState>>, app: tauri::AppHandle) -> NativeResult<Status> {
    let result = state.lock()?;
    let _ = app.emit("vault-locked", ());
    Ok(result)
}
#[tauri::command]
fn user_activity(state: State<'_, Arc<AppState>>) {
    state.touch();
}
#[tauri::command]
async fn list_entries(state: State<'_, Arc<AppState>>) -> NativeResult<Vec<EntrySummary>> {
    with_vault(state.inner().clone(), |vault| vault.list(None)).await
}
#[tauri::command]
async fn get_entry(id: String, state: State<'_, Arc<AppState>>) -> NativeResult<Entry> {
    state.touch();
    with_vault(state.inner().clone(), move |vault| vault.get(&id)).await
}
#[tauri::command]
async fn save_entry(input: EntryInput, state: State<'_, Arc<AppState>>) -> NativeResult<()> {
    with_vault(state.inner().clone(), move |vault| {
        vault.upsert(input).map(|_| ())
    })
    .await?;
    state.touch();
    Ok(())
}
#[tauri::command]
async fn delete_entry(id: String, state: State<'_, Arc<AppState>>) -> NativeResult<()> {
    with_vault(state.inner().clone(), move |vault| vault.delete(&id)).await?;
    state.touch();
    Ok(())
}
#[tauri::command]
async fn entry_history(id: String, state: State<'_, Arc<AppState>>) -> NativeResult<Vec<Entry>> {
    state.touch();
    with_vault(state.inner().clone(), move |vault| vault.get_conflicts(&id)).await
}
#[tauri::command]
async fn list_recovery_entries(state: State<'_, Arc<AppState>>) -> NativeResult<Vec<EntrySummary>> {
    state.touch();
    with_vault(state.inner().clone(), |vault| vault.list_recovery_entries()).await
}
#[tauri::command]
async fn recovery_history(id: String, state: State<'_, Arc<AppState>>) -> NativeResult<Vec<Entry>> {
    state.touch();
    with_vault(state.inner().clone(), move |vault| {
        vault.recovery_history(&id)
    })
    .await
}
#[tauri::command]
async fn restore_entry(
    id: String,
    version: Version,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<Entry> {
    let restored = with_vault(state.inner().clone(), move |vault| {
        vault.restore_entry(&id, version)
    })
    .await?;
    state.touch();
    Ok(restored)
}
#[tauri::command]
fn detect_devices(state: State<'_, Arc<AppState>>) -> NativeResult<()> {
    state.touch();
    state
        .service
        .as_ref()
        .ok_or("局域网服务未启动")?
        .detect_devices()
        .map_err(|error| error.to_string())
}
#[tauri::command]
fn request_merge(device_id: String, state: State<'_, Arc<AppState>>) -> NativeResult<MergeSession> {
    state.touch();
    state
        .service
        .as_ref()
        .ok_or("局域网服务未启动")?
        .request_merge(&device_id)
        .map_err(|error| error.to_string())
}
#[tauri::command]
fn respond_merge(
    session_id: String,
    accept: bool,
    state: State<'_, Arc<AppState>>,
) -> NativeResult<()> {
    state.touch();
    state
        .service
        .as_ref()
        .ok_or("局域网服务未启动")?
        .respond_merge(&session_id, accept)
        .map_err(|error| error.to_string())
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
            let state = Arc::new(AppState {
                vault,
                service,
                service_error,
                activity: Mutex::new(Instant::now()),
                generation: AtomicU64::new(0),
                stopping: AtomicBool::new(false),
            });
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
                state.stopping.store(true, Ordering::SeqCst);
                let _ = state.lock();
            }
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        tauri::RunEvent::WindowEvent {
            event: tauri::WindowEvent::Suspended,
            ..
        } => {
            if let Some(state) = app.try_state::<Arc<AppState>>() {
                let _ = state.lock();
                let _ = app.emit("vault-locked", ());
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
        let status = match state.vault.lock() {
            Ok(vault) => vault.status(),
            Err(_) => continue,
        };
        if idle && !status.locked {
            let _ = state.lock();
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
            let locked = idle || status.locked;
            if locked && discovery_started {
                let _ = app.discovery().stop();
                discovery_started = false;
                scan_generation = None;
                seen.clear();
            }
            if !locked {
                if let Some(service) = &state.service {
                    if !discovery_started {
                        discovery_started = app
                            .discovery()
                            .start(tauri_plugin_discovery::StartRequest {
                                device_id: status.device_id.clone(),
                                name: status.device_name.clone(),
                                port: service.status().lan_port,
                            })
                            .is_ok();
                    }
                    if discovery_started {
                        let discovery_status = service.status();
                        if discovery_status.discovering
                            && scan_generation != Some(discovery_status.discovery_generation)
                            && app.discovery().scan().is_ok()
                        {
                            scan_generation = Some(discovery_status.discovery_generation);
                        }
                        if let Ok(result) = app.discovery().peers() {
                            let mut present = std::collections::HashSet::new();
                            for peer in result.peers {
                                present.insert(peer.id.clone());
                                let observation = (peer.endpoint.clone(), peer.last_seen);
                                // Polling a cached resolution must not keep an offline
                                // device alive forever in the service discovery cache.
                                if seen.get(&peer.id) != Some(&observation) {
                                    if let Ok(endpoint) = peer.endpoint.parse() {
                                        service.discovered_peer(&peer.id, endpoint);
                                        seen.insert(peer.id, observation);
                                    }
                                }
                            }
                            seen.retain(|id, _| present.contains(id));
                        }
                    }
                }
            }
        }
    }
}
