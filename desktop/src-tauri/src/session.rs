//! Application-interface authentication is distinct from the browser's vault
//! session. Lifecycle transitions are serialized, but KDF work never holds the
//! lifecycle gate; a full lock can invalidate a pending authentication.
use ohmypassword_core::{Status, Vault};
use ohmypassword_service::{Service, ServiceStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(crate) type NativeResult<T> = std::result::Result<T, String>;
const ENDED: &str = "密码库界面已锁定，请重新解锁";

fn hide_interface_metadata(status: &mut Status) {
    status.device_name = "此设备".into();
    status.entry_count = 0;
    status.peer_count = 0;
}

pub(crate) struct AppState {
    pub vault: Arc<Mutex<Vault>>,
    pub service: Option<Arc<Service>>,
    pub service_error: Option<String>,
    pub activity: Mutex<Instant>,
    pub generation: AtomicU64,
    pub stopping: AtomicBool,
    interface_locked: AtomicBool,
    foreground: AtomicBool,
    lifecycle: Mutex<()>,
    authentication: Mutex<()>,
}

pub(crate) struct InterfaceSnapshot {
    pub session_generation: u64,
    pub interface_locked: bool,
    pub browser_available: bool,
    pub vault: Status,
    pub service: Option<ServiceStatus>,
}

impl AppState {
    /// The caller opens a locked vault and pauses its service before exposing
    /// this state to IPC. No key or browser authorization is restored at launch.
    pub fn new(
        vault: Arc<Mutex<Vault>>,
        service: Option<Arc<Service>>,
        service_error: Option<String>,
    ) -> Self {
        Self {
            vault,
            service,
            service_error,
            activity: Mutex::new(Instant::now()),
            generation: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
            interface_locked: AtomicBool::new(true),
            foreground: AtomicBool::new(true),
            lifecycle: Mutex::new(()),
            authentication: Mutex::new(()),
        }
    }

    pub fn interface_locked(&self) -> bool {
        self.interface_locked.load(Ordering::SeqCst)
    }

    pub fn touch(&self) {
        if !self.interface_locked() {
            if let Ok(mut time) = self.activity.lock() {
                *time = Instant::now();
            }
        }
    }

    fn available(&self) -> bool {
        !self.stopping.load(Ordering::SeqCst) && self.foreground.load(Ordering::SeqCst)
    }

    fn check_interface(&self, generation: u64) -> NativeResult<()> {
        if !self.available()
            || self.interface_locked()
            || self.generation.load(Ordering::SeqCst) != generation
        {
            Err(ENDED.into())
        } else {
            Ok(())
        }
    }

    pub fn interface_ticket(&self, expected_generation: u64) -> NativeResult<u64> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| ENDED)?;
        let generation = self.generation.load(Ordering::SeqCst);
        if expected_generation != generation {
            return Err(ENDED.into());
        }
        self.check_interface(generation)?;
        Ok(generation)
    }

    pub fn authentication_ticket(&self, expected_generation: u64) -> NativeResult<u64> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| ENDED)?;
        if !self.available() {
            return Err("应用已暂停，请回到前台后解锁".into());
        }
        let generation = self.generation.load(Ordering::SeqCst);
        if expected_generation != generation {
            return Err(ENDED.into());
        }
        Ok(generation)
    }

    pub fn ui_operation<T>(
        &self,
        generation: u64,
        operation: impl FnOnce(&mut Vault) -> ohmypassword_core::Result<T>,
    ) -> NativeResult<T> {
        let mut vault = self.vault.lock().map_err(|_| "密码库暂不可用")?;
        self.check_interface(generation)?;
        let value = operation(&mut vault).map_err(|error| error.to_string())?;
        // Reject late UI results. A soft lock must never erase the browser's
        // live key; a concurrent full lock clears it after this mutex is freed.
        self.check_interface(generation)?;
        Ok(value)
    }

    pub fn with_service<T>(
        &self,
        expected_generation: u64,
        operation: impl FnOnce(&Service) -> ohmypassword_service::Result<T>,
    ) -> NativeResult<T> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| ENDED)?;
        self.check_interface(expected_generation)?;
        let service = self.service.as_ref().ok_or("局域网服务未启动")?;
        operation(service).map_err(|error| error.to_string())
    }

    pub fn authenticate(
        &self,
        generation: u64,
        password: &str,
        device_name: Option<&str>,
    ) -> NativeResult<Status> {
        // Serialize the entire authentication, including stale cold-key cleanup.
        // A newer attempt cannot start using a key awaiting that cleanup.
        let _authentication = self.authentication.lock().map_err(|_| ENDED)?;
        let was_locked = {
            let mut vault = self.vault.lock().map_err(|_| "密码库暂不可用")?;
            if self.generation.load(Ordering::SeqCst) != generation || !self.available() {
                return Err(ENDED.into());
            }
            let was_locked = vault.status().locked;
            match device_name {
                Some(name) => vault.create(password, name).map(|_| ()),
                None if was_locked => vault.unlock(password).map(|_| ()),
                None => vault.verify_password(password),
            }
            .map_err(|error| error.to_string())?;
            was_locked
        };
        self.finish_authentication(generation, was_locked)
    }

    fn finish_authentication(&self, generation: u64, was_locked: bool) -> NativeResult<Status> {
        // Never hold the vault mutex while calling Service: its lock order is
        // sessions -> vault. The gate covers both validation and service resume.
        let _lifecycle = self.lifecycle.lock().map_err(|_| ENDED)?;
        if self.generation.load(Ordering::SeqCst) != generation || !self.available() {
            if was_locked {
                if let Some(service) = &self.service {
                    service.pause();
                }
                self.vault.lock().map_err(|_| "密码库暂不可用")?.lock();
            }
            return Err(ENDED.into());
        }
        if self
            .vault
            .lock()
            .map_err(|_| "密码库暂不可用")?
            .status()
            .locked
        {
            return Err(ENDED.into());
        }
        if let Some(service) = &self.service {
            service.resume();
        }
        self.interface_locked.store(false, Ordering::SeqCst);
        self.touch();
        Ok(self.vault.lock().map_err(|_| "密码库暂不可用")?.status())
    }

    fn lock_inside_lifecycle(&self, fully: bool) -> NativeResult<Status> {
        self.interface_locked.store(true, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst);
        if let Some(service) = &self.service {
            if fully {
                service.pause();
            } else {
                service.pause_lan();
            }
        }
        let mut vault = self.vault.lock().map_err(|_| "密码库暂不可用")?;
        let mut status = if fully { vault.lock() } else { vault.status() };
        hide_interface_metadata(&mut status);
        Ok(status)
    }

    pub fn lock_interface(&self) -> NativeResult<Status> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| ENDED)?;
        self.lock_inside_lifecycle(false)
    }

    pub fn fully_lock(&self) -> NativeResult<Status> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| ENDED)?;
        self.lock_inside_lifecycle(true)
    }

    #[cfg(any(test, target_os = "android", target_os = "ios"))]
    pub fn suspend(&self) -> NativeResult<Status> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| ENDED)?;
        self.foreground.store(false, Ordering::SeqCst);
        self.lock_inside_lifecycle(true)
    }

    #[cfg(any(test, target_os = "android", target_os = "ios"))]
    pub fn resume_foreground(&self) {
        if let Ok(_lifecycle) = self.lifecycle.lock() {
            if !self.stopping.load(Ordering::SeqCst) {
                self.foreground.store(true, Ordering::SeqCst);
            }
        }
    }

    pub fn stop(&self) -> NativeResult<Status> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| ENDED)?;
        self.stopping.store(true, Ordering::SeqCst);
        self.foreground.store(false, Ordering::SeqCst);
        self.lock_inside_lifecycle(true)
    }

    pub fn snapshot(&self) -> NativeResult<InterfaceSnapshot> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| ENDED)?;
        let interface_locked = self.interface_locked();
        let mut vault = self.vault.lock().map_err(|_| "密码库暂不可用")?.status();
        // Preserve the actual encrypted state but do not expose vault metadata
        // or remembered LAN peers through a locked interface's status polling.
        if interface_locked {
            hide_interface_metadata(&mut vault);
        }
        let browser_available = self
            .service
            .as_ref()
            .is_some_and(|service| service.browser_available());
        let service = if interface_locked {
            None
        } else {
            self.service.as_ref().map(|service| service.status())
        };
        Ok(InterfaceSnapshot {
            session_generation: self.generation.load(Ordering::SeqCst),
            interface_locked,
            browser_available,
            vault,
            service,
        })
    }
}

#[cfg(test)]
mod tests;
