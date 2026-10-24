use crate::{lock, protocol::*, Inner};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{
    net::SocketAddr,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
const SERVICE: &str = "_ohmypassword._tcp.local.";
pub(super) struct Discovery {
    daemon: ServiceDaemon,
    fullname: String,
    thread: Option<thread::JoinHandle<()>>,
}
impl Discovery {
    pub fn start(state: Arc<Inner>) -> crate::Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|_| crate::Error::Unavailable)?;
        let id = lock(&state.vault)?.status().device_id;
        let hostname = format!("ohmypassword-{id}.local.");
        let properties = [("protocol", "3"), ("device_id", id.as_str())];
        let info = ServiceInfo::new(SERVICE, &id, &hostname, "", state.lan_port, &properties[..])
            .map_err(|_| crate::Error::Unavailable)?
            .enable_addr_auto();
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .map_err(|_| crate::Error::Unavailable)?;
        let browser = daemon.clone();
        let worker = thread::Builder::new()
            .name("ohmypassword-discovery".into())
            .spawn(move || {
                let mut generation = 0;
                while !*state.shutdown.borrow() {
                    let requested = state
                        .status
                        .lock()
                        .map(|s| s.discovery_generation)
                        .unwrap_or(generation);
                    if state.ensure_active().is_err() || requested == generation {
                        thread::sleep(Duration::from_millis(150));
                        continue;
                    }
                    generation = requested;
                    let Ok(receiver) = browser.browse(SERVICE) else {
                        thread::sleep(Duration::from_millis(150));
                        continue;
                    };
                    let until = Instant::now() + Duration::from_secs(20);
                    while Instant::now() < until
                        && state.ensure_active().is_ok()
                        && !*state.shutdown.borrow()
                    {
                        if state
                            .status
                            .lock()
                            .is_ok_and(|s| s.discovery_generation != generation)
                        {
                            break;
                        }
                        if let Ok(ServiceEvent::ServiceResolved(info)) =
                            receiver.recv_timeout(Duration::from_millis(150))
                        {
                            if info.get_property_val_str("protocol") != Some("3") {
                                continue;
                            }
                            let Some(peer) = info.get_property_val_str("device_id") else {
                                continue;
                            };
                            if !valid_id(peer) || peer == id {
                                continue;
                            }
                            for ip in info.get_addresses() {
                                if ip.is_ipv4() && local_ip(*ip) {
                                    state.discovered_peer(
                                        peer,
                                        "",
                                        SocketAddr::new(*ip, info.get_port()),
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    let _ = browser.stop_browse(SERVICE);
                }
            })?;
        Ok(Self {
            daemon,
            fullname,
            thread: Some(worker),
        })
    }
}
impl Drop for Discovery {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.stop_browse(SERVICE);
        let _ = self.daemon.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
