use crate::{lock, protocol::*, Inner};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{net::SocketAddr, sync::Arc, thread, time::Duration};
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
        let properties = [("protocol", "1"), ("device_id", id.as_str())];
        let info = ServiceInfo::new(SERVICE, &id, &hostname, "", state.lan_port, &properties[..])
            .map_err(|_| crate::Error::Unavailable)?
            .enable_addr_auto();
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .map_err(|_| crate::Error::Unavailable)?;
        let receiver = daemon
            .browse(SERVICE)
            .map_err(|_| crate::Error::Unavailable)?;
        let worker = thread::Builder::new()
            .name("ohmypassword-discovery".into())
            .spawn(move || {
                while !*state.shutdown.borrow() {
                    if let Ok(ServiceEvent::ServiceResolved(info)) =
                        receiver.recv_timeout(Duration::from_millis(200))
                    {
                        if info.get_property_val_str("protocol") != Some("1") {
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
                                state.discovered_peer(peer, SocketAddr::new(*ip, info.get_port()));
                                break;
                            }
                        }
                    }
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
