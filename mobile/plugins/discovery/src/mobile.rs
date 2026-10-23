use crate::models::*;
use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};
#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_discovery);
pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<Discovery<R>> {
    #[cfg(target_os = "android")]
    let handle =
        api.register_android_plugin("com.ecojust.ohmypassword.discovery", "DiscoveryPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_discovery)?;
    Ok(Discovery(handle))
}
pub struct Discovery<R: Runtime>(PluginHandle<R>);
impl<R: Runtime> Discovery<R> {
    pub fn start(&self, payload: StartRequest) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<serde_json::Value>("start", payload)
            .map(|_| ())
            .map_err(Into::into)
    }
    pub fn stop(&self) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<serde_json::Value>("stop", ())
            .map(|_| ())
            .map_err(Into::into)
    }
    pub fn peers(&self) -> crate::Result<PeersResponse> {
        self.0.run_mobile_plugin("peers", ()).map_err(Into::into)
    }
}
