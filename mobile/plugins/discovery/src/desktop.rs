use crate::models::*;
use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};
pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<Discovery<R>> {
    Ok(Discovery(app.clone()))
}
pub struct Discovery<R: Runtime>(AppHandle<R>);
impl<R: Runtime> Discovery<R> {
    pub fn start(&self, _payload: StartRequest) -> crate::Result<()> {
        let _ = &self.0;
        Ok(())
    }
    pub fn stop(&self) -> crate::Result<()> {
        Ok(())
    }
    pub fn scan(&self) -> crate::Result<()> {
        Ok(())
    }
    pub fn peers(&self) -> crate::Result<PeersResponse> {
        Ok(PeersResponse::default())
    }
}
