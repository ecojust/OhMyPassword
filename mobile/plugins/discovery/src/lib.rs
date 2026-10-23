use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};
#[cfg(desktop)]
mod desktop;
mod error;
#[cfg(mobile)]
mod mobile;
mod models;
#[cfg(desktop)]
use desktop::Discovery;
pub use error::{Error, Result};
#[cfg(mobile)]
use mobile::Discovery;
pub use models::*;
pub trait DiscoveryExt<R: Runtime> {
    fn discovery(&self) -> &Discovery<R>;
}
impl<R: Runtime, T: Manager<R>> DiscoveryExt<R> for T {
    fn discovery(&self) -> &Discovery<R> {
        self.state::<Discovery<R>>().inner()
    }
}
/// No WebView commands: only the native shell starts discovery.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("discovery")
        .setup(|app, api| {
            #[cfg(mobile)]
            let discovery = mobile::init(app, api)?;
            #[cfg(desktop)]
            let discovery = desktop::init(app, api)?;
            app.manage(discovery);
            Ok(())
        })
        .build()
}
