#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    ohmypassword_desktop::run(tauri::generate_context!());
}
