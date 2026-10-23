#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
fn main() {
    ohmypassword_desktop::run(tauri::generate_context!());
}
