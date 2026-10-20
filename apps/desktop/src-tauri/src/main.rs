// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    morphgate_desktop_lib::tun_helper_if_requested();
    morphgate_desktop_lib::run();
}
