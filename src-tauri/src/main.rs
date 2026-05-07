#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[tauri::command]
fn get_peer_id() -> String {
    "not yet implemented".to_string()
}

#[tauri::command]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_peer_id, get_version])
        .setup(|_app| {
            #[cfg(debug_assertions)]
            {
                use tauri::Manager;
                let app = _app;
                let window = app.get_webview_window("main").unwrap();
                window.open_devtools();
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_version_returns_value() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn get_peer_id_returns_placeholder() {
        let peer_id = get_peer_id();
        assert_eq!(peer_id, "not yet implemented");
    }
}
