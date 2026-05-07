#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// Maximum number of IPC commands per window per second.
const IPC_RATE_LIMIT: u32 = 30;

/// Per-window IPC rate limiter state.
struct RateLimiter {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
        }
    }

    fn check(&mut self) -> Result<(), String> {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.count = 0;
            self.window_start = now;
        }
        self.count += 1;
        if self.count > IPC_RATE_LIMIT {
            return Err("rate limit exceeded".to_string());
        }
        Ok(())
    }
}

/// Global rate limiter. In production, this should be per-window.
static RATE_LIMITER: LazyLock<std::sync::Mutex<RateLimiter>> =
    LazyLock::new(|| std::sync::Mutex::new(RateLimiter::new()));

/// Enforce rate limit before handling any IPC command.
fn check_rate_limit() -> Result<(), String> {
    RATE_LIMITER
        .lock()
        .map_err(|_| "rate limiter lock poisoned")?
        .check()
}

/// Validate that a string input is within acceptable length bounds.
fn validate_string_input(input: &str, max_len: usize, field_name: &str) -> Result<String, String> {
    if input.len() > max_len {
        return Err(format!("{field_name} exceeds maximum length ({max_len})"));
    }
    Ok(input.to_string())
}

#[tauri::command]
fn get_peer_id() -> Result<String, String> {
    check_rate_limit()?;
    // TODO: Wire to pqnodium-core identity
    Ok("not yet implemented".to_string())
}

#[tauri::command]
fn get_version() -> Result<String, String> {
    check_rate_limit()?;
    Ok(env!("CARGO_PKG_VERSION").to_string())
}

#[tauri::command]
fn get_status() -> Result<String, String> {
    check_rate_limit()?;
    // TODO: Wire to pqnodium-p2p node status
    Ok("disconnected".to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_peer_id, get_version, get_status])
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
        let version = get_version().unwrap();
        assert!(!version.is_empty());
    }

    #[test]
    fn get_peer_id_returns_placeholder() {
        let peer_id = get_peer_id().unwrap();
        assert_eq!(peer_id, "not yet implemented");
    }

    #[test]
    fn get_status_returns_disconnected() {
        let status = get_status().unwrap();
        assert_eq!(status, "disconnected");
    }

    #[test]
    fn validate_string_normal() {
        assert!(validate_string_input("hello", 100, "test").is_ok());
    }

    #[test]
    fn validate_string_too_long() {
        let long = "x".repeat(101);
        assert!(validate_string_input(&long, 100, "test").is_err());
    }

    #[test]
    fn rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new();
        for _ in 0..IPC_RATE_LIMIT {
            assert!(limiter.check().is_ok());
        }
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::new();
        for _ in 0..IPC_RATE_LIMIT {
            let _ = limiter.check();
        }
        assert!(limiter.check().is_err());
    }
}
