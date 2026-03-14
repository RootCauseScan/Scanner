use crate::config::config_dir;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn error_log_path() -> std::path::PathBuf {
    config_dir().join("rootcause.error.log")
}

pub fn append_error_log(kind: &str, details: &str) {
    let path = error_log_path();
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }

    let mut file = match OpenOptions::new().create(true).append(true).open(path) {
        Ok(file) => file,
        Err(_) => return,
    };

    let _ = writeln!(file, "[{}] kind={kind}\n{details}\n---", now_unix_secs());
}
