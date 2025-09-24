//! User interface functions for the CLI.
//! Contains helpers for displaying headers, help, and other visual elements.

use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

use tracing::info;

pub fn print_header() {
    let version = env!("CARGO_PKG_VERSION");
    // Avoid panics when the version exceeds the expected width
    let spaces = " ".repeat(24usize.saturating_sub(version.len()));
    eprintln!(
        r#"
    ╭──────────────────────────────────────╮
    │                                      │
    │     🐾  ROOTCAUSE  SAST  TOOL  🐾    │
    │                                      │
    │     Static Analysis Security         │
    │     Testing for Multi-lang           │
    │     Version: {version}{spaces}│
    │                                      │
    ╰──────────────────────────────────────╯
"#
    );
}

pub fn print_plugin_status(plugins: &[String]) {
    if !plugins.is_empty() {
        for plugin in plugins {
            info!("Plugin '{}' loaded successfully", plugin);
        }
    }
}


/// The bar renders only when stderr is attached to a terminal. For
/// non-interactive environments (CI, redirections), progress updates
/// are skipped to avoid noisy logs.
pub struct ProgressBar {
    num_rules: usize,
    total_files: usize,
    files_completed: usize,
    width: usize,
    last_line_len: usize,
    min_interval: Duration,
    last_draw: Instant,
    start: Instant,
}

impl ProgressBar {
    /// Creates a new progress bar if the environment supports it.
    /// Returns `None` when there is nothing to track or when stderr is
    /// not attached to a terminal.
    pub fn new(num_rules: usize, total_files: usize) -> Option<Self> {
        if num_rules == 0 || total_files == 0 {
            return None;
        }
        if !io::stderr().is_terminal() {
            return None;
        }
        let min_interval = Duration::from_millis(75);
        let start = Instant::now();
        let mut bar = Self {
            num_rules,
            total_files,
            files_completed: 0,
            width: 28,
            last_line_len: 0,
            min_interval,
            last_draw: start,
            start,
        };
        bar.draw(true);
        bar.relax_throttle();
        Some(bar)
    }

    /// Increases the total number of files when transformers discover
    /// additional artefacts to analyse.
    pub fn extend_total_files(&mut self, additional_files: usize) {
        if additional_files == 0 {
            return;
        }
        self.total_files += additional_files;
        self.draw(true);
        self.relax_throttle();
    }

    /// Marks `count` files as processed and redraws the bar. The
    /// redraw is throttled to avoid flooding the terminal.
    pub fn increment_files(&mut self, count: usize) {
        if count == 0 {
            return;
        }
        self.files_completed = (self.files_completed + count).min(self.total_files);
        self.draw(false);
    }

    /// Forces a final draw and moves the cursor to the next line,
    /// making sure the bar leaves the terminal in a consistent state.
    pub fn finish(&mut self) {
        self.files_completed = self.total_files;
        self.draw(true);
        let mut stderr = io::stderr();
        let _ = writeln!(stderr);
        self.last_line_len = 0;
    }

    fn draw(&mut self, force: bool) {
        let now = Instant::now();
        if !force
            && self.last_line_len != 0
            && now.duration_since(self.last_draw) < self.min_interval
        {
            return;
        }
        self.last_draw = now;

        let total_ops = (self.num_rules as u128) * (self.total_files as u128);
        if total_ops == 0 {
            return;
        }
        let completed_files = self.files_completed.min(self.total_files);
        let completed_ops = (self.num_rules as u128) * (completed_files as u128);
        let percent = (completed_ops as f64 / total_ops as f64).clamp(0.0, 1.0);
        let filled = ((self.width as f64) * percent).round() as usize;
        let filled = filled.clamp(0, self.width);

        let bar = format!(
            "{}{}",
            "█".repeat(filled),
            "░".repeat(self.width.saturating_sub(filled))
        );
        let percent_display = percent * 100.0;
        let eta = self.estimate_eta(total_ops, completed_ops);
        let eta_display = eta.unwrap_or_else(|| "--:--".to_string());

        let message = format!(
            "▸ Scan progress |{bar}| {percent_display:6.2}% | ops {completed_ops}/{total_ops} | files {completed_files}/{total_files} | ETA {eta_display}",
            total_files = self.total_files,
        );

        let mut stderr = io::stderr();
        let padding = if self.last_line_len > message.len() {
            " ".repeat(self.last_line_len - message.len())
        } else {
            String::new()
        };
        let _ = write!(stderr, "\r{message}{padding}");
        let _ = stderr.flush();
        self.last_line_len = message.len();
    }

    fn relax_throttle(&mut self) {
        if let Some(adjusted) = self.last_draw.checked_sub(self.min_interval) {
            self.last_draw = adjusted;
        }
    }

    fn estimate_eta(&self, total_ops: u128, completed_ops: u128) -> Option<String> {
        if completed_ops == 0 {
            return None;
        }
        if completed_ops >= total_ops {
            return Some("00:00".to_string());
        }
        let elapsed = self.start.elapsed();
        if elapsed.as_secs_f64() < f64::EPSILON {
            return None;
        }
        let ops_per_second = completed_ops as f64 / elapsed.as_secs_f64();
        if ops_per_second <= 0.0 {
            return None;
        }
        let remaining_ops = (total_ops - completed_ops) as f64;
        let remaining_seconds = remaining_ops / ops_per_second;
        let eta = Duration::from_secs_f64(remaining_seconds);
        Some(format_duration(eta))
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() == 0 {
        return "00:00".to_string();
    }
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    if hours > 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}
