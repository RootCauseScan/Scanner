use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn run_command(cmd: &str, args: &[&str]) -> std::io::Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| std::io::Error::new(e.kind(), format!("failed to run {cmd}: {e}")))?;
    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "{cmd} exited with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn current_utc_iso8601() -> String {
    fn is_leap(year: i32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut days = now.as_secs() / 86_400;
    let secs = now.as_secs() % 86_400;
    let hours = secs / 3_600;
    let minutes = (secs % 3_600) / 60;
    let seconds = secs % 60;

    let mut year: i32 = 1970;
    loop {
        let leap = if is_leap(year) { 366 } else { 365 } as u64;
        if days >= leap {
            days -= leap;
            year += 1;
        } else {
            break;
        }
    }

    let month_lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0usize;
    let mut day = days as i64;
    while month < 12 {
        let mut len = month_lengths[month] as i64;
        if month == 1 && is_leap(year) {
            len = 29;
        }
        if day < len {
            break;
        }
        day -= len;
        month += 1;
    }
    let month = month as u32 + 1;
    let day = day as u32 + 1;

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn main() -> std::io::Result<()> {
    // gather metadata
    let commit = run_command("git", &["rev-parse", "HEAD"])?;
    let date = current_utc_iso8601();
    let rustc = run_command("rustc", &["--version"])?;

    // collect reports
    let mut links = Vec::new();
    if let Ok(entries) = fs::read_dir("target/criterion") {
        for entry in entries.flatten() {
            if entry.file_type()?.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let path = entry.path().join("report/index.html");
                if path.exists() {
                    let href = format!("{name}/report/index.html");
                    links.push((name, href));
                }
            }
        }
    }
    links.sort_by(|a, b| a.0.cmp(&b.0));

    // build html
    let mut html = String::new();
    html.push_str(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Benchmarks</title></head><body>",
    );
    html.push_str(&format!(
        "<p>commit: {commit}</p><p>date: {date}</p><p>rustc: {rustc}</p><ul>"
    ));
    for (name, href) in links {
        html.push_str(&format!("<li><a href=\"{href}\">{name}</a></li>"));
    }
    html.push_str("</ul></body></html>");

    fs::write("target/criterion/index.html", html)?;
    Ok(())
}
