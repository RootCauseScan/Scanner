//! Formatters for findings in text, JSON and SARIF.
//! Provide human and tool-friendly output.

use engine::Finding;
use loader::Severity;
use serde::Serialize;
use std::io::{self, Write};

mod sarif;

/// Returns the severity colored with simple ANSI codes.
/// Adds no external dependencies.
fn color_severity(sev: Severity) -> String {
    let (code, text) = match sev {
        Severity::Info => ("\x1b[32m", "INFO"),
        Severity::Error => ("\x1b[31m", "ERROR"),
        Severity::Critical => ("\x1b[31m", "CRITICAL"),
        Severity::Low => ("\x1b[32m", "LOW"),
        Severity::Medium => ("\x1b[33m", "MEDIUM"),
        Severity::High => ("\x1b[31m", "HIGH"),
    };
    format!("{code}{text}\x1b[0m")
}

/// Crea un recuadro simple
fn simple_box(title: &str) -> String {
    let width = title.len() + 2;
    format!(
        "╭{}╮\n│ {} │\n╰{}╯\n",
        "─".repeat(width),
        title,
        "─".repeat(width)
    )
}

/// Crea estadísticas estilo Semgrep con recuadros elegantes
fn create_semgrep_style_stats(info: &ScanInfo) -> String {
    let mut output = String::new();

    // Header principal con tabs para consistencia
    output.push_str("╭─────────────────╮\n");
    output.push_str("│ Analysis Status │\n");
    output.push_str("╰─────────────────╯\n");
    output.push('\n');

    // Scan information
    output.push_str(&format!(
        "    Scanning {} files with {} rules:\n\n",
        info.files_analyzed, info.rules_loaded
    ));

    // Rules table with cleaner style
    output.push_str("    RULES\n");
    output.push_str(
        "    ──────────────────────────────────────────────────────────────────────────────\n",
    );
    output.push('\n');
    output.push_str("    Type           Rules  Files                Origin\n");
    output.push_str(
        "    ──────────────────────────────────────────────────────────────────────────────\n",
    );
    output.push_str(&format!(
        "    Security           {}     {}                RootCause\n",
        info.rules_loaded, info.files_analyzed
    ));
    output.push('\n');

    // Tabla de rendimiento con estilo más limpio
    output.push_str("    PERFORMANCE\n");
    output.push_str(
        "    ──────────────────────────────────────────────────────────────────────────────\n",
    );
    output.push('\n');
    output.push_str("    Metric                    Value\n");
    output.push_str(
        "    ──────────────────────────────────────────────────────────────────────────────\n",
    );
    output.push_str(&format!(
        "    Duration                  {}ms\n",
        info.duration_ms
    ));
    output.push_str(&format!(
        "    Failed files              {}\n",
        info.failed_files
    ));
    output.push_str(&format!(
        "    Success rate              {:.1}%\n",
        if info.files_analyzed > 0 {
            ((info.files_analyzed - info.failed_files) as f64 / info.files_analyzed as f64) * 100.0
        } else {
            0.0
        }
    ));

    if !info.plugins.is_empty() {
        output.push('\n');
        output.push_str("╭─────────╮\n");
        output.push_str("│ Plugins │\n");
        output.push_str("╰─────────╯\n");
        output.push('\n');
        output.push_str("    Name             Version   Capabilities\n");
        output.push_str(
            "    ──────────────────────────────────────────────────────────────────────────────\n",
        );
        for p in &info.plugins {
            let ver = p.version.as_deref().unwrap_or("-");
            output.push_str(&format!(
                "    {:<16} {:<9} {}\n",
                p.name,
                ver,
                p.capabilities.join(", ")
            ));
        }
    }

    output
}

#[derive(Debug, Clone, Copy)]
/// Supported formats for printing findings.
pub enum Format {
    /// Human-readable output in plain text.
    Text,
    /// JSON structure for integrations.
    Json,
    /// Report conforming to the SARIF specification.
    Sarif,
}

#[derive(Serialize)]
/// Simple wrapper used when serialising to JSON.
struct FindingsOut<'a> {
    findings: &'a [Finding],
    total: usize,
}

/// Summary information about loaded plugins.
#[derive(Debug, Clone)]
pub struct PluginSummary {
    pub name: String,
    pub version: Option<String>,
    pub capabilities: Vec<String>,
}

/// Additional information to display in statistics
pub struct ScanInfo {
    pub rules_loaded: usize,
    pub files_analyzed: usize,
    pub duration_ms: u64,
    pub failed_files: usize,
    pub plugins: Vec<PluginSummary>,
}

/// Prints findings in the selected format.
///
/// # Example
/// ```
/// use reporters::{print_findings, Format, ScanInfo, PluginSummary};
/// let info = ScanInfo {
///     rules_loaded: 10,
///     files_analyzed: 5,
///     duration_ms: 1000,
///     failed_files: 0,
///     plugins: vec![PluginSummary {
///         name: "demo".into(),
///         version: Some("1.0".into()),
///         capabilities: vec!["rules".into()],
///     }],
/// };
/// print_findings(&[], Format::Text, Some(&info)).unwrap();
/// ```
pub fn print_findings(
    findings: &[Finding],
    fmt: Format,
    scan_info: Option<&ScanInfo>,
) -> io::Result<()> {
    let mut out = io::stdout();
    write_findings(&mut out, findings, fmt, scan_info)
}

/// Writes findings to a generic `Write`, used for tests.
pub(crate) fn write_findings<W: Write>(
    out: &mut W,
    findings: &[Finding],
    fmt: Format,
    scan_info: Option<&ScanInfo>,
) -> io::Result<()> {
    match fmt {
        Format::Text => {
            // Statistics section (if information is available)
            if let Some(info) = scan_info {
                // Show Semgrep style
                writeln!(out, "{}", create_semgrep_style_stats(info))?;
                writeln!(out)?;
            }

            // Results section
            if findings.is_empty() {
                writeln!(out, "{}", simple_box("Results"))?;
                writeln!(out, "✔ No issues found.")?;
            } else {
                writeln!(out, "{}", simple_box("Results"))?;
                writeln!(out, "⚠ Found {} issue(s):\n", findings.len())?;
                for f in findings {
                    writeln!(
                        out,
                        "{} {}:{} {}",
                        color_severity(f.severity),
                        f.file.display(),
                        f.line,
                        f.rule_id
                    )?;
                    writeln!(out, "    {}", f.message)?;
                    writeln!(out, "    ↳  {}", f.excerpt.trim())?;
                    if let Some(r) = &f.remediation {
                        writeln!(out, "    • Remediation: {r}")?;
                    }
                    if let Some(fx) = &f.fix {
                        writeln!(out, "    • Fix: {fx}")?;
                    }
                    writeln!(out)?;
                }
                writeln!(out, "Total: {}", findings.len())?;
            }
        }
        Format::Json => {
            let json = FindingsOut {
                findings,
                total: findings.len(),
            };
            serde_json::to_writer_pretty(&mut *out, &json)?;
            writeln!(out)?;
        }
        Format::Sarif => {
            let sarif = sarif::to_sarif(findings);
            serde_json::to_writer_pretty(&mut *out, &sarif)?;
            writeln!(out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
