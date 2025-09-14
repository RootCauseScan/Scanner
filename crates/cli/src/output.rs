use clap::ValueEnum;
use engine::Finding;
use reporters::{self, ScanInfo};

/// Supported output formats for scan results.
#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

impl std::str::FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            "sarif" => Ok(Format::Sarif),
            _ => Err("invalid format".into()),
        }
    }
}

impl From<Format> for reporters::Format {
    fn from(fmt: Format) -> Self {
        match fmt {
            Format::Text => reporters::Format::Text,
            Format::Json => reporters::Format::Json,
            Format::Sarif => reporters::Format::Sarif,
        }
    }
}

pub fn print_findings(findings: &[Finding], fmt: Format, info: &ScanInfo) -> anyhow::Result<()> {
    reporters::print_findings(findings, fmt.into(), Some(info))?;
    Ok(())
}
