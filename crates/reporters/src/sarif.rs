//! Conversion of findings to SARIF 2.1.0 specification.

use engine::Finding;
use loader::Severity;
use serde_sarif::sarif;

pub fn to_sarif(findings: &[Finding]) -> sarif::Sarif {
    let results: Vec<sarif::Result> = findings
        .iter()
        .map(|f| {
            let location = sarif::Location::builder()
                .physical_location(
                    sarif::PhysicalLocation::builder()
                        .artifact_location(
                            sarif::ArtifactLocation::builder()
                                .uri(f.file.display().to_string())
                                .build(),
                        )
                        .region(
                            sarif::Region::builder()
                                .start_line(f.line as i64)
                                .start_column(f.column as i64)
                                .build(),
                        )
                        .build(),
                )
                .build();

            let level = match f.severity {
                Severity::Info => sarif::ResultLevel::Note,
                Severity::Error => sarif::ResultLevel::Error,
                Severity::Critical => sarif::ResultLevel::Error,
                Severity::Low => sarif::ResultLevel::Note,
                Severity::Medium => sarif::ResultLevel::Warning,
                Severity::High => sarif::ResultLevel::Error,
            };

            sarif::Result::builder()
                .rule_id(f.rule_id.clone())
                .message(sarif::Message::builder().text(f.message.clone()).build())
                .level(level)
                .locations(vec![location])
                .build()
        })
        .collect();

    sarif::Sarif::builder()
        .version(serde_json::json!("2.1.0"))
        .schema(sarif::SCHEMA_URL.to_string())
        .runs(vec![sarif::Run::builder()
            .tool(
                sarif::Tool::builder()
                    // RootCause is the SAST tool name emitted in SARIF reports.
                    .driver(sarif::ToolComponent::builder().name("RootCause").build())
                    .build(),
            )
            .results(results)
            .build()])
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn generates_expected_sarif() {
        let id = blake3::hash(b"rule:src/main.rs:10:5").to_hex().to_string();
        let findings = vec![Finding {
            id,
            rule_id: "rule".into(),
            severity: Severity::High,
            file: PathBuf::from("src/main.rs"),
            line: 10,
            column: 5,
            excerpt: "let x = 1".into(),
            message: "dummy".into(),
            remediation: None,
            fix: None,
        }];

        let sarif = to_sarif(&findings);
        let rendered = serde_json::to_string_pretty(&sarif).unwrap();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/fixtures/sarif/basic.sarif.json");
        let expected = std::fs::read_to_string(path).unwrap();
        let rendered: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let expected: serde_json::Value = serde_json::from_str(&expected).unwrap();
        assert_eq!(rendered, expected);
    }
}
