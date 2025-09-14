use crate::{write_findings, Format, PluginSummary, ScanInfo};
use engine::Finding;

#[test]
fn text_report_includes_plugins() {
    let info = ScanInfo {
        rules_loaded: 0,
        files_analyzed: 0,
        duration_ms: 0,
        failed_files: 0,
        plugins: vec![PluginSummary {
            name: "demo".into(),
            version: Some("1.0".into()),
            capabilities: vec!["report".into(), "rules".into()],
        }],
    };
    let mut buf = Vec::new();
    let findings: Vec<Finding> = Vec::new();
    write_findings(&mut buf, &findings, Format::Text, Some(&info)).unwrap();
    let rendered = String::from_utf8(buf).unwrap();
    assert!(rendered.contains("Plugins"));
    assert!(rendered.contains("demo"));
    assert!(rendered.contains("report, rules"));
}
