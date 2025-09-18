use super::*;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;

struct VecWriter(Arc<Mutex<Vec<u8>>>);

impl Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

fn capture_logs<F: FnOnce()>(f: F) -> String {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let writer_buf = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || VecWriter(writer_buf.clone()))
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        f();
    });
    let bytes = buf.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn logs_warning_when_wasm_not_found() {
    let rule = CompiledRule {
        id: "test.wasm".into(),
        severity: Severity::Low,
        category: "test".into(),
        message: String::new(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::RegoWasm {
            wasm_path: "nonexistent.wasm".into(),
            entrypoint: "eval".into(),
        },
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["generic".into()],
    };
    let rules = RuleSet { rules: vec![rule] };
    let output = capture_logs(|| warmup_wasm_rules(&rules));
    assert!(output.contains("failed to read WASM"), "logs: {output}");
}

#[test]
fn logs_warning_on_invalid_wasm() {
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "not wasm").unwrap();
    let path = tmp.path().to_string_lossy().to_string();
    let rule = CompiledRule {
        id: "invalid.wasm".into(),
        severity: Severity::Low,
        category: "test".into(),
        message: String::new(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::RegoWasm {
            wasm_path: path,
            entrypoint: "eval".into(),
        },
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["generic".into()],
    };
    let rules = RuleSet { rules: vec![rule] };
    let output = capture_logs(|| warmup_wasm_rules(&rules));
    assert!(
        output.contains("failed to instantiate Rego WASM"),
        "logs: {output}"
    );
}
