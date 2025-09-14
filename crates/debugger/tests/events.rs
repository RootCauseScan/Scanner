use debugger::{EventFormat, FormatterSink};
use engine::{
    analyze_file, load_rules_with_events, parse_file_with_events, reset_rule_cache, set_debug_sink,
};
use std::path::Path;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn debug_events_text() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset_rule_cache();
    let sink = FormatterSink::new(EventFormat::Text);
    set_debug_sink(Some(Box::new(sink.clone())));
    let rules =
        load_rules_with_events(Path::new("../../examples/rules/python/py.no-exec.yaml")).unwrap();
    let ir = parse_file_with_events(
        Path::new("../../examples/fixtures/python/py.no-exec/bad.py"),
        None,
        None,
    )
    .unwrap()
    .unwrap();
    analyze_file(&ir, &rules);
    set_debug_sink(None);
    insta::assert_snapshot!(sink.output());
}

#[test]
fn debug_events_json() {
    let _guard = TEST_LOCK.lock().unwrap();
    reset_rule_cache();
    let sink = FormatterSink::new(EventFormat::Json);
    set_debug_sink(Some(Box::new(sink.clone())));
    let rules =
        load_rules_with_events(Path::new("../../examples/rules/python/py.no-exec.yaml")).unwrap();
    let ir = parse_file_with_events(
        Path::new("../../examples/fixtures/python/py.no-exec/bad.py"),
        None,
        None,
    )
    .unwrap()
    .unwrap();
    analyze_file(&ir, &rules);
    set_debug_sink(None);
    insta::assert_snapshot!(sink.output());
}
