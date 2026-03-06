use debugger::{EventFormat, FormatterSink};
use engine::{
    analyze_file, load_rules_with_events, parse_file_with_events, reset_rule_cache, set_debug_sink,
};
use std::path::Path;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn normalize_text_output(raw: String) -> String {
    raw.lines()
        .map(|line| {
            if let Some(rest) = line.strip_prefix("[+ ") {
                if let Some((_elapsed, tail)) = rest.split_once("] ") {
                    return format!("[+ <elapsed>] {tail}");
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_json_output(raw: String) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return raw;
    };

    if let Some(events) = value.as_array_mut() {
        for event in events {
            if let Some(obj) = event.as_object_mut() {
                obj.insert("elapsed_ms".to_string(), serde_json::json!(0));
            }
        }
    }

    serde_json::to_string_pretty(&value).unwrap_or(raw)
}

#[test]
fn debug_events_text() {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
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
    insta::assert_snapshot!(normalize_text_output(sink.output()));
}

#[test]
fn debug_events_json() {
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
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
    insta::assert_snapshot!(normalize_json_output(sink.output()));
}
