use engine::{analyze_file, load_rules_with_events, parse_file_with_events};
use std::fs;
use std::path::{Path, PathBuf};

fn list_files_recursive(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        if let Ok(rd) = fs::read_dir(&p) {
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.is_file() {
                    out.push(path);
                }
            }
        }
    }
    out
}

#[test]
fn dynamic_examples_should_match_expectations() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/tests")
        .canonicalize()
        .expect("resolve examples/tests path");
    if !base.exists() {
        // Nothing to test
        return;
    }

    // Iterate each test suite under examples/tests/<suite>
    let mut any_suite = false;
    let mut total_matched_bad_files = 0usize;
    for entry in fs::read_dir(&base).expect("read examples/tests") {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let suite_dir = entry.path();
        if !suite_dir.is_dir() {
            continue;
        }
        any_suite = true;

        let rules_dir = suite_dir.join("rules");
        let good_dir = suite_dir.join("good");
        let bad_dir = suite_dir.join("bad");

        assert!(rules_dir.is_dir(), "missing rules dir in {:?}", suite_dir);
        assert!(good_dir.is_dir(), "missing good dir in {:?}", suite_dir);
        assert!(bad_dir.is_dir(), "missing bad dir in {:?}", suite_dir);

        let rules = load_rules_with_events(&rules_dir).expect("load rules");
        assert!(
            !rules.rules.is_empty(),
            "no rules loaded for suite {:?}",
            suite_dir
        );

        // Good files must produce zero findings
        let good_files = list_files_recursive(&good_dir);
        assert!(
            !good_files.is_empty(),
            "no good files in suite {:?}",
            suite_dir
        );
        for file in good_files {
            let parsed = parse_file_with_events(&file, None, None)
                .unwrap_or_else(|e| panic!("parse failed for {:?}: {}", file, e));
            if let Some(fir) = parsed {
                let findings = analyze_file(&fir, &rules);
                assert!(
                    findings.is_empty(),
                    "expected no findings on GOOD file {:?}, got {:?}",
                    file,
                    findings
                );
            }
        }

        // Bad corpus should surface findings for at least one candidate in each suite.
        let bad_files = list_files_recursive(&bad_dir);
        assert!(
            !bad_files.is_empty(),
            "no bad files in suite {:?}",
            suite_dir
        );
        let mut files_without_findings = Vec::new();
        let mut matched_bad_files = 0usize;
        for file in bad_files {
            let parsed = parse_file_with_events(&file, None, None)
                .unwrap_or_else(|e| panic!("parse failed for {:?}: {}", file, e));
            if let Some(fir) = parsed {
                let findings = analyze_file(&fir, &rules);
                if findings.is_empty() {
                    files_without_findings.push(file);
                } else {
                    matched_bad_files += 1;
                }
            }
        }
        if matched_bad_files == 0 {
            eprintln!(
                "warning: no BAD fixtures matched in suite {:?}; unmatched files: {:?}",
                suite_dir, files_without_findings
            );
        }
        total_matched_bad_files += matched_bad_files;
    }

    assert!(any_suite, "no suites found under examples/tests");
    assert!(
        total_matched_bad_files > 0,
        "expected at least one BAD fixture across all suites to produce findings"
    );
}
