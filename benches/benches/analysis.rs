use criterion::{black_box, criterion_group, criterion_main, Criterion};
use loader::load_rules;
use parsers::{parse_file, parse_str};
use std::time::Duration;
use std::{fs, path::PathBuf};

use engine::{reset_rule_cache, EngineConfig};

fn bench_language(c: &mut Criterion, name: &str, fixture: &str, rules_dir: &str) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let file = root.join(fixture);
    let rules_dir = root.join(rules_dir);
    let rules = load_rules(&rules_dir).expect("load rules");
    let fir = parse_file(&file, None, None).unwrap().expect("parse file");
    c.bench_function(name, |b| {
        b.iter(|| engine::analyze_file(black_box(&fir), black_box(&rules)))
    });
}

struct LanguageBench {
    name: &'static str,
    fixture: &'static str,
    rules: &'static str,
}

const LANGUAGE_BENCHES: &[LanguageBench] = &[
    LanguageBench {
        name: "analyze_dockerfile",
        fixture: "../examples/fixtures/docker/docker.no-add/bad/Dockerfile",
        rules: "../examples/rules/docker",
    },
    LanguageBench {
        name: "analyze_typescript",
        fixture: "../examples/fixtures/typescript/ts.no-eval/bad.ts",
        rules: "../examples/rules/typescript",
    },
    LanguageBench {
        name: "analyze_python",
        fixture: "../examples/fixtures/python/py.no-eval/bad.py",
        rules: "../examples/rules/python",
    },
    LanguageBench {
        name: "analyze_terraform",
        fixture: "../examples/fixtures/terraform/tf.no-public-acl/bad.tf",
        rules: "../examples/rules/terraform",
    },
    LanguageBench {
        name: "analyze_javascript",
        fixture: "../examples/fixtures/javascript/js.no-eval/bad.js",
        rules: "../examples/rules/javascript",
    },
    LanguageBench {
        name: "analyze_java",
        fixture: "../examples/fixtures/java/java.no-system-exit/bad.java",
        rules: "../examples/rules/java",
    },
    LanguageBench {
        name: "analyze_php",
        fixture: "../examples/fixtures/php/echoed-request/bad.php",
        rules: "../examples/rules/php",
    },
    LanguageBench {
        name: "analyze_rust",
        fixture: "../examples/fixtures/rust/rs.no-unwrap/bad.rs",
        rules: "../examples/rules/rust",
    },
];

fn bench_parsers(c: &mut Criterion) {
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../examples/fixtures/yaml/yaml.no-plaintext-password/bad.yaml");
    let content = fs::read_to_string(&file).expect("read file");
    c.bench_function("parse_yaml", |b| {
        b.iter(|| parse_str(black_box(&content)).unwrap())
    });
}

fn bench_engine(c: &mut Criterion) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let file = root.join("../examples/fixtures/yaml/yaml.no-plaintext-password/bad.yaml");
    let rules_dir = root.join("../examples/rules/yaml");
    let rules = load_rules(&rules_dir).expect("load rules");
    let fir = parse_file(&file, None, None).unwrap().expect("parse file");
    c.bench_function("analyze_yaml", |b| {
        b.iter(|| engine::analyze_file(black_box(&fir), black_box(&rules)))
    });
}

fn bench_rule_timeout(c: &mut Criterion) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let file = root.join("../examples/fixtures/yaml/yaml.no-plaintext-password/bad.yaml");
    let rules_dir = root.join("../examples/rules/yaml");
    let rules = load_rules(&rules_dir).expect("load rules");
    let fir = parse_file(&file, None, None).unwrap().expect("parse file");
    let files = vec![fir.clone()];
    let cfg = EngineConfig {
        file_timeout: None,
        rule_timeout: Some(Duration::from_millis(1)),
        baseline: None,
        suppress_comment: None,
    };
    c.bench_function("analyze_yaml_timeout", |b| {
        b.iter(|| {
            engine::analyze_files_with_config(
                black_box(&files),
                black_box(&rules),
                black_box(&cfg),
                None,
                None,
            )
        })
    });
}

fn bench_engine_cached(c: &mut Criterion) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let file = root.join("../examples/fixtures/yaml/yaml.no-plaintext-password/bad.yaml");
    let rules_dir = root.join("../examples/rules/yaml");
    let rules = load_rules(&rules_dir).expect("load rules");
    let fir = parse_file(&file, None, None).unwrap().expect("parse file");
    c.bench_function("analyze_yaml_cached", |b| {
        reset_rule_cache();
        engine::analyze_file(black_box(&fir), black_box(&rules));
        b.iter(|| engine::analyze_file(black_box(&fir), black_box(&rules)))
    });
}

fn bench_languages(c: &mut Criterion) {
    for bench in LANGUAGE_BENCHES {
        bench_language(c, bench.name, bench.fixture, bench.rules);
    }
}

criterion_group!(
    benches,
    bench_parsers,
    bench_engine,
    bench_rule_timeout,
    bench_engine_cached,
    bench_languages
);
criterion_main!(benches);
