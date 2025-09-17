//! Level 2 focuses on resolving imports and aliases into canonical names.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::{catalog as catalog_module, languages::java::parse_java_project, parse_java};
use ir::{FileIR, SymbolKind};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/java/java.aliasing")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "java".into());
    parse_java(&content, &mut fir).expect("parse java fixture");
    fir
}

fn write_java_file(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create directories for java fixture");
    }
    fs::write(path, contents).expect("write java fixture");
}

// Static import allows calling method without class prefix while keeping original call.
#[test]
fn l2_aliasing_y_canonicalizacion() {
    let fir = parse_fixture("good.java");
    assert!(fir
        .nodes
        .iter()
        .any(|n| n.path == "call.Collections.emptyList"));
    assert!(fir.nodes.iter().any(|n| n.path == "call.emptyList"));
}

// Without import, only unqualified call remains.
#[test]
fn l2_aliasing_y_canonicalizacion_invalido() {
    let fir = parse_fixture("bad.java");
    assert!(fir.nodes.iter().any(|n| n.path == "call.emptyList"));
    assert!(!fir
        .nodes
        .iter()
        .any(|n| n.path == "call.Collections.emptyList"));
}

#[test]
fn l2_imports_compuestos() {
    let tmp = tempdir().expect("temp dir");
    let root = tmp.path();

    write_java_file(
        root,
        "sanitizers/Sanitizers.java",
        r#"package sanitizers;

public class Sanitizers {
    public static String clean(String input) {
        return input;
    }
}
"#,
    );

    write_java_file(
        root,
        "app/App.java",
        r#"package app;

import sanitizers.*;
import static sanitizers.Sanitizers.clean;

public class App {
    public String render(String input) {
        String safe = clean(input);
        return safe;
    }

    public String explicit(String input) {
        return Sanitizers.clean(input);
    }
}
"#,
    );

    let cache = root.join("cache.json");
    catalog_module::extend("java", &[], &[], &["sanitizers.Sanitizers.clean"]);

    let (modules, parsed) = parse_java_project(root, &cache, None).expect("parse project");
    assert_eq!(parsed, 2);

    let app = modules.get("app.App").expect("App module");
    let sanitizers_alias = app
        .symbols
        .get("Sanitizers")
        .expect("Sanitizers symbol should exist");
    assert_eq!(
        sanitizers_alias.alias_of.as_deref(),
        Some("sanitizers.Sanitizers"),
        "Wildcard import should map class alias",
    );
    assert_eq!(
        app.symbol_modules.get("Sanitizers").map(String::as_str),
        Some("sanitizers.Sanitizers"),
        "Class alias should record originating module",
    );

    let clean_symbol = app
        .symbols
        .get("clean")
        .expect("clean symbol should be present");
    assert!(
        clean_symbol.sanitized,
        "Static import should mark sanitizer alias",
    );
    assert_eq!(
        app.symbol_types.get("clean"),
        Some(&SymbolKind::Sanitizer),
        "Static import should register sanitizer symbol kind",
    );
}

#[test]
fn l2_static_wildcard_sanitizer_aliases() {
    let tmp = tempdir().expect("temp dir");
    let root = tmp.path();

    write_java_file(
        root,
        "sanitizers/Sanitizers.java",
        r#"package sanitizers;

public class Sanitizers {
    public static String clean(String input) {
        return input;
    }

    public static String keep(String input) {
        return input;
    }
}
"#,
    );

    write_java_file(
        root,
        "app/StaticWildcard.java",
        r#"package app;

import static sanitizers.Sanitizers.*;

public class StaticWildcard {
    public String render(String input) {
        String safe = clean(input);
        return safe;
    }
}
"#,
    );

    let cache = root.join("cache.json");
    catalog_module::extend("java", &[], &[], &["sanitizers.Sanitizers.clean"]);

    let (modules, parsed) = parse_java_project(root, &cache, None).expect("parse project");
    assert_eq!(parsed, 2);

    let module = modules
        .get("app.StaticWildcard")
        .expect("StaticWildcard module");
    let clean_symbol = module
        .symbols
        .get("clean")
        .expect("clean alias should exist");
    assert!(
        clean_symbol.sanitized,
        "Static wildcard import should mark sanitizer alias",
    );
    assert_eq!(
        clean_symbol.alias_of.as_deref(),
        Some("sanitizers.Sanitizers.clean"),
    );
    assert_eq!(
        module.symbol_modules.get("clean").map(String::as_str),
        Some("sanitizers.Sanitizers"),
        "Static wildcard alias should retain originating class",
    );
    assert_eq!(
        module.symbol_types.get("clean"),
        Some(&SymbolKind::Sanitizer),
        "Alias should be registered as sanitizer",
    );
}
