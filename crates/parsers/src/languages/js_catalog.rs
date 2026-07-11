//! Shared taint catalog for JavaScript and TypeScript.
//!
//! Registered for both `"javascript"` and `"typescript"`. Currently the JS/TS
//! parsers consult the **sanitizer** set (see `parse` in `javascript.rs` /
//! `typescript.rs`), which marks a variable sanitized when it flows through one
//! of these calls. The `sources`/`sinks` sets are provided for completeness and
//! future use — JS/TS taint sources and sinks are today driven by the rule
//! patterns themselves, so those two sets are not yet consumed by the parsers.
//!
//! Entries are matched against the callee name as the parser builds it, i.e. a
//! bare global (`encodeURIComponent`) or a member expression (`DOMPurify.sanitize`).

use std::collections::HashSet;

use crate::catalog::Catalog;

pub fn load_catalog() -> Catalog {
    Catalog {
        sources: HashSet::from([
            // Browser / DOM input
            "location.search".into(),
            "location.hash".into(),
            "location.href".into(),
            "document.URL".into(),
            "document.cookie".into(),
            "window.name".into(),
            "URLSearchParams.get".into(),
            // Node.js request input (Express-style)
            "req.query".into(),
            "req.body".into(),
            "req.params".into(),
            "req.headers".into(),
            "req.cookies".into(),
            "process.env".into(),
            "process.argv".into(),
        ]),
        sinks: HashSet::from([
            // Code execution
            "eval".into(),
            "Function".into(),
            "setTimeout".into(),
            "setInterval".into(),
            // Command execution (Node)
            "child_process.exec".into(),
            "child_process.execSync".into(),
            "child_process.spawn".into(),
            "exec".into(),
            "execSync".into(),
            // DOM XSS
            "document.write".into(),
            "document.writeln".into(),
            "element.innerHTML".into(),
            "element.outerHTML".into(),
            "insertAdjacentHTML".into(),
            // Filesystem (Node)
            "fs.readFile".into(),
            "fs.readFileSync".into(),
            "fs.writeFile".into(),
            "fs.writeFileSync".into(),
            // SQL (common drivers)
            "connection.query".into(),
            "db.query".into(),
            "pool.query".into(),
        ]),
        sanitizers: HashSet::from([
            // The historical hard-coded sanitizer, kept so behavior is unchanged.
            "sanitize".into(),
            // URL / HTML encoding
            "encodeURIComponent".into(),
            "encodeURI".into(),
            "escape".into(),
            // Popular libraries
            "DOMPurify.sanitize".into(),
            "dompurify.sanitize".into(),
            "validator.escape".into(),
            "validator.blacklist".into(),
            "he.encode".into(),
            "xss".into(),
            "sanitizeHtml".into(),
            // Type coercion used as validation
            "parseInt".into(),
            "parseFloat".into(),
            "Number".into(),
        ]),
    }
}
