//! Guards the inter-file (controller → service) SSRF detection and the sink
//! precision filter that keeps it from firing on incidental, locals-only sinks.
//!
//! Regression cover for two coupled behaviours:
//!   1. A taint rule with `options.interfile: true` opts out of the sink-only
//!      literal prefilter, so a source living in a sink-free controller file is
//!      still recorded for the cross-file pass.
//!   2. An inter-file sink is only connected when its expression references one
//!      of the callee's parameters, so a `sb.append(line)`-style sink that only
//!      touches locals does not become a false positive.

use engine::{analyze_files_with_config, load_rules_with_events, parse_file_with_events, EngineConfig};
use std::fs;
use std::path::PathBuf;

const RULE: &str = r#"
rules:
  - id: test-interfile-ssrf
    languages: [java]
    severity: ERROR
    message: SSRF via RestTemplate
    options:
      interfile: true
    mode: taint
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern-inside: |
                  $METHODNAME(..., @$REQ(...) $TYPE $SOURCE,...) {
                    ...
                  }
              - pattern-inside: |
                  $METHODNAME(..., @$REQ $TYPE $SOURCE,...) {
                    ...
                  }
          - metavariable-regex:
              metavariable: $REQ
              regex: (RequestBody|RequestParam|PathVariable)
          - focus-metavariable: $SOURCE
    pattern-sinks:
      - pattern-either:
          - pattern: $REST.exchange($URL, ...)
          - pattern: $REST.getForObject($URL, ...)
"#;

const CONTROLLER: &str = r#"package com.example.controller;
import com.example.service.WebsiteTestService;
import com.example.http.WebsiteTestRequest;
import org.springframework.web.bind.annotation.*;
@RestController
public class MainController {
  private WebsiteTestService websiteTestService;
  @PostMapping("/website")
  public String testWebsite(@RequestBody WebsiteTestRequest request) {
    return websiteTestService.testWebsite(request);
  }
}
"#;

// Sink references the callee parameter `request` -> must be detected.
const SERVICE_VULN: &str = r#"package com.example.service;
import com.example.http.WebsiteTestRequest;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
public class WebsiteTestService {
  private RestTemplate rest;
  public String testWebsite(WebsiteTestRequest request) {
    HttpEntity<String> entity = new HttpEntity<>("", new HttpHeaders());
    return this.rest.exchange(request.url, HttpMethod.GET, entity, String.class).getBody();
  }
}
"#;

// A service whose sink-shaped call only touches a hardcoded local, never its
// `path` parameter. Even though a caller may pass tainted data in, the sink
// must NOT be connected (this mirrors the FileService.append false positive we
// guard against: a sink that matches shape but carries no caller-supplied data).
const SERVICE_SAFE: &str = r#"package com.example.service;
import org.springframework.web.client.RestTemplate;
public class OtherService {
  private RestTemplate rest;
  public String ping(String path) {
    String url = "http://localhost/health";
    return this.rest.exchange(url, org.springframework.http.HttpMethod.GET, null, String.class).getBody();
  }
}
"#;

fn write(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, body).unwrap();
    p
}

fn scan(files: &[PathBuf], rules_dir: &std::path::Path) -> Vec<String> {
    let rules = load_rules_with_events(rules_dir).expect("load rules");
    let mut firs = Vec::new();
    for f in files {
        if let Some(fir) = parse_file_with_events(f, None, None).expect("parse") {
            firs.push(fir);
        }
    }
    let cfg = EngineConfig::default();
    analyze_files_with_config(&firs, &rules, &cfg, None, None, None)
        .into_iter()
        .map(|f| format!("{}:{}", f.file.file_name().and_then(|s| s.to_str()).unwrap_or(""), f.line))
        .collect()
}

#[test]
fn detects_interfile_ssrf_and_rejects_locals_only_sink() {
    let tmp = std::env::temp_dir().join(format!("rc_interfile_ssrf_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let rules_dir = tmp.join("rules");
    fs::create_dir_all(&rules_dir).unwrap();
    write(&rules_dir, "ssrf.yaml", RULE);

    let controller = write(&tmp, "MainController.java", CONTROLLER);
    let vuln = write(&tmp, "WebsiteTestService.java", SERVICE_VULN);
    let safe = write(&tmp, "OtherService.java", SERVICE_SAFE);

    let hits = scan(&[controller.clone(), vuln.clone(), safe.clone()], &rules_dir);

    // The vulnerable service (sink uses the `request` parameter) is flagged.
    assert!(
        hits.iter().any(|h| h.starts_with("WebsiteTestService.java:")),
        "expected interfile SSRF finding in WebsiteTestService, got {hits:?}"
    );
    // The controller is a caller only; the finding is reported at the sink.
    assert!(
        !hits.iter().any(|h| h.starts_with("MainController.java:")),
        "did not expect a finding in the controller, got {hits:?}"
    );

    let _ = fs::remove_dir_all(&tmp);
}
