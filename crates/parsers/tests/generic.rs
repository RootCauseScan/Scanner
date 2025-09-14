use parsers::{detect_type, parse_file};
use tempfile::tempdir;

#[test]
fn parses_html_as_generic() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("index.html");
    std::fs::write(&path, "<html>\n<body></body>\n</html>").unwrap();
    assert_eq!(detect_type(&path), Some("generic"));
    let ir = parse_file(&path, None, None).unwrap().unwrap();
    assert_eq!(ir.file_type, "generic");
    assert_eq!(ir.nodes.len(), 3);
    assert_eq!(ir.nodes[0].value.as_str().unwrap(), "<html>");
}
