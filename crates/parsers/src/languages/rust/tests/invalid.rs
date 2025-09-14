use crate::languages::rust::parse_rust;
use ir::FileIR;

#[test]
fn parse_valid_rust_succeeds() {
    let code = "fn main() {}";
    let mut fir = FileIR::new("valid.rs".into(), "rust".into());
    assert!(parse_rust(code, &mut fir).is_ok());
}

#[test]
fn parse_invalid_rust_still_succeeds() {
    let code = "fn main( {";
    let mut fir = FileIR::new("invalid.rs".into(), "rust".into());
    assert!(parse_rust(code, &mut fir).is_ok());
}
