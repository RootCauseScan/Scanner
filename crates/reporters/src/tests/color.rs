use crate::color_severity;
use loader::Severity;

#[test]
fn low_severity_is_green() {
    assert_eq!(color_severity(Severity::Low), "\x1b[32mLOW\x1b[0m");
}

#[test]
fn medium_severity_is_yellow() {
    assert_eq!(color_severity(Severity::Medium), "\x1b[33mMEDIUM\x1b[0m");
}

#[test]
fn high_severity_is_red() {
    assert_eq!(color_severity(Severity::High), "\x1b[31mHIGH\x1b[0m");
}
