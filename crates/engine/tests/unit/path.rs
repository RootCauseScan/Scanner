use super::*;

// Checks valid glob patterns with multiple '*'.
#[test]
fn matches_multiple_stars() {
    assert!(path_matches("a*b*c", "axbyc"));
    assert!(!path_matches("a*b*c", "axby"));
}

// Supports '**' for nested directories.
#[test]
fn matches_double_star_directory() {
    assert!(path_matches("**/foo/*.rs", "src/foo/main.rs"));
    assert!(!path_matches("**/foo/*.rs", "src/bar/main.rs"));
}

// Returns false when the pattern contains disallowed characters.
#[test]
fn rejects_invalid_pattern() {
    assert!(!path_matches("foo/?.rs", "foo/?.rs"));
}

// Reuses the compiled regular expression in repeated calls.
#[test]
fn reuses_regex_from_cache() {
    for _ in 0..3 {
        assert!(path_matches("a*b", "axxb"));
    }
}

// Invalid patterns should not be cached.
#[test]
fn invalid_pattern_multiple_calls() {
    for _ in 0..2 {
        assert!(!path_matches("foo/?.rs", "foo/?.rs"));
    }
}

// Inserts patterns and stores them in the cache.
#[test]
fn caches_patterns() {
    reset_path_regex_cache();
    assert_eq!(path_regex_cache_size(), 0);
    assert!(path_matches("foo*", "foobar"));
    assert_eq!(path_regex_cache_size(), 1);
    assert!(path_regex_cache_contains("foo*"));
}

// Evicts the oldest pattern when the limit is exceeded.
#[test]
fn evicts_oldest_pattern() {
    reset_path_regex_cache();
    path_matches("a*", "ab");
    path_matches("b*", "bb");
    path_matches("c*", "cc");
    assert_eq!(path_regex_cache_size(), PATH_REGEX_CACHE_CAPACITY);
    path_matches("d*", "dd");
    assert_eq!(path_regex_cache_size(), PATH_REGEX_CACHE_CAPACITY);
    assert!(!path_regex_cache_contains("a*"));
    assert!(path_regex_cache_contains("b*"));
    assert!(path_regex_cache_contains("c*"));
    assert!(path_regex_cache_contains("d*"));
}
