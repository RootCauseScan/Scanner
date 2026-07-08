/// Parses a function call expression into `(name, args)`.
///
/// Handles generic type parameters (`foo::<T>`) and nested calls in arguments.
pub fn parse_call(code: &str) -> Option<(String, Vec<String>)> {
    let call = code.trim();
    let mut open = None;
    let mut paren = 0usize;
    let mut angle = 0usize;
    for (i, ch) in call.char_indices() {
        match ch {
            '<' => angle += 1,
            '>' => angle = angle.saturating_sub(1),
            '(' if angle == 0 => {
                if paren == 0 {
                    open = Some(i);
                }
                paren += 1;
            }
            ')' if angle == 0 => {
                paren = paren.saturating_sub(1);
                if paren == 0 {
                    let open = open?;
                    let name = call[..open].trim().to_string();
                    let args_str = &call[open + 1..i];
                    let args = split_args(args_str);
                    return Some((name, args));
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut paren = 0usize;
    let mut angle = 0usize;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '<' => angle += 1,
            '>' => angle = angle.saturating_sub(1),
            ',' if paren == 0 && angle == 0 => {
                out.push(s[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        let arg = s[start..].trim();
        if !arg.is_empty() {
            out.push(arg.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_call() {
        let (name, args) = parse_call("foo(a, b)").unwrap();
        assert_eq!(name, "foo");
        assert_eq!(args, vec!["a", "b"]);
    }

    #[test]
    fn no_args() {
        let (name, args) = parse_call("bar()").unwrap();
        assert_eq!(name, "bar");
        assert!(args.is_empty());
    }

    #[test]
    fn generic_call() {
        let (name, args) = parse_call("foo::<T>(x)").unwrap();
        assert_eq!(name, "foo::<T>");
        assert_eq!(args, vec!["x"]);
    }

    #[test]
    fn nested_args() {
        let (name, args) = parse_call("f(g(x), y)").unwrap();
        assert_eq!(name, "f");
        assert_eq!(args, vec!["g(x)", "y"]);
    }

    #[test]
    fn not_a_call() {
        assert!(parse_call("just_an_identifier").is_none());
    }
}
