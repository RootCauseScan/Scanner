use ir::{DFNodeKind, FileIR};
use parsers::languages::{python::parse_python, rust::parse_rust};
use std::collections::{HashMap, HashSet, VecDeque};

fn has_flow(fir: &FileIR, from: &str, to: &str) -> bool {
    let dfg = match &fir.dfg {
        Some(d) => d,
        None => return false,
    };
    let start = match fir.symbols.get(from).and_then(|s| s.def) {
        Some(id) => id,
        None => return false,
    };
    let mut targets = Vec::new();
    for n in &dfg.nodes {
        if n.name == to && matches!(n.kind, DFNodeKind::Use) {
            targets.push(n.id);
        }
    }
    let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
    for &(s, t) in &dfg.edges {
        adj.entry(s).or_default().push(t);
    }
    let mut queue = VecDeque::new();
    let mut seen = HashSet::new();
    queue.push_back(start);
    while let Some(id) = queue.pop_front() {
        if targets.contains(&id) {
            return true;
        }
        if seen.insert(id) {
            if let Some(next) = adj.get(&id) {
                for &n in next {
                    queue.push_back(n);
                }
            }
        }
    }
    false
}

#[test]
fn python_flow_across_call() {
    let code = r#"
def process(x):
    return x
def main():
    data = source()
    res = process(data)
    sink(res)
"#;
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    assert!(has_flow(&fir, "data", "res"));
}

#[test]
fn rust_flow_across_call() {
    let code = r#"
fn process(x: i32) -> i32 { return x; }
fn main() {
    let data = source();
    let res = process(data);
    sink(res);
}
"#;
    let mut fir = FileIR::new("<mem>".into(), "rust".into());
    parse_rust(code, &mut fir).unwrap();
    assert!(has_flow(&fir, "data", "res"));
}
