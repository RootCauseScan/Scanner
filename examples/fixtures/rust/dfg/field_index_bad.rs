struct Cfg { endpoint: String }

fn main() {
    let mut cfg = Cfg { endpoint: String::new() };
    let mut m = std::collections::HashMap::new();
    cfg.endpoint = missing;
    m["k"] = missing2;
}
