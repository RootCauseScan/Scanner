struct Cfg { endpoint: String }

fn main() {
    let mut cfg = Cfg { endpoint: String::new() };
    let mut m = std::collections::HashMap::new();
    let val = String::new();
    cfg.endpoint = val;
    m["k"] = cfg.endpoint;
    let _x = m["k"]; 
}
