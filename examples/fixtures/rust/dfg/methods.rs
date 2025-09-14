fn methods() {
    let mut v: Vec<i32> = Vec::new();
    let x = 1;
    v.push(x);
    let y = v.pop();
    let mut m = std::collections::HashMap::new();
    let k = "k";
    let val = 2;
    m.insert(k, val);
    let z = m.get(k);
    let opt = Some(y);
    let unwrapped = opt.unwrap();
}
