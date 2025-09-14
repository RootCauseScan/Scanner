fn methods_bad() {
    let mut v: Vec<i32> = Vec::new();
    v.push(1);
    let y = v.pop().unwrap();
}
