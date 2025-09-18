fn main() {
    let x: Option<i32> = None;
    // This unwrap will panic in this example
    let _ = x.unwrap();
}

