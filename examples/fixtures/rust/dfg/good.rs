fn good() -> i32 {
    let mut x = 0;
    if x == 0 {
        x = 1;
    } else {
        x = 2;
    }
    match x {
        1 => x = 3,
        _ => x = 4,
    }
    loop {
        x += 1;
        if x > 10 {
            break;
        }
    }
    return x;
}
