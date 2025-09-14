fn bad() -> i32 {
    let mut y = 0;
    loop {
        if y > 5 {
            break;
        }
        match y {
            0 => y = 1,
            _ => {}
        }
        return y;
    }
}
