macro_rules! id {
    ($x:expr) => { $x };
}

fn main() {
    let a = 1;
    let b = id!(a);
}
