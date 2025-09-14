macro_rules! clean_macro {
    ($x:expr) => {
        sanitize($x)
    };
}

fn main() {
    let user = source();
    let data = clean_macro!(user);
    sink(data);
}
