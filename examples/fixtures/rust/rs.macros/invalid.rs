use std::fmt::Result as;

macro_rules! bad_macro (
    () => {
        println!("broken");
    }
);

fn main() {}
