use std::fmt::Result as FmtResult;

macro_rules! my_macro {
    () => {
        println!("macro called");
    };
}

fn main() {
    println!("Hello");
}
