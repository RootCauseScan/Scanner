mod a {
    pub mod b {
        pub fn passthrough(x: String) -> String {
            x
        }
    }
}

use crate::a::b as c;

fn main() {
    let mut data = source();
    data = c::passthrough(data);
    sink(data);
}
