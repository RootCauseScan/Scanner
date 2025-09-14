mod a {
    pub mod b {
        pub fn sanitize(x: String) -> String {
            x
        }
    }
}

use crate::a::b as c;

fn main() {
    let mut data = source();
    data = c::sanitize(data);
    sink(data);
}
