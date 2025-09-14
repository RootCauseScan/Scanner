mod utils {
    pub fn helper() {}
}

use utils as u;
use utils::helper as h;

fn main() {
    h();
    u::helper();
}
