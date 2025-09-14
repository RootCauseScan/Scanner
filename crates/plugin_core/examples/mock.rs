use plugin_core::{Context, Plugin, API_VERSION};

struct Mock;

impl Plugin for Mock {
    fn init(&self) {
        println!("Mock plugin init with API {API_VERSION}");
    }

    fn execute(&self, _ctx: &Context) {
        println!("Mock plugin executed");
    }
}

fn main() {
    let plugin = Mock;
    let ctx = Context;
    plugin.init();
    plugin.execute(&ctx);
}
