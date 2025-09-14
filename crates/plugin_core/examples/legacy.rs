use plugin_core::{Context, Plugin};

const LEGACY_API: &str = "0.9.0";

struct Legacy;

impl Plugin for Legacy {
    fn init(&self) {
        println!("Legacy plugin expecting API {LEGACY_API}");
    }

    fn execute(&self, _ctx: &Context) {
        println!("Legacy plugin executed");
    }
}

fn main() {
    let plugin = Legacy;
    let ctx = Context;
    plugin.init();
    plugin.execute(&ctx);
}
