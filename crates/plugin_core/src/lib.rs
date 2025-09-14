//! Shared primitives for communicating with external plugins.

pub mod discovery;
pub mod limits;
pub mod plugin_manager;
pub mod protocol;

pub use discovery::{discover_plugins, PluginInfo, PluginManifest};
pub use limits::apply_limits;
pub use plugin_manager::PluginManager;
pub use protocol::*;

/// Current version of the plugin API expected by the host.
pub const API_VERSION: &str = "1.0.0";

/// Context provided to plugins when executing.
#[derive(Debug, Default)]
pub struct Context;

/// Basic behaviour that a plugin must implement.
pub trait Plugin {
    /// Initialises the plugin before any execution.
    ///
    /// This method allows preparing shared resources or verifying
    /// API compatibility.
    ///
    /// # Errors
    ///
    /// Implementations must communicate initialisation failures
    /// via `panic!` or the plugin's own error mechanism.
    fn init(&self) {}

    /// Executes the plugin's main task on the given context.
    ///
    /// # Parameters
    ///
    /// * `ctx` - Context provided by the host with execution
    ///   information.
    ///
    /// # Errors
    ///
    /// Implementations must signal errors during execution
    /// via `panic!` or the plugin's own error mechanism.
    fn execute(&self, ctx: &Context);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dummy;

    impl Plugin for Dummy {
        fn execute(&self, _ctx: &Context) {}
    }

    #[test]
    fn dummy_runs() {
        let plugin = Dummy;
        let ctx = Context;
        plugin.init();
        plugin.execute(&ctx);
    }

    #[test]
    fn limits_default() {
        let limits = Limits::default();
        assert!(limits.cpu_ms.is_none());
        assert!(limits.mem_mb.is_none());
    }
}
