use rego_wasm::RegoWasm;
use serde_json::json;

const WASM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/rules/opa/docker-security.wasm"
));

// Helper to run async tests on a basic tokio runtime
fn run_async<F, Fut>(f: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(f());
}

#[test]
fn fails_with_low_fuel() {
    run_async(|| async {
        let _err = RegoWasm::from_bytes_with_limits(WASM, None, Some(1), None)
            .await
            .err()
            .expect("expected fuel error");
    });
}

#[test]
fn fails_with_low_memory() {
    run_async(|| async {
        let err = RegoWasm::from_bytes_with_limits(WASM, None, None, Some(1))
            .await
            .err()
            .expect("expected memory limit error");
        assert!(err.to_string().to_lowercase().contains("memory"));
    });
}

#[test]
fn succeeds_with_sufficient_limits() {
    run_async(|| async {
        let mut rego =
            RegoWasm::from_bytes_with_limits(WASM, None, Some(1_000_000), Some(1_000_000))
                .await
                .expect("instantiate with limits");
        rego.set_input(json!({
            "file_type": "dockerfile",
            "nodes": [{"path": "USER", "value": "root"}]
        }));
        let entry = rego
            .entrypoints()
            .into_iter()
            .next()
            .expect("has entrypoint");
        let result = rego.evaluate(&entry).await.expect("evaluation succeeds");
        let arr = result.as_array().expect("array result");
        assert_eq!(arr.len(), 1);
        let inner = arr[0]["result"].as_object().expect("inner object");
        assert_eq!(inner.len(), 1);
        assert_eq!(
            inner.get("Container runs as root user - use a non-root user for security"),
            Some(&serde_json::Value::Bool(true)),
        );
    });
}
