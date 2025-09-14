#![no_main]
use libfuzzer_sys::fuzz_target;
use parsers::parse_yaml;
use ir::FileIR;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let mut fir = FileIR::new("fuzz.yaml".into(), "yaml".into());
        let _ = parse_yaml(s, &mut fir);
    }
});
