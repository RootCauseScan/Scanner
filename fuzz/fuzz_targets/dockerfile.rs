#![no_main]
use libfuzzer_sys::fuzz_target;
use parsers::parse_dockerfile;
use ir::FileIR;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let mut fir = FileIR::new("fuzz.Dockerfile".into(), "dockerfile".into());
        parse_dockerfile(s, &mut fir);
    }
});
