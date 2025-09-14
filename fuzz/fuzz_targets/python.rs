#![no_main]
use libfuzzer_sys::fuzz_target;
use parsers::languages::python::parse_python;
use ir::FileIR;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let mut fir = FileIR::new("fuzz.py".into(), "python".into());
        let _ = parse_python(s, &mut fir);
    }
});
