#![no_main]
//! O parser SQL relacional nunca entra em pânico.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sql) = std::str::from_utf8(data) {
        let _ = mini_db::rel::parser::parse(sql);
    }
});
