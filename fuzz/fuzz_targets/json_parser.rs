#![no_main]
//! JSON aceito precisa sobreviver a stringify → parse sem mudar.
use libfuzzer_sys::fuzz_target;
use mini_db::json::Json;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(value) = Json::parse(text) {
            assert_eq!(Json::parse(&value.stringify()).unwrap(), value);
        }
    }
});
