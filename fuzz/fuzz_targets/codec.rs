#![no_main]
//! Compressão faz roundtrip exato; decodificar lixo nunca entra em pânico.
use libfuzzer_sys::fuzz_target;
use mini_db::codec::{decode_value, encode_value};

fuzz_target!(|data: &[u8]| {
    assert_eq!(decode_value(&encode_value(data)).unwrap(), data);
    let _ = decode_value(data);
});
