#![no_main]
//! Corpo de frame WAL arbitrário: decodificar nunca entra em pânico e todo
//! registro aceito é reencodado de forma idêntica.
use libfuzzer_sys::fuzz_target;
use mini_db::wal::WalRecord;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = WalRecord::decode_body(data) {
        let frame = record.encode_frame();
        assert_eq!(&frame[8..], data);
    }
});
