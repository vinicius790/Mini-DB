#![no_main]
//! O parser SQL nunca entra em pânico; statements aceitos têm EXPLAIN estável.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sql) = std::str::from_utf8(data) {
        if let Ok(statement) = mini_db::parse_sql(sql) {
            let _ = mini_db::sql::explain(&statement);
        }
    }
});
