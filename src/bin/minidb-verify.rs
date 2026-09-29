//! Corre o verificador de invariantes e sai ≠0 se o arquivo estiver inconsistente.

use mini_db::Db;
use std::env;
use std::process;

fn main() {
    let dir = env::args().nth(1).unwrap_or_else(|| "./data".into());
    match Db::open(&dir).and_then(|mut db| {
        let r = db.verify();
        let _ = db.close();
        r
    }) {
        Ok(r) => {
            println!(
                "ok pages={} leaves={} internals={} keys={}",
                r.pages_ok, r.leaves, r.internals, r.keys
            );
        }
        Err(e) => {
            eprintln!("verify: {e}");
            process::exit(1);
        }
    }
}
