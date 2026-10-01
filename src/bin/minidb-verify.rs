//! Corre o verificador de invariantes e sai ≠0 se o arquivo estiver inconsistente.

use mini_db::Db;
use std::env;
use std::process;

fn main() {
    let dir = env::args().nth(1).unwrap_or_else(|| "./data".into());
    // Banco cifrado: senha em MINIDB_PASSPHRASE. Abrir refaz o WAL em memória, mas
    // o handle é largado sem checkpoint: a verificação não reescreve `data.mdb`.
    let secret = env::var("MINIDB_PASSPHRASE").unwrap_or_default();
    let pass = (!secret.is_empty()).then_some(secret.as_str());
    let opened = Db::open_encrypted(dir, 1024, true, pass);
    match opened.and_then(|db| {
        let r = db.verify();
        db.drop_without_checkpoint();
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
