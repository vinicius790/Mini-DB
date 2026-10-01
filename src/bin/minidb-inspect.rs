//! Forense de `data.mdb`: meta, dump de página, hexdump.

use mini_db::Db;
use std::env;
use std::process;

fn main() {
    if let Err(e) = run() {
        eprintln!("erro: {e}");
        process::exit(1);
    }
}

fn run() -> mini_db::Result<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("uso: minidb-inspect <dir> [page_id] [--hex [nbytes]]");
        process::exit(2);
    }
    let dir = args.remove(0);
    // Banco cifrado: senha em MINIDB_PASSPHRASE. Abrir refaz o WAL em memória, mas
    // o handle é largado sem checkpoint: a inspeção não reescreve `data.mdb`.
    let secret = env::var("MINIDB_PASSPHRASE").unwrap_or_default();
    let pass = (!secret.is_empty()).then_some(secret.as_str());
    let db = Db::open_encrypted(&dir, 1024, true, pass)?;
    print!("{}", db.inspect_meta_text());
    if let Some(id_s) = args.first() {
        if id_s != "--hex" {
            let id: u32 = id_s
                .parse()
                .map_err(|_| mini_db::Error::Cli(format!("page_id inválido: {id_s}")))?;
            if let Some(at) = args.iter().position(|a| a == "--hex") {
                // O tamanho é o argumento logo depois de `--hex` (padrão: 256 bytes).
                let n = args
                    .get(at + 1)
                    .and_then(|a| a.parse::<usize>().ok())
                    .unwrap_or(256);
                print!("{}", db.inspect_hex(id, n)?);
            } else {
                print!("{}", db.inspect_page(id)?);
            }
        }
    }
    db.drop_without_checkpoint();
    Ok(())
}
