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
    let mut db = Db::open(&dir)?;
    print!("{}", db.inspect_meta_text());
    if let Some(id_s) = args.first() {
        if id_s != "--hex" {
            let id: u32 = id_s.parse().unwrap_or(0);
            if args.iter().any(|a| a == "--hex") {
                let n = args
                    .iter()
                    .rev()
                    .find_map(|a| a.parse::<usize>().ok())
                    .unwrap_or(256);
                print!("{}", db.inspect_hex(id, n)?);
            } else {
                print!("{}", db.inspect_page(id)?);
            }
        }
    }
    db.close()?;
    Ok(())
}
