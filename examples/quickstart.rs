//! Exemplo embeddable: put / get / scan / checkpoint.
//!
//! ```bash
//! cargo run --example quickstart
//! ```

use mini_db::Db;
use std::env;
use std::fs;

fn main() -> mini_db::Result<()> {
    let dir = env::temp_dir().join("minidb-quickstart");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    let mut db = Db::open(&dir)?;
    db.put(b"player:1", b"Geraliza")?;
    db.put(b"player:2", b"Alucard")?;
    db.put(b"score:1", b"9000")?;

    println!(
        "GET player:1 => {:?}",
        String::from_utf8_lossy(&db.get(b"player:1")?.unwrap())
    );

    println!("SCAN player: .. score:");
    for (k, v) in db.scan(b"player:", Some(b"score:"))? {
        println!(
            "  {} = {}",
            String::from_utf8_lossy(&k),
            String::from_utf8_lossy(&v)
        );
    }

    db.checkpoint()?;
    println!("checkpoint ok (lsn={})", db.meta().checkpoint_lsn);
    db.close()?;
    println!("dados em {}", dir.display());
    Ok(())
}
