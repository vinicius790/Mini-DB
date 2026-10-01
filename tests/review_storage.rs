//! Regressões de durabilidade: lock do diretório durante o `convert` e replay do
//! WAL com um `Begin` que nunca foi fechado.

use mini_db::encryption::{convert, keyfile_path};
use mini_db::wal::{Wal, WalRecord};
use mini_db::Db;

/// Sufixo único por processo: só pid + relógio colide entre testes paralelos.
static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmpdir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-review-storage-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Banco vazio, com checkpoint feito, e `records` gravados direto no WAL.
fn dir_with_wal(records: Vec<WalRecord>) -> std::path::PathBuf {
    let dir = tmpdir();
    {
        let mut db = Db::open(&dir).unwrap();
        db.checkpoint().unwrap();
    }
    let mut wal = Wal::open(Db::wal_path(&dir), 1).unwrap();
    for record in records {
        wal.append(record).unwrap();
    }
    wal.sync().unwrap();
    dir
}

fn insert(key: &[u8]) -> WalRecord {
    WalRecord::Insert {
        lsn: 0,
        key: key.to_vec(),
        value: b"v".to_vec(),
    }
}

fn has(db: &Db, key: &[u8]) -> bool {
    db.get(key).unwrap().is_some()
}

#[test]
fn convert_refuses_open_database_and_releases_the_lock() {
    let dir = tmpdir();
    let mut db = Db::open(&dir).unwrap();
    db.put(b"k", b"v").unwrap();
    // Banco aberto: o `convert` não consegue o lock do diretório e não toca em nada.
    assert!(convert(&dir, None, Some("nova")).is_err());
    assert!(!keyfile_path(&dir).exists());
    assert!(has(&db, b"k"));
    db.close().unwrap();
    drop(db);
    // Banco fechado: converte, e o lock é solto no retorno (com sucesso ou com erro).
    convert(&dir, None, Some("nova")).unwrap();
    assert!(convert(&dir, Some("errada"), None).is_err());
    let db = Db::open_encrypted(&dir, 64, true, Some("nova")).unwrap();
    assert!(has(&db, b"k"));
}

#[test]
fn begin_after_dangling_begin_with_pending_ops_fails_loudly() {
    // O `Begin` 1 nunca foi fechado e `solta` pode ser um autocommit já confirmado ao
    // cliente: ao ver o `Begin` 2 o recovery não pode descartá-la em silêncio.
    let dir = dir_with_wal(vec![
        WalRecord::Begin { lsn: 0, txn_id: 1 },
        insert(b"solta"),
        WalRecord::Begin { lsn: 0, txn_id: 2 },
        insert(b"b"),
        WalRecord::Commit { lsn: 0, txn_id: 2 },
    ]);
    let opened = Db::open(dir);
    assert!(matches!(opened, Err(mini_db::Error::CorruptWal(_))));
}

#[test]
fn begin_right_after_dangling_begin_is_tolerated() {
    // Único caso legítimo: o frame 1 parou no `Begin` (nem a primeira operação nem o
    // `Abort` couberam no disco) e o handle seguiu escrevendo. Nada é descartado.
    let dir = dir_with_wal(vec![
        WalRecord::Begin { lsn: 0, txn_id: 1 },
        WalRecord::Begin { lsn: 0, txn_id: 2 },
        insert(b"b"),
        WalRecord::Commit { lsn: 0, txn_id: 2 },
        insert(b"c"),
    ]);
    let mut db = Db::open(dir).unwrap();
    assert!(has(&db, b"b"));
    assert!(has(&db, b"c"));
    assert!(db.begin().unwrap() > 2);
}
