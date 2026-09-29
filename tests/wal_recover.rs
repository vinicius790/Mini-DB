//! Recover após crash: WAL syncado, páginas dirty descartadas, reopen refaz redo.
//! Inclui truncamento mid-write (kill -9 no meio do frame).

use std::fs::OpenOptions;
use std::io::Write;

use mini_db::db::simulate_crash_after_wal;
use mini_db::wal::{truncate_file_at, Wal, WalRecord, WAL_MAGIC};
use mini_db::Db;

fn tmpdir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn recover_after_crash_without_checkpoint() {
    let dir = tmpdir();
    let ops: Vec<(&[u8], &[u8])> = vec![
        (b"hero", b"alucard"),
        (b"castle", b"dracula"),
        (b"whip", b"vampire_killer"),
    ];
    simulate_crash_after_wal(dir.as_path(), &ops).unwrap();

    // data.mdb pode estar sem as páginas dirty; WAL tem os inserts.
    let mut db = Db::open(dir.as_path()).unwrap();
    assert_eq!(
        db.get(b"hero").unwrap().as_deref(),
        Some(b"alucard".as_ref())
    );
    assert_eq!(
        db.get(b"castle").unwrap().as_deref(),
        Some(b"dracula".as_ref())
    );
    assert_eq!(
        db.get(b"whip").unwrap().as_deref(),
        Some(b"vampire_killer".as_ref())
    );
}

#[test]
fn recover_many_keys_after_crash() {
    let dir = tmpdir();
    {
        let mut db = Db::open_with_capacity(dir.as_path(), 16).unwrap();
        for i in 0..80 {
            let k = format!("k{:03}", i);
            let v = format!("v{:03}", i);
            db.put(k.as_bytes(), v.as_bytes()).unwrap();
        }
        // Crash: sem checkpoint / sem flush final.
        db.drop_without_checkpoint();
    }
    let mut db = Db::open(dir.as_path()).unwrap();
    for i in 0..80 {
        let k = format!("k{:03}", i);
        let v = format!("v{:03}", i);
        assert_eq!(
            db.get(k.as_bytes()).unwrap().as_deref(),
            Some(v.as_bytes()),
            "missing after recover: {k}"
        );
    }
}

#[test]
fn truncated_wal_frame_is_ignored() {
    let dir = tmpdir();
    {
        let mut db = Db::open(dir.as_path()).unwrap();
        db.put(b"ok", b"1").unwrap();
        db.checkpoint().unwrap();
        db.put(b"also_ok", b"2").unwrap();
        // Deixa WAL com registro válido; em seguida truncamos mid-frame.
        db.drop_without_checkpoint();
    }

    let wal_path = Db::wal_path(dir.as_path());
    let meta_len = std::fs::metadata(&wal_path).unwrap().len();
    // Corta os últimos 7 bytes → último frame incompleto.
    assert!(meta_len > 20);
    truncate_file_at(&wal_path, meta_len - 7).unwrap();

    let mut db = Db::open(dir.as_path()).unwrap();
    // "ok" veio do checkpoint (páginas no data.mdb).
    assert_eq!(db.get(b"ok").unwrap().as_deref(), Some(b"1".as_ref()));
    // Frame de "also_ok" foi truncado → ignorado no recover; chave ausente.
    assert_eq!(
        db.get(b"also_ok").unwrap(),
        None,
        "truncated WAL frame must not redo"
    );
}

#[test]
fn append_partial_bytes_then_recover() {
    let dir = tmpdir();
    {
        let mut db = Db::open(dir.as_path()).unwrap();
        db.put(b"stable", b"yes").unwrap();
        db.checkpoint().unwrap();
        db.drop_without_checkpoint();
    }

    // Injeta lixo / frame parcial no fim do WAL.
    let wal_path = Db::wal_path(dir.as_path());
    {
        let mut f = OpenOptions::new().append(true).open(&wal_path).unwrap();
        // payload_len grande demais + bytes parciais
        f.write_all(&100u32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(b"PARTIAL").unwrap();
        f.sync_all().unwrap();
    }

    let mut db = Db::open(dir.as_path()).unwrap();
    assert_eq!(db.get(b"stable").unwrap().as_deref(), Some(b"yes".as_ref()));

    // Novo put após recover deve funcionar.
    db.put(b"after", b"crash").unwrap();
    assert_eq!(
        db.get(b"after").unwrap().as_deref(),
        Some(b"crash".as_ref())
    );
}

#[test]
fn wal_crc_roundtrip() {
    let dir = tmpdir();
    let path = dir.as_path().join("t.wal");
    {
        let mut w = Wal::open(&path, 1).unwrap();
        w.append(WalRecord::Insert {
            lsn: 0,
            key: b"a".to_vec(),
            value: b"b".to_vec(),
        })
        .unwrap();
        w.sync().unwrap();
    }
    let (next, recs) = Wal::read_all(&path).unwrap();
    assert_eq!(next, 2);
    assert_eq!(recs.len(), 1);
    match &recs[0] {
        WalRecord::Insert { key, value, lsn } => {
            assert_eq!(*lsn, 1);
            assert_eq!(key, b"a");
            assert_eq!(value, b"b");
        }
        _ => panic!("expected insert"),
    }
    let _ = WAL_MAGIC;
}

#[test]
fn lsn_survives_checkpoint_truncate() {
    let dir = tmpdir();
    {
        let mut db = Db::open(dir.as_path()).unwrap();
        db.put(b"x", b"1").unwrap();
        let before = db.stats().next_lsn;
        db.checkpoint().unwrap();
        assert!(db.stats().next_lsn >= before);
        db.put(b"y", b"2").unwrap();
        assert!(db.stats().next_lsn > before);
        db.close().unwrap();
    }
    let db = Db::open(dir.as_path()).unwrap();
    // Após reopen, next_lsn não regrediu para 1.
    assert!(db.stats().next_lsn >= 3, "next_lsn={}", db.stats().next_lsn);
}
