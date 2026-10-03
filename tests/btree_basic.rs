//! Insert / get / upsert e splits de folha.

use mini_db::Db;

/// Sufixo único por processo: só pid + relógio colide entre testes paralelos.
static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmpdir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-test-{}-{}-{}",
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

#[test]
fn put_get_roundtrip() {
    let dir = tmpdir();
    let mut db = Db::open(dir.as_path()).unwrap();
    db.put(b"alpha", b"1").unwrap();
    db.put(b"beta", b"2").unwrap();
    assert_eq!(db.get(b"alpha").unwrap().as_deref(), Some(b"1".as_ref()));
    assert_eq!(db.get(b"beta").unwrap().as_deref(), Some(b"2".as_ref()));
    assert_eq!(db.get(b"gamma").unwrap(), None);
}

#[test]
fn upsert_overwrites() {
    let dir = tmpdir();
    let mut db = Db::open(dir.as_path()).unwrap();
    db.put(b"k", b"v1").unwrap();
    db.put(b"k", b"v2").unwrap();
    assert_eq!(db.get(b"k").unwrap().as_deref(), Some(b"v2".as_ref()));
}

#[test]
fn many_keys_force_leaf_splits() {
    let dir = tmpdir();
    let mut db = Db::open_with_capacity(dir.as_path(), 32).unwrap();
    // Valores médios para forçar vários splits de folha (página 4KiB).
    let val = vec![b'x'; 64];
    for i in 0..200 {
        let key = format!("key-{:04}", i);
        db.put(key.as_bytes(), &val).unwrap();
    }
    for i in 0..200 {
        let key = format!("key-{:04}", i);
        let got = db.get(key.as_bytes()).unwrap().expect("missing");
        assert_eq!(got, val);
    }
    // root deve ter virado interno após splits
    assert!(db.meta().next_page_id > 2);
}

#[test]
fn reopen_after_clean_close() {
    let dir = tmpdir();
    {
        let mut db = Db::open(dir.as_path()).unwrap();
        db.put(b"persist", b"yes").unwrap();
        db.close().unwrap();
    }
    let db = Db::open(dir.as_path()).unwrap();
    assert_eq!(
        db.get(b"persist").unwrap().as_deref(),
        Some(b"yes".as_ref())
    );
}

#[test]
fn rejects_oversized_key() {
    let dir = tmpdir();
    let mut db = Db::open(dir.as_path()).unwrap();
    let key = vec![b'k'; mini_db::MAX_KEY_LEN + 1];
    assert!(db.put(&key, b"v").is_err());
}
