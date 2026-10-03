//! Range scan `[start, end)` atravessando irmãos de folha.

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
fn scan_half_open_range() {
    let dir = tmpdir();
    let mut db = Db::open(dir.as_path()).unwrap();
    for (k, v) in [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")] {
        db.put(k.as_bytes(), v.as_bytes()).unwrap();
    }
    let pairs = db.scan(b"b", Some(b"d")).unwrap();
    let keys: Vec<_> = pairs
        .iter()
        .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
        .collect();
    assert_eq!(keys, vec!["b", "c"]);
}

#[test]
fn scan_across_leaf_siblings() {
    let dir = tmpdir();
    let mut db = Db::open_with_capacity(dir.as_path(), 64).unwrap();
    let val = vec![b'v'; 80];
    for i in 0..120 {
        let key = format!("{:04}", i);
        db.put(key.as_bytes(), &val).unwrap();
    }
    let pairs = db.scan(b"0040", Some(b"0060")).unwrap();
    assert_eq!(pairs.len(), 20);
    assert_eq!(pairs.first().unwrap().0, b"0040");
    assert_eq!(pairs.last().unwrap().0, b"0059");
}

#[test]
fn scan_to_end() {
    let dir = tmpdir();
    let mut db = Db::open(dir.as_path()).unwrap();
    db.put(b"m", b"1").unwrap();
    db.put(b"z", b"2").unwrap();
    db.put(b"a", b"0").unwrap();
    let pairs = db.scan(b"m", None).unwrap();
    let keys: Vec<_> = pairs
        .iter()
        .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
        .collect();
    assert_eq!(keys, vec!["m", "z"]);
}
