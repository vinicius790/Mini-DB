//! Exclusões que esvaziam folhas inteiras e VACUUM que reconstrói a árvore.
use mini_db::Db;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn key(i: usize) -> Vec<u8> {
    format!("k{i:04}").into_bytes()
}

#[test]
fn emptied_leaves_keep_remaining_keys_reachable() {
    let dir = tmpdir("empty-leaves");
    let mut db = Db::open_with_capacity(&dir, 8).unwrap();
    let val = vec![b'v'; 200];
    for i in 0..300 {
        db.put(&key(i), &val).unwrap();
    }
    // Remove blocos contíguos: esvazia folhas inteiras no meio e no começo.
    for i in (0..60).chain(100..220) {
        assert!(db.delete(&key(i)).unwrap(), "delete {i}");
    }
    for i in 0..300 {
        let alive = (60..100).contains(&i) || i >= 220;
        assert_eq!(db.get(&key(i)).unwrap().is_some(), alive, "key {i}");
    }
    assert_eq!(db.scan(b"k", None).unwrap().len(), 120);
    db.verify().unwrap();
    // Reinserir nas faixas esvaziadas continua correto.
    for i in 100..130 {
        db.put(&key(i), b"again").unwrap();
    }
    assert_eq!(db.scan(b"k", None).unwrap().len(), 150);
    db.close().unwrap();
    drop(db);
    let db = Db::open(&dir).unwrap();
    assert_eq!(
        db.get(&key(110)).unwrap().as_deref(),
        Some(b"again".as_ref())
    );
    db.verify().unwrap();
}

#[test]
fn vacuum_rebuilds_tree_and_shrinks_file() {
    let dir = tmpdir("vacuum");
    let mut db = Db::open_with_capacity(&dir, 8).unwrap();
    for i in 0..400 {
        db.put(&key(i), &[b'x'; 100]).unwrap();
    }
    db.create_value_index().unwrap();
    for i in 0..380 {
        db.delete(&key(i)).unwrap();
    }
    db.checkpoint().unwrap();
    let before = db.meta().next_page_id;
    let size_before = std::fs::metadata(Db::data_path(&dir)).unwrap().len();
    db.vacuum().unwrap();
    assert!(
        db.meta().next_page_id < before,
        "vacuum não liberou páginas"
    );
    let size_after = std::fs::metadata(Db::data_path(&dir)).unwrap().len();
    assert!(size_after < size_before, "{size_after} >= {size_before}");
    assert_eq!(db.scan(b"k", None).unwrap().len(), 20);
    assert_eq!(db.get_by_value(&[b'x'; 100]).unwrap().len(), 20);
    db.verify().unwrap();
    db.close().unwrap();
    drop(db);
    let db = Db::open(&dir).unwrap();
    assert_eq!(db.get(&key(390)).unwrap(), Some(vec![b'x'; 100]));
    db.verify().unwrap();
}

#[test]
fn value_index_accepts_values_of_any_size() {
    let dir = tmpdir("index-any-size");
    let mut db = Db::open(&dir).unwrap();
    db.create_value_index().unwrap();
    let big = vec![b'v'; 3 << 20];
    db.put(b"a", &big).unwrap();
    db.put(b"b", &big).unwrap();
    db.put(&[b'k'; 1024], b"curto").unwrap();
    assert_eq!(
        db.get_by_value(&big).unwrap(),
        [b"a".to_vec(), b"b".to_vec()]
    );
    assert_eq!(db.get_by_value(b"curto").unwrap(), [vec![b'k'; 1024]]);
    db.delete(b"a").unwrap();
    assert_eq!(db.get_by_value(&big).unwrap(), [b"b".to_vec()]);
    db.verify().unwrap();
}
