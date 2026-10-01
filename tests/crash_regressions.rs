use mini_db::Db;
use std::{fs, path::PathBuf};

/// Sufixo único por processo: só pid + relógio colide entre testes paralelos.
static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn dir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-regression-{tag}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn eviction_and_root_splits_survive_repeated_crashes() {
    let dir = dir("splits");
    for round in 0..3 {
        let mut db = Db::open_with_capacity(&dir, 4).unwrap();
        for i in 0..400 {
            let key = format!("k{i:04}");
            let value = vec![round as u8; 180];
            db.put(key.as_bytes(), &value).unwrap();
        }
        db.drop_without_checkpoint();
        let db = Db::open_with_capacity(&dir, 4).unwrap();
        for i in 0..400 {
            assert_eq!(
                db.get(format!("k{i:04}").as_bytes()).unwrap(),
                Some(vec![round as u8; 180]),
                "round={round} key={i}"
            );
        }
        assert_eq!(db.scan(b"k", None).unwrap().len(), 400);
        db.drop_without_checkpoint();
    }
}

#[test]
fn checkpoint_then_evicted_updates_recover_consistently() {
    let dir = dir("checkpoint");
    let mut db = Db::open_with_capacity(&dir, 4).unwrap();
    for i in 0..200 {
        db.put(format!("k{i:04}").as_bytes(), &[1; 100]).unwrap();
    }
    db.checkpoint().unwrap();
    for i in 0..200 {
        if i % 3 == 0 {
            db.delete(format!("k{i:04}").as_bytes()).unwrap();
        } else {
            db.put(format!("k{i:04}").as_bytes(), &vec![2; 240])
                .unwrap();
        }
    }
    db.drop_without_checkpoint();
    let db = Db::open_with_capacity(&dir, 4).unwrap();
    for i in 0..200 {
        let want = if i % 3 == 0 { None } else { Some(vec![2; 240]) };
        assert_eq!(
            db.get(format!("k{i:04}").as_bytes()).unwrap(),
            want,
            "key={i}"
        );
    }
}

#[test]
fn failed_second_open_does_not_change_database() {
    let dir = dir("lock");
    let mut first = Db::open(&dir).unwrap();
    first.put(b"owner", b"one").unwrap();
    assert!(
        Db::open(&dir).is_err(),
        "a second writer must not open the same database"
    );
    first.close().unwrap();
    drop(first);
    let reopened = Db::open(&dir).unwrap();
    assert_eq!(
        reopened.get(b"owner").unwrap().as_deref(),
        Some(b"one".as_slice())
    );
}

#[test]
fn incomplete_transaction_does_not_swallow_later_writes() {
    use mini_db::wal::{Wal, WalRecord};
    let dir = dir("incomplete");
    {
        let mut db = Db::open(&dir).unwrap();
        db.checkpoint().unwrap();
    }
    {
        let mut wal = Wal::open(Db::wal_path(&dir), 1).unwrap();
        wal.append(WalRecord::Begin { lsn: 0, txn_id: 42 }).unwrap();
        wal.append(WalRecord::Insert {
            lsn: 0,
            key: b"abandoned".to_vec(),
            value: b"no".to_vec(),
        })
        .unwrap();
        wal.sync().unwrap();
    }
    let mut db = Db::open(&dir).unwrap();
    assert_eq!(db.get(b"abandoned").unwrap(), None);
    db.put(b"later", b"yes").unwrap();
    db.drop_without_checkpoint();
    let mut db = Db::open(&dir).unwrap();
    assert_eq!(db.get(b"abandoned").unwrap(), None);
    assert_eq!(
        db.get(b"later").unwrap().as_deref(),
        Some(b"yes".as_slice())
    );
    assert!(db.begin().unwrap() > 42);
}

#[test]
fn partial_data_file_is_rejected_without_reinitialization() {
    let dir = dir("corrupt");
    fs::write(Db::data_path(&dir), b"not-a-valid-database").unwrap();
    assert!(Db::open(&dir).is_err());
    assert_eq!(
        fs::read(Db::data_path(&dir)).unwrap(),
        b"not-a-valid-database"
    );
}

#[test]
fn backup_roundtrips_binary_values_and_import_is_atomic() {
    use mini_db::backup::{export_jsonl, import_jsonl};
    let source = dir("backup");
    let destination = dir("restore");
    let mut db = Db::open(&source).unwrap();
    db.put(&[0x01, 0xff, 0x00], &[0x80, 0xff, 0x00, b'\n'])
        .unwrap();
    db.execute_sql("CREATE TABLE t2 (id INT PRIMARY KEY)")
        .unwrap();
    db.execute_sql("INSERT INTO t2 VALUES (7)").unwrap();
    let backup = source.join("backup.jsonl");
    export_jsonl(&mut db, &backup).unwrap();
    let mut restored = Db::open(&destination).unwrap();
    assert_eq!(
        import_jsonl(&mut restored, &backup).unwrap(),
        5,
        "kv + catálogo + seqs + linha"
    );
    assert!(matches!(
        restored.execute_sql("SELECT COUNT(*) FROM t2").unwrap(),
        mini_db::ExecResult::Table { .. }
    ));
    assert_eq!(
        restored.get(&[0x01, 0xff, 0x00]).unwrap(),
        Some(vec![0x80, 0xff, 0x00, b'\n'])
    );
    fs::write(
        &backup,
        "{\"key\":\"new\",\"value\":\"data\"}\n{\"key\":\"bad\"}\n",
    )
    .unwrap();
    assert!(import_jsonl(&mut restored, &backup).is_err());
    assert_eq!(restored.get(b"new").unwrap(), None);
    assert!(!restored.stats().txn_open);
}

#[test]
fn committed_transaction_survives_process_exit_without_destructors() {
    let dir = dir("process");
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "process_crash_writer"])
        .env("MINIDB_CRASH_TEST_DIR", &dir)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(73));
    let db = Db::open_with_capacity(&dir, 4).unwrap();
    assert_eq!(db.scan(b"k", None).unwrap().len(), 200);
    for i in 0..200 {
        assert_eq!(
            db.get(format!("k{i:04}").as_bytes()).unwrap(),
            Some(vec![3; 150])
        );
    }
}

#[test]
#[ignore = "subprocess helper; invoked by the parent crash test"]
fn process_crash_writer() {
    let dir = std::env::var_os("MINIDB_CRASH_TEST_DIR").unwrap();
    let mut db = Db::open_with_capacity(dir, 4).unwrap();
    db.begin().unwrap();
    for i in 0..200 {
        db.put(format!("k{i:04}").as_bytes(), &[3; 150]).unwrap();
    }
    db.commit().unwrap();
    std::process::exit(73);
}
