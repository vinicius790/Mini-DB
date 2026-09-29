//! TTL, iteradores por folha, prefixo, contagem, lote atômico e SQL 0.4.
use mini_db::{BatchOp, Db, ExecResult, KeyTtl};
use std::thread::sleep;
use std::time::Duration;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-v04-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

const SHORT: Duration = Duration::from_millis(40);
const WAIT: Duration = Duration::from_millis(120);
const LONG: Duration = Duration::from_secs(3600);

#[test]
fn ttl_hides_expired_keys_everywhere() {
    let mut db = Db::open(tmpdir("ttl-hide")).unwrap();
    db.create_value_index().unwrap();
    db.put_with_ttl(b"tmp", b"v", SHORT).unwrap();
    db.put(b"keep", b"v").unwrap();
    assert!(db.contains(b"tmp").unwrap());
    sleep(WAIT);
    assert_eq!(db.get(b"tmp").unwrap(), None);
    assert_eq!(db.ttl(b"tmp").unwrap(), KeyTtl::Missing);
    assert_eq!(db.count(b"\0", None).unwrap(), 1);
    assert_eq!(db.get_by_value(b"v").unwrap(), vec![b"keep".to_vec()]);
    assert!(!db.delete(b"tmp").unwrap(), "expirada conta como ausente");
    assert_eq!(db.ttl(b"keep").unwrap(), KeyTtl::Persistent);
    db.verify().unwrap();
}

#[test]
fn put_clears_ttl_and_persist_expire_work() {
    let mut db = Db::open(tmpdir("ttl-ops")).unwrap();
    db.put_with_ttl(b"k", b"1", SHORT).unwrap();
    db.put(b"k", b"2").unwrap();
    sleep(WAIT);
    assert_eq!(db.get(b"k").unwrap().as_deref(), Some(b"2".as_ref()));
    assert!(db.expire(b"k", LONG).unwrap());
    assert!(matches!(db.ttl(b"k").unwrap(), KeyTtl::ExpiresIn(d) if d > Duration::from_secs(3500)));
    assert!(db.persist(b"k").unwrap());
    assert!(!db.persist(b"k").unwrap());
    assert!(!db.expire(b"missing", LONG).unwrap());
}

#[test]
fn ttl_survives_crash_and_purge_is_logged() {
    let dir = tmpdir("ttl-crash");
    let mut db = Db::open_with_capacity(&dir, 4).unwrap();
    for i in 0..100u32 {
        let ttl = if i % 2 == 0 { SHORT } else { LONG };
        db.put_with_ttl(format!("k{i:03}").as_bytes(), b"v", ttl)
            .unwrap();
    }
    db.drop_without_checkpoint();
    sleep(WAIT);
    let mut db = Db::open_with_capacity(&dir, 4).unwrap();
    assert_eq!(db.count(b"k", None).unwrap(), 50);
    assert_eq!(db.purge_expired().unwrap(), 50);
    db.drop_without_checkpoint();
    let mut db = Db::open(&dir).unwrap();
    assert_eq!(db.scan(b"k", None).unwrap().len(), 50);
    assert_eq!(db.purge_expired().unwrap(), 0);
    let pages = db.vacuum().unwrap();
    assert!(pages >= 3, "primária + TTL");
    assert!(matches!(db.ttl(b"k001").unwrap(), KeyTtl::ExpiresIn(_)));
    db.verify().unwrap();
}

#[test]
fn iterator_streams_across_leaves_with_bounds_and_prefix() {
    let mut db = Db::open_with_capacity(tmpdir("iter"), 4).unwrap();
    for i in 0..500u32 {
        let group = if i % 2 == 0 { "even" } else { "odd" };
        db.put(format!("{group}:{i:04}").as_bytes(), &[b'x'; 90])
            .unwrap();
    }
    assert_eq!(db.scan_prefix(b"even:").unwrap().count(), 250);
    assert_eq!(db.count(b"odd:", Some(b"odd:0100")).unwrap(), 50);
    let first: Vec<_> = db
        .iter(b"odd:", None)
        .unwrap()
        .take(3)
        .map(|r| r.unwrap().0)
        .collect();
    assert_eq!(
        first,
        [
            b"odd:0001".to_vec(),
            b"odd:0003".to_vec(),
            b"odd:0005".to_vec()
        ]
    );
    let page = db
        .scan_page(b"even:", Some(b"even;"), Some(b"even:0496"), 10)
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(db.scan_prefix(&[0xff]).unwrap().count(), 0);
}

#[test]
fn iterator_merges_open_transaction() {
    let mut db = Db::open(tmpdir("iter-txn")).unwrap();
    db.put(b"a", b"1").unwrap();
    db.put(b"b", b"2").unwrap();
    db.begin().unwrap();
    db.delete(b"a").unwrap();
    db.put(b"c", b"3").unwrap();
    db.put_with_ttl(b"d", b"4", LONG).unwrap();
    let keys: Vec<_> = db.iter(b"a", None).unwrap().map(|r| r.unwrap().0).collect();
    assert_eq!(keys, [b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]);
    db.rollback().unwrap();
    assert_eq!(db.count(b"a", None).unwrap(), 2);
}

#[test]
fn batch_is_atomic_across_crash() {
    let dir = tmpdir("batch");
    let mut db = Db::open(&dir).unwrap();
    db.put(b"old", b"x").unwrap();
    db.write_batch(&[
        BatchOp::Put {
            key: b"a".to_vec(),
            value: b"1".to_vec(),
        },
        BatchOp::PutWithTtl {
            key: b"b".to_vec(),
            value: b"2".to_vec(),
            ttl: LONG,
        },
        BatchOp::Delete {
            key: b"old".to_vec(),
        },
    ])
    .unwrap();
    let invalid = db.write_batch(&[
        BatchOp::Put {
            key: b"c".to_vec(),
            value: b"3".to_vec(),
        },
        BatchOp::Put {
            key: Vec::new(),
            value: b"x".to_vec(),
        },
    ]);
    assert!(invalid.is_err());
    db.drop_without_checkpoint();
    let mut db = Db::open(&dir).unwrap();
    let keys: Vec<_> = db
        .scan(b"\0", None)
        .unwrap()
        .into_iter()
        .map(|r| r.0)
        .collect();
    assert_eq!(keys, [b"a".to_vec(), b"b".to_vec()]);
    assert!(matches!(db.ttl(b"b").unwrap(), KeyTtl::ExpiresIn(_)));
}

#[test]
fn sql_count_like_and_ttl() {
    let mut db = Db::open(tmpdir("sql")).unwrap();
    for key in ["user:1", "user:2", "user_x", "zeta"] {
        db.execute_sql(&format!("INSERT INTO kv VALUES ('{key}', 'v')"))
            .unwrap();
    }
    let run = |db: &mut Db, sql: &str| db.execute_sql(sql).unwrap();
    assert_eq!(
        run(&mut db, "SELECT COUNT(*) FROM kv"),
        ExecResult::Count(4)
    );
    assert_eq!(
        run(&mut db, "SELECT COUNT(*) FROM kv WHERE key LIKE 'user:%'"),
        ExecResult::Count(2)
    );
    assert_eq!(
        run(&mut db, "SELECT COUNT(*) FROM kv WHERE key <= 'user:2'"),
        ExecResult::Count(2)
    );
    match run(
        &mut db,
        "SELECT key, value FROM kv WHERE key LIKE 'user_%' LIMIT 5",
    ) {
        ExecResult::Rows(rows) => assert_eq!(rows.len(), 1, "_ é literal"),
        other => panic!("{other:?}"),
    }
    run(&mut db, "INSERT INTO kv VALUES ('s', 'v') TTL 3600");
    assert!(matches!(db.ttl(b"s").unwrap(), KeyTtl::ExpiresIn(_)));
    for bad in [
        "SELECT COUNT(key) FROM kv",
        "SELECT * FROM kv WHERE key LIKE '%x'",
        "SELECT * FROM kv WHERE value LIKE 'a%'",
        "INSERT INTO kv VALUES ('a', 'b') TTL 0",
    ] {
        assert!(db.execute_sql(bad).is_err(), "aceitou: {bad}");
    }
    match run(
        &mut db,
        "EXPLAIN SELECT COUNT(*) FROM kv WHERE key LIKE 'u%'",
    ) {
        ExecResult::Ok(plan) => assert!(plan.contains("COUNT plan=primary prefix")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn page_stats_track_empty_leaves_and_vacuum() {
    let mut db = Db::open_with_capacity(tmpdir("pages"), 8).unwrap();
    for i in 0..300u32 {
        db.put(format!("k{i:04}").as_bytes(), &[b'v'; 200]).unwrap();
    }
    for i in 0..290u32 {
        db.delete(format!("k{i:04}").as_bytes()).unwrap();
    }
    let before = db.page_stats().unwrap();
    assert!(before.empty_leaves > 0 && before.height >= 2, "{before}");
    db.vacuum().unwrap();
    let after = db.page_stats().unwrap();
    assert_eq!(after.empty_leaves, 0, "{after}");
    assert!(after.total_pages < before.total_pages);
    assert!(after.fill_percent > before.fill_percent);
}

#[test]
fn cli_commands_cover_new_features() {
    let mut db = Db::open(tmpdir("cli")).unwrap();
    let mut run = |line: &str| mini_db::cmd::apply(&mut db, line).unwrap();
    assert!(run("SETEX s 3600 valor com espaços").starts_with("OK"));
    assert!(run("TTL s").starts_with("ttl_ms="));
    assert_eq!(run("PERSIST s"), "OK\n");
    assert_eq!(run("TTL s"), "(persistent)\n");
    assert_eq!(run("EXISTS s"), "1\n");
    run("PUT p:1 a");
    run("PUT p:2 b");
    assert_eq!(run("COUNT p: p;"), "COUNT 2\n");
    assert!(run("PREFIX p: 1").ends_with("END count=1\n"));
    assert!(run("PAGES").contains("height="));
    assert_eq!(run("PURGE"), "OK purged=0\n");
    assert!(run("HELP").contains("SETEX"));
}
