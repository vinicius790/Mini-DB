//! SQL subset, transações e índice secundário.

use mini_db::db::ExecResult;
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
fn delete_and_reopen() {
    let dir = tmpdir();
    {
        let mut db = Db::open(dir.as_path()).unwrap();
        db.put(b"keep", b"1").unwrap();
        db.put(b"drop", b"2").unwrap();
        assert!(db.delete(b"drop").unwrap());
        assert_eq!(db.get(b"drop").unwrap(), None);
        db.close().unwrap();
    }
    let db = Db::open(dir.as_path()).unwrap();
    assert_eq!(db.get(b"keep").unwrap().as_deref(), Some(b"1".as_ref()));
    assert_eq!(db.get(b"drop").unwrap(), None);
}

#[test]
fn txn_commit_and_rollback() {
    let dir = tmpdir();
    let mut db = Db::open(dir.as_path()).unwrap();
    db.put(b"base", b"0").unwrap();
    db.begin().unwrap();
    db.put(b"base", b"1").unwrap();
    db.put(b"extra", b"x").unwrap();
    assert_eq!(db.get(b"base").unwrap().as_deref(), Some(b"1".as_ref()));
    db.rollback().unwrap();
    assert_eq!(db.get(b"base").unwrap().as_deref(), Some(b"0".as_ref()));
    assert_eq!(db.get(b"extra").unwrap(), None);

    db.begin().unwrap();
    db.put(b"extra", b"y").unwrap();
    db.commit().unwrap();
    assert_eq!(db.get(b"extra").unwrap().as_deref(), Some(b"y".as_ref()));
}

#[test]
fn txn_crash_without_commit_is_aborted() {
    let dir = tmpdir();
    {
        let mut db = Db::open(dir.as_path()).unwrap();
        db.put(b"stable", b"s").unwrap();
        db.begin().unwrap();
        db.put(b"ghost", b"no").unwrap();
        // WAL ainda não tem COMMIT; abandonar sem close/checkpoint.
        db.drop_without_checkpoint();
    }
    let db = Db::open(dir.as_path()).unwrap();
    assert_eq!(db.get(b"stable").unwrap().as_deref(), Some(b"s".as_ref()));
    // ghost só existia no write-set em memória — sem BEGIN no WAL se rollback...
    // begin() não grava WAL até commit(). Logo ghost some. Correto.
    assert_eq!(db.get(b"ghost").unwrap(), None);
}

#[test]
fn sql_insert_select_update_delete() {
    let dir = tmpdir();
    let mut db = Db::open(dir.as_path()).unwrap();
    match db
        .execute_sql("INSERT INTO kv (key, value) VALUES ('hero', 'alucard')")
        .unwrap()
    {
        ExecResult::Ok(s) => assert!(s.contains("INSERT")),
        _ => panic!("expected ok"),
    }
    match db
        .execute_sql("SELECT * FROM kv WHERE key = 'hero'")
        .unwrap()
    {
        ExecResult::Rows(rows) => {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].1, b"alucard");
        }
        _ => panic!("expected rows"),
    }
    db.execute_sql("UPDATE kv SET value = 'trevor' WHERE key = 'hero'")
        .unwrap();
    assert_eq!(
        db.get(b"hero").unwrap().as_deref(),
        Some(b"trevor".as_ref())
    );
    db.execute_sql("DELETE FROM kv WHERE key = 'hero'").unwrap();
    assert_eq!(db.get(b"hero").unwrap(), None);
}

#[test]
fn value_index_lookup() {
    let dir = tmpdir();
    let mut db = Db::open(dir.as_path()).unwrap();
    db.put(b"a", b"red").unwrap();
    db.put(b"b", b"blue").unwrap();
    db.put(b"c", b"red").unwrap();
    db.create_value_index().unwrap();
    let mut keys = db.get_by_value(b"red").unwrap();
    keys.sort();
    assert_eq!(keys, vec![b"a".to_vec(), b"c".to_vec()]);
    db.put(b"a", b"green").unwrap();
    let mut keys = db.get_by_value(b"red").unwrap();
    keys.sort();
    assert_eq!(keys, vec![b"c".to_vec()]);
}

#[test]
fn sql_explain_and_limit() {
    let dir = tmpdir();
    let mut db = Db::open(dir.as_path()).unwrap();
    for i in 0..10 {
        db.put(format!("k{i}").as_bytes(), b"v").unwrap();
    }
    match db
        .execute_sql("SELECT * FROM kv WHERE key >= 'k2' ORDER BY key ASC LIMIT 3")
        .unwrap()
    {
        ExecResult::Rows(rows) => assert_eq!(rows.len(), 3),
        _ => panic!("rows"),
    }
    match db
        .execute_sql("EXPLAIN SELECT * FROM kv WHERE value = 'v'")
        .unwrap()
    {
        ExecResult::Ok(s) => assert!(s.contains("secondary") || s.contains("plan")),
        _ => panic!("explain"),
    }
}

#[test]
fn sql_rejects_unknown_tables_invalid_columns_and_trailing_tokens() {
    for sql in [
        "INSERT INTO users VALUES ('k', 'v')",
        "INSERT INTO kv (value, key) VALUES ('v', 'k')",
        "UPDATE users SET value = 'v' WHERE key = 'k'",
        "DELETE FROM users WHERE key = 'k'",
        "CREATE INDEX ON kv",
        "SELECT * FROM kv ORDER BY value",
        "SELECT * FROM kv; SELECT * FROM kv",
    ] {
        assert!(db_parse_fails(sql), "accepted invalid SQL: {sql}");
    }
}

fn db_parse_fails(sql: &str) -> bool {
    mini_db::parse_sql(sql).is_err()
}
