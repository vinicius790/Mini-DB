//! JSON, backup JSONL e config.

use mini_db::backup::{export_jsonl, import_jsonl};
use mini_db::config::Config;
use mini_db::json::Json;
use mini_db::metrics::Metrics;
use mini_db::Db;
use std::fs;

/// Sufixo único por processo: só pid + relógio colide entre testes paralelos.
static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmpdir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-prod-{}-{}-{}",
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
fn json_roundtrip() {
    let j = Json::obj()
        .put("key", Json::String("k".into()))
        .put("n", Json::Number(3));
    let p = Json::parse(&j.stringify()).unwrap();
    assert_eq!(p.get("key").and_then(Json::as_str), Some("k"));
}

#[test]
fn backup_export_import() {
    let a = tmpdir();
    let b = tmpdir();
    let dump = a.join("dump.jsonl");
    {
        let mut db = Db::open(&a).unwrap();
        db.put(b"x", b"1").unwrap();
        db.put(b"y", b"2").unwrap();
        assert_eq!(export_jsonl(&mut db, &dump).unwrap(), 2);
        db.close().unwrap();
    }
    let mut db = Db::open(&b).unwrap();
    assert_eq!(import_jsonl(&mut db, &dump).unwrap(), 2);
    assert_eq!(db.get(b"x").unwrap().as_deref(), Some(b"1".as_ref()));
    assert_eq!(db.get(b"y").unwrap().as_deref(), Some(b"2".as_ref()));
}

#[test]
fn metrics_prometheus_contains_counters() {
    let m = Metrics::new();
    m.inc_put();
    m.inc_get(true);
    let s = m.render_prometheus();
    assert!(s.contains("minidb_puts_total 1"));
    assert!(s.contains("minidb_get_hits_total 1"));
}

#[test]
fn config_parses_toml_snippet() {
    let dir = tmpdir();
    fs::write(
        dir.join("minidb.toml"),
        "pool_frames = 32\nhttp_addr = \"0.0.0.0:9\"\n",
    )
    .unwrap();
    let cfg = Config::load(Some(&dir)).unwrap();
    assert_eq!(cfg.pool_frames, 32);
    assert_eq!(cfg.http_addr, "0.0.0.0:9");
}
