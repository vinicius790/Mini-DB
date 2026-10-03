//! Invariantes pesados: delete em massa, verify após splits, réplica, bloom.

use mini_db::replica::{compare_sample, open_standby, ship_snapshot};
use mini_db::{Db, MAX_KEY_LEN};
use std::fs;

/// Sufixo único por processo: só pid + relógio colide entre testes paralelos.
static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-{tag}-{}-{}-{}",
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
fn delete_half_then_verify() {
    let dir = tmpdir("del");
    let mut db = Db::open_with_capacity(&dir, 32).unwrap();
    let val = vec![b'z'; 48];
    for i in 0..120 {
        db.put(format!("k{i:04}").as_bytes(), &val).unwrap();
    }
    for i in (0..120).step_by(2) {
        assert!(db.delete(format!("k{i:04}").as_bytes()).unwrap());
    }
    for i in 0..120 {
        let got = db.get(format!("k{i:04}").as_bytes()).unwrap();
        if i % 2 == 0 {
            assert!(got.is_none(), "ainda viva {i}");
        } else {
            assert!(got.is_some(), "sumiu {i}");
        }
    }
    let r = db.verify().unwrap();
    assert!(r.keys >= 60);
    db.close().unwrap();
}

#[test]
fn bloom_does_not_hide_existing_keys() {
    let dir = tmpdir("bloom");
    let mut db = Db::open(&dir).unwrap();
    db.put(b"hero", b"alucard").unwrap();
    db.put(b"whip", b"vk").unwrap();
    assert_eq!(
        db.get(b"hero").unwrap().as_deref(),
        Some(b"alucard".as_ref())
    );
    assert_eq!(db.get(b"missing-key-xyz").unwrap(), None);
    assert!(db.get(b"").is_err());
    assert!(db.get(&[b'x'; MAX_KEY_LEN + 1]).is_err());
    db.close().unwrap();
}

#[test]
fn replica_ship_sees_same_keys() {
    let src = tmpdir("pri");
    let dst = tmpdir("stb");
    {
        let mut db = Db::open(&src).unwrap();
        db.put(b"a", b"1").unwrap();
        db.put(b"b", b"2").unwrap();
        db.checkpoint().unwrap();
        db.close().unwrap();
    }
    ship_snapshot(&src, &dst).unwrap();
    let mut pri = Db::open(&src).unwrap();
    let mut stb = open_standby(&dst).unwrap();
    assert!(compare_sample(&mut pri, &mut stb, &[b"a", b"b", b"c"]).unwrap());
}

#[test]
fn replica_ship_rejects_open_primary() {
    let src = tmpdir("pri-open");
    let dst = tmpdir("stb-open");
    let mut primary = Db::open(&src).unwrap();
    primary.put(b"a", b"1").unwrap();
    assert!(ship_snapshot(&src, &dst).is_err());
    primary.close().unwrap();
    drop(primary);
    ship_snapshot(&src, &dst).unwrap();
    let standby = open_standby(&dst).unwrap();
    assert_eq!(standby.get(b"a").unwrap().as_deref(), Some(b"1".as_ref()));
}

#[test]
fn inspect_root_mentions_kind() {
    let dir = tmpdir("insp");
    let mut db = Db::open(&dir).unwrap();
    db.put(b"k", b"v").unwrap();
    let text = db.inspect_page(1).unwrap();
    assert!(text.contains("page 1"));
    let hex = db.inspect_hex(0, 64).unwrap();
    assert!(hex.contains("0000"));
}
