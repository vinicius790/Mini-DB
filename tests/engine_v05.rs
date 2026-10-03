//! Compressão, MVCC entre threads e replicação primário → réplica.
use mini_db::mvcc::SharedDb;
use mini_db::replication::{applied_lsn, enable_feed, run_replica, serve_primary};
use mini_db::{Db, Error, ExecResult};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("minidb-v05-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

#[test]
fn compression_shrinks_file_and_survives_crash_and_vacuum() {
    let size = |compress: bool| {
        let dir = tmpdir(&format!("zip-{compress}"));
        let mut db = Db::open(&dir).unwrap();
        let value =
            br#"{"type":"event","user":"someone","payload":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#
                .repeat(8);
        for i in 0..400u32 {
            let v = if compress {
                value.clone()
            } else {
                (0..value.len())
                    .map(|j| (i as usize * 31 + j * 17) as u8)
                    .collect()
            };
            db.put(format!("k{i:05}").as_bytes(), &v).unwrap();
        }
        db.drop_without_checkpoint();
        let mut db = Db::open(&dir).unwrap();
        assert_eq!(db.count(b"k", None).unwrap(), 400);
        if compress {
            assert_eq!(db.get(b"k00007").unwrap().unwrap(), value);
        }
        db.vacuum().unwrap();
        db.verify().unwrap();
        db.close().unwrap();
        drop(db);
        std::fs::metadata(Db::data_path(&dir)).unwrap().len()
    };
    let (small, big) = (size(true), size(false));
    assert!(small * 2 < big, "comprimido={small} cru={big}");
}

#[test]
fn snapshots_see_a_frozen_sql_view_while_writers_continue() {
    let shared = SharedDb::new(Db::open(tmpdir("snap")).unwrap());
    shared
        .sql("CREATE TABLE acc (id INT PRIMARY KEY, balance INT)")
        .unwrap();
    shared
        .sql("INSERT INTO acc VALUES (1, 100), (2, 100)")
        .unwrap();
    let snap = shared.snapshot().unwrap();
    let writer = {
        let shared = shared.clone();
        thread::spawn(move || {
            for _ in 0..50 {
                shared
                    .sql("UPDATE acc SET balance = balance - 1 WHERE id = 1")
                    .unwrap();
                shared
                    .sql("UPDATE acc SET balance = balance + 1 WHERE id = 2")
                    .unwrap();
            }
            shared.sql("INSERT INTO acc VALUES (3, 0)").unwrap();
        })
    };
    for _ in 0..20 {
        match snap
            .query("SELECT COUNT(*), SUM(balance) FROM acc")
            .unwrap()
        {
            ExecResult::Table { rows, .. } => assert_eq!(
                rows[0][0].to_string() + "|" + &rows[0][1].to_string(),
                "2|200"
            ),
            other => panic!("{other:?}"),
        }
    }
    writer.join().unwrap();
    let ExecResult::Table { rows, .. } =
        snap.query("SELECT balance FROM acc WHERE id = 1").unwrap()
    else {
        panic!()
    };
    assert_eq!(rows[0][0].to_string(), "100", "snapshot congelado");
    assert!(
        snap.query("DELETE FROM acc").is_err(),
        "snapshot é somente leitura"
    );
    drop(snap);
    let ExecResult::Table { rows, .. } = shared.sql("SELECT balance FROM acc ORDER BY id").unwrap()
    else {
        panic!()
    };
    assert_eq!(
        rows.iter().map(|r| r[0].to_string()).collect::<Vec<_>>(),
        ["50", "150", "0"]
    );
}

#[test]
fn optimistic_transactions_detect_conflicts() {
    let shared = SharedDb::new(Db::open(tmpdir("occ")).unwrap());
    let mut a = shared.begin().unwrap();
    let mut b = shared.begin().unwrap();
    a.put(b"x", b"a").unwrap();
    b.put(b"y", b"b").unwrap();
    assert_eq!(b.get(b"y").unwrap().as_deref(), Some(&b"b"[..]));
    assert_eq!(a.get(b"y").unwrap(), None, "isolamento");
    a.commit().unwrap();
    b.commit().unwrap(); // chaves disjuntas: sem conflito
    let mut c = shared.begin().unwrap();
    shared.put(b"x", b"direto").unwrap();
    c.put(b"x", b"c").unwrap();
    assert!(matches!(c.commit(), Err(Error::Conflict(_))));
    assert!(shared.begin().unwrap().put(&[0xFF], b"v").is_err());
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timeout esperando {what}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn get_ok(db: &SharedDb, key: &[u8]) -> Option<Vec<u8>> {
    db.read().ok().and_then(|g| g.get(key).ok().flatten())
}

#[test]
fn replica_follows_primary_snapshot_then_stream_and_is_read_only() {
    let primary = SharedDb::new(Db::open(tmpdir("primary")).unwrap());
    // Estado anterior ao feed: chega à réplica por snapshot completo.
    primary.put(b"antes", b"1").unwrap();
    primary
        .sql("CREATE TABLE t2 (id INT PRIMARY KEY, v TEXT)")
        .unwrap();
    enable_feed(&primary, 10_000).unwrap();
    let addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    {
        let (p, a) = (primary.clone(), addr.clone());
        thread::spawn(move || serve_primary(p, &a, 10_000));
    }
    let replica = SharedDb::new(Db::open(tmpdir("replica")).unwrap());
    replica.put(b"lixo-local", b"x").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let follower = {
        let (r, s, a) = (replica.clone(), Arc::clone(&stop), addr.clone());
        thread::spawn(move || run_replica(r, &a, s))
    };
    wait_until("snapshot", || get_ok(&replica, b"antes").is_some());
    assert_eq!(
        get_ok(&replica, b"lixo-local"),
        None,
        "snapshot substitui o estado"
    );
    // Mudanças novas chegam pelo stream, inclusive TTL e SQL.
    primary
        .put_with_ttl(b"ttl", b"v", Duration::from_secs(3600))
        .unwrap();
    primary
        .sql("INSERT INTO t2 VALUES (1, 'um'), (2, 'dois')")
        .unwrap();
    primary.delete(b"antes").unwrap();
    wait_until("stream", || {
        get_ok(&replica, b"antes").is_none() && get_ok(&replica, b"ttl").is_some()
    });
    {
        let r = replica.read().unwrap();
        assert!(matches!(
            r.ttl(b"ttl").unwrap(),
            mini_db::KeyTtl::ExpiresIn(_)
        ));
        let ExecResult::Table { rows, .. } = r.query("SELECT v FROM t2 ORDER BY id").unwrap()
        else {
            panic!()
        };
        assert_eq!(rows.len(), 2);
        assert!(applied_lsn(&r).unwrap() > 0);
        r.verify().unwrap();
    }
    assert!(matches!(replica.put(b"w", b"v"), Err(Error::ReadOnly)));
    assert!(matches!(
        replica.sql("INSERT INTO t2 VALUES (3, 'x')"),
        Err(Error::ReadOnly)
    ));
    stop.store(true, Ordering::Relaxed);
    primary.put(b"acorda", b"1").unwrap(); // desbloqueia a leitura
    follower.join().unwrap().unwrap();
}
