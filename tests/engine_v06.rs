//! 0.6: valores grandes (overflow), chaves de 1 KiB, splits por bytes,
//! checkpoint automático, VACUUM em streaming, TCP com token e replicação
//! autenticada, retomada pelo WAL arquivado, semi-síncrona, promoção e fencing.
use mini_db::config::NetOptions;
use mini_db::mvcc::SharedDb;
use mini_db::replication::{
    self, enable_feed, promote, run_replica_with, serve_primary_with, set_sync_replicas,
    ReplicationConfig, Role,
};
use mini_db::{Db, Error, MAX_KEY_LEN};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("minidb-v06-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Bytes pseudoaleatórios (incompressíveis) e determinísticos.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}

#[test]
fn large_values_and_keys_survive_crash_update_delete_and_vacuum() {
    let dir = tmpdir("large");
    let mut db = Db::open_with_capacity(&dir, 16).unwrap();
    let big = noise(5 << 20, 1);
    let text = b"linha repetitiva de log ".repeat(200_000);
    let long_key = vec![b'k'; MAX_KEY_LEN];
    db.put(b"big", &big).unwrap();
    db.put(b"text", &text).unwrap();
    db.put(&long_key, &noise(3000, 2)).unwrap();
    for i in 0..300u32 {
        db.put(
            format!("mid{i:04}").as_bytes(),
            &noise(700 + i as usize * 7, i as u64),
        )
        .unwrap();
    }
    assert!(db.page_stats().unwrap().overflow_pages > 1000);
    db.drop_without_checkpoint();

    let mut db = Db::open_with_capacity(&dir, 16).unwrap();
    assert_eq!(db.get(b"big").unwrap().unwrap(), big);
    assert_eq!(db.get(b"text").unwrap().unwrap(), text);
    assert_eq!(db.get(&long_key).unwrap().unwrap(), noise(3000, 2));
    db.verify().unwrap();
    // Encolher, apagar e regravar reaproveita as páginas liberadas.
    let pages_before = db.meta().next_page_id;
    db.put(b"big", b"agora pequeno").unwrap();
    db.delete(b"text").unwrap();
    assert!(db.page_stats().unwrap().free_pages > 1000);
    db.put(b"again", &noise(4 << 20, 3)).unwrap();
    assert!(
        db.meta().next_page_id <= pages_before,
        "freelist reutilizada"
    );
    db.verify().unwrap();
    let pages = db.vacuum().unwrap();
    assert!(pages < pages_before);
    assert_eq!(db.page_stats().unwrap().free_pages, 0);
    assert_eq!(db.get(b"again").unwrap().unwrap(), noise(4 << 20, 3));
    assert_eq!(db.count(b"mid", Some(b"mie")).unwrap(), 300);
    db.verify().unwrap();
    assert!(matches!(
        db.put(&vec![b'k'; MAX_KEY_LEN + 1], b"v"),
        Err(Error::KeyTooLarge(..))
    ));
}

#[test]
fn splits_by_bytes_handle_worst_case_cell_mixes() {
    // Células no limite do inline misturadas com mínimas, em ordens adversas:
    // o split por contagem da 0.5 falhava aqui.
    let dir = tmpdir("splits");
    let mut db = Db::open_with_capacity(&dir, 8).unwrap();
    let mut expected = std::collections::BTreeMap::new();
    for round in 0..6u64 {
        for i in 0..400u64 {
            let k = format!("{:06}", (i * 7919 + round * 104_729) % 5000).into_bytes();
            let len = match (i + round) % 4 {
                0 => 1,
                1 => 1200 - k.len(),
                2 => 900,
                _ => 60,
            };
            let v = noise(len, i ^ round);
            db.put(&k, &v).unwrap();
            expected.insert(k, v);
        }
    }
    let all = db.scan(b"\0", None).unwrap();
    assert_eq!(all.len(), expected.len());
    assert!(all.into_iter().eq(expected.into_iter()));
    db.verify().unwrap();
}

#[test]
fn auto_checkpoint_bounds_the_wal() {
    let dir = tmpdir("autockpt");
    let mut db = Db::open(&dir).unwrap();
    db.set_auto_checkpoint(256 << 10);
    for i in 0..200u32 {
        db.put(format!("k{i}").as_bytes(), &noise(8 << 10, i as u64))
            .unwrap();
        assert!(db.stats().wal_bytes < (256 << 10) + (16 << 10));
    }
    db.drop_without_checkpoint();
    let db = Db::open(&dir).unwrap();
    assert_eq!(db.count(b"k", Some(b"l")).unwrap(), 200);
}

#[test]
fn tcp_server_requires_token_when_configured() {
    let dir = tmpdir("tcp-auth");
    let db = SharedDb::new(Db::open(&dir).unwrap());
    let addr = free_addr();
    {
        let (db, addr) = (db.clone(), addr.clone());
        let opts = NetOptions {
            token: Some("t0k3n".into()),
            ..NetOptions::default()
        };
        thread::spawn(move || mini_db::server::serve_with(db, &addr, opts));
    }
    let connect = || {
        let start = Instant::now();
        loop {
            match TcpStream::connect(&addr) {
                Ok(s) => break s,
                Err(_) if start.elapsed() < Duration::from_secs(5) => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(e) => panic!("{e}"),
            }
        }
    };
    let stream = connect();
    let mut out = stream.try_clone().unwrap();
    let mut lines = BufReader::new(stream).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "minidb 1.3 ready");
    let mut ask = |cmd: &str| {
        writeln!(out, "{cmd}").unwrap();
        lines.next().unwrap().unwrap()
    };
    assert!(ask("GET a").contains("autenticação exigida"));
    assert_eq!(ask("AUTH t0k3n"), "OK authenticated");
    assert!(ask("PUT a 1").starts_with("OK lsn="));
    assert_eq!(ask("GET a"), "1");
    let stream = connect();
    let mut out = stream.try_clone().unwrap();
    let mut lines = BufReader::new(stream).lines();
    lines.next();
    writeln!(out, "AUTH errado").unwrap();
    assert_eq!(lines.next().unwrap().unwrap(), "ERR credenciais inválidas");
    assert!(lines.next().is_none(), "conexão encerrada");
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "timeout esperando {what}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn get_ok(db: &SharedDb, key: &[u8]) -> Option<Vec<u8>> {
    db.read().ok().and_then(|g| g.get(key).ok().flatten())
}

struct Node {
    db: SharedDb,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<mini_db::Result<()>>>,
}

impl Node {
    /// Para de seguir o upstream e fecha o banco (libera o diretório).
    fn shutdown(mut self) -> SharedDb {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            h.join().unwrap().unwrap();
        }
        self.db
    }
}

fn primary(dir: &std::path::Path, addr: &str, secret: Option<&str>) -> SharedDb {
    let mut raw = Db::open(dir).unwrap();
    raw.set_wal_retention(64 << 20);
    let db = SharedDb::new(raw);
    let cfg = ReplicationConfig {
        secret: secret.map(|s| s.as_bytes().to_vec()),
        ..ReplicationConfig::default()
    };
    enable_feed(&db, cfg.max_feed_ops).unwrap();
    let (d, a) = (db.clone(), addr.to_string());
    thread::spawn(move || serve_primary_with(d, &a, cfg));
    db
}

fn replica(dir: &std::path::Path, upstream: &str, secret: Option<&str>) -> Node {
    let db = SharedDb::new(Db::open(dir).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let cfg = ReplicationConfig {
        secret: secret.map(|s| s.as_bytes().to_vec()),
        ..ReplicationConfig::default()
    };
    let (d, s, u) = (db.clone(), Arc::clone(&stop), upstream.to_string());
    let handle = Some(thread::spawn(move || run_replica_with(d, &u, s, &cfg)));
    Node { db, stop, handle }
}

#[test]
fn encrypted_replication_rejects_wrong_secret_and_resumes_after_primary_restart() {
    let (pdir, rdir) = (tmpdir("enc-p"), tmpdir("enc-r"));
    let addr = free_addr();
    let p = primary(&pdir, &addr, Some("segredo-forte"));
    for i in 0..2000u32 {
        p.put(format!("k{i:05}").as_bytes(), &noise(64, i as u64))
            .unwrap();
    }
    // Segredo errado: nada chega.
    let wrong = replica(&tmpdir("enc-wrong"), &addr, Some("outro"));
    let r = replica(&rdir, &addr, Some("segredo-forte"));
    wait_until("snapshot em pedaços", || {
        get_ok(&r.db, b"k01999").is_some()
    });
    assert_eq!(get_ok(&wrong.db, b"k00000"), None);
    wrong.shutdown();
    assert_eq!(r.db.read().unwrap().count(b"k", Some(b"l")).unwrap(), 2000);

    // Reinicia o primário (checkpoint arquiva o WAL) e escreve mais.
    p.put(b"antes-do-restart", b"1").unwrap();
    wait_until("stream", || get_ok(&r.db, b"antes-do-restart").is_some());
    p.write().unwrap().close().unwrap();
    drop(p);
    thread::sleep(Duration::from_millis(100));
    let addr2 = free_addr();
    let p = primary(&pdir, &addr2, Some("segredo-forte"));
    p.put(b"depois", b"2").unwrap();
    r.shutdown().write().unwrap().close().unwrap();
    let r2 = replica(&rdir, &addr2, Some("segredo-forte"));
    wait_until("retomada", || get_ok(&r2.db, b"depois").is_some());
    let status = replication::status(&p).unwrap();
    assert_eq!(
        status.snapshots_sent, 0,
        "retomou pelo WAL arquivado, sem snapshot"
    );
    r2.db.read().unwrap().verify().unwrap();
    r2.shutdown();
}

#[test]
fn semi_sync_waits_for_acks_and_times_out_without_replicas() {
    let addr = free_addr();
    let p = primary(&tmpdir("sync-p"), &addr, None);
    set_sync_replicas(&p, 1, Some(Duration::from_millis(300))).unwrap();
    let t = Instant::now();
    p.put(b"sozinho", b"1").unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(250),
        "esperou o timeout"
    );
    assert_eq!(replication::status(&p).unwrap().sync_timeouts, 1);
    let r = replica(&tmpdir("sync-r"), &addr, None);
    wait_until("réplica pronta", || get_ok(&r.db, b"sozinho").is_some());
    set_sync_replicas(&p, 1, None).unwrap();
    for i in 0..20u32 {
        let k = format!("sync{i}");
        p.put(k.as_bytes(), b"v").unwrap();
        // Commit síncrono: quando put volta, a réplica já confirmou.
        assert!(get_ok(&r.db, k.as_bytes()).is_some(), "{k}");
    }
    set_sync_replicas(&p, 0, None).unwrap();
    r.shutdown();
}

#[test]
fn promotion_bumps_epoch_and_fences_the_old_primary() {
    let (a1, a2) = (free_addr(), free_addr());
    let old = primary(&tmpdir("fence-p"), &a1, None);
    old.put(b"x", b"1").unwrap();
    // Réplica em cascata: segue o primário e também serve réplicas (a2).
    let r = replica(&tmpdir("fence-r"), &a1, None);
    {
        let db = r.db.clone();
        enable_feed(&db, 10_000).unwrap();
        let a = a2.clone();
        thread::spawn(move || serve_primary_with(db, &a, ReplicationConfig::default()));
    }
    wait_until("réplica", || get_ok(&r.db, b"x").is_some());
    assert!(matches!(r.db.put(b"y", b"2"), Err(Error::ReadOnly)));
    assert_eq!(promote(&r.db).unwrap(), 1);
    r.db.put(b"y", b"2").unwrap();
    assert_eq!(replication::status(&r.db).unwrap().role, Role::Primary);
    // Uma réplica do novo primário (época 1) que encontra o primário antigo
    // (época 0) o isola.
    let c = replica(&tmpdir("fence-c"), &a2, None);
    wait_until("época nova", || get_ok(&c.db, b"y").is_some());
    let c_db = c.shutdown();
    let c_view = c_db.clone();
    let stop = Arc::new(AtomicBool::new(false));
    {
        let (s, a) = (Arc::clone(&stop), a1.clone());
        thread::spawn(move || run_replica_with(c_db, &a, s, &ReplicationConfig::default()));
    }
    wait_until("fencing", || {
        replication::status(&old).unwrap().role == Role::Fenced
    });
    assert!(matches!(old.put(b"z", b"3"), Err(Error::ReadOnly)));
    assert_eq!(get_ok(&c_view, b"z"), None);
    stop.store(true, Ordering::Release);
}
