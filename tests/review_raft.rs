//! Modo cluster com três nós reais: elegem um líder, a escrita confirmada chega
//! aos outros e, derrubado o líder, outro assume e aceita escrita sem perder o
//! que já tinha sido confirmado.

use mini_db::mvcc::SharedDb;
use mini_db::replication::{self, start_cluster, ClusterConfig, ReplicationConfig, Role};
use mini_db::{Db, Error};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Sufixo único por processo: só pid + relógio colide entre testes paralelos.
static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmpdir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-review-raft-{}-{}-{}",
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

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

/// Espera uma condição com prazo (nunca um `sleep` fixo como sincronização).
fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timeout esperando {what}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn get_ok(db: &SharedDb, key: &[u8]) -> Option<Vec<u8>> {
    db.read().ok().and_then(|g| g.get(key).ok().flatten())
}

fn leaders(dbs: &[SharedDb]) -> Vec<usize> {
    dbs.iter()
        .enumerate()
        .filter(|(_, db)| replication::status(db).unwrap().role == Role::Primary)
        .map(|(i, _)| i)
        .collect()
}

/// Escreve `key` no líder atual (fora de `skip`) e devolve quem aceitou. O
/// commit espera a maioria, então roda em outra thread com prazo; uma troca de
/// líder no meio (CI lento) só faz tentar de novo.
fn write_to_leader(dbs: &[SharedDb], skip: &[usize], key: &'static [u8]) -> usize {
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timeout escrevendo {key:?}"
        );
        let found = leaders(dbs).into_iter().find(|i| !skip.contains(i));
        if let Some(i) = found {
            let (tx, rx) = mpsc::channel();
            let db = dbs[i].clone();
            thread::spawn(move || tx.send(db.put(key, b"v")));
            if let Ok(Ok(())) = rx.recv_timeout(Duration::from_secs(20)) {
                return i;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn leader_failover_elects_another_node_that_accepts_writes() {
    let addrs: Vec<String> = (0..3).map(|_| free_addr()).collect();
    let mut dbs = Vec::new();
    let mut handles = Vec::new();
    for (i, addr) in addrs.iter().enumerate() {
        let db = SharedDb::new(Db::open(tmpdir()).unwrap());
        let peers = (0..3)
            .filter(|&j| j != i)
            .map(|j| (j as u64 + 1, addrs[j].clone()))
            .collect();
        let cluster = ClusterConfig {
            id: i as u64 + 1,
            peers,
            election_timeout: Duration::from_millis(500),
        };
        let cfg = ReplicationConfig {
            secret: Some(b"segredo-do-cluster".to_vec()),
            ..ReplicationConfig::default()
        };
        handles.push(Some(start_cluster(&db, addr, cfg, cluster).unwrap()));
        dbs.push(db);
    }

    // Um líder; a escrita confirmada por ele chega a todos.
    let old = write_to_leader(&dbs, &[], b"antes");
    for db in &dbs {
        wait_until("três nós", || get_ok(db, b"antes").is_some());
    }

    // Derruba o líder: ele fica somente leitura e outro nó assume.
    handles[old].take().unwrap().shutdown();
    assert!(matches!(dbs[old].put(b"x", b"1"), Err(Error::ReadOnly)));
    let new = write_to_leader(&dbs, &[old], b"depois");
    assert_ne!(new, old);
    assert_eq!(
        get_ok(&dbs[new], b"antes"),
        Some(b"v".to_vec()),
        "a escrita confirmada sobreviveu ao failover"
    );
    let other = 3 - old - new;
    wait_until("seguidor", || get_ok(&dbs[other], b"depois").is_some());
    let old_role = replication::status(&dbs[old]).unwrap().role;
    assert_ne!(old_role, Role::Primary);

    // Sem segredo o modo cluster recusa subir.
    let lone = SharedDb::new(Db::open(tmpdir()).unwrap());
    let cluster = ClusterConfig {
        id: 1,
        peers: vec![(2, free_addr())],
        election_timeout: Duration::from_millis(300),
    };
    let cfg = ReplicationConfig::default();
    let refused = start_cluster(&lone, &free_addr(), cfg, cluster);
    assert!(refused.is_err());

    for handle in handles.into_iter().flatten() {
        handle.shutdown();
    }
}
