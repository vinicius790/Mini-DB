//! Modo cluster com nós reais: elegem um líder, a escrita confirmada chega aos
//! outros e, derrubado o líder, outro assume e aceita escrita sem perder o que já
//! tinha sido confirmado. Um commit que o líder não viu confirmado pela maioria
//! volta com erro, e membros entram e saem um por vez (inclusive o líder).

use mini_db::mvcc::SharedDb;
use mini_db::raft::Change;
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

/// Sobe o nó `i` (id `i + 1`) em `addrs[i]`, com os nós `members` (índices em
/// `addrs`) em `cluster_peers`.
fn start_node(
    addrs: &[String],
    i: usize,
    members: &[usize],
    timeout: Duration,
) -> (SharedDb, replication::ClusterHandle) {
    let db = SharedDb::new(Db::open(tmpdir()).unwrap());
    let peers = members
        .iter()
        .filter(|&&j| j != i)
        .map(|&j| (j as u64 + 1, addrs[j].clone()))
        .collect();
    let cluster = ClusterConfig {
        id: i as u64 + 1,
        peers,
        election_timeout: timeout,
    };
    let cfg = ReplicationConfig {
        secret: Some(b"segredo-do-cluster".to_vec()),
        ..ReplicationConfig::default()
    };
    let handle = start_cluster(&db, &addrs[i], cfg, cluster).unwrap();
    (db, handle)
}

fn role(db: &SharedDb) -> Role {
    replication::status(db).unwrap().role
}

/// A configuração de membros gravada em `db` tem exatamente os nós `ids`.
fn has_members(db: &SharedDb, ids: &[u64]) -> bool {
    let config = replication::membership(db).ok().flatten();
    config.is_some_and(|c| c.members.keys().copied().eq(ids.iter().copied()))
}

/// Aplica `change` no líder atual (fora de `skip`) até ele ter os membros `ids`.
/// Uma troca de líder no meio (CI lento) só faz tentar de novo.
fn change_members(dbs: &[SharedDb], skip: &[usize], change: Change, ids: &[u64]) {
    let start = Instant::now();
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "timeout trocando membros: {change:?}"
        );
        if let Some(i) = leaders(dbs).into_iter().find(|i| !skip.contains(i)) {
            if has_members(&dbs[i], ids) {
                return;
            }
            let _ = replication::change_membership(&dbs[i], change.clone());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn commit_waiting_when_the_leader_loses_the_majority_returns_an_error() {
    // Timeout longo: o líder só desiste uns 2 s depois do último contato, então o
    // commit abaixo começa bem antes e fica esperando confirmações.
    let timeout = Duration::from_secs(2);
    let addrs: Vec<String> = (0..3).map(|_| free_addr()).collect();
    let mut dbs = Vec::new();
    let mut handles = Vec::new();
    for i in 0..3 {
        let (db, handle) = start_node(&addrs, i, &[0, 1, 2], timeout);
        dbs.push(db);
        handles.push(Some(handle));
    }
    let leader = write_to_leader(&dbs, &[], b"antes");
    for db in &dbs {
        wait_until("três nós", || get_ok(db, b"antes").is_some());
    }

    // Os dois seguidores saem: ninguém mais confirma e o líder perde a maioria.
    for (i, handle) in handles.iter_mut().enumerate() {
        if i != leader {
            handle.take().unwrap().shutdown();
        }
    }
    match dbs[leader].put(b"durante", b"v") {
        Err(Error::Unavailable(msg)) => assert!(msg.contains("maioria"), "{msg}"),
        other => panic!("commit sem a maioria voltou como {other:?}"),
    }
    wait_until("líder deposto", || role(&dbs[leader]) != Role::Primary);
    assert!(matches!(dbs[leader].put(b"x", b"1"), Err(Error::ReadOnly)));

    for handle in handles.into_iter().flatten() {
        handle.shutdown();
    }
}

#[test]
fn members_are_added_and_removed_one_at_a_time_even_the_leader() {
    let timeout = Duration::from_millis(800);
    let addrs: Vec<String> = (0..4).map(|_| free_addr()).collect();
    let mut dbs = Vec::new();
    let mut handles = Vec::new();
    for i in 0..3 {
        let (db, handle) = start_node(&addrs, i, &[0, 1, 2], timeout);
        dbs.push(db);
        handles.push(handle);
    }
    write_to_leader(&dbs, &[], b"antes");

    // O nó 4 sobe com os membros atuais em cluster_peers e entra pelo líder.
    let (db, handle) = start_node(&addrs, 3, &[0, 1, 2], timeout);
    dbs.push(db);
    handles.push(handle);
    let add = Change::Add(4, addrs[3].clone());
    change_members(&dbs, &[], add, &[1, 2, 3, 4]);
    for db in &dbs {
        wait_until("quatro membros", || has_members(db, &[1, 2, 3, 4]));
    }
    wait_until("nó 4 com dados", || get_ok(&dbs[3], b"antes").is_some());

    // Sai um seguidor dos três primeiros: ele fica fora (fenced) e não volta.
    let leader = write_to_leader(&dbs, &[], b"com-quatro");
    let gone = (0..3).find(|&i| i != leader).unwrap();
    let rest: Vec<usize> = (0..4).filter(|&i| i != gone).collect();
    let ids: Vec<u64> = rest.iter().map(|&i| i as u64 + 1).collect();
    change_members(&dbs, &[], Change::Remove(gone as u64 + 1), &ids);
    for &i in &rest {
        wait_until("três membros", || has_members(&dbs[i], &ids));
    }
    wait_until("removido fora", || role(&dbs[gone]) == Role::Fenced);

    // Sai o próprio líder: ele deixa de liderar e os dois que ficam elegem outro,
    // sem perder o que já estava confirmado.
    let old = write_to_leader(&dbs, &[gone], b"com-tres");
    let old_id = old as u64 + 1;
    let last: Vec<u64> = ids.iter().copied().filter(|&id| id != old_id).collect();
    change_members(&dbs, &[gone], Change::Remove(old_id), &last);
    wait_until("antigo líder fora", || role(&dbs[old]) != Role::Primary);
    let new = write_to_leader(&dbs, &[gone, old], b"depois");
    assert_ne!(new, old);
    assert_eq!(get_ok(&dbs[new], b"com-tres"), Some(b"v".to_vec()));
    for &id in &last {
        let i = id as usize - 1;
        wait_until("dois membros", || has_members(&dbs[i], &last));
        wait_until("escrita", || get_ok(&dbs[i], b"depois").is_some());
    }
    assert!(matches!(dbs[old].put(b"x", b"1"), Err(Error::ReadOnly)));

    for handle in handles {
        handle.shutdown();
    }
}
