//! Replicação lógica primário → réplicas por streaming dos commits.
//!
//! **Feed e histórico.** O primário publica cada lote confirmado em um
//! [`ChangeFeed`] em memória (identificado pelo LSN do commit). Com
//! [`crate::Db::set_wal_retention`], os WALs são arquivados no checkpoint em vez
//! de truncados: uma réplica atrasada — inclusive depois de o primário
//! reiniciar — retoma a partir desse histórico. Só quando nem feed nem
//! histórico cobrem o ponto pedido o primário envia um snapshot completo.
//!
//! **Snapshot sem bloquear.** O snapshot usa um snapshot MVCC e é enviado em
//! pedaços (`SNAPSHOT_BEGIN`, `CHUNK`…, `SNAPSHOT_END`): o primário continua
//! aceitando escritas e a memória fica limitada a um pedaço. Durante a
//! ressincronização a réplica responde [`Error::Unavailable`] (como o
//! `LOADING` do Redis) e, se cair no meio, recomeça do zero ao reconectar.
//!
//! **Exatamente uma vez.** A réplica grava o LSN aplicado ([`APPLIED_KEY`]) no
//! mesmo lote atômico dos dados: um crash nunca duplica nem pula commits. Ela
//! confirma (`ACK`) cada lote depois de durável.
//!
//! **Semi-síncrona.** Com [`set_sync_replicas`], cada commit do primário espera
//! `n` réplicas confirmarem (ou o timeout, se houver) antes de voltar.
//!
//! **Segurança.** Com segredo compartilhado ([`ReplicationConfig::secret`]),
//! o handshake é autenticado por HMAC-SHA256 com nonces dos dois lados e
//! todo o tráfego é cifrado com ChaCha20 e autenticado por HMAC (chaves por
//! sessão). Um lado com segredo recusa o outro sem.
//!
//! **Failover.** [`promote`] transforma a réplica em primário e incrementa a
//! época ([`EPOCH_KEY`], replicada como dado). Um primário antigo que encontre
//! uma réplica de época maior se isola (fica somente leitura); uma réplica
//! nunca segue um primário de época menor.
//!
//! Protocolo: o primário envia `MINIDB-REPL 2 <época> <nonce> <auth>`; a réplica
//! responde `SYNC <lsn> <época> <nonce> <snapshot?> <mac|->`; o primário diz
//! `OK` ou `ERR <motivo>`. Depois, quadros `[len:u32][corpo]`, com corpo
//! `[tipo:u8][lsn:u64][ops]` (cifrado + tag de 16 bytes quando autenticado).
//! Op: `[1][klen:u16][key][vlen:u32][val]` (put), `[2][klen][key]` (delete),
//! `[3][klen][key][at:u64]` (expiração absoluta em ms).

use crate::crypto;
use crate::db::{Db, Op, RESERVED_PREFIX};
use crate::error::{Error, Result};
use crate::mvcc::SharedDb;
use crate::wal::Wal;
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// Chave local da réplica: último LSN do primário aplicado.
pub const APPLIED_KEY: &[u8] = &[RESERVED_PREFIX, b'r', b'l', b's', b'n'];
/// Chave local da réplica: ressincronização completa em andamento.
pub const RESYNC_KEY: &[u8] = &[RESERVED_PREFIX, b'r', b's', b'y', b'n'];
/// Época do cluster (replicada): cresce a cada promoção.
pub const EPOCH_KEY: &[u8] = &[RESERVED_PREFIX, b'r', b'e', b'p', b'o'];

const PROTOCOL: u32 = 2;
const T_BATCH: u8 = 1;
const T_SNAP_BEGIN: u8 = 2;
const T_SNAP_CHUNK: u8 = 3;
const T_SNAP_END: u8 = 4;
const T_HEARTBEAT: u8 = 5;
const T_ACK: u8 = 6;
const HEARTBEAT_EVERY: Duration = Duration::from_secs(1);
const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Linhas por pedaço de snapshot e chaves por lote de limpeza.
const CHUNK_ROWS: usize = 512;
const TAG_LEN: usize = 16;
/// Teto de um quadro (lotes podem ter vários valores grandes). O corpo é lido
/// sob demanda, sem pré-alocar: lixo na rede não reserva memória.
const MAX_FRAME: u64 = 1 << 30;

/// Chaves que pertencem à réplica e nunca trafegam.
fn is_local(key: &[u8]) -> bool {
    key == APPLIED_KEY || key == RESYNC_KEY
}

fn transferable(ops: &[Op]) -> Vec<Op> {
    ops.iter()
        .filter(|op| !is_local(op.key()))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Feed e estado compartilhado
// ---------------------------------------------------------------------------

/// Lotes `(lsn do commit, operações)` em ordem.
type Batches = Vec<(u64, Vec<Op>)>;

/// Lotes confirmados recentes, completos para todo LSN `> base`.
pub struct ChangeFeed {
    base: u64,
    head: u64,
    batches: VecDeque<(u64, Vec<Op>)>,
    ops: usize,
    max_ops: usize,
}

impl ChangeFeed {
    fn new(base: u64, max_ops: usize) -> Self {
        Self {
            base,
            head: base,
            batches: VecDeque::new(),
            ops: 0,
            max_ops: max_ops.max(1),
        }
    }

    fn push(&mut self, lsn: u64, ops: &[Op]) {
        let ops = transferable(ops);
        self.head = self.head.max(lsn);
        self.ops += ops.len();
        self.batches.push_back((lsn, ops));
        while self.ops > self.max_ops && self.batches.len() > 1 {
            let (lsn, old) = self.batches.pop_front().expect("len > 1");
            self.ops -= old.len();
            self.base = lsn;
        }
    }

    /// Lotes com LSN `> after`, ou `None` se o feed não cobre esse ponto.
    fn since(&self, after: u64) -> Option<Batches> {
        if after < self.base || after > self.head {
            return None;
        }
        Some(
            self.batches
                .iter()
                .filter(|(lsn, _)| *lsn > after)
                .cloned()
                .collect(),
        )
    }
}

#[derive(Default)]
struct HubState {
    feed: Option<ChangeFeed>,
    acks: HashMap<u64, u64>,
    next_session: u64,
    sync_replicas: usize,
    sync_timeout: Option<Duration>,
    sync_timeouts: u64,
    snapshots_sent: u64,
    stop_replica: Option<Arc<AtomicBool>>,
    upstream: Option<String>,
}

/// Estado de replicação de um banco (feed, confirmações, papel).
#[derive(Default)]
pub struct Hub {
    state: Mutex<HubState>,
    cv: Condvar,
    resyncing: AtomicBool,
    fenced: AtomicBool,
}

impl Hub {
    fn lock(&self) -> MutexGuard<'_, HubState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn publish(&self, lsn: u64, ops: &[Op]) {
        let mut state = self.lock();
        if let Some(feed) = &mut state.feed {
            feed.push(lsn, ops);
            self.cv.notify_all();
        }
    }

    /// Replicação semi-síncrona: espera `sync_replicas` confirmarem `lsn`.
    pub(crate) fn wait_for_replicas(&self, lsn: u64) {
        let mut state = self.lock();
        if state.sync_replicas == 0 || state.feed.is_none() {
            return;
        }
        let deadline = state.sync_timeout.map(|t| Instant::now() + t);
        loop {
            let confirmed = state.acks.values().filter(|&&a| a >= lsn).count();
            if confirmed >= state.sync_replicas {
                return;
            }
            state = match deadline {
                None => self.cv.wait(state).unwrap_or_else(|e| e.into_inner()),
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        state.sync_timeouts += 1;
                        return;
                    }
                    self.cv
                        .wait_timeout(state, deadline - now)
                        .unwrap_or_else(|e| e.into_inner())
                        .0
                }
            };
        }
    }

    pub(crate) fn resyncing(&self) -> bool {
        self.resyncing.load(Ordering::Acquire)
    }
}

/// Papel atual do nó.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// Aceita escritas (com ou sem réplicas).
    Primary,
    /// Segue outro nó; somente leitura.
    Replica { upstream: String },
    /// Primário antigo que encontrou uma época maior: somente leitura.
    Fenced,
}

/// Situação da replicação para `/v1/replication` e `ROLE`.
#[derive(Clone, Debug)]
pub struct ReplicationStatus {
    pub role: Role,
    pub epoch: u64,
    /// Réplica: último LSN do upstream aplicado.
    pub applied_lsn: u64,
    /// Primário: LSN mais recente publicado no feed.
    pub head_lsn: u64,
    pub feed_enabled: bool,
    /// Sessões de réplicas conectadas e o último LSN confirmado de cada uma.
    pub replicas: Vec<u64>,
    pub sync_replicas: usize,
    pub sync_timeouts: u64,
    /// Snapshots completos enviados por este primário desde que abriu.
    pub snapshots_sent: u64,
    pub resyncing: bool,
}

/// Configuração de rede da replicação (dos dois lados).
#[derive(Clone, Debug)]
pub struct ReplicationConfig {
    /// Segredo compartilhado: autentica e cifra o canal. `None` = texto claro.
    pub secret: Option<Vec<u8>>,
    /// Operações mantidas no feed em memória.
    pub max_feed_ops: usize,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            secret: None,
            max_feed_ops: 100_000,
        }
    }
}

fn read_u64_key(db: &Db, key: &[u8]) -> Result<u64> {
    Ok(db
        .get_raw(key)?
        .and_then(|v| v.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0))
}

/// Último LSN do upstream aplicado nesta réplica (0 = nunca sincronizou).
pub fn applied_lsn(db: &Db) -> Result<u64> {
    read_u64_key(db, APPLIED_KEY)
}

/// Época do cluster vista por este nó.
pub fn epoch(db: &Db) -> Result<u64> {
    read_u64_key(db, EPOCH_KEY)
}

fn put_u64(key: &[u8], value: u64) -> Op {
    Op::Put {
        key: key.to_vec(),
        value: value.to_le_bytes().to_vec(),
    }
}

/// Liga o feed de mudanças (retendo até `max_ops` operações em memória).
pub fn enable_feed(shared: &SharedDb, max_ops: usize) -> Result<()> {
    let db = shared.read_unchecked()?;
    let mut state = db.repl.lock();
    if state.feed.is_none() {
        let base = db.last_lsn();
        state.feed = Some(ChangeFeed::new(base, max_ops));
    }
    Ok(())
}

/// Cada commit espera `n` réplicas confirmarem (0 desliga). Com `timeout`,
/// depois dele o commit segue (e `sync_timeouts` conta); sem, espera sempre.
pub fn set_sync_replicas(shared: &SharedDb, n: usize, timeout: Option<Duration>) -> Result<()> {
    let db = shared.read_unchecked()?;
    let mut state = db.repl.lock();
    state.sync_replicas = n;
    state.sync_timeout = timeout;
    Ok(())
}

pub fn status(shared: &SharedDb) -> Result<ReplicationStatus> {
    let db = shared.read_unchecked()?;
    let hub = &db.repl;
    let state = hub.lock();
    let role = if hub.fenced.load(Ordering::Acquire) {
        Role::Fenced
    } else if let (true, Some(upstream)) = (db.is_read_only(), &state.upstream) {
        Role::Replica {
            upstream: upstream.clone(),
        }
    } else {
        Role::Primary
    };
    let mut replicas: Vec<u64> = state.acks.values().copied().collect();
    replicas.sort_unstable();
    Ok(ReplicationStatus {
        role,
        epoch: epoch(&db)?,
        applied_lsn: applied_lsn(&db)?,
        head_lsn: state.feed.as_ref().map_or(0, |f| f.head),
        feed_enabled: state.feed.is_some(),
        replicas,
        sync_replicas: state.sync_replicas,
        sync_timeouts: state.sync_timeouts,
        snapshots_sent: state.snapshots_sent,
        resyncing: hub.resyncing(),
    })
}

/// Promove esta réplica a primário: para de seguir o upstream, incrementa a
/// época e passa a aceitar escritas. Devolve a nova época.
pub fn promote(shared: &SharedDb) -> Result<u64> {
    let mut db = shared.write()?;
    if db.repl.resyncing() {
        return Err(Error::Unavailable(
            "réplica no meio de uma ressincronização não pode ser promovida".into(),
        ));
    }
    {
        let mut state = db.repl.lock();
        if let Some(stop) = state.stop_replica.take() {
            stop.store(true, Ordering::Release);
        }
        state.upstream = None;
    }
    let next = epoch(&db)? + 1;
    db.write_internal(vec![put_u64(EPOCH_KEY, next)])?;
    db.set_read_only(false);
    db.repl.fenced.store(false, Ordering::Release);
    Ok(next)
}

// ---------------------------------------------------------------------------
// Canal (quadros, autenticação e cifra)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Keys {
    enc: [u8; 32],
    mac: [u8; 32],
}

fn derive_keys(secret: &[u8], np: &[u8], nr: &[u8]) -> Keys {
    Keys {
        enc: crypto::hmac_sha256(secret, &[b"minidb-repl-enc", np, nr]),
        mac: crypto::hmac_sha256(secret, &[b"minidb-repl-mac", np, nr]),
    }
}

fn nonce(dir: u8, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = dir;
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Metade de um canal: cifra/decifra numa direção com contador próprio.
struct Half {
    keys: Option<Keys>,
    dir: u8,
    counter: u64,
}

impl Half {
    fn seal(&mut self, body: &mut Vec<u8>) {
        if let Some(keys) = &self.keys {
            crypto::chacha20_xor(&keys.enc, &nonce(self.dir, self.counter), 0, body);
            let tag =
                crypto::hmac_sha256(&keys.mac, &[&[self.dir], &self.counter.to_le_bytes(), body]);
            body.extend_from_slice(&tag[..TAG_LEN]);
        }
        self.counter += 1;
    }

    fn open(&mut self, mut body: Vec<u8>) -> Result<Vec<u8>> {
        if let Some(keys) = &self.keys {
            if body.len() < TAG_LEN {
                return Err(Error::Other("quadro autenticado curto demais".into()));
            }
            let tag = body.split_off(body.len() - TAG_LEN);
            let expected = crypto::hmac_sha256(
                &keys.mac,
                &[&[self.dir], &self.counter.to_le_bytes(), &body],
            );
            if !crypto::constant_time_eq(&tag, &expected[..TAG_LEN]) {
                return Err(Error::Other(
                    "quadro de replicação com autenticação inválida".into(),
                ));
            }
            crypto::chacha20_xor(&keys.enc, &nonce(self.dir, self.counter), 0, &mut body);
        }
        self.counter += 1;
        Ok(body)
    }
}

fn encode_body(kind: u8, lsn: u64, ops: &[Op]) -> Vec<u8> {
    let mut body = vec![kind];
    body.extend_from_slice(&lsn.to_le_bytes());
    let bytes16 = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend_from_slice(&(b.len() as u16).to_le_bytes());
        out.extend_from_slice(b);
    };
    for op in ops {
        match op {
            Op::Put { key, value } => {
                body.push(1);
                bytes16(&mut body, key);
                body.extend_from_slice(&(value.len() as u32).to_le_bytes());
                body.extend_from_slice(value);
            }
            Op::Delete { key } => {
                body.push(2);
                bytes16(&mut body, key);
            }
            Op::Expire { key, at } => {
                body.push(3);
                bytes16(&mut body, key);
                body.extend_from_slice(&at.to_le_bytes());
            }
        }
    }
    body
}

struct Cursor<'a> {
    body: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let slice = self
            .body
            .get(self.at..self.at.saturating_add(n))
            .ok_or_else(|| Error::Other("quadro de replicação malformado".into()))?;
        self.at += n;
        Ok(slice)
    }

    fn u16_bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.take(2)?;
        let n = u16::from_le_bytes([n[0], n[1]]) as usize;
        Ok(self.take(n)?.to_vec())
    }

    fn u32_bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.take(4)?;
        let n = u32::from_le_bytes([n[0], n[1], n[2], n[3]]) as usize;
        Ok(self.take(n)?.to_vec())
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
}

fn decode_body(body: &[u8]) -> Result<(u8, u64, Vec<Op>)> {
    let mut cur = Cursor { body, at: 0 };
    let kind = cur.take(1)?[0];
    let lsn = cur.u64()?;
    let mut ops = Vec::new();
    while cur.at < body.len() {
        let tag = cur.take(1)?[0];
        let key = cur.u16_bytes()?;
        ops.push(match tag {
            1 => Op::Put {
                key,
                value: cur.u32_bytes()?,
            },
            2 => Op::Delete { key },
            3 => Op::Expire {
                key,
                at: cur.u64()?,
            },
            _ => return Err(Error::Other("operação de replicação desconhecida".into())),
        });
    }
    Ok((kind, lsn, ops))
}

fn write_frame(w: &mut impl Write, half: &mut Half, kind: u8, lsn: u64, ops: &[Op]) -> Result<()> {
    let mut body = encode_body(kind, lsn, ops);
    half.seal(&mut body);
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend(body);
    w.write_all(&frame)?;
    w.flush()?;
    Ok(())
}

fn read_frame(r: &mut impl Read, half: &mut Half) -> Result<(u8, u64, Vec<Op>)> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as u64;
    if !(9..=MAX_FRAME).contains(&len) {
        return Err(Error::Other(format!(
            "quadro de replicação inválido ({len} bytes)"
        )));
    }
    let mut body = Vec::new();
    r.take(len).read_to_end(&mut body)?;
    if body.len() as u64 != len {
        return Err(Error::Other(
            "conexão encerrada no meio de um quadro".into(),
        ));
    }
    decode_body(&half.open(body)?)
}

fn read_line(r: &mut impl BufRead) -> Result<String> {
    let mut line = String::new();
    r.by_ref().take(4096).read_line(&mut line)?;
    if line.is_empty() {
        return Err(Error::Other("conexão encerrada no handshake".into()));
    }
    Ok(line.trim_end().to_string())
}

fn sync_mac(secret: &[u8], np: &[u8], nr: &[u8], after: u64, epoch: u64, snap: bool) -> String {
    crypto::to_hex(&crypto::hmac_sha256(
        secret,
        &[
            b"minidb-repl-sync",
            np,
            nr,
            &after.to_le_bytes(),
            &epoch.to_le_bytes(),
            &[snap as u8],
        ],
    ))
}

// ---------------------------------------------------------------------------
// Primário
// ---------------------------------------------------------------------------

/// Liga o feed e aceita réplicas em `addr` (texto claro). Bloqueia.
pub fn serve_primary(shared: SharedDb, addr: &str, max_ops: usize) -> Result<()> {
    serve_primary_with(
        shared,
        addr,
        ReplicationConfig {
            max_feed_ops: max_ops,
            ..ReplicationConfig::default()
        },
    )
}

/// Como [`serve_primary`], com autenticação/cifra opcionais.
pub fn serve_primary_with(shared: SharedDb, addr: &str, cfg: ReplicationConfig) -> Result<()> {
    enable_feed(&shared, cfg.max_feed_ops)?;
    let listener = TcpListener::bind(addr)?;
    eprintln!(
        "minidb replicação: primário em {addr} ({})",
        if cfg.secret.is_some() {
            "autenticado + cifrado"
        } else {
            "texto claro"
        }
    );
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let (shared, cfg) = (shared.clone(), cfg.clone());
        thread::spawn(move || {
            let peer = stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_default();
            if let Err(e) = serve_replica(&shared, stream, &cfg) {
                eprintln!("minidb replicação: réplica {peer} desconectou: {e}");
            }
        });
    }
    Ok(())
}

fn hub_of(shared: &SharedDb) -> Result<Arc<Hub>> {
    Ok(Arc::clone(&shared.read_unchecked()?.repl))
}

fn serve_replica(shared: &SharedDb, stream: TcpStream, cfg: &ReplicationConfig) -> Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let hub = hub_of(shared)?;
    let np: [u8; 16] = crypto::random_bytes();
    let my_epoch = epoch(&*shared.read_unchecked()?)?;
    let mut out = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    writeln!(
        out,
        "MINIDB-REPL {PROTOCOL} {my_epoch} {} {}",
        crypto::to_hex(&np),
        u8::from(cfg.secret.is_some())
    )?;
    let line = read_line(&mut reader)?;
    let parts: Vec<&str> = line.split(' ').collect();
    let (after, their_epoch, nr, want_snapshot, mac) = match parts.as_slice() {
        ["SYNC", after, ep, nr, snap, mac] => (
            after.parse::<u64>().ok(),
            ep.parse::<u64>().ok(),
            crypto::from_hex(nr),
            *snap == "1",
            *mac,
        ),
        _ => (None, None, None, false, ""),
    };
    let (Some(after), Some(their_epoch), Some(nr)) = (after, their_epoch, nr) else {
        writeln!(out, "ERR handshake inválido")?;
        return Err(Error::Other(format!("handshake inválido: {line:?}")));
    };
    let keys = match &cfg.secret {
        Some(secret) => {
            let expected = sync_mac(secret, &np, &nr, after, their_epoch, want_snapshot);
            if !crypto::constant_time_eq(expected.as_bytes(), mac.as_bytes()) {
                writeln!(out, "ERR autenticação recusada")?;
                return Err(Error::Other("réplica com segredo inválido".into()));
            }
            Some(derive_keys(secret, &np, &nr))
        }
        None => None,
    };
    if their_epoch > my_epoch {
        // Alguém foi promovido depois de nós: este primário está obsoleto.
        hub.fenced.store(true, Ordering::Release);
        shared.write()?.set_read_only(true);
        writeln!(
            out,
            "ERR primário obsoleto (época {my_epoch} < {their_epoch})"
        )?;
        return Err(Error::Other(format!(
            "isolado: réplica com época {their_epoch} > {my_epoch}"
        )));
    }
    writeln!(out, "OK")?;
    reader.get_mut().set_read_timeout(None)?;
    let session = {
        let mut state = hub.lock();
        state.next_session += 1;
        let id = state.next_session;
        state.acks.insert(id, 0);
        id
    };
    let result = (|| {
        let mut send = Half {
            keys: keys.clone(),
            dir: 0,
            counter: 0,
        };
        let recv = Half {
            keys,
            dir: 1,
            counter: 0,
        };
        spawn_ack_reader(Arc::clone(&hub), session, reader, recv);
        let lineage_changed = their_epoch < my_epoch;
        let mut after = (!want_snapshot && !lineage_changed).then_some(after);
        loop {
            let batches = match after {
                Some(a) => catch_up(shared, &hub, a)?,
                None => None,
            };
            let Some(batches) = batches else {
                hub.lock().snapshots_sent += 1;
                after = Some(send_snapshot(shared, &mut out, &mut send)?);
                continue;
            };
            if batches.is_empty() {
                let current = after.expect("definido acima");
                if !wait_for_feed(&hub, current) {
                    write_frame(&mut out, &mut send, T_HEARTBEAT, current, &[])?;
                }
                continue;
            }
            for (lsn, ops) in batches {
                write_frame(&mut out, &mut send, T_BATCH, lsn, &ops)?;
                after = Some(lsn);
            }
        }
    })();
    hub.lock().acks.remove(&session);
    hub.cv.notify_all();
    // Derruba o leitor de ACKs, que pode estar bloqueado no socket.
    let _ = out.shutdown(std::net::Shutdown::Both);
    result
}

/// Espera o feed passar de `after`. `false` = deu o tempo do heartbeat.
fn wait_for_feed(hub: &Hub, after: u64) -> bool {
    let state = hub.lock();
    let (state, timeout) = hub
        .cv
        .wait_timeout_while(state, HEARTBEAT_EVERY, |s| {
            s.feed.as_ref().is_some_and(|f| f.head <= after)
        })
        .unwrap_or_else(|e| e.into_inner());
    drop(state);
    !timeout.timed_out()
}

fn spawn_ack_reader(hub: Arc<Hub>, session: u64, mut reader: BufReader<TcpStream>, mut recv: Half) {
    thread::spawn(move || {
        while let Ok((T_ACK, lsn, _)) = read_frame(&mut reader, &mut recv) {
            let mut state = hub.lock();
            if let Some(acked) = state.acks.get_mut(&session) {
                *acked = (*acked).max(lsn);
            }
            drop(state);
            hub.cv.notify_all();
        }
        let _ = reader.get_ref().shutdown(std::net::Shutdown::Both);
    });
}

/// Lotes depois de `after`: do feed em memória ou do histórico em disco.
/// `None` = ninguém cobre esse ponto (precisa de snapshot).
fn catch_up(shared: &SharedDb, hub: &Hub, after: u64) -> Result<Option<Batches>> {
    let base = {
        let state = hub.lock();
        let feed = state
            .feed
            .as_ref()
            .ok_or_else(|| Error::Other("feed de replicação desligado".into()))?;
        if after > feed.head {
            // A réplica diz ter visto algo que este primário nunca publicou:
            // outra linhagem. Só um snapshot resolve.
            return Ok(None);
        }
        if let Some(batches) = feed.since(after) {
            return Ok(Some(batches));
        }
        feed.base
    };
    // Segura o lock de leitura: impede que um checkpoint gire os arquivos.
    let db = shared.read_unchecked()?;
    history(&db, after, base)
}

/// Reconstrói os lotes `(after, upto]` a partir dos WALs arquivados + atual.
fn history(db: &Db, after: u64, upto: u64) -> Result<Option<Batches>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(Db::archive_dir(db.dir()))
        .map(|dir| {
            dir.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "wal"))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files.push(Db::wal_path(db.dir()));
    let mut out = Vec::new();
    let mut first_seen = None;
    let mut pending: Option<Vec<Op>> = None;
    for file in files {
        let (_, records) = Wal::read_all_with(&file, db.cipher().as_deref())?;
        for rec in records {
            let lsn = rec.lsn();
            first_seen.get_or_insert(lsn);
            if lsn > upto {
                break;
            }
            use crate::wal::WalRecord as R;
            let batch = match &rec {
                R::Begin { .. } => {
                    pending = Some(Vec::new());
                    None
                }
                R::Commit { .. } => pending.take(),
                R::Abort { .. } => {
                    pending = None;
                    None
                }
                R::Checkpoint { .. } | R::Time { .. } => None,
                data => {
                    let op = Op::from_record(data).expect("registro de dados");
                    match &mut pending {
                        Some(ops) => {
                            ops.push(op);
                            None
                        }
                        None => Some(vec![op]),
                    }
                }
            };
            if let Some(ops) = batch {
                if lsn > after {
                    out.push((lsn, transferable(&ops)));
                }
            }
        }
    }
    // Cobertura: o histórico precisa começar no máximo em `after + 1`.
    Ok(match first_seen {
        Some(first) if first <= after + 1 => Some(out),
        None if after >= upto => Some(out),
        _ => None,
    })
}

/// Envia o estado completo em pedaços a partir de um snapshot MVCC; devolve
/// o LSN do snapshot (o stream continua dali).
fn send_snapshot(shared: &SharedDb, out: &mut impl Write, send: &mut Half) -> Result<u64> {
    let snap = shared.snapshot()?;
    let seq = snap.seq();
    write_frame(out, send, T_SNAP_BEGIN, seq, &[])?;
    let mut cursor: Vec<u8> = vec![0];
    let mut skip: Option<Vec<u8>> = None;
    loop {
        let chunk = snap.with(|view| {
            let mut ops = Vec::new();
            let mut last = None;
            view.scan_raw(&cursor, None, &mut |key, value| {
                if skip.as_deref() == Some(key.as_slice()) || is_local(&key) {
                    return Ok(true);
                }
                let at = view.db.expiry_of(&key)?;
                ops.push(Op::Put {
                    key: key.clone(),
                    value,
                });
                if let Some(at) = at {
                    ops.push(Op::Expire {
                        key: key.clone(),
                        at,
                    });
                }
                last = Some(key);
                Ok(ops.len() < CHUNK_ROWS)
            })?;
            Ok((ops, last))
        })?;
        let (ops, last) = chunk;
        if ops.is_empty() {
            break;
        }
        write_frame(out, send, T_SNAP_CHUNK, seq, &ops)?;
        match last {
            Some(key) => {
                cursor = key.clone();
                skip = Some(key);
            }
            None => break,
        }
    }
    write_frame(out, send, T_SNAP_END, seq, &[])?;
    Ok(seq)
}

// ---------------------------------------------------------------------------
// Réplica
// ---------------------------------------------------------------------------

/// Segue o primário (texto claro) até `stop` virar `true`.
pub fn run_replica(shared: SharedDb, primary: &str, stop: Arc<AtomicBool>) -> Result<()> {
    run_replica_with(shared, primary, stop, &ReplicationConfig::default())
}

/// Conecta ao primário e aplica o fluxo até `stop` (ou uma promoção),
/// reconectando com backoff exponencial. O banco fica somente leitura para
/// clientes enquanto segue o upstream.
pub fn run_replica_with(
    shared: SharedDb,
    primary: &str,
    stop: Arc<AtomicBool>,
    cfg: &ReplicationConfig,
) -> Result<()> {
    {
        let mut db = shared.write()?;
        db.set_read_only(true);
        let resync = db.get_raw(RESYNC_KEY)?.is_some();
        db.repl.resyncing.store(resync, Ordering::Release);
        let mut state = db.repl.lock();
        state.stop_replica = Some(Arc::clone(&stop));
        state.upstream = Some(primary.to_string());
    }
    let mut backoff = Duration::from_millis(100);
    while !stop.load(Ordering::Acquire) {
        match follow(&shared, primary, &stop, cfg) {
            Ok(()) => break,
            Err(e) => {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                eprintln!("minidb réplica: {e}; reconectando em {backoff:?}");
                thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        }
    }
    Ok(())
}

fn apply(shared: &SharedDb, ops: Vec<Op>) -> Result<()> {
    shared.commit_with(move |_| Ok((ops, true, ()))).map(|_| ())
}

fn follow(
    shared: &SharedDb,
    primary: &str,
    stop: &AtomicBool,
    cfg: &ReplicationConfig,
) -> Result<()> {
    let (mut after, my_epoch) = {
        let db = shared.read_unchecked()?;
        (applied_lsn(&db)?, epoch(&db)?)
    };
    let addr = primary
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::Other(format!("endereço inválido: {primary}")))?;
    let stream = TcpStream::connect_timeout(&addr, READ_TIMEOUT)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let mut out = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let hello = read_line(&mut reader)?;
    let parts: Vec<&str> = hello.split(' ').collect();
    let ["MINIDB-REPL", version, ep, np, auth] = parts.as_slice() else {
        return Err(Error::Other(format!(
            "upstream não é um primário minidb: {hello:?}"
        )));
    };
    if version.parse::<u32>().ok() != Some(PROTOCOL) {
        return Err(Error::Other(format!(
            "versão de protocolo incompatível: {version}"
        )));
    }
    let their_epoch: u64 = ep
        .parse()
        .map_err(|_| Error::Other("época inválida".into()))?;
    let np = crypto::from_hex(np).ok_or_else(|| Error::Other("nonce inválido".into()))?;
    if cfg.secret.is_some() && *auth != "1" {
        return Err(Error::Other(
            "o primário não exige autenticação; recusado para evitar downgrade".into(),
        ));
    }
    // Um primário de época menor é obsoleto: o SYNC ainda é enviado para que
    // ele se isole (fencing), e a resposta dele nunca é aplicada.
    let stale = their_epoch < my_epoch;
    let nr: [u8; 16] = crypto::random_bytes();
    // Nunca sincronizou (ou parou no meio de uma ressincronização): o estado
    // local não corresponde a nenhum ponto do primário, então pede snapshot.
    let want_snapshot = after == 0 || shared.read_unchecked()?.repl.resyncing();
    let mac = match (&cfg.secret, *auth == "1") {
        (Some(secret), true) => sync_mac(secret, &np, &nr, after, my_epoch, want_snapshot),
        (None, true) => {
            return Err(Error::Other(
                "o primário exige autenticação: configure o segredo".into(),
            ))
        }
        _ => "-".into(),
    };
    writeln!(
        out,
        "SYNC {after} {my_epoch} {} {} {mac}",
        crypto::to_hex(&nr),
        u8::from(want_snapshot)
    )?;
    let answer = read_line(&mut reader)?;
    if stale {
        return Err(Error::Other(format!(
            "primário obsoleto (época {their_epoch} < {my_epoch}); isolado e recusado"
        )));
    }
    if answer != "OK" {
        return Err(Error::Other(format!("primário recusou: {answer}")));
    }
    let keys = cfg
        .secret
        .as_ref()
        .map(|secret| derive_keys(secret, &np, &nr));
    let mut recv = Half {
        keys: keys.clone(),
        dir: 0,
        counter: 0,
    };
    let mut send = Half {
        keys,
        dir: 1,
        counter: 0,
    };
    let hub = hub_of(shared)?;
    while !stop.load(Ordering::Acquire) {
        let (kind, lsn, ops) = read_frame(&mut reader, &mut recv)?;
        match kind {
            T_BATCH => {
                let mut ops = transferable(&ops);
                ops.push(put_u64(APPLIED_KEY, lsn));
                apply(shared, ops)?;
                after = lsn;
            }
            T_SNAP_BEGIN => begin_resync(shared, &hub)?,
            T_SNAP_CHUNK => apply(shared, transferable(&ops))?,
            T_SNAP_END => {
                apply(
                    shared,
                    vec![
                        Op::Delete {
                            key: RESYNC_KEY.to_vec(),
                        },
                        put_u64(APPLIED_KEY, lsn),
                    ],
                )?;
                hub.resyncing.store(false, Ordering::Release);
                after = lsn;
            }
            T_HEARTBEAT => {}
            other => return Err(Error::Other(format!("tipo de quadro desconhecido {other}"))),
        }
        if matches!(kind, T_BATCH | T_SNAP_END | T_HEARTBEAT) {
            write_frame(&mut out, &mut send, T_ACK, after, &[])?;
        }
    }
    Ok(())
}

/// Marca a ressincronização (persistida) e apaga o estado antigo em lotes.
fn begin_resync(shared: &SharedDb, hub: &Hub) -> Result<()> {
    hub.resyncing.store(true, Ordering::Release);
    apply(
        shared,
        vec![put_u64(RESYNC_KEY, 1), put_u64(APPLIED_KEY, 0)],
    )?;
    loop {
        let keys: Vec<Vec<u8>> = {
            let db = shared.read_unchecked()?;
            db.iter_raw(&[0], None)?
                .filter_map(|row| match row {
                    // A época fica: sem ela, uma queda no meio da ressincronização
                    // apagaria a referência contra primários obsoletos.
                    Ok((key, _)) if !is_local(&key) && key != EPOCH_KEY => Some(Ok(key)),
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                })
                .take(CHUNK_ROWS)
                .collect::<Result<_>>()?
        };
        if keys.is_empty() {
            return Ok(());
        }
        apply(
            shared,
            keys.into_iter().map(|key| Op::Delete { key }).collect(),
        )?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn half(keys: Option<Keys>, dir: u8) -> Half {
        Half {
            keys,
            dir,
            counter: 0,
        }
    }

    #[test]
    fn frames_roundtrip_plain_and_encrypted_and_reject_tampering() {
        let ops = vec![
            Op::Put {
                key: b"k".to_vec(),
                value: vec![7; 70_000],
            },
            Op::Delete { key: b"d".to_vec() },
            Op::Expire {
                key: b"k".to_vec(),
                at: 42,
            },
        ];
        for keys in [None, Some(derive_keys(b"s3gr3do", b"np", b"nr"))] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &mut half(keys.clone(), 0), T_BATCH, 7, &ops).unwrap();
            write_frame(&mut buf, &mut half(keys.clone(), 0), T_BATCH, 7, &ops).unwrap_or(());
            let mut r = &buf[..];
            let mut recv = half(keys.clone(), 0);
            assert_eq!(
                read_frame(&mut r, &mut recv).unwrap(),
                (T_BATCH, 7, ops.clone())
            );
            if keys.is_some() {
                // O segundo quadro foi selado com contador 0 de novo: replay.
                assert!(read_frame(&mut r, &mut recv).is_err(), "replay recusado");
                let mut tampered = buf.clone();
                tampered[20] ^= 1;
                assert!(read_frame(&mut &tampered[..], &mut half(keys.clone(), 0)).is_err());
                let wrong = Some(derive_keys(b"outro", b"np", b"nr"));
                assert!(read_frame(&mut &buf[..], &mut half(wrong, 0)).is_err());
            }
        }
        for cut in 0..40 {
            let _ = read_frame(
                &mut &[5u8, 0, 0, 0, 1, 2, 3][..cut.min(7)],
                &mut half(None, 0),
            );
        }
    }

    #[test]
    fn feed_trims_reports_gaps_and_filters_local_keys() {
        let op = || vec![Op::Delete { key: b"x".to_vec() }, put_u64(APPLIED_KEY, 9)];
        let mut feed = ChangeFeed::new(10, 2);
        feed.push(11, &op());
        assert_eq!(feed.since(10).unwrap()[0].1.len(), 1, "chave local some");
        feed.push(12, &op());
        feed.push(13, &op());
        assert!(feed.since(10).is_none(), "lote 11 saiu do feed");
        assert_eq!(feed.since(11).unwrap().len(), 2);
        assert!(feed.since(99).is_none(), "à frente do primário");
    }
}
