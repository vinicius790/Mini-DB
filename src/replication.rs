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
//! **Cluster (opcional).** Com [`start_cluster`], os nós elegem o líder
//! sozinhos ([`crate::raft`], estilo Raft): o vencedor do termo `T` é promovido
//! com época `T` e cada commit dele espera a maioria da configuração de membros
//! ([`CONFIG_KEY`], replicada como dado; [`change_membership`] troca um membro
//! por vez). Um commit que o líder deposto não viu confirmado volta com erro.
//! Sem pares configurados, nada disso roda e o comportamento é o descrito acima.
//!
//! Protocolo: o primário envia `MINIDB-REPL 2 <época> <nonce> <auth>`; a réplica
//! responde `SYNC <lsn> <época> <nonce> <snapshot?> <mac|-> [<nó>]` (o id de
//! nó só vem de um membro do cluster, coberto pelo MAC); o primário diz
//! `OK` ou `ERR <motivo>`. Depois, quadros `[len:u32][corpo]`, com corpo
//! `[tipo:u8][lsn:u64][ops]` (cifrado + tag de 16 bytes quando autenticado).
//! Op: `[1][klen:u16][key][vlen:u32][val]` (put), `[2][klen][key]` (delete),
//! `[3][klen][key][at:u64]` (expiração absoluta em ms). Um par do cluster
//! responde `RAFT <nonce> <mac>` em vez de `SYNC`; os quadros seguintes levam
//! mensagens da eleição ([`crate::raft::Message`]), sempre cifradas.

use crate::crypto;
use crate::db::{Db, Op, RESERVED_PREFIX};
use crate::error::{Error, Result};
use crate::mvcc::SharedDb;
use crate::raft::{self, Action, Change, LogPos, Membership, Message, Node, NodeId};
use crate::wal::Wal;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// Chave local da réplica: último LSN do primário aplicado.
pub const APPLIED_KEY: &[u8] = &[RESERVED_PREFIX, b'r', b'l', b's', b'n'];
/// Chave local da réplica: ressincronização completa em andamento (o valor é a
/// posição do log de antes dela, com a qual o nó do cluster continua votando).
pub const RESYNC_KEY: &[u8] = &[RESERVED_PREFIX, b'r', b's', b'y', b'n'];
/// Época do cluster (replicada): cresce a cada promoção.
pub const EPOCH_KEY: &[u8] = &[RESERVED_PREFIX, b'r', b'e', b'p', b'o'];
/// Modo cluster: configuração de membros (replicada; [`Membership::encode`]).
/// Ausente = a inicial, de `cluster_peers`.
pub const CONFIG_KEY: &[u8] = &[RESERVED_PREFIX, b'r', b'c', b'f', b'g'];

/// Erro de um commit que o líder registrou, mas que a maioria não confirmou.
const UNCERTAIN_COMMIT: &str =
    "commit não confirmado pela maioria do cluster: resultado incerto, o líder perdeu a maioria";

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
    /// Sessão de réplica -> (nó do cluster, ou 0; último LSN confirmado).
    acks: HashMap<u64, (NodeId, u64)>,
    next_session: u64,
    sync_replicas: usize,
    sync_timeout: Option<Duration>,
    sync_timeouts: u64,
    snapshots_sent: u64,
    stop_replica: Option<Arc<AtomicBool>>,
    upstream: Option<String>,
    /// Modo cluster: canal para o laço da eleição (pedidos de pares).
    raft: Option<mpsc::Sender<Event>>,
    /// Líder do cluster: quem conta para a maioria de cada commit.
    quorum: Option<Quorum>,
}

/// Membros da configuração em vigor no líder (ele incluso, se for membro).
struct Quorum {
    me: NodeId,
    voters: BTreeSet<NodeId>,
}

impl HubState {
    /// Líder do cluster: a maioria passa a ser a de `config`.
    fn set_quorum(&mut self, me: NodeId, config: &Membership) {
        let voters: BTreeSet<NodeId> = config.members.keys().copied().collect();
        // Só informativo (ROLE): confirmações de outros nós que cada commit espera.
        self.sync_replicas = config.majority() - usize::from(voters.contains(&me));
        self.quorum = Some(Quorum { me, voters });
    }

    /// `lsn` já foi confirmado: por `sync_replicas` réplicas ou, no cluster,
    /// pela maioria dos membros (cada nó conta uma vez; réplicas de fora, não).
    fn confirmed(&self, lsn: u64) -> bool {
        let acked = self.acks.values().filter(|ack| ack.1 >= lsn);
        let Some(quorum) = &self.quorum else {
            return acked.count() >= self.sync_replicas;
        };
        let nodes: BTreeSet<NodeId> = acked
            .map(|ack| ack.0)
            .filter(|node| *node != quorum.me && quorum.voters.contains(node))
            .collect();
        let me = usize::from(quorum.voters.contains(&quorum.me));
        nodes.len() + me > quorum.voters.len() / 2
    }
}

/// Estado de replicação de um banco (feed, confirmações, papel).
#[derive(Default)]
pub struct Hub {
    state: Mutex<HubState>,
    cv: Condvar,
    resyncing: AtomicBool,
    fenced: AtomicBool,
    /// Modo cluster ligado: promoção manual recusada e `SYNC` só no líder.
    cluster: AtomicBool,
    /// Modo cluster: este nó é o líder promovido do termo atual.
    leading: AtomicBool,
    /// Líder deposto: os commits que esperavam confirmações voltam com erro.
    deposed: AtomicBool,
    /// Serializa cada quadro aplicado do upstream com a parada da réplica.
    gate: Mutex<()>,
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
        // Líder do cluster: a configuração nova vale para a maioria assim que
        // entra no log, inclusive para o próprio registro dela (regra do Raft).
        let me = state.quorum.as_ref().map(|quorum| quorum.me);
        if let (Some(me), Some(config)) = (me, ops.iter().rev().find_map(membership_of)) {
            state.set_quorum(me, &config);
        }
    }

    /// Replicação semi-síncrona: espera `lsn` ser confirmado (`sync_replicas`
    /// réplicas ou, no modo cluster, a maioria dos membros). Fora do cluster, o
    /// timeout libera o commit como sempre. No cluster, se o líder foi deposto
    /// antes da confirmação, devolve erro: o commit já está no WAL local, mas
    /// pode não estar na maioria (e se perder na ressincronização).
    pub(crate) fn wait_for_replicas(&self, lsn: u64) -> Result<()> {
        let mut state = self.lock();
        let waits = state.sync_replicas > 0 || state.quorum.is_some();
        if !waits || state.feed.is_none() {
            return Ok(());
        }
        let deadline = state.sync_timeout.map(|t| Instant::now() + t);
        loop {
            if state.confirmed(lsn) {
                return Ok(());
            }
            if self.deposed.load(Ordering::Acquire) {
                // Líder deposto: ninguém mais confirma (ver docs/REPLICA.md).
                state.sync_timeouts += 1;
                return Err(Error::Unavailable(UNCERTAIN_COMMIT.into()));
            }
            state = match deadline {
                None => self.cv.wait(state).unwrap_or_else(|e| e.into_inner()),
                Some(deadline) => {
                    let now = Instant::now();
                    if now >= deadline {
                        state.sync_timeouts += 1;
                        return Ok(());
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

/// Configuração de membros do cluster gravada neste banco (`None` = nenhuma
/// troca ainda: vale a inicial, de `cluster_peers`).
pub fn membership(shared: &SharedDb) -> Result<Option<Membership>> {
    stored_membership(&*shared.read_unchecked()?)
}

fn stored_membership(db: &Db) -> Result<Option<Membership>> {
    let Some(raw) = db.get_raw(CONFIG_KEY)? else {
        return Ok(None);
    };
    let text = String::from_utf8_lossy(&raw);
    Membership::decode(&text).map(Some)
}

/// A configuração de membros gravada por `op`, se for o registro dela.
fn membership_of(op: &Op) -> Option<Membership> {
    match op {
        Op::Put { key, value } if key.as_slice() == CONFIG_KEY => {
            Membership::decode(&String::from_utf8_lossy(value)).ok()
        }
        _ => None,
    }
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
    let mut replicas: Vec<u64> = state.acks.values().map(|ack| ack.1).collect();
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
    if hub_of(shared)?.cluster.load(Ordering::Acquire) {
        return Err(Error::Unavailable(
            "modo cluster ativo: a promoção é automática, por eleição".into(),
        ));
    }
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

/// Promoção do líder eleito: como [`promote`], mas com época = `term` (maior que
/// a atual), `APPLIED_KEY` zerado (marca os dados como originados neste nó; ver
/// `data_position`) e cada commit esperando a maioria da configuração gravada
/// (ou da `initial`), tudo sob o mesmo lock para nenhuma escrita entrar antes da
/// exigência de maioria.
fn promote_cluster(shared: &SharedDb, term: u64, me: NodeId, initial: &Membership) -> Result<()> {
    let mut db = shared.write()?;
    if db.repl.resyncing() || db.get_raw(RESYNC_KEY)?.is_some() {
        return Err(Error::Unavailable(
            "nó no meio de uma ressincronização não pode liderar".into(),
        ));
    }
    let current = epoch(&db)?;
    if term <= current {
        return Err(Error::Other(format!(
            "termo {term} não é maior que a época {current}"
        )));
    }
    {
        let mut state = db.repl.lock();
        if let Some(stop) = state.stop_replica.take() {
            stop.store(true, Ordering::Release);
        }
        state.upstream = None;
    }
    let ops = vec![put_u64(EPOCH_KEY, term), put_u64(APPLIED_KEY, 0)];
    db.write_internal(ops)?;
    let stored = stored_membership(&db)?;
    let config = stored.unwrap_or_else(|| initial.clone());
    {
        let mut state = db.repl.lock();
        state.set_quorum(me, &config);
        state.sync_timeout = None;
    }
    db.set_read_only(false);
    db.repl.fenced.store(false, Ordering::Release);
    db.repl.deposed.store(false, Ordering::Release);
    Ok(())
}

/// Posição do log nos dados: `(época, LSN)`. O LSN é o do upstream aplicado
/// (`APPLIED_KEY`) ou, se os dados são deste nó (líder da época, ou nunca
/// sincronizou), o último LSN local.
fn data_position(db: &Db) -> Result<LogPos> {
    let lsn = match applied_lsn(db)? {
        0 => db.last_lsn(),
        upstream => upstream,
    };
    Ok(LogPos {
        epoch: epoch(db)?,
        lsn,
    })
}

/// `[época:u64][lsn:u64]`, o valor de [`RESYNC_KEY`].
fn encode_position(pos: LogPos) -> Vec<u8> {
    let mut out = pos.epoch.to_le_bytes().to_vec();
    out.extend_from_slice(&pos.lsn.to_le_bytes());
    out
}

fn decode_position(raw: &[u8]) -> Option<LogPos> {
    if raw.len() != 16 {
        return None;
    }
    let (epoch, lsn) = raw.split_at(8);
    Some(LogPos {
        epoch: u64::from_le_bytes(epoch.try_into().ok()?),
        lsn: u64::from_le_bytes(lsn.try_into().ok()?),
    })
}

/// O que a eleição precisa do banco: a posição para se candidatar, a posição
/// para votar e a configuração de membros gravada. Durante uma ressincronização
/// o estado local foi apagado em parte: o nó não se candidata, mas vota com a
/// posição de antes dela (gravada em [`RESYNC_KEY`]), que cobre tudo o que ele
/// já confirmou a algum líder; sem ela (versão anterior), não vota.
type LocalView = (Option<LogPos>, Option<LogPos>, Option<Membership>);

fn local_view(shared: &SharedDb) -> Result<LocalView> {
    let db = shared.read_unchecked()?;
    let config = stored_membership(&db)?;
    let resync = db.get_raw(RESYNC_KEY)?;
    if db.repl.resyncing() || resync.is_some() {
        let before = resync.as_deref().and_then(decode_position);
        return Ok((None, before, config));
    }
    let pos = data_position(&db)?;
    Ok((Some(pos), Some(pos), config))
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
    fn new(keys: Option<Keys>, dir: u8) -> Self {
        Self {
            keys,
            dir,
            counter: 0,
        }
    }

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
    write_sealed(w, half, encode_body(kind, lsn, ops))
}

/// Envia um corpo qualquer como quadro `[len:u32][corpo selado]`.
fn write_sealed(w: &mut impl Write, half: &mut Half, mut body: Vec<u8>) -> Result<()> {
    half.seal(&mut body);
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend(body);
    w.write_all(&frame)?;
    w.flush()?;
    Ok(())
}

fn read_frame(r: &mut impl Read, half: &mut Half) -> Result<(u8, u64, Vec<Op>)> {
    decode_body(&read_sealed(r, half)?)
}

/// Lê um quadro e devolve o corpo aberto (autenticado e decifrado).
fn read_sealed(r: &mut impl Read, half: &mut Half) -> Result<Vec<u8>> {
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
    half.open(body)
}

fn read_line(r: &mut impl BufRead) -> Result<String> {
    let mut line = String::new();
    r.by_ref().take(4096).read_line(&mut line)?;
    if line.is_empty() {
        return Err(Error::Other("conexão encerrada no handshake".into()));
    }
    Ok(line.trim_end().to_string())
}

/// MAC do `SYNC`. O id de nó (só de membros do cluster) entra no MAC; sem ele
/// (0, réplica comum), o MAC é o mesmo das versões anteriores.
fn sync_mac(
    secret: &[u8],
    np: &[u8],
    nr: &[u8],
    after: u64,
    epoch: u64,
    snap: bool,
    node: NodeId,
) -> String {
    let id = node.to_le_bytes();
    let id: &[u8] = if node == 0 { &[] } else { &id };
    crypto::to_hex(&crypto::hmac_sha256(
        secret,
        &[
            b"minidb-repl-sync",
            np,
            nr,
            &after.to_le_bytes(),
            &epoch.to_le_bytes(),
            &[snap as u8],
            id,
        ],
    ))
}

/// Campos do `SYNC`: LSN, época, nonce, snapshot?, MAC e nó (0 = réplica comum).
type SyncRequest<'a> = (u64, u64, Vec<u8>, bool, &'a str, NodeId);

fn parse_sync(line: &str) -> Option<SyncRequest<'_>> {
    let parts: Vec<&str> = line.split(' ').collect();
    let ["SYNC", after, ep, nr, snap, mac, rest @ ..] = parts.as_slice() else {
        return None;
    };
    let node = match rest {
        [] => 0,
        [node] => node.parse::<NodeId>().ok()?,
        _ => return None,
    };
    let request = (
        after.parse::<u64>().ok()?,
        ep.parse::<u64>().ok()?,
        crypto::from_hex(nr)?,
        *snap == "1",
        *mac,
        node,
    );
    Some(request)
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
    accept_loop(shared, listener, cfg);
    Ok(())
}

/// Atende réplicas (e, no modo cluster, pares) que chegam em `listener`.
fn accept_loop(shared: SharedDb, listener: TcpListener, cfg: ReplicationConfig) {
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
    if line.starts_with("RAFT ") {
        return serve_raft(&hub, reader, out, &np, &line, cfg);
    }
    let Some((after, their_epoch, nr, want_snapshot, mac, node)) = parse_sync(&line) else {
        writeln!(out, "ERR handshake inválido")?;
        return Err(Error::Other(format!("handshake inválido: {line:?}")));
    };
    let keys = match &cfg.secret {
        Some(secret) => {
            let snap = want_snapshot;
            let expected = sync_mac(secret, &np, &nr, after, their_epoch, snap, node);
            if !crypto::constant_time_eq(expected.as_bytes(), mac.as_bytes()) {
                writeln!(out, "ERR autenticação recusada")?;
                return Err(Error::Other("réplica com segredo inválido".into()));
            }
            Some(derive_keys(secret, &np, &nr))
        }
        None => None,
    };
    if hub.cluster.load(Ordering::Acquire) && !hub.leading.load(Ordering::Acquire) {
        writeln!(out, "ERR este nó não é o líder do cluster")?;
        return Err(Error::Other("SYNC recusado: não é o líder".into()));
    }
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
        state.acks.insert(id, (node, 0));
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
                acked.1 = acked.1.max(lsn);
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
        match follow(&shared, primary, &stop, cfg, 0) {
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

/// Segue `primary` até `stop`. `node` é o id deste nó no cluster (0 fora dele):
/// o líder só conta para a maioria as confirmações de membros.
fn follow(
    shared: &SharedDb,
    primary: &str,
    stop: &AtomicBool,
    cfg: &ReplicationConfig,
    node: NodeId,
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
    let snap = want_snapshot;
    let mac = match (&cfg.secret, *auth == "1") {
        (Some(secret), true) => sync_mac(secret, &np, &nr, after, my_epoch, snap, node),
        (None, true) => {
            return Err(Error::Other(
                "o primário exige autenticação: configure o segredo".into(),
            ))
        }
        _ => "-".into(),
    };
    let id = if node == 0 {
        String::new()
    } else {
        format!(" {node}")
    };
    writeln!(
        out,
        "SYNC {after} {my_epoch} {} {} {mac}{id}",
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
        // Quem para a réplica (promoção, troca de líder no cluster) espera este
        // quadro terminar; depois da parada nada mais é aplicado nem confirmado.
        let _gate = hub.gate.lock().unwrap_or_else(|e| e.into_inner());
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        match kind {
            T_BATCH => {
                let mut ops = transferable(&ops);
                ops.push(put_u64(APPLIED_KEY, lsn));
                apply(shared, ops)?;
                after = lsn;
            }
            T_SNAP_BEGIN => begin_resync(shared, &hub, stop)?,
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
        if matches!(kind, T_BATCH | T_SNAP_END | T_HEARTBEAT) && !stop.load(Ordering::Acquire) {
            write_frame(&mut out, &mut send, T_ACK, after, &[])?;
        }
    }
    Ok(())
}

/// Marca a ressincronização (persistida) e apaga o estado antigo em lotes. A
/// marca guarda a posição do log de antes dela (numa retomada, a da primeira
/// tentativa): com ela o nó do cluster continua votando.
fn begin_resync(shared: &SharedDb, hub: &Hub, stop: &AtomicBool) -> Result<()> {
    let before = {
        let db = shared.read_unchecked()?;
        match db.get_raw(RESYNC_KEY)? {
            Some(marked) => marked,
            None => encode_position(data_position(&db)?),
        }
    };
    hub.resyncing.store(true, Ordering::Release);
    let mark = Op::Put {
        key: RESYNC_KEY.to_vec(),
        value: before,
    };
    apply(shared, vec![mark, put_u64(APPLIED_KEY, 0)])?;
    loop {
        if stop.load(Ordering::Acquire) {
            // A marca fica: a próxima sessão recomeça do snapshot.
            return Err(Error::Other("ressincronização interrompida".into()));
        }
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

// ---------------------------------------------------------------------------
// Cluster: eleição automática (estilo Raft) sobre a replicação
// ---------------------------------------------------------------------------

/// Configuração do modo cluster.
#[derive(Clone, Debug)]
pub struct ClusterConfig {
    /// Identificador deste nó (`cluster_id`, maior que 0).
    pub id: NodeId,
    /// Os outros nós da configuração inicial: `(id, endereço de replicação)`.
    /// Pode incluir este nó: o endereço dele é o anunciado aos outros nas trocas
    /// de membros (sem ele, vale `listen`).
    pub peers: Vec<(NodeId, String)>,
    /// Base do timeout de eleição: cada nó sorteia entre `base` e `2 * base` a
    /// cada eleição; o líder manda batimentos a cada `base / 5`.
    pub election_timeout: Duration,
}

/// Nó do cluster em execução (devolvido por [`start_cluster`]).
pub struct ClusterHandle {
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

impl ClusterHandle {
    /// Tira este nó do cluster: deixa de votar, de mandar batimentos e de seguir
    /// o líder, e fica somente leitura. O banco continua aberto e o endereço de
    /// replicação continua escutando, mas recusa pares e réplicas.
    pub fn shutdown(self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.handle.join();
    }
}

/// Evento para o laço da eleição.
enum Event {
    /// Pedido de um par e o canal da resposta.
    Rpc(Message, mpsc::Sender<Message>),
    /// Resposta de um par a um pedido deste nó.
    Reply(Message),
    /// Pedido de troca de membro e o canal da resposta (termo e configuração).
    Propose(Change, mpsc::Sender<Result<(u64, Membership)>>),
    /// Fim da troca proposta no termo dado: confirmada pela maioria ou não.
    Finish(u64, bool),
}

/// Configuração inicial: este nó (com o endereço anunciado, a própria entrada
/// em `peers` ou `listen`) e os pares.
fn initial_membership(cluster: &ClusterConfig, listen: &str) -> Result<Membership> {
    let mut members = BTreeMap::from([(cluster.id, listen.to_string())]);
    let mut seen = BTreeSet::new();
    for (id, addr) in &cluster.peers {
        seen.insert(*id);
        members.insert(*id, addr.clone());
    }
    let repeated = seen.len() != cluster.peers.len();
    if repeated || members.contains_key(&0) || members.len() < 2 {
        return Err(Error::Other(
            "modo cluster: ids de nó (cluster_id e pares) distintos e maiores que 0".into(),
        ));
    }
    Ok(Membership { index: 0, members })
}

/// Liga o modo cluster: escuta réplicas e pares em `listen` (o endereço de
/// replicação deste nó), começa como seguidor somente leitura e elege um líder
/// com os pares de `cluster` ([`crate::raft`]). O vencedor do termo `T` é
/// promovido com época `T`; os outros passam a segui-lo. Cada commit do líder
/// espera a maioria dos membros, sem timeout. A configuração de membros é a
/// gravada no banco ([`CONFIG_KEY`]) ou, sem troca nenhuma, a de `cluster`.
/// Exige o segredo de replicação: votos e batimentos usam o canal autenticado
/// e cifrado.
pub fn start_cluster(
    shared: &SharedDb,
    listen: &str,
    cfg: ReplicationConfig,
    cluster: ClusterConfig,
) -> Result<ClusterHandle> {
    let Some(secret) = cfg.secret.clone() else {
        return Err(Error::Other(
            "modo cluster exige o segredo de replicação (MINIDB_REPL_SECRET)".into(),
        ));
    };
    let initial = initial_membership(&cluster, listen)?;
    let dir = shared.read_unchecked()?.dir().to_path_buf();
    let mut hard = raft::load_hard_state(&dir)?;
    let (current, stored) = {
        let db = shared.read_unchecked()?;
        (epoch(&db)?, stored_membership(&db)?)
    };
    if hard.term < current {
        // O termo nunca fica atrás da época já gravada nos dados.
        hard = raft::HardState {
            term: current,
            voted_for: None,
        };
    }
    let listener = TcpListener::bind(listen)?;
    enable_feed(shared, cfg.max_feed_ops)?;
    set_sync_replicas(shared, 0, None)?;
    shared.write()?.set_read_only(true);
    let hub = hub_of(shared)?;
    hub.cluster.store(true, Ordering::Release);
    hub.fenced.store(true, Ordering::Release);
    let (events_tx, events) = mpsc::channel();
    hub.lock().raft = Some(events_tx.clone());
    let idle = TargetState {
        addr: None,
        stop: Arc::new(AtomicBool::new(true)),
        closed: false,
    };
    let target = Arc::new(Target {
        state: Mutex::new(idle),
        cv: Condvar::new(),
    });
    {
        let (shared, cfg) = (shared.clone(), cfg.clone());
        thread::spawn(move || accept_loop(shared, listener, cfg));
    }
    {
        let (shared, hub, target) = (shared.clone(), Arc::clone(&hub), Arc::clone(&target));
        let me = cluster.id;
        thread::spawn(move || cluster_follow(shared, hub, target, cfg, me));
    }
    let timeout = cluster.election_timeout;
    let seed = u64::from_le_bytes(crypto::random_bytes());
    let timing = raft::Timing::new(timeout, seed);
    let config = stored.unwrap_or_else(|| initial.clone());
    let node = Node::new(cluster.id, config, hard, timing, Instant::now());
    let driver = Driver {
        shared: shared.clone(),
        hub,
        target,
        dir,
        id: cluster.id,
        initial,
        links: BTreeMap::new(),
        secret,
        events: events_tx,
        timeout,
        saved: hard,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let tick = (timing.heartbeat() / 2).max(Duration::from_millis(5));
    let handle = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || driver.run(node, events, &stop, tick))
    };
    Ok(ClusterHandle { stop, handle })
}

/// Upstream que a réplica do cluster segue, trocável em execução.
struct Target {
    state: Mutex<TargetState>,
    cv: Condvar,
}

struct TargetState {
    addr: Option<String>,
    /// Parada da sessão atual (cada troca de upstream cria outra).
    stop: Arc<AtomicBool>,
    closed: bool,
}

impl Target {
    fn lock(&self) -> MutexGuard<'_, TargetState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Troca o upstream (`None` = não seguir ninguém). Ao voltar, a sessão
    /// anterior não aplica nem confirma mais nada: um nó que viu um termo maior
    /// não confirma mais escritas do líder antigo (regra do Raft).
    fn set(&self, hub: &Hub, addr: Option<String>) {
        let mut state = self.lock();
        if state.addr == addr {
            return;
        }
        state.stop.store(true, Ordering::Release);
        state.stop = Arc::new(AtomicBool::new(false));
        state.addr = addr;
        drop(state);
        self.cv.notify_all();
        // Espera o quadro em andamento, se houver, terminar.
        drop(hub.gate.lock().unwrap_or_else(|e| e.into_inner()));
    }

    fn close(&self, hub: &Hub) {
        self.set(hub, None);
        self.lock().closed = true;
        self.cv.notify_all();
    }

    /// Bloqueia até haver upstream; `None` = encerrado.
    fn next(&self) -> Option<(String, Arc<AtomicBool>)> {
        let mut state = self.lock();
        loop {
            if state.closed {
                return None;
            }
            let live = !state.stop.load(Ordering::Acquire);
            if let (Some(addr), true) = (&state.addr, live) {
                return Some((addr.clone(), Arc::clone(&state.stop)));
            }
            state = self.cv.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// Réplica do cluster: segue o upstream escolhido pela eleição até o fim. `me`
/// vai no `SYNC`, para o líder contar as confirmações deste nó na maioria.
fn cluster_follow(
    shared: SharedDb,
    hub: Arc<Hub>,
    target: Arc<Target>,
    cfg: ReplicationConfig,
    me: NodeId,
) {
    while let Some((addr, stop)) = target.next() {
        if let Err(e) = start_following(&shared, &addr, &stop) {
            eprintln!("minidb cluster: não consegui seguir {addr}: {e}");
            thread::sleep(Duration::from_millis(200));
            continue;
        }
        while !stop.load(Ordering::Acquire) {
            if let Err(e) = follow(&shared, &addr, &stop, &cfg, me) {
                if !stop.load(Ordering::Acquire) {
                    eprintln!("minidb cluster: upstream {addr}: {e}");
                    thread::sleep(Duration::from_millis(200));
                }
            }
        }
        // `fenced` antes de largar o upstream: ROLE nunca mostra "primary" aqui.
        if !hub.leading.load(Ordering::Acquire) {
            hub.fenced.store(true, Ordering::Release);
        }
        let mut state = hub.lock();
        if state.upstream.as_deref() == Some(addr.as_str()) {
            state.upstream = None;
        }
    }
}

/// O preparo de [`run_replica_with`], para uma sessão do cluster.
fn start_following(shared: &SharedDb, addr: &str, stop: &Arc<AtomicBool>) -> Result<()> {
    let mut db = shared.write()?;
    db.set_read_only(true);
    let resync = db.get_raw(RESYNC_KEY)?.is_some();
    db.repl.resyncing.store(resync, Ordering::Release);
    db.repl.fenced.store(false, Ordering::Release);
    let mut state = db.repl.lock();
    state.stop_replica = Some(Arc::clone(stop));
    state.upstream = Some(addr.to_string());
    Ok(())
}

fn raft_mac(secret: &[u8], np: &[u8], nr: &[u8]) -> String {
    let mac = crypto::hmac_sha256(secret, &[b"minidb-repl-raft", np, nr]);
    crypto::to_hex(&mac)
}

/// Conexão autenticada com um par, para pedidos da eleição.
struct RaftConn {
    out: TcpStream,
    reader: BufReader<TcpStream>,
    send: Half,
    recv: Half,
}

impl RaftConn {
    fn connect(addr: &str, secret: &[u8], timeout: Duration) -> Result<Self> {
        let resolved = addr.to_socket_addrs()?.next();
        let Some(sock) = resolved else {
            return Err(Error::Other(format!("endereço inválido: {addr}")));
        };
        let stream = TcpStream::connect_timeout(&sock, timeout)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(timeout))?;
        let mut out = stream.try_clone()?;
        let mut reader = BufReader::new(stream);
        let hello = read_line(&mut reader)?;
        let parts: Vec<&str> = hello.split(' ').collect();
        let np = match parts.as_slice() {
            ["MINIDB-REPL", _, _, np, "1"] => crypto::from_hex(np),
            _ => None,
        };
        let Some(np) = np else {
            return Err(Error::Other(format!(
                "par sem canal de replicação autenticado: {hello:?}"
            )));
        };
        let nr: [u8; 16] = crypto::random_bytes();
        let (nr_hex, mac) = (crypto::to_hex(&nr), raft_mac(secret, &np, &nr));
        writeln!(out, "RAFT {nr_hex} {mac}")?;
        let answer = read_line(&mut reader)?;
        if answer != "OK" {
            return Err(Error::Other(format!("par recusou: {answer}")));
        }
        let keys = derive_keys(secret, &np, &nr);
        Ok(Self {
            out,
            reader,
            send: Half::new(Some(keys.clone()), 1),
            recv: Half::new(Some(keys), 0),
        })
    }

    fn call(&mut self, msg: Message) -> Result<Message> {
        write_sealed(&mut self.out, &mut self.send, msg.encode())?;
        let body = read_sealed(&mut self.reader, &mut self.recv)?;
        match Message::decode(&body) {
            Some(reply) => Ok(reply),
            None => Err(Error::Other("resposta de eleição malformada".into())),
        }
    }
}

/// Envia os pedidos deste nó a um par, um por vez, e entrega as respostas ao
/// laço da eleição. Mensagens acumuladas são descartadas: só a mais nova importa.
fn peer_link(
    addr: &str,
    secret: &[u8],
    outbox: mpsc::Receiver<Message>,
    events: mpsc::Sender<Event>,
    timeout: Duration,
) {
    let mut conn: Option<RaftConn> = None;
    while let Ok(mut msg) = outbox.recv() {
        while let Ok(newer) = outbox.try_recv() {
            msg = newer;
        }
        if conn.is_none() {
            conn = RaftConn::connect(addr, secret, timeout).ok();
        }
        let Some(c) = conn.as_mut() else { continue };
        match c.call(msg) {
            Ok(reply) => {
                if events.send(Event::Reply(reply)).is_err() {
                    return;
                }
            }
            Err(_) => conn = None,
        }
    }
}

/// Sessão de um par do cluster: pedidos de voto e batimentos, um por vez.
fn serve_raft(
    hub: &Hub,
    mut reader: BufReader<TcpStream>,
    mut out: TcpStream,
    np: &[u8],
    line: &str,
    cfg: &ReplicationConfig,
) -> Result<()> {
    let events = hub.lock().raft.clone();
    let parts: Vec<&str> = line.split(' ').collect();
    let (nr, mac) = match parts.as_slice() {
        ["RAFT", nr, mac] => (crypto::from_hex(nr), *mac),
        _ => (None, ""),
    };
    let (Some(secret), Some(events), Some(nr)) = (&cfg.secret, events, nr) else {
        writeln!(out, "ERR pedido de eleição recusado")?;
        return Err(Error::Other("pedido de eleição recusado".into()));
    };
    let expected = raft_mac(secret, np, &nr);
    if !crypto::constant_time_eq(expected.as_bytes(), mac.as_bytes()) {
        writeln!(out, "ERR autenticação recusada")?;
        return Err(Error::Other("segredo inválido de par".into()));
    }
    writeln!(out, "OK")?;
    let keys = derive_keys(secret, np, &nr);
    let mut send = Half::new(Some(keys.clone()), 0);
    let mut recv = Half::new(Some(keys), 1);
    let idle = Some(Duration::from_secs(60));
    reader.get_mut().set_read_timeout(idle)?;
    loop {
        let body = read_sealed(&mut reader, &mut recv)?;
        let msg = match Message::decode(&body) {
            Some(msg) => msg,
            None => return Err(Error::Other("pedido de eleição malformado".into())),
        };
        let (tx, rx) = mpsc::channel();
        if events.send(Event::Rpc(msg, tx)).is_err() {
            return Err(Error::Other("nó fora do cluster".into()));
        }
        let reply = match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(reply) => reply,
            Err(_) => return Err(Error::Other("laço da eleição não respondeu".into())),
        };
        write_sealed(&mut out, &mut send, reply.encode())?;
    }
}

/// Troca um membro do cluster (só no líder, uma troca por vez): o
/// "single-server change" do Raft. Primeiro confirma, pela maioria da
/// configuração em uso, um registro do termo atual (sem isso, trocas de líderes
/// diferentes podem se cruzar); depois grava a configuração nova no log
/// replicado e espera a maioria dela. Um erro depois de ela entrar no log tem o
/// sentido de um commit incerto. Devolve a configuração nova.
pub fn change_membership(shared: &SharedDb, change: Change) -> Result<Membership> {
    let events = hub_of(shared)?.lock().raft.clone();
    let Some(events) = events else {
        return Err(Error::Unavailable("modo cluster desligado".into()));
    };
    let (tx, rx) = mpsc::channel();
    let silent = || Error::Unavailable("o laço da eleição não respondeu".into());
    let request = Event::Propose(change, tx);
    events.send(request).map_err(|_| silent())?;
    let answer = rx.recv_timeout(Duration::from_secs(5));
    let (term, next) = answer.map_err(|_| silent())??;
    let result = commit_membership(shared, term, &next);
    let _ = events.send(Event::Finish(term, result.is_ok()));
    result.map(|()| next)
}

/// As duas escritas de [`change_membership`], cada uma conferindo sob o lock
/// dos escritores que este nó ainda lidera o termo da proposta.
fn commit_membership(shared: &SharedDb, term: u64, next: &Membership) -> Result<()> {
    shared.commit_with(|db| {
        check_leading(db, term)?;
        Ok((vec![put_u64(EPOCH_KEY, term)], true, ()))
    })?;
    shared.commit_with(|db| {
        check_leading(db, term)?;
        let index = stored_membership(db)?.map_or(0, |current| current.index);
        if index + 1 != next.index {
            return Err(Error::Unavailable("configuração mudou; repita".into()));
        }
        let record = Op::Put {
            key: CONFIG_KEY.to_vec(),
            value: next.encode().into_bytes(),
        };
        Ok((vec![record], true, ()))
    })?;
    Ok(())
}

fn check_leading(db: &Db, term: u64) -> Result<()> {
    if db.repl.leading.load(Ordering::Acquire) && epoch(db)? == term {
        return Ok(());
    }
    Err(Error::Unavailable("este nó deixou de ser o líder".into()))
}

/// Laço da eleição de um nó: camada fina entre [`raft::Node`] e o banco.
struct Driver {
    shared: SharedDb,
    hub: Arc<Hub>,
    target: Arc<Target>,
    dir: PathBuf,
    id: NodeId,
    /// Configuração de `cluster_peers`, que vale enquanto o banco não tem outra.
    initial: Membership,
    /// Canal de cada par (membros e, numa troca, o nó que entra): endereço e fila.
    links: BTreeMap<NodeId, (String, mpsc::Sender<Message>)>,
    secret: Vec<u8>,
    events: mpsc::Sender<Event>,
    timeout: Duration,
    /// Último estado gravado em disco.
    saved: raft::HardState,
}

impl Driver {
    fn run(
        mut self,
        mut node: Node,
        events: mpsc::Receiver<Event>,
        stop: &AtomicBool,
        tick: Duration,
    ) {
        while !stop.load(Ordering::Acquire) {
            let event = match events.recv_timeout(tick) {
                Ok(event) => Some(event),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let now = Instant::now();
            let (position, vote, mut out) = self.refresh(&mut node, now);
            let (term, leader) = (node.term(), node.leader());
            let mut asker = None;
            match event {
                Some(Event::Rpc(msg, reply)) => {
                    out.extend(node.on_message(now, msg, vote));
                    asker = Some(reply);
                }
                Some(Event::Reply(msg)) => out.extend(node.on_message(now, msg, vote)),
                Some(Event::Propose(change, reply)) => {
                    let proposed = node.propose(&change).map(|next| (node.term(), next));
                    let _ = reply.send(proposed);
                }
                Some(Event::Finish(at, committed)) => {
                    out.extend(node.finish_change(now, at, committed));
                }
                None => {}
            }
            out.extend(node.on_timeout(now, position));
            // Termo novo ou líder perdido, antes de qualquer mensagem sair: nada
            // mais do líder antigo é aplicado nem confirmado aqui (regra do Raft).
            if node.term() > term || (leader.is_some() && node.leader().is_none()) {
                self.freeze();
            }
            if !self.persist(&node) {
                // Sem termo e voto no disco, nada sai deste nó.
                out.retain(|action| matches!(action, Action::StepDown));
                out.extend(node.resign(now));
            }
            self.connect(&node);
            for action in out {
                self.perform(&mut node, action, asker.as_ref());
            }
            self.follow_leader(&node);
        }
        self.hub.lock().raft = None;
        self.target.close(&self.hub);
        self.step_down();
    }

    /// Lê o banco: posição para se candidatar, posição para votar e, se mudou, a
    /// configuração de membros (sem registro gravado, a inicial).
    fn refresh(
        &self,
        node: &mut Node,
        now: Instant,
    ) -> (Option<LogPos>, Option<LogPos>, Vec<Action>) {
        match local_view(&self.shared) {
            Ok((position, vote, stored)) => {
                let config = stored.unwrap_or_else(|| self.initial.clone());
                (position, vote, node.set_config(config, now))
            }
            Err(e) => {
                eprintln!("minidb cluster: estado local indisponível: {e}");
                (None, None, Vec::new())
            }
        }
    }

    /// Um canal por par: os membros e, durante uma troca, o nó que está entrando.
    /// O canal de quem saiu é fechado (a thread dele termina).
    fn connect(&mut self, node: &Node) {
        let mut wanted = node.config().members.clone();
        if let Some(next) = node.pending() {
            wanted.extend(next.members.clone());
        }
        wanted.remove(&self.id);
        self.links.retain(|id, link| wanted.get(id) == Some(&link.0));
        for (id, addr) in wanted {
            if self.links.contains_key(&id) {
                continue;
            }
            let (tx, rx) = mpsc::channel();
            let (secret, events) = (self.secret.clone(), self.events.clone());
            let (peer, timeout) = (addr.clone(), self.timeout);
            thread::spawn(move || peer_link(&peer, &secret, rx, events, timeout));
            self.links.insert(id, (addr, tx));
        }
    }

    /// Para de seguir o upstream e, se liderava, desiste. Vem antes de qualquer
    /// mensagem de um termo novo sair deste nó.
    fn freeze(&self) {
        self.target.set(&self.hub, None);
        if self.hub.leading.load(Ordering::Acquire) {
            self.step_down();
        }
    }

    fn step_down(&self) {
        let hub = &self.hub;
        hub.leading.store(false, Ordering::Release);
        hub.deposed.store(true, Ordering::Release);
        // Sob o lock: um commit entre a checagem e o `wait` não perde o aviso.
        drop(hub.lock());
        hub.cv.notify_all();
        if let Err(e) = self.demote() {
            eprintln!("minidb cluster: erro ao deixar a liderança: {e}");
        }
    }

    fn demote(&self) -> Result<()> {
        let mut db = self.shared.write()?;
        db.set_read_only(true);
        {
            let mut state = db.repl.lock();
            state.sync_replicas = 0;
            state.quorum = None;
        }
        db.repl.fenced.store(true, Ordering::Release);
        Ok(())
    }

    fn become_leader(&self, term: u64) -> Result<()> {
        self.target.set(&self.hub, None);
        promote_cluster(&self.shared, term, self.id, &self.initial)?;
        self.hub.leading.store(true, Ordering::Release);
        eprintln!("minidb cluster: nó {} é o líder do termo {term}", self.id);
        Ok(())
    }

    fn perform(&self, node: &mut Node, action: Action, asker: Option<&mpsc::Sender<Message>>) {
        match action {
            Action::Send { to, msg } => {
                if let Some((_, link)) = self.links.get(&to) {
                    let _ = link.send(msg);
                }
            }
            Action::Reply(msg) => {
                if let Some(asker) = asker {
                    let _ = asker.send(msg);
                }
            }
            Action::BecomeLeader { term } => {
                if let Err(e) = self.become_leader(term) {
                    eprintln!("minidb cluster: promoção no termo {term} falhou: {e}");
                    let _ = node.resign(Instant::now());
                    self.step_down();
                }
            }
            Action::StepDown => self.step_down(),
        }
    }

    /// Seguidor que conhece o líder do termo passa a segui-lo.
    fn follow_leader(&self, node: &Node) {
        let leader = match (node.state(), node.leader()) {
            (raft::State::Follower, Some(leader)) => leader,
            _ => return,
        };
        let known = node.config().members.get(&leader);
        let addr = known.or_else(|| self.initial.members.get(&leader));
        if let Some(addr) = addr {
            self.target.set(&self.hub, Some(addr.clone()));
        }
    }

    /// Grava termo e voto antes de qualquer mensagem sair (regra do Raft).
    fn persist(&mut self, node: &Node) -> bool {
        let hard = node.hard_state();
        if hard == self.saved {
            return true;
        }
        match raft::save_hard_state(&self.dir, hard) {
            Ok(()) => {
                self.saved = hard;
                true
            }
            Err(e) => {
                eprintln!("minidb cluster: não consegui gravar o estado da eleição: {e}");
                false
            }
        }
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
