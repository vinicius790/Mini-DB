//! Banco: open/close, escrita com WAL, transações, TTL, iteradores, SQL,
//! checkpoint, vacuum e recover.
//!
//! Toda escrita segue um único caminho: validação → registro no WAL (com
//! `fsync` por padrão) → aplicação na árvore. O mesmo `apply` é usado no
//! recovery, então o estado reconstruído é idêntico ao estado em memória.
//!
//! O registro no WAL só precisa de `&self`: o WAL tem mutex próprio.
//! Assim o [`crate::mvcc::SharedDb`] faz o `fsync` sem bloquear leitores e só
//! pega o lock exclusivo para aplicar o lote já durável.
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::bloom::Bloom;
use crate::btree::{self, validate_key, validate_user_key, validate_value, BTree, TreeId};
use crate::buffer::BufferPool;
use crate::error::{Error, Result};
use crate::index;
use crate::inspect::{self, PageStats};
use crate::mvcc::VersionStore;
use crate::page::{
    MetaInfo, Page, PageKind, MAX_KEY_LEN, META_FLAG_COMPRESSED_VALUES, META_FLAG_INDEX_V2,
    META_FLAG_VALUE_INDEX,
};
use crate::replication::Hub;
use crate::sql::{explain, parse_sql, Cmp, Pred, Statement};
use crate::verify;
use crate::wal::{Wal, WalRecord};

/// Páginas em cache por padrão (4 MiB).
const DEFAULT_POOL_FRAMES: usize = 1024;
/// Checkpoint automático quando o WAL passa deste tamanho (padrão).
pub const DEFAULT_AUTO_CHECKPOINT: u64 = 64 << 20;
/// Arquivo temporário do VACUUM (removido na abertura se sobrar de um crash).
const VACUUM_FILE: &str = "vacuum.mdb";
/// Operações por lote no `purge_expired` (memória limitada).
const PURGE_CHUNK: usize = 10_000;

/// Linha devolvida por scans: `(chave, valor)`.
pub type Row = (Vec<u8>, Vec<u8>);

/// Operação de escrita para [`Db::write_batch`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchOp {
    /// Upsert; remove qualquer TTL anterior da chave.
    Put { key: Vec<u8>, value: Vec<u8> },
    /// Upsert com expiração relativa ao momento da escrita.
    PutWithTtl {
        key: Vec<u8>,
        value: Vec<u8>,
        ttl: Duration,
    },
    /// Remove a chave; ausência não é erro.
    Delete { key: Vec<u8> },
}

/// Situação de expiração de uma chave (ver [`Db::ttl`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyTtl {
    /// A chave não existe (ou já expirou).
    Missing,
    /// A chave existe e não expira.
    Persistent,
    /// A chave expira depois deste intervalo.
    ExpiresIn(Duration),
}

/// Primeiro byte das chaves internas (tabelas SQL e metadados de replicação).
/// A API chave-valor pública não lê nem grava chaves com esse prefixo.
pub const RESERVED_PREFIX: u8 = 0xFF;

pub(crate) fn is_reserved(key: &[u8]) -> bool {
    key.first() == Some(&RESERVED_PREFIX)
}

fn reject_reserved(key: &[u8]) -> Result<()> {
    if is_reserved(key) {
        return Err(Error::InvalidInput(
            "chaves iniciadas por 0xFF são reservadas ao motor".into(),
        ));
    }
    Ok(())
}

/// Operação lógica registrada no WAL, aplicada às árvores e replicada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Put {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        key: Vec<u8>,
    },
    /// `at` em ms desde a época; 0 remove o TTL.
    Expire {
        key: Vec<u8>,
        at: u64,
    },
}

impl Op {
    pub(crate) fn key(&self) -> &[u8] {
        match self {
            Op::Put { key, .. } | Op::Delete { key } | Op::Expire { key, .. } => key,
        }
    }

    fn record(&self) -> WalRecord {
        match self {
            Op::Put { key, value } => WalRecord::Insert {
                lsn: 0,
                key: key.clone(),
                value: value.clone(),
            },
            Op::Delete { key } => WalRecord::Delete {
                lsn: 0,
                key: key.clone(),
            },
            Op::Expire { key, at } => WalRecord::Expire {
                lsn: 0,
                key: key.clone(),
                expires_at: *at,
            },
        }
    }

    pub(crate) fn from_record(rec: &WalRecord) -> Option<Self> {
        match rec {
            WalRecord::Insert { key, value, .. } => Some(Op::Put {
                key: key.clone(),
                value: value.clone(),
            }),
            WalRecord::Delete { key, .. } => Some(Op::Delete { key: key.clone() }),
            WalRecord::Expire {
                key, expires_at, ..
            } => Some(Op::Expire {
                key: key.clone(),
                at: *expires_at,
            }),
            _ => None,
        }
    }
}

pub(crate) fn batch_to_ops(batch: &[BatchOp]) -> Vec<Op> {
    let mut ops = Vec::with_capacity(batch.len());
    for item in batch {
        match item {
            BatchOp::Put { key, value } => ops.push(Op::Put {
                key: key.clone(),
                value: value.clone(),
            }),
            BatchOp::PutWithTtl { key, value, ttl } => {
                ops.push(Op::Put {
                    key: key.clone(),
                    value: value.clone(),
                });
                ops.push(Op::Expire {
                    key: key.clone(),
                    at: expiry_after(*ttl),
                });
            }
            BatchOp::Delete { key } => ops.push(Op::Delete { key: key.clone() }),
        }
    }
    ops
}

pub struct Db {
    dir: PathBuf,
    pool: BufferPool,
    wal: Mutex<Wal>,
    meta: MetaInfo,
    open: bool,
    txn: Option<TxnState>,
    bloom: Bloom,
    sync_wal: bool,
    read_only: bool,
    next_txn_id: AtomicU64,
    /// Último LSN aplicado às árvores (versão vista por leitores e snapshots).
    applied_lsn: u64,
    auto_checkpoint: u64,
    wal_retention: u64,
    /// Imagens anteriores para snapshots MVCC ativos ([`crate::mvcc`]).
    pub(crate) versions: Arc<Mutex<VersionStore>>,
    /// Feed de commits, confirmações e fencing da replicação.
    pub(crate) repl: Arc<Hub>,
    /// Barramento de eventos (mudanças de linhas e NOTIFY), compartilhado com
    /// o `SharedDb`.
    pub(crate) events: Arc<crate::events::EventBus>,
    /// Comandos SQL já analisados, por texto.
    plans: Mutex<HashMap<String, Arc<crate::rel::Prepared>>>,
    /// Segundo Unix da última marca de relógio gravada no WAL (PITR).
    last_time_mark: AtomicU64,
    // Mantém o lock do diretório até `close` (ou o fim do handle).
    lock: Option<File>,
}

struct TxnState {
    id: u64,
    ops: Vec<Op>,
    /// Eventos a publicar no commit.
    changes: Vec<crate::events::Change>,
    notifications: Vec<(String, String)>,
    /// Última operação de cada chave (leituras e scans dentro da transação).
    latest: BTreeMap<Vec<u8>, usize>,
    /// `SAVEPOINT nome` = quantas operações havia na hora.
    savepoints: Vec<(String, usize)>,
}

impl TxnState {
    fn push(&mut self, ops: Vec<Op>) {
        for op in ops {
            self.latest.insert(op.key().to_vec(), self.ops.len());
            self.ops.push(op);
        }
    }

    fn truncate(&mut self, n: usize) {
        self.ops.truncate(n);
        self.latest.clear();
        for (i, op) in self.ops.iter().enumerate() {
            self.latest.insert(op.key().to_vec(), i);
        }
    }

    /// Efeito da transação sobre `key`: `Some(Some(v))` gravou, `Some(None)`
    /// apagou/expirou, `None` não decide (só `Expire` sem vencimento).
    fn effect(&self, key: &[u8], now: u64) -> Option<Option<Vec<u8>>> {
        let mut at = self.latest.get(key).copied();
        while let Some(i) = at {
            match &self.ops[i] {
                Op::Put { value, .. } => return Some(Some(value.clone())),
                Op::Delete { .. } => return Some(None),
                Op::Expire { at: when, .. } if *when != 0 && *when <= now => return Some(None),
                Op::Expire { .. } => {
                    at = self.ops[..i].iter().rposition(|op| op.key() == key);
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExecResult {
    Ok(String),
    Rows(Vec<Row>),
    Value(Option<Vec<u8>>),
    Count(u64),
    /// Resultado tabular do SQL relacional ([`crate::rel`]).
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<crate::rel::Value>>,
    },
    /// Um resultado por comando de um script (`a; b; c`).
    Batch(Vec<ExecResult>),
}

/// O que [`Db::maintain`] fez.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    pub purged: usize,
    pub vacuumed: bool,
    pub checkpointed: bool,
}

fn lock_poisoned<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Db {
    pub fn data_path(dir: impl AsRef<Path>) -> PathBuf {
        dir.as_ref().join("data.mdb")
    }

    pub fn wal_path(dir: impl AsRef<Path>) -> PathBuf {
        dir.as_ref().join("wal.log")
    }

    /// Diretório dos WALs arquivados (retenção para réplicas).
    pub fn archive_dir(dir: impl AsRef<Path>) -> PathBuf {
        dir.as_ref().join("wal-archive")
    }

    /// Abre (ou cria) o banco com 1024 frames de pool e `fsync` por operação.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_capacity(dir, DEFAULT_POOL_FRAMES)
    }

    pub fn open_with_capacity(dir: impl AsRef<Path>, pool_capacity: usize) -> Result<Self> {
        Self::open_with_options(dir, pool_capacity, true)
    }

    pub fn open_with_options(
        dir: impl AsRef<Path>,
        pool_capacity: usize,
        sync_wal: bool,
    ) -> Result<Self> {
        Self::open_encrypted(dir, pool_capacity, sync_wal, None)
    }

    /// Abre com criptografia em repouso: `passphrase` cria a chave num banco
    /// novo e é exigida (e conferida) nas aberturas seguintes. Ver
    /// [`crate::encryption`].
    ///
    /// Um banco cifrado em formato antigo (páginas v1/v2) é migrado para v3 nesta
    /// abertura, com a mesma chave ([`crate::encryption::upgrade`]). Se a migração
    /// falhar (disco cheio, diretório só de leitura), o banco abre no formato antigo
    /// e a próxima abertura tenta de novo.
    pub fn open_encrypted(
        dir: impl AsRef<Path>,
        pool_capacity: usize,
        sync_wal: bool,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        Self::open_impl(dir.as_ref(), pool_capacity, sync_wal, passphrase, true)
    }

    /// Como [`Db::open_encrypted`], sem migrar o formato das páginas (usado pela
    /// própria conversão).
    pub(crate) fn open_without_upgrade(
        dir: impl AsRef<Path>,
        pool_capacity: usize,
        sync_wal: bool,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        Self::open_impl(dir.as_ref(), pool_capacity, sync_wal, passphrase, false)
    }

    fn open_impl(
        dir: &Path,
        pool_capacity: usize,
        sync_wal: bool,
        passphrase: Option<&str>,
        upgrade: bool,
    ) -> Result<Self> {
        let dir = dir.to_path_buf();
        fs::create_dir_all(&dir)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("LOCK"))?;
        lock.try_lock()
            .map_err(|e| Error::Other(format!("banco {} já está em uso: {e}", dir.display())))?;
        // Sobra de um VACUUM interrompido antes do rename: o original vale.
        for leftover in ["", ".spill", ".journal", ".pages"] {
            let _ = fs::remove_file(dir.join(format!("{VACUUM_FILE}{leftover}")));
        }
        // `encrypt`/`decrypt`/`rekey` interrompido: volta ao original ou conclui.
        crate::encryption::recover_convert(&dir)?;
        let wal_path = Self::wal_path(&dir);
        let has_data = fs::metadata(Self::data_path(&dir)).is_ok_and(|m| m.len() > 0)
            || fs::metadata(&wal_path).is_ok_and(|m| m.len() > 8);
        let cipher = crate::encryption::open_key(&dir, passphrase, has_data)?;
        if let (true, Some(c), Some(pass)) = (upgrade, &cipher, passphrase) {
            if !c.uses_page_map() {
                // Banco cifrado em formato antigo: migra (a conversão toma o lock) e
                // reabre. Uma falha deixa o banco como estava (`recover_convert`).
                drop(lock);
                let _ = crate::encryption::upgrade(&dir, pass);
                return Self::open_impl(&dir, pool_capacity, sync_wal, passphrase, false);
            }
        }
        let cipher = cipher.map(Arc::new);
        let mut pool = BufferPool::open_with(Self::data_path(&dir), pool_capacity, cipher.clone())?;
        let mut meta = Self::load_or_init_meta(&mut pool)?;
        let (wal_next, records) = Wal::read_all_with(&wal_path, cipher.as_deref())?;
        meta.next_lsn = wal_next
            .max(meta.next_lsn)
            .max(meta.checkpoint_lsn.saturating_add(1))
            .max(1);
        let wal = Wal::open_with(&wal_path, meta.next_lsn, cipher)?;
        let mut db = Self {
            dir,
            pool,
            wal: Mutex::new(wal),
            next_txn_id: AtomicU64::new(meta.next_txn_id.max(1)),
            meta,
            open: false,
            txn: None,
            bloom: Bloom::new(),
            sync_wal,
            read_only: false,
            applied_lsn: 0,
            auto_checkpoint: DEFAULT_AUTO_CHECKPOINT,
            wal_retention: 0,
            versions: Default::default(),
            repl: Arc::new(Hub::default()),
            events: Arc::new(crate::events::EventBus::default()),
            plans: Mutex::new(HashMap::new()),
            last_time_mark: AtomicU64::new(0),
            lock: Some(lock),
        };
        db.recover(&records)?;
        BTree::ensure_root(&mut db.pool, &mut db.meta)?;
        db.meta.next_lsn = db.wal_mut().next_lsn();
        db.applied_lsn = db.meta.next_lsn.saturating_sub(1);
        db.rebuild_bloom()?;
        db.persist_meta()?;
        db.open = true;
        db.migrate_value_index()?;
        Ok(db)
    }

    fn load_or_init_meta(pool: &mut BufferPool) -> Result<MetaInfo> {
        let existing = fs::metadata(pool.path())?.len() != 0;
        let page = pool.get_page(MetaInfo::META_PAGE_ID)?;
        let valid = page.magic() == crate::page::MAGIC && page.kind() == PageKind::Meta;
        let meta = if valid {
            MetaInfo::from_page(&page)
        } else {
            MetaInfo::fresh_file()
        };
        drop(page);
        if !valid {
            if existing {
                return Err(Error::CorruptPage(MetaInfo::META_PAGE_ID));
            }
            let mut mp = Page::zeroed(MetaInfo::META_PAGE_ID, PageKind::Meta);
            meta.write_to_page(&mut mp);
            pool.put_new_page(mp)?;
            pool.put_new_page(Page::zeroed(meta.root_page, PageKind::Leaf))?;
            pool.flush_all()?;
        }
        Ok(meta)
    }

    fn persist_meta(&mut self) -> Result<()> {
        self.meta.next_txn_id = self.next_txn_id.load(Ordering::Relaxed);
        let mut mp = Page::zeroed(MetaInfo::META_PAGE_ID, PageKind::Meta);
        self.meta.write_to_page(&mut mp);
        mp.set_lsn(self.wal_mut().next_lsn().saturating_sub(1));
        mp.write_checksum();
        self.pool.put_new_page(mp)
    }

    fn wal(&self) -> MutexGuard<'_, Wal> {
        lock_poisoned(&self.wal)
    }

    fn wal_mut(&mut self) -> &mut Wal {
        self.wal.get_mut().unwrap_or_else(|e| e.into_inner())
    }

    pub fn sync_wal(&mut self) -> Result<()> {
        if self.sync_wal {
            self.wal_mut().sync()?;
        }
        Ok(())
    }

    /// Redo das operações confirmadas após o último checkpoint.
    fn recover(&mut self, records: &[WalRecord]) -> Result<()> {
        let ckpt = self.meta.checkpoint_lsn;
        let mut pending: Vec<(Op, u64)> = Vec::new();
        let mut active_txn = None;
        let bump = |db: &Self, txn_id: u64| {
            db.next_txn_id
                .fetch_max(txn_id.saturating_add(1), Ordering::Relaxed);
        };
        for rec in records.iter().filter(|r| r.lsn() > ckpt) {
            match rec {
                WalRecord::Begin { txn_id, lsn } => {
                    // `Begin` com outra transação aberta só é aceito logo depois do
                    // `Begin` dela: a primeira operação do frame não coube no disco, o
                    // `Abort` também não, e o handle seguiu escrevendo (versões antigas;
                    // hoje o WAL recusa escritas até a reabertura). Com operações
                    // pendentes não dá para separar as do frame interrompido de
                    // autocommits já confirmados: falha, em vez de descartá-las em silêncio.
                    if !pending.is_empty() {
                        return Err(Error::CorruptWal(*lsn));
                    }
                    active_txn = Some(*txn_id);
                    bump(self, *txn_id);
                }
                WalRecord::Commit { txn_id, lsn } => {
                    if active_txn != Some(*txn_id) {
                        return Err(Error::CorruptWal(*lsn));
                    }
                    for (op, lsn) in pending.drain(..) {
                        self.apply(&op, lsn)?;
                    }
                    active_txn = None;
                }
                WalRecord::Abort { txn_id, lsn } => {
                    if active_txn.is_some() && active_txn != Some(*txn_id) {
                        return Err(Error::CorruptWal(*lsn));
                    }
                    bump(self, *txn_id);
                    pending.clear();
                    active_txn = None;
                }
                WalRecord::Checkpoint {
                    root_page,
                    freelist_head,
                    next_page_id,
                    checkpoint_lsn,
                    ..
                } => {
                    self.meta.root_page = *root_page;
                    self.meta.freelist_head = *freelist_head;
                    self.meta.next_page_id = *next_page_id;
                    self.meta.checkpoint_lsn = *checkpoint_lsn;
                }
                WalRecord::Time { .. } => {}
                other => {
                    let op = Op::from_record(other).expect("registro de dados");
                    if active_txn.is_some() {
                        pending.push((op, other.lsn()));
                    } else {
                        self.apply(&op, other.lsn())?;
                    }
                }
            }
        }
        // Fecha uma transação interrompida para que escritas futuras em
        // autocommit não sejam absorvidas por ela no próximo recovery.
        if let Some(txn_id) = active_txn {
            self.wal_mut().append(WalRecord::Abort { lsn: 0, txn_id })?;
            self.sync_wal()?;
        }
        Ok(())
    }

    fn has_value_index(&self) -> bool {
        self.meta.index_root != 0 || self.meta.flags & META_FLAG_VALUE_INDEX != 0
    }

    /// Índices por valor de versões anteriores são reconstruídos no formato
    /// por hash (idempotente: sem a flag, refaz de novo após um crash).
    fn migrate_value_index(&mut self) -> Result<()> {
        if self.meta.flags & META_FLAG_INDEX_V2 != 0 {
            return Ok(());
        }
        let had_index = self.has_value_index();
        if self.meta.index_root != 0 {
            let root = self.meta.index_root;
            btree::free_tree(&mut self.pool, &mut self.meta, root)?;
            self.meta.index_root = 0;
        }
        self.meta.flags |= META_FLAG_INDEX_V2;
        if had_index {
            self.backfill_value_index()?;
        }
        self.checkpoint()
    }

    fn backfill_value_index(&mut self) -> Result<usize> {
        BTree::ensure_tree(&mut self.pool, &mut self.meta, TreeId::Secondary)?;
        self.meta.flags |= META_FLAG_VALUE_INDEX;
        let lsn = self.applied_lsn;
        let mut leaf = BTree::first_leaf(&self.pool, &self.meta, TreeId::Primary, &[0])?;
        let mut left = self.meta.next_page_id;
        let mut n = 0;
        while leaf != 0 {
            left = left
                .checked_sub(1)
                .ok_or_else(|| Error::Other("ciclo no encadeamento de folhas".into()))?;
            let (rows, next) =
                BTree::leaf_rows(&self.pool, &self.meta, TreeId::Primary, leaf, &[0])?;
            for (key, value) in rows.iter().filter(|(k, _)| !is_reserved(k)) {
                index::upsert_value_index(&mut self.pool, &mut self.meta, key, None, value, lsn)?;
                n += 1;
            }
            leaf = next;
        }
        Ok(n)
    }

    /// Aplica uma operação já durável às árvores (primária, índice e TTL).
    fn apply(&mut self, op: &Op, lsn: u64) -> Result<()> {
        let (pool, meta) = (&mut self.pool, &mut self.meta);
        match op {
            Op::Put { key, value } => {
                let indexed = !is_reserved(key)
                    && (meta.index_root != 0 || meta.flags & META_FLAG_VALUE_INDEX != 0);
                let old = if indexed {
                    BTree::get(pool, meta, key)?
                } else {
                    None
                };
                BTree::insert(pool, meta, key, value, lsn)?;
                self.bloom.insert(key);
                if indexed {
                    index::upsert_value_index(pool, meta, key, old.as_deref(), value, lsn)?;
                }
                if meta.ttl_root != 0 {
                    BTree::delete_in(pool, meta, TreeId::Ttl, key, lsn)?;
                }
            }
            Op::Delete { key } => {
                let indexed = !is_reserved(key) && meta.index_root != 0;
                if indexed {
                    if let Some(old) = BTree::get(pool, meta, key)? {
                        index::remove_value_index(pool, meta, key, &old, lsn)?;
                    }
                }
                BTree::delete(pool, meta, key, lsn)?;
                if meta.ttl_root != 0 {
                    BTree::delete_in(pool, meta, TreeId::Ttl, key, lsn)?;
                }
            }
            Op::Expire { key, at: 0 } => {
                BTree::delete_in(pool, meta, TreeId::Ttl, key, lsn)?;
            }
            Op::Expire { key, at } => {
                BTree::insert_in(pool, meta, TreeId::Ttl, key, &at.to_be_bytes(), lsn)?;
            }
        }
        Ok(())
    }

    fn alloc_txn_id(&self) -> u64 {
        self.next_txn_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Registra `ops` no WAL (em um frame BEGIN/COMMIT quando há mais de uma
    /// ou quando vêm de uma transação) e publica no feed de replicação. Não toca
    /// as árvores: só precisa de `&self`, então leitores continuam durante o
    /// `fsync`. Devolve o LSN do commit. Chamadores serializam os escritores e,
    /// antes de aplicar, esperam as réplicas (`repl.wait_for_replicas`).
    pub(crate) fn log(&self, ops: &[Op], txn_id: Option<u64>) -> Result<u64> {
        self.ensure_open()?;
        let framed = match txn_id {
            Some(id) => Some(id),
            None if ops.len() > 1 => Some(self.alloc_txn_id()),
            None => None,
        };
        let lsn = {
            let mut wal = self.wal();
            let logged = (|| {
                // Marca de relógio no máximo uma vez por segundo (PITR por instante).
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                if self.last_time_mark.load(Ordering::Relaxed) != now / 1000 {
                    wal.append(WalRecord::Time {
                        lsn: 0,
                        unix_ms: now,
                    })?;
                    self.last_time_mark.store(now / 1000, Ordering::Relaxed);
                }
                if let Some(txn_id) = framed {
                    wal.append(WalRecord::Begin { lsn: 0, txn_id })?;
                }
                for op in ops {
                    wal.append(op.record())?;
                }
                if let Some(txn_id) = framed {
                    wal.append(WalRecord::Commit { lsn: 0, txn_id })?;
                }
                if self.sync_wal {
                    wal.sync()?;
                }
                Ok(())
            })();
            if let Err(error) = logged {
                if let Some(txn_id) = framed {
                    // Garante que o frame parcial nunca engula registros futuros. Se nem o
                    // `Abort` couber, o WAL recusa novas escritas até a reabertura (que fecha
                    // o frame): um autocommit confirmado depois dele sumiria no recovery.
                    let closed = wal.append(WalRecord::Abort { lsn: 0, txn_id });
                    if closed.is_err() {
                        wal.poison();
                    }
                }
                return Err(error);
            }
            let lsn = wal.next_lsn().saturating_sub(1);
            // Ainda sob o lock do WAL: o feed recebe os lotes na ordem do log.
            self.repl.publish(lsn, ops);
            lsn
        };
        Ok(lsn)
    }

    /// Aplica um lote já registrado por [`Db::log`].
    ///
    /// Se a aplicação falhar depois do registro durável, o handle é marcado
    /// como fechado: o estado em memória não é mais confiável, e reabrir o
    /// banco refaz as operações a partir do WAL.
    pub(crate) fn apply_logged(&mut self, ops: &[Op], lsn: u64) -> Result<()> {
        self.meta.next_lsn = self.wal_mut().next_lsn();
        if lock_poisoned(&self.versions).recording() {
            self.record_before_images(ops, lsn)?;
        }
        for op in ops {
            if let Err(error) = self.apply(op, lsn) {
                self.open = false;
                return Err(Error::Other(format!(
                    "falha ao aplicar operação já registrada no WAL; reabra o banco para recuperar: {error}"
                )));
            }
        }
        self.applied_lsn = lsn;
        Ok(())
    }

    fn log_and_apply(&mut self, ops: &[Op], txn_id: Option<u64>) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        self.maybe_checkpoint()?;
        let lsn = self.log(ops, txn_id)?;
        // Espera antes de aplicar (só fica visível depois de confirmado). Sem a
        // confirmação o lote já está no WAL: aplica e devolve o erro depois.
        let replicated = self.repl.wait_for_replicas(lsn);
        self.apply_logged(ops, lsn)?;
        replicated
    }

    /// Checkpoint automático quando o WAL passa do limite (antes de escrever,
    /// para que um erro de I/O aqui nunca vire uma escrita "meio feita").
    pub(crate) fn maybe_checkpoint(&mut self) -> Result<()> {
        if self.needs_checkpoint() {
            self.checkpoint()?;
        }
        Ok(())
    }

    pub(crate) fn needs_checkpoint(&self) -> bool {
        self.auto_checkpoint > 0 && self.txn.is_none() && self.wal().size() >= self.auto_checkpoint
    }

    /// Guarda o valor anterior de cada chave escrita para os snapshots MVCC.
    fn record_before_images(&mut self, ops: &[Op], lsn: u64) -> Result<()> {
        let mut seen = HashSet::new();
        let mut images = Vec::new();
        for op in ops {
            if matches!(op, Op::Expire { .. }) || !seen.insert(op.key()) {
                continue;
            }
            images.push((op.key().to_vec(), self.stored_visible(op.key())?));
        }
        let mut versions = lock_poisoned(&self.versions);
        for (key, before) in images {
            versions.record(&key, lsn, before);
        }
        Ok(())
    }

    /// Valor gravado e não expirado (ignora transação aberta).
    pub(crate) fn stored_visible(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match BTree::get(&self.pool, &self.meta, key)? {
            Some(value) if !self.is_expired(key)? => Ok(Some(value)),
            _ => Ok(None),
        }
    }

    /// LSN do último lote aplicado (versão do banco para MVCC/replicação).
    pub fn last_lsn(&self) -> u64 {
        self.applied_lsn
    }

    /// Modo somente leitura (réplicas): a API pública recusa escritas.
    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Checkpoint automático quando o WAL passa de `bytes` (0 desliga).
    pub fn set_auto_checkpoint(&mut self, bytes: u64) {
        self.auto_checkpoint = bytes;
    }

    /// Mantém até `bytes` de WALs arquivados em `wal-archive/` para réplicas
    /// retomarem de onde pararam mesmo depois de checkpoints e reinícios
    /// (0 desliga: o checkpoint só trunca o WAL).
    pub fn set_wal_retention(&mut self, bytes: u64) {
        self.wal_retention = bytes;
    }

    pub fn wal_retention(&self) -> u64 {
        self.wal_retention
    }

    /// Escrita interna (SQL relacional, replicação): aceita o prefixo reservado
    /// e ignora o modo somente leitura. Atômica como [`Db::write_batch`].
    pub(crate) fn write_internal(&mut self, ops: Vec<Op>) -> Result<()> {
        self.write_ops(ops, true)
    }

    pub(crate) fn validate_op(&self, op: &Op, internal: bool) -> Result<()> {
        if internal {
            validate_key(op.key())?;
        } else {
            validate_user_key(op.key())?;
            reject_reserved(op.key())?;
        }
        if let Op::Put { value, .. } = op {
            validate_value(value)?;
        }
        Ok(())
    }

    /// Valida `ops` para a escrita pública (ou interna).
    pub(crate) fn validate_ops(&self, ops: &[Op], internal: bool) -> Result<()> {
        self.ensure_open()?;
        if self.read_only && !internal {
            return Err(Error::ReadOnly);
        }
        ops.iter().try_for_each(|op| self.validate_op(op, internal))
    }

    pub(crate) fn has_txn(&self) -> bool {
        self.txn.is_some()
    }

    /// Valida e executa `ops` atomicamente (ou acumula na transação aberta).
    fn write(&mut self, ops: Vec<Op>) -> Result<()> {
        self.write_ops(ops, false)
    }

    pub(crate) fn write_ops(&mut self, ops: Vec<Op>, internal: bool) -> Result<()> {
        self.validate_ops(&ops, internal)?;
        match self.txn.as_mut() {
            Some(txn) => {
                txn.push(ops);
                Ok(())
            }
            None => self.log_and_apply(&ops, None),
        }
    }

    // ------------------------------------------------------------------
    // Escrita
    // ------------------------------------------------------------------

    /// Upsert. Remove um TTL anterior da chave.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.write(vec![Op::Put {
            key: key.to_vec(),
            value: value.to_vec(),
        }])
    }

    /// Upsert que expira após `ttl`. Chave e expiração são gravadas no mesmo
    /// frame do WAL, então um crash nunca deixa o valor sem o TTL.
    ///
    /// ```
    /// # let dir = std::env::temp_dir().join(format!("minidb-doc-ttl-{}", std::process::id()));
    /// let mut db = mini_db::Db::open(&dir)?;
    /// db.put_with_ttl(b"session:1", b"token", std::time::Duration::from_secs(60))?;
    /// assert!(matches!(db.ttl(b"session:1")?, mini_db::KeyTtl::ExpiresIn(_)));
    /// # db.close()?; drop(db); std::fs::remove_dir_all(dir).unwrap();
    /// # Ok::<(), mini_db::Error>(())
    /// ```
    pub fn put_with_ttl(&mut self, key: &[u8], value: &[u8], ttl: Duration) -> Result<()> {
        self.write(vec![
            Op::Put {
                key: key.to_vec(),
                value: value.to_vec(),
            },
            Op::Expire {
                key: key.to_vec(),
                at: expiry_after(ttl),
            },
        ])
    }

    /// Remove a chave. Devolve `true` se ela existia (e não estava expirada).
    pub fn delete(&mut self, key: &[u8]) -> Result<bool> {
        self.ensure_open()?;
        validate_user_key(key)?;
        reject_reserved(key)?;
        let visible = self.get(key)?.is_some();
        let stored = self.txn.is_some() || BTree::get(&self.pool, &self.meta, key)?.is_some();
        if visible || stored {
            self.write(vec![Op::Delete { key: key.to_vec() }])?;
        }
        Ok(visible)
    }

    /// Define a expiração de uma chave existente. Devolve `false` se ausente.
    pub fn expire(&mut self, key: &[u8], ttl: Duration) -> Result<bool> {
        if self.get(key)?.is_none() {
            return Ok(false);
        }
        self.write(vec![Op::Expire {
            key: key.to_vec(),
            at: expiry_after(ttl),
        }])?;
        Ok(true)
    }

    /// Remove o TTL de uma chave. Devolve `true` se havia TTL a remover.
    pub fn persist(&mut self, key: &[u8]) -> Result<bool> {
        if !matches!(self.ttl(key)?, KeyTtl::ExpiresIn(_)) {
            return Ok(false);
        }
        self.write(vec![Op::Expire {
            key: key.to_vec(),
            at: 0,
        }])?;
        Ok(true)
    }

    /// Aplica várias escritas de forma atômica: todas ou nenhuma sobrevivem a
    /// um crash. Com transação aberta, as operações entram no write-set dela.
    ///
    /// ```
    /// use mini_db::{BatchOp, Db};
    /// # let dir = std::env::temp_dir().join(format!("minidb-doc-batch-{}", std::process::id()));
    /// let mut db = Db::open(&dir)?;
    /// db.write_batch(&[
    ///     BatchOp::Put { key: b"a".to_vec(), value: b"1".to_vec() },
    ///     BatchOp::Put { key: b"b".to_vec(), value: b"2".to_vec() },
    ///     BatchOp::Delete { key: b"a".to_vec() },
    /// ])?;
    /// assert_eq!(db.count(b"a", None)?, 1);
    /// # db.close()?; drop(db); std::fs::remove_dir_all(dir).unwrap();
    /// # Ok::<(), mini_db::Error>(())
    /// ```
    pub fn write_batch(&mut self, batch: &[BatchOp]) -> Result<()> {
        let ops = batch_to_ops(batch);
        if ops.len() == 1 && self.txn.is_none() {
            // Mesmo um lote unitário é registrado em frame para ser explícito.
            self.validate_ops(&ops, false)?;
            let id = self.alloc_txn_id();
            return self.log_and_apply(&ops, Some(id));
        }
        self.write(ops)
    }

    /// Remove fisicamente as chaves expiradas (registrado no WAL), em lotes de
    /// tamanho limitado. A leitura já as esconde; isto libera espaço.
    pub fn purge_expired(&mut self) -> Result<usize> {
        self.ensure_open()?;
        if self.txn.is_some() {
            return Err(Error::TxnOpen);
        }
        let mut purged = 0;
        loop {
            let ops = self.expired_chunk(PURGE_CHUNK)?;
            if ops.is_empty() {
                return Ok(purged);
            }
            purged += ops.len();
            let id = self.alloc_txn_id();
            self.log_and_apply(&ops, Some(id))?;
        }
    }

    /// Até `limit` exclusões de chaves já expiradas.
    pub(crate) fn expired_chunk(&self, limit: usize) -> Result<Vec<Op>> {
        let mut ops = Vec::new();
        if self.meta.ttl_root == 0 {
            return Ok(ops);
        }
        let now = now_ms();
        let mut leaf = BTree::first_leaf(&self.pool, &self.meta, TreeId::Ttl, &[0])?;
        let mut left = self.meta.next_page_id;
        while leaf != 0 && ops.len() < limit {
            left = left
                .checked_sub(1)
                .ok_or_else(|| Error::Other("ciclo na árvore de TTL".into()))?;
            let (rows, next) = BTree::leaf_rows(&self.pool, &self.meta, TreeId::Ttl, leaf, &[0])?;
            for (key, at) in rows {
                if decode_at(&at).is_some_and(|at| at <= now) {
                    ops.push(Op::Delete { key });
                    if ops.len() == limit {
                        break;
                    }
                }
            }
            leaf = next;
        }
        Ok(ops)
    }

    // ------------------------------------------------------------------
    // Leitura (todas com `&self`: várias threads podem ler ao mesmo tempo)
    // ------------------------------------------------------------------

    /// Lê o valor visível para este handle (write-set da transação incluso).
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        reject_reserved(key)?;
        validate_user_key(key)?;
        self.get_raw(key)
    }

    /// Como [`Db::get`], mas também enxerga o prefixo reservado.
    pub(crate) fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.ensure_open()?;
        validate_key(key)?;
        if let Some(txn) = &self.txn {
            if let Some(effect) = txn.effect(key, now_ms()) {
                return Ok(effect);
            }
        }
        if !self.bloom.may_contain(key) {
            return Ok(None);
        }
        self.stored_visible(key)
    }

    /// `true` se a chave existe e está visível.
    pub fn contains(&self, key: &[u8]) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// Situação de TTL da chave (ignora o write-set de transação aberta).
    pub fn ttl(&self, key: &[u8]) -> Result<KeyTtl> {
        if self.get(key)?.is_none() {
            return Ok(KeyTtl::Missing);
        }
        Ok(match self.expiry_of(key)? {
            None => KeyTtl::Persistent,
            Some(at) => KeyTtl::ExpiresIn(Duration::from_millis(at.saturating_sub(now_ms()))),
        })
    }

    pub(crate) fn expiry_of(&self, key: &[u8]) -> Result<Option<u64>> {
        if self.meta.ttl_root == 0 {
            return Ok(None);
        }
        Ok(BTree::get_in(&self.pool, &self.meta, TreeId::Ttl, key)?
            .as_deref()
            .and_then(decode_at))
    }

    fn is_expired(&self, key: &[u8]) -> Result<bool> {
        Ok(self.expiry_of(key)?.is_some_and(|at| at <= now_ms()))
    }

    /// Iterador ordenado sobre `[start, end)`. Sem transação aberta, carrega
    /// uma folha por vez: a memória é proporcional a uma página, não ao
    /// resultado. Com transação, materializa a visão mesclada.
    ///
    /// ```
    /// # let dir = std::env::temp_dir().join(format!("minidb-doc-iter-{}", std::process::id()));
    /// let mut db = mini_db::Db::open(&dir)?;
    /// for i in 0..5u8 {
    ///     db.put(&[b'k', b'0' + i], b"v")?;
    /// }
    /// let keys: Vec<Vec<u8>> = db
    ///     .iter(b"k1", Some(b"k4"))?
    ///     .map(|row| row.map(|(k, _)| k))
    ///     .collect::<Result<_, _>>()?;
    /// assert_eq!(keys, vec![b"k1".to_vec(), b"k2".to_vec(), b"k3".to_vec()]);
    /// # db.close()?; drop(db); std::fs::remove_dir_all(dir).unwrap();
    /// # Ok::<(), mini_db::Error>(())
    /// ```
    pub fn iter(&self, start: &[u8], end: Option<&[u8]>) -> Result<ScanIter<'_>> {
        // O espaço reservado (0xFF..) fica fora de qualquer faixa pública.
        const LIMIT: &[u8] = &[RESERVED_PREFIX];
        let end = Some(end.map_or(LIMIT, |e| e.min(LIMIT)));
        if start >= LIMIT {
            return self.iter_raw(LIMIT, Some(LIMIT));
        }
        self.iter_raw(start, end)
    }

    /// Iterador sem o corte do prefixo reservado (uso interno).
    pub(crate) fn iter_raw(&self, start: &[u8], end: Option<&[u8]>) -> Result<ScanIter<'_>> {
        self.ensure_open()?;
        validate_key(start)?;
        if let Some(end) = end {
            validate_key(end)?;
        }
        if self.txn.is_some() {
            let rows = self.merged_txn_view(start, end)?;
            return Ok(ScanIter::materialized(self, rows));
        }
        let first = BTree::first_leaf(&self.pool, &self.meta, TreeId::Primary, start)?;
        Ok(ScanIter {
            leaves_left: self.meta.next_page_id,
            db: self,
            buffered: VecDeque::new(),
            next_leaf: first,
            from: start.to_vec(),
            end: end.map(<[u8]>::to_vec),
            check_ttl: true,
            done: false,
        })
    }

    /// Iterador sobre todas as chaves que começam com `prefix`.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<ScanIter<'_>> {
        let end = prefix_successor(prefix);
        self.iter(prefix, end.as_deref())
    }

    /// Scan materializado de `[start, end)`.
    pub fn scan(&self, start: &[u8], end: Option<&[u8]>) -> Result<Vec<Row>> {
        self.iter(start, end)?.collect()
    }

    /// Conta as chaves visíveis em `[start, end)` sem materializá-las.
    pub fn count(&self, start: &[u8], end: Option<&[u8]>) -> Result<u64> {
        let mut n = 0u64;
        for row in self.iter(start, end)? {
            row?;
            n += 1;
        }
        Ok(n)
    }

    /// Paginação por chave (keyset). `after` é a última chave já recebida;
    /// `end` é exclusivo. Lê só o necessário para preencher `limit` linhas.
    pub fn scan_page(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        after: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<Row>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        // Chaves nunca são vazias: o byte zero é o menor limite possível.
        let start = if start.is_empty() { &b"\0"[..] } else { start };
        let lower = after.filter(|cursor| *cursor > start).unwrap_or(start);
        let mut out = Vec::with_capacity(limit.min(1024));
        for row in self.iter(lower, end)? {
            let row = row?;
            if after.is_some_and(|cursor| row.0.as_slice() <= cursor) {
                continue;
            }
            out.push(row);
            if out.len() == limit {
                break;
            }
        }
        Ok(out)
    }

    fn merged_txn_view(&self, start: &[u8], end: Option<&[u8]>) -> Result<Vec<Row>> {
        let mut visible: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let mut leaf = BTree::first_leaf(&self.pool, &self.meta, TreeId::Primary, start)?;
        let mut left = self.meta.next_page_id;
        'leaves: while leaf != 0 {
            left = left
                .checked_sub(1)
                .ok_or_else(|| Error::Other("ciclo no encadeamento de folhas".into()))?;
            let (rows, next) =
                BTree::leaf_rows(&self.pool, &self.meta, TreeId::Primary, leaf, start)?;
            for (key, value) in rows {
                if end.is_some_and(|e| key.as_slice() >= e) {
                    break 'leaves;
                }
                if !self.is_expired(&key)? {
                    visible.insert(key, value);
                }
            }
            leaf = next;
        }
        let now = now_ms();
        if let Some(txn) = &self.txn {
            let keys: Vec<&Vec<u8>> = match end {
                Some(stop) => txn
                    .latest
                    .range(start.to_vec()..stop.to_vec())
                    .map(|(k, _)| k)
                    .collect(),
                None => txn.latest.range(start.to_vec()..).map(|(k, _)| k).collect(),
            };
            for key in keys {
                match txn.effect(key, now) {
                    Some(Some(value)) => {
                        visible.insert(key.clone(), value);
                    }
                    Some(None) => {
                        visible.remove(key);
                    }
                    None => {}
                }
            }
        }
        Ok(visible.into_iter().collect())
    }

    /// Chaves cujo valor é exatamente `value` (índice quando existe).
    pub fn get_by_value(&self, value: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.ensure_open()?;
        let keys = if self.meta.index_root == 0 || self.txn.is_some() {
            self.iter(&[0], None)?
                .filter_map(|row| match row {
                    Ok((k, v)) if v.as_slice() == value => Some(Ok(k)),
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            index::find_keys_by_value(&self.pool, &self.meta, value)?
        };
        let mut live = Vec::with_capacity(keys.len());
        for key in keys {
            if !is_reserved(&key) && (self.txn.is_some() || !self.is_expired(&key)?) {
                live.push(key);
            }
        }
        Ok(live)
    }

    // ------------------------------------------------------------------
    // Transações
    // ------------------------------------------------------------------

    /// Inicia um write-set local ao handle. Para isolamento entre threads,
    /// use [`crate::mvcc::SharedDb::begin`].
    pub fn begin(&mut self) -> Result<u64> {
        self.ensure_open()?;
        if self.txn.is_some() {
            return Err(Error::TxnOpen);
        }
        let id = self.alloc_txn_id();
        self.txn = Some(TxnState {
            id,
            ops: Vec::new(),
            changes: Vec::new(),
            notifications: Vec::new(),
            latest: BTreeMap::new(),
            savepoints: Vec::new(),
        });
        Ok(id)
    }

    /// Escrita relacional com os eventos do comando: publicados no commit
    /// (transação aberta) ou logo após aplicar.
    pub(crate) fn write_internal_events(
        &mut self,
        ops: Vec<Op>,
        changes: Vec<crate::events::Change>,
        notifications: Vec<(String, String)>,
    ) -> Result<()> {
        self.write_internal(ops)?;
        match self.txn.as_mut() {
            Some(txn) => {
                txn.changes.extend(changes);
                txn.notifications.extend(notifications);
            }
            None => {
                if !changes.is_empty() || !notifications.is_empty() {
                    self.events
                        .publish(self.applied_lsn, changes, notifications);
                }
            }
        }
        Ok(())
    }

    /// Comando preparado do cache (analisa uma vez por texto).
    pub(crate) fn cached_plan(&self, sql: &str) -> Result<Arc<crate::rel::Prepared>> {
        let mut plans = self.plans.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = plans.get(sql) {
            return Ok(Arc::clone(p));
        }
        let p = Arc::new(crate::rel::prepare(sql)?);
        if plans.len() >= 512 {
            plans.clear();
        }
        plans.insert(sql.to_string(), Arc::clone(&p));
        Ok(p)
    }

    /// Marca um ponto na transação aberta para `rollback_to`.
    pub fn savepoint(&mut self, name: &str) -> Result<()> {
        let txn = self.txn.as_mut().ok_or(Error::TxnNotOpen)?;
        let n = txn.ops.len();
        txn.savepoints.retain(|(s, _)| s != name);
        txn.savepoints.push((name.to_string(), n));
        Ok(())
    }

    /// Desfaz o que veio depois do savepoint (que continua valendo).
    pub fn rollback_to(&mut self, name: &str) -> Result<()> {
        let txn = self.txn.as_mut().ok_or(Error::TxnNotOpen)?;
        let pos = txn
            .savepoints
            .iter()
            .rposition(|(s, _)| s == name)
            .ok_or_else(|| Error::Sql(format!("savepoint {name} não existe")))?;
        let n = txn.savepoints[pos].1;
        txn.savepoints.truncate(pos + 1);
        txn.truncate(n);
        Ok(())
    }

    /// Esquece o savepoint (as operações ficam na transação).
    pub fn release_savepoint(&mut self, name: &str) -> Result<()> {
        let txn = self.txn.as_mut().ok_or(Error::TxnNotOpen)?;
        let pos = txn
            .savepoints
            .iter()
            .rposition(|(s, _)| s == name)
            .ok_or_else(|| Error::Sql(format!("savepoint {name} não existe")))?;
        txn.savepoints.truncate(pos);
        Ok(())
    }

    /// Grava o write-set em um único frame BEGIN/COMMIT e aplica.
    pub fn commit(&mut self) -> Result<u64> {
        self.ensure_open()?;
        let txn = self.txn.take().ok_or(Error::TxnNotOpen)?;
        self.log_and_apply(&txn.ops, Some(txn.id))?;
        if !txn.changes.is_empty() || !txn.notifications.is_empty() {
            self.events
                .publish(self.applied_lsn, txn.changes, txn.notifications);
        }
        Ok(txn.id)
    }

    /// Descarta o write-set. Nada foi escrito no WAL, então não há o que desfazer.
    pub fn rollback(&mut self) -> Result<()> {
        self.ensure_open()?;
        self.txn.take().ok_or(Error::TxnNotOpen)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Manutenção
    // ------------------------------------------------------------------

    /// Publica as páginas alteradas em `data.mdb` (via journal) e recomeça o
    /// WAL — arquivando-o quando há retenção para réplicas.
    pub fn checkpoint(&mut self) -> Result<()> {
        self.ensure_open()?;
        // Frame interrompido sem `Abort` no WAL (ver `Wal::poison`): avançar o checkpoint
        // o tiraria do alcance do recovery e arquivá-lo levaria o `Begin` solto para o
        // histórico das réplicas e do PITR. Só a reabertura fecha o frame.
        self.wal_mut().check_usable()?;
        self.sync_wal()?;
        let next = self.wal_mut().next_lsn();
        self.meta.checkpoint_lsn = next.saturating_sub(1);
        self.meta.next_lsn = next;
        self.persist_meta()?;
        self.pool.flush_all()?;
        if self.wal_retention > 0 {
            let archive = Self::archive_dir(&self.dir);
            self.wal_mut().archive(&archive, next)?;
            prune_archive(&archive, self.wal_retention)?;
            Ok(())
        } else {
            self.wal_mut().truncate_after_checkpoint(next)
        }
    }

    /// Remove chaves expiradas e reconstrói as árvores **em streaming** em um
    /// arquivo novo (`vacuum.mdb`), que substitui `data.mdb` por rename. A
    /// memória usada é a de uma folha mais o maior valor, qualquer que seja o
    /// tamanho do banco; um crash antes do rename mantém o arquivo antigo.
    /// Devolve as páginas em uso.
    pub fn vacuum(&mut self) -> Result<u32> {
        self.ensure_open()?;
        if self.txn.is_some() {
            return Err(Error::TxnOpen);
        }
        self.purge_expired()?;
        self.checkpoint()?;
        let vpath = self.dir.join(VACUUM_FILE);
        let capacity = self.pool.capacity();
        let had_index = self.has_value_index();
        let lsn = self.applied_lsn;
        let cipher = self.pool.cipher();
        let mut vpool = BufferPool::open_with(&vpath, capacity, cipher.clone())?;
        let mut vmeta = MetaInfo {
            checkpoint_lsn: self.meta.checkpoint_lsn,
            next_lsn: self.meta.next_lsn,
            next_txn_id: self.next_txn_id.load(Ordering::Relaxed),
            ..MetaInfo::fresh_file()
        };
        vpool.put_new_page(Page::zeroed(vmeta.root_page, PageKind::Leaf))?;
        if had_index {
            BTree::ensure_tree(&mut vpool, &mut vmeta, TreeId::Secondary)?;
        }
        for tree in [TreeId::Primary, TreeId::Ttl] {
            let mut leaf = BTree::first_leaf(&self.pool, &self.meta, tree, &[0])?;
            let mut left = self.meta.next_page_id;
            while leaf != 0 {
                left = left
                    .checked_sub(1)
                    .ok_or_else(|| Error::Other("ciclo no encadeamento de folhas".into()))?;
                let (rows, next) = BTree::leaf_rows(&self.pool, &self.meta, tree, leaf, &[0])?;
                for (key, value) in rows {
                    BTree::insert_in(&mut vpool, &mut vmeta, tree, &key, &value, lsn)?;
                    if tree == TreeId::Primary && had_index && !is_reserved(&key) {
                        index::upsert_value_index(&mut vpool, &mut vmeta, &key, None, &value, lsn)?;
                    }
                }
                leaf = next;
            }
        }
        let mut mp = Page::zeroed(MetaInfo::META_PAGE_ID, PageKind::Meta);
        vmeta.write_to_page(&mut mp);
        mp.set_lsn(lsn);
        mp.write_checksum();
        vpool.put_new_page(mp)?;
        vpool.flush_all()?;
        drop(vpool);
        // Troca: fecha o arquivo antigo (no Windows o destino do rename não
        // pode estar aberto), publica o novo e reabre.
        let data = Self::data_path(&self.dir);
        drop(std::mem::replace(
            &mut self.pool,
            BufferPool::open_with(&vpath, capacity, cipher.clone())?,
        ));
        crate::buffer::replace_data_file(&vpath, &data)?;
        self.pool = BufferPool::open_with(&data, capacity, cipher)?;
        let _ = fs::remove_file(self.dir.join(format!("{VACUUM_FILE}.spill")));
        self.meta = vmeta;
        Ok(self.meta.next_page_id)
    }

    /// Manutenção de rotina (servidores chamam periodicamente): remove chaves
    /// expiradas, faz `VACUUM` quando folhas vazias/páginas livres passam de
    /// `vacuum_ratio` (0.0–1.0) do arquivo e checkpoint quando o WAL cresceu.
    pub fn maintain(&mut self, vacuum_ratio: f64) -> Result<MaintenanceReport> {
        let mut report = MaintenanceReport {
            purged: self.purge_expired()?,
            ..MaintenanceReport::default()
        };
        let stats = self.page_stats()?;
        let wasted = f64::from(stats.empty_leaves + stats.free_pages);
        if stats.total_pages > 64 && wasted / f64::from(stats.total_pages) > vacuum_ratio {
            self.vacuum()?;
            report.vacuumed = true;
        } else if self.wal().size() > 8 {
            self.checkpoint()?;
            report.checkpointed = true;
        }
        Ok(report)
    }

    /// Cria o índice por valor e faz backfill com as linhas vivas.
    pub fn create_value_index(&mut self) -> Result<usize> {
        self.ensure_open()?;
        if self.txn.is_some() {
            return Err(Error::TxnOpen);
        }
        if self.meta.index_root != 0 {
            let root = self.meta.index_root;
            btree::free_tree(&mut self.pool, &mut self.meta, root)?;
            self.meta.index_root = 0;
        }
        let n = self.backfill_value_index()?;
        self.checkpoint()?;
        Ok(n)
    }

    /// Descarta transação aberta, faz checkpoint e fecha o handle.
    pub fn close(&mut self) -> Result<()> {
        if !self.open {
            return Ok(());
        }
        self.txn = None;
        self.checkpoint()?;
        self.open = false;
        // Libera o diretório: outro handle pode abrir mesmo que este objeto
        // ainda exista (ex.: clones de um `SharedDb` em outras threads).
        self.lock = None;
        Ok(())
    }

    /// Entrega o lock do diretório a quem chamou, que continua dono dele depois do
    /// `close`: [`crate::encryption::convert`] reescreve `data.mdb` com o banco fechado
    /// e nenhum outro handle pode abri-lo no meio.
    pub(crate) fn take_lock(&mut self) -> Option<File> {
        self.lock.take()
    }

    /// Abandona o handle sem checkpoint (simula crash em testes).
    pub fn drop_without_checkpoint(mut self) {
        self.open = false;
    }

    // ------------------------------------------------------------------
    // Introspecção
    // ------------------------------------------------------------------

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Cifra da criptografia em repouso (`None` = banco em claro).
    pub fn cipher(&self) -> Option<Arc<crate::encryption::Cipher>> {
        self.pool.cipher()
    }

    pub fn is_encrypted(&self) -> bool {
        self.pool.cipher().is_some()
    }

    pub fn meta(&self) -> &MetaInfo {
        &self.meta
    }

    /// `false` depois de `close` ou de uma falha que exige reabertura.
    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn stats(&self) -> DbStats {
        let (snapshots, versions) = lock_poisoned(&self.versions).stats();
        let (next_lsn, wal_bytes) = {
            let wal = self.wal();
            (wal.next_lsn(), wal.size())
        };
        DbStats {
            root_page: self.meta.root_page,
            index_root: self.meta.index_root,
            ttl_root: self.meta.ttl_root,
            next_page_id: self.meta.next_page_id,
            checkpoint_lsn: self.meta.checkpoint_lsn,
            next_lsn,
            applied_lsn: self.applied_lsn,
            wal_bytes,
            pool_capacity: self.pool.capacity(),
            cached_pages: self.pool.cached_pages(),
            next_txn_id: self.next_txn_id.load(Ordering::Relaxed),
            value_index: self.has_value_index(),
            txn_open: self.txn.is_some(),
            read_only: self.read_only,
            snapshots,
            versions,
            compressed: self.meta.flags & META_FLAG_COMPRESSED_VALUES != 0,
        }
    }

    /// Ocupação das páginas: folhas, internos, livres, vazias e preenchimento.
    pub fn page_stats(&self) -> Result<PageStats> {
        self.ensure_open()?;
        inspect::page_stats(&self.pool, &self.meta)
    }

    pub fn verify(&self) -> Result<verify::VerifyReport> {
        self.ensure_open()?;
        verify::verify_pool(&self.pool, &self.meta)
    }

    pub fn inspect_page(&self, page_id: u32) -> Result<String> {
        self.ensure_open()?;
        inspect::dump_page(&self.pool, page_id)
    }

    pub fn inspect_hex(&self, page_id: u32, n: usize) -> Result<String> {
        self.ensure_open()?;
        inspect::hexdump_page(&self.pool, page_id, n)
    }

    pub fn inspect_meta_text(&self) -> String {
        inspect::dump_meta(&self.meta)
    }

    pub fn bloom_inserts(&self) -> u64 {
        self.bloom.inserts()
    }

    fn rebuild_bloom(&mut self) -> Result<()> {
        self.bloom = Bloom::new();
        let mut leaf = BTree::first_leaf(&self.pool, &self.meta, TreeId::Primary, &[0])?;
        let mut left = self.meta.next_page_id;
        while leaf != 0 {
            left = left
                .checked_sub(1)
                .ok_or_else(|| Error::Other("ciclo no encadeamento de folhas".into()))?;
            let page = self.pool.get_page(leaf)?;
            for i in 0..page.n_slots() as usize {
                self.bloom.insert(page.leaf_entry(i).0);
            }
            leaf = page.right_sibling();
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<()> {
        if self.open {
            Ok(())
        } else {
            Err(Error::Closed)
        }
    }

    // ------------------------------------------------------------------
    // SQL
    // ------------------------------------------------------------------

    /// Executa SQL: o dialeto chave-valor (`FROM kv`) ou o relacional
    /// ([`crate::rel`]: `CREATE TABLE`, `JOIN`, subconsultas, `UNION`...).
    pub fn execute_sql(&mut self, sql: &str) -> Result<ExecResult> {
        self.execute_sql_params(sql, &[])
    }

    /// SQL com parâmetros posicionais (`?`, `?1`, `$1`) — valores nunca são
    /// interpolados no texto, então não há injeção.
    ///
    /// ```
    /// use mini_db::{rel::Value, Db, ExecResult};
    /// # let dir = std::env::temp_dir().join(format!("minidb-doc-params-{}", std::process::id()));
    /// let mut db = Db::open(&dir)?;
    /// db.execute_sql("CREATE TABLE t2 (id INT PRIMARY KEY, name TEXT)")?;
    /// db.execute_sql_params("INSERT INTO t2 VALUES (?, ?)", &[Value::Int(1), Value::Text("o'brien".into())])?;
    /// let ExecResult::Table { rows, .. } =
    ///     db.execute_sql_params("SELECT name FROM t2 WHERE id = $1", &[Value::Int(1)])? else { unreachable!() };
    /// assert_eq!(rows[0][0], Value::Text("o'brien".into()));
    /// # db.close()?; drop(db); std::fs::remove_dir_all(dir).unwrap();
    /// # Ok::<(), mini_db::Error>(())
    /// ```
    pub fn execute_sql_params(
        &mut self,
        sql: &str,
        params: &[crate::rel::Value],
    ) -> Result<ExecResult> {
        let statements = crate::rel::split_statements(sql).unwrap_or_else(|_| vec![sql]);
        if statements.len() > 1 {
            if !params.is_empty() {
                return Err(Error::Sql(
                    "parâmetros só valem para um comando por vez; scripts não aceitam".into(),
                ));
            }
            return self.execute_script(&statements);
        }
        let sql = statements.first().copied().unwrap_or(sql);
        if is_transaction_control(sql) {
            let prepared = crate::rel::prepare(sql)?;
            return self.transaction_control(prepared.stmt());
        }
        match parse_sql(sql) {
            Ok(stmt) if params.is_empty() => self.execute_stmt(stmt),
            Ok(_) => Err(Error::Sql(
                "o dialeto chave-valor (FROM kv) não aceita parâmetros".into(),
            )),
            Err(legacy) => {
                let prepared = self.cached_plan(sql).map_err(|e| kv_error(e, &legacy))?;
                self.execute_prepared(&prepared, params)
                    .map_err(|e| kv_error(e, &legacy))
            }
        }
    }

    /// Barramento de eventos: mudanças confirmadas e notificações.
    pub fn events(&self) -> &Arc<crate::events::EventBus> {
        &self.events
    }

    /// `BEGIN`/`COMMIT`/`ROLLBACK [TO]`/`SAVEPOINT`/`RELEASE` sobre a
    /// transação local do handle.
    fn transaction_control(&mut self, stmt: &crate::rel::parser::Stmt) -> Result<ExecResult> {
        use crate::rel::parser::Stmt;
        Ok(ExecResult::Ok(match stmt {
            Stmt::Begin { .. } => format!("BEGIN txn={}", self.begin()?),
            Stmt::Commit => format!("COMMIT txn={}", self.commit()?),
            Stmt::Rollback { to: None } => {
                self.rollback()?;
                "ROLLBACK".into()
            }
            Stmt::Rollback { to: Some(name) } => {
                self.rollback_to(name)?;
                format!("ROLLBACK TO {name}")
            }
            Stmt::Savepoint(name) => {
                self.savepoint(name)?;
                format!("SAVEPOINT {name}")
            }
            Stmt::Release(name) => {
                self.release_savepoint(name)?;
                format!("RELEASE {name}")
            }
            _ => unreachable!("só controle de transação"),
        }))
    }

    /// Vários comandos separados por `;`. Sem `BEGIN` explícito o script
    /// inteiro roda numa transação e qualquer erro desfaz tudo; com `BEGIN`
    /// próprio, a transação pode ficar aberta para os comandos seguintes.
    pub fn execute_script(&mut self, statements: &[&str]) -> Result<ExecResult> {
        let had_txn = self.txn.is_some();
        let implicit = !had_txn && !statements.iter().any(|s| is_transaction_control(s));
        if implicit {
            self.begin()?;
        }
        let mut results = Vec::with_capacity(statements.len());
        for s in statements {
            match self.execute_sql_params(s, &[]) {
                Ok(r) => results.push(r),
                Err(e) => {
                    if !had_txn && self.txn.is_some() {
                        self.rollback()?;
                    }
                    return Err(e);
                }
            }
        }
        if implicit {
            self.commit()?;
        }
        Ok(ExecResult::Batch(results))
    }

    /// Analisa uma vez para executar várias vezes com parâmetros diferentes.
    pub fn prepare(&self, sql: &str) -> Result<crate::rel::Prepared> {
        crate::rel::prepare(sql)
    }

    pub fn execute_prepared(
        &mut self,
        prepared: &crate::rel::Prepared,
        params: &[crate::rel::Value],
    ) -> Result<ExecResult> {
        crate::rel::execute_prepared(self, prepared, params)
    }

    /// Executa só leitura (`SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN`) com `&self`:
    /// várias threads consultam ao mesmo tempo. Escritas devolvem erro.
    pub fn query(&self, sql: &str) -> Result<ExecResult> {
        self.query_params(sql, &[])
    }

    pub fn query_params(&self, sql: &str, params: &[crate::rel::Value]) -> Result<ExecResult> {
        match parse_sql(sql) {
            Ok(stmt @ (Statement::Select { .. } | Statement::Explain(_))) if params.is_empty() => {
                self.execute_read_stmt(stmt)
            }
            Ok(_) => Err(Error::Sql(
                "query aceita só leitura; use execute_sql para escritas".into(),
            )),
            Err(legacy) => {
                let prepared = self.cached_plan(sql).map_err(|e| kv_error(e, &legacy))?;
                crate::rel::query_prepared(self, &prepared, params)
                    .map_err(|e| kv_error(e, &legacy))
            }
        }
    }

    pub fn execute_stmt(&mut self, stmt: Statement) -> Result<ExecResult> {
        Ok(match stmt {
            Statement::Select { .. } | Statement::Explain(_) => self.execute_read_stmt(stmt)?,
            Statement::Begin => ExecResult::Ok(format!("BEGIN txn={}", self.begin()?)),
            Statement::Commit => ExecResult::Ok(format!("COMMIT txn={}", self.commit()?)),
            Statement::Rollback => {
                self.rollback()?;
                ExecResult::Ok("ROLLBACK".into())
            }
            Statement::Checkpoint => {
                self.checkpoint()?;
                ExecResult::Ok("CHECKPOINT".into())
            }
            Statement::Vacuum => ExecResult::Ok(format!("VACUUM pages={}", self.vacuum()?)),
            Statement::CreateValueIndex => {
                ExecResult::Ok(format!("INDEX value keys={}", self.create_value_index()?))
            }
            Statement::Insert { key, value, ttl } => {
                match ttl {
                    Some(ttl) => self.put_with_ttl(&key, &value, ttl)?,
                    None => self.put(&key, &value)?,
                }
                ExecResult::Ok("INSERT 1".into())
            }
            Statement::Update { key, value } => {
                if self.get(&key)?.is_none() {
                    return Ok(ExecResult::Ok("UPDATE 0".into()));
                }
                self.put(&key, &value)?;
                ExecResult::Ok("UPDATE 1".into())
            }
            Statement::Delete { key } => {
                let n = u8::from(self.delete(&key)?);
                ExecResult::Ok(format!("DELETE {n}"))
            }
        })
    }

    /// `SELECT`/`EXPLAIN` do dialeto chave-valor.
    fn execute_read_stmt(&self, stmt: Statement) -> Result<ExecResult> {
        Ok(match stmt {
            Statement::Explain(inner) => ExecResult::Ok(explain(&inner)),
            Statement::Select {
                pred,
                order_desc,
                limit,
                count,
            } => {
                if count {
                    let n = match pred {
                        None => self.count(&[0], None)?,
                        Some(Pred::KeyPrefix { prefix }) => {
                            let end = prefix_successor(&prefix);
                            self.count(&prefix, end.as_deref())?
                        }
                        other => self.plan_select(other, None)?.len() as u64,
                    };
                    ExecResult::Count(n)
                } else {
                    let hint = if order_desc { None } else { limit };
                    let mut rows = self.plan_select(pred, hint)?;
                    if order_desc {
                        rows.reverse();
                    }
                    if let Some(n) = limit {
                        rows.truncate(n);
                    }
                    ExecResult::Rows(rows)
                }
            }
            _ => return Err(Error::Sql("comando de escrita".into())),
        })
    }

    /// Executa o predicado; `limit` (quando a ordem é ascendente) interrompe a
    /// leitura cedo, sem percorrer o restante da árvore.
    fn plan_select(&self, pred: Option<Pred>, limit: Option<usize>) -> Result<Vec<Row>> {
        let take = limit.unwrap_or(usize::MAX);
        let collect = |iter: ScanIter<'_>| -> Result<Vec<Row>> { iter.take(take).collect() };
        match pred {
            None => collect(self.iter(&[0], None)?),
            Some(Pred::KeyPrefix { prefix }) => collect(self.scan_prefix(&prefix)?),
            Some(Pred::KeyCmp { op, value }) => match op {
                Cmp::Eq => Ok(self
                    .get(&value)?
                    .map(|v| vec![(value, v)])
                    .unwrap_or_default()),
                Cmp::Ge => collect(self.iter(&value, None)?),
                Cmp::Gt => self
                    .iter(&value, None)?
                    .filter(|row| !matches!(row, Ok((k, _)) if *k == value))
                    .take(take)
                    .collect(),
                Cmp::Lt => collect(self.iter(&[0], Some(&value))?),
                Cmp::Le if value.len() < MAX_KEY_LEN => {
                    // `k <= v` ⇔ `k < v ++ [0x00]` na ordem lexicográfica.
                    let mut end = value;
                    end.push(0);
                    collect(self.iter(&[0], Some(&end))?)
                }
                Cmp::Le => self
                    .iter(&[0], None)?
                    .filter(|row| !matches!(row, Ok((k, _)) if *k > value))
                    .take(take)
                    .collect(),
            },
            Some(Pred::ValueEq { value }) => {
                let mut rows = Vec::new();
                for key in self.get_by_value(&value)? {
                    if let Some(v) = self.get(&key)? {
                        rows.push((key, v));
                        if rows.len() == take {
                            break;
                        }
                    }
                }
                Ok(rows)
            }
        }
    }
}

/// Um erro de "tabela desconhecida" para `kv`/`t` vem do dialeto chave-valor:
/// devolve o erro original dele, que explica o que está errado.
/// O comando começa com uma palavra de controle de transação?
pub(crate) fn is_transaction_control(sql: &str) -> bool {
    let word: String = sql
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        word.as_str(),
        "begin" | "start" | "commit" | "end" | "rollback" | "savepoint" | "release"
    )
}

fn kv_error(error: Error, legacy: &Error) -> Error {
    match error {
        Error::UnknownTable(t) if t == "kv" || t == "t" => Error::Sql(legacy.to_string()),
        other => other,
    }
}

/// Apaga os WALs arquivados mais antigos até o total caber em `limit` bytes.
fn prune_archive(dir: &Path, limit: u64) -> Result<()> {
    // Sem nada arquivado ainda (WAL vazio no primeiro checkpoint com retenção), o
    // diretório nem existe.
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut files: Vec<(PathBuf, u64)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "wal"))
        .filter_map(|e| Some((e.path(), e.metadata().ok()?.len())))
        .collect();
    files.sort();
    let mut total: u64 = files.iter().map(|(_, n)| n).sum();
    for (path, len) in files {
        if total <= limit {
            break;
        }
        fs::remove_file(&path)?;
        total -= len;
    }
    Ok(())
}

impl Drop for Db {
    fn drop(&mut self) {
        if self.open {
            let _ = self.close();
        }
    }
}

/// Iterador de [`Db::iter`]: produz `Result<(chave, valor)>` em ordem.
pub struct ScanIter<'a> {
    db: &'a Db,
    buffered: VecDeque<Row>,
    next_leaf: u32,
    from: Vec<u8>,
    end: Option<Vec<u8>>,
    check_ttl: bool,
    leaves_left: u32,
    done: bool,
}

impl<'a> ScanIter<'a> {
    fn materialized(db: &'a Db, rows: Vec<Row>) -> Self {
        Self {
            db,
            buffered: rows.into(),
            next_leaf: 0,
            from: Vec::new(),
            end: None,
            check_ttl: false,
            leaves_left: 0,
            done: false,
        }
    }

    fn fail(&mut self, error: Error) -> Option<Result<Row>> {
        self.done = true;
        self.buffered.clear();
        Some(Err(error))
    }
}

impl Iterator for ScanIter<'_> {
    type Item = Result<Row>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            if let Some((key, value)) = self.buffered.pop_front() {
                if self.end.as_deref().is_some_and(|end| key.as_slice() >= end) {
                    self.done = true;
                    return None;
                }
                if self.check_ttl {
                    match self.db.is_expired(&key) {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(error) => return self.fail(error),
                    }
                }
                return Some(Ok((key, value)));
            }
            if self.next_leaf == 0 {
                self.done = true;
                return None;
            }
            if self.leaves_left == 0 {
                return self.fail(Error::Other("ciclo no encadeamento de folhas".into()));
            }
            self.leaves_left -= 1;
            match BTree::leaf_rows(
                &self.db.pool,
                &self.db.meta,
                TreeId::Primary,
                self.next_leaf,
                &self.from,
            ) {
                Ok((rows, sibling)) => {
                    self.buffered.extend(rows);
                    self.next_leaf = sibling;
                }
                Err(error) => return self.fail(error),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DbStats {
    pub root_page: u32,
    pub index_root: u32,
    pub ttl_root: u32,
    pub next_page_id: u32,
    pub checkpoint_lsn: u64,
    pub next_lsn: u64,
    /// Último LSN aplicado (visível para leitores).
    pub applied_lsn: u64,
    /// Tamanho atual do WAL em bytes.
    pub wal_bytes: u64,
    pub pool_capacity: usize,
    pub cached_pages: usize,
    pub next_txn_id: u64,
    pub value_index: bool,
    pub txn_open: bool,
    pub read_only: bool,
    /// Snapshots MVCC ativos e imagens anteriores retidas.
    pub snapshots: usize,
    pub versions: usize,
    pub compressed: bool,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Instante absoluto de expiração; nunca 0 (0 significa "sem TTL").
fn expiry_after(ttl: Duration) -> u64 {
    now_ms()
        .saturating_add(ttl.as_millis().min(u64::MAX as u128) as u64)
        .max(1)
}

fn decode_at(raw: &[u8]) -> Option<u64> {
    raw.try_into().ok().map(u64::from_be_bytes)
}

/// Menor chave maior que todas as chaves com o prefixo dado, ou `None` se o
/// prefixo é só `0xff` (não há limite superior).
pub fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

/// Abre o DB, aplica puts, **não** faz checkpoint e abandona as páginas dirty.
pub fn simulate_crash_after_wal(dir: impl AsRef<Path>, ops: &[(&[u8], &[u8])]) -> Result<()> {
    let mut db = Db::open(dir)?;
    for (k, v) in ops {
        db.put(k, v)?;
    }
    db.drop_without_checkpoint();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::prefix_successor;

    #[test]
    fn prefix_successor_handles_carry_and_all_ff() {
        assert_eq!(prefix_successor(b"ab"), Some(b"ac".to_vec()));
        assert_eq!(prefix_successor(&[0x61, 0xff]), Some(vec![0x62]));
        assert_eq!(prefix_successor(&[0xff, 0xff]), None);
    }
}
