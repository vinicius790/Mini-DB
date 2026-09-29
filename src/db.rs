//! Banco: open/close, escrita com WAL, transações, TTL, iteradores, SQL,
//! checkpoint, vacuum e recover.
//!
//! Toda escrita segue um único caminho: validação → registro no WAL (com
//! `fsync` por padrão) → aplicação na árvore. O mesmo `apply` é usado no
//! recovery, então o estado reconstruído é idêntico ao estado em memória.
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::bloom::Bloom;
use crate::btree::{validate_key, validate_value, BTree, TreeId};
use crate::buffer::BufferPool;
use crate::error::{Error, Result};
use crate::index;
use crate::inspect::{self, PageStats};
use crate::page::{MetaInfo, Page, PageKind, MAX_KEY_LEN, META_FLAG_VALUE_INDEX};
use crate::sql::{explain, parse_sql, Cmp, Pred, Statement};
use crate::verify;
use crate::wal::{Wal, WalRecord};

const DEFAULT_POOL_FRAMES: usize = 64;

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

    fn from_record(rec: &WalRecord) -> Option<Self> {
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

pub struct Db {
    dir: PathBuf,
    pool: BufferPool,
    wal: Wal,
    meta: MetaInfo,
    open: bool,
    txn: Option<TxnState>,
    bloom: Bloom,
    sync_wal: bool,
    read_only: bool,
    /// Imagens anteriores para snapshots MVCC ativos ([`crate::mvcc`]).
    pub(crate) versions: crate::mvcc::VersionStore,
    /// Fluxo de mudanças confirmadas para réplicas ([`crate::replication`]).
    pub(crate) feed: Option<crate::replication::ChangeFeed>,
    // Mantém o lock até o handle ser destruído.
    _lock: File,
}

struct TxnState {
    id: u64,
    ops: Vec<Op>,
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
}

impl Db {
    pub fn data_path(dir: impl AsRef<Path>) -> PathBuf {
        dir.as_ref().join("data.mdb")
    }

    pub fn wal_path(dir: impl AsRef<Path>) -> PathBuf {
        dir.as_ref().join("wal.log")
    }

    /// Abre (ou cria) o banco com 64 frames de pool e `fsync` por operação.
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
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("LOCK"))?;
        lock.try_lock()
            .map_err(|e| Error::Other(format!("database lock {}: {e}", dir.display())))?;
        let wal_path = Self::wal_path(&dir);
        let mut pool = BufferPool::open(Self::data_path(&dir), pool_capacity)?;
        let mut meta = Self::load_or_init_meta(&mut pool)?;
        let (wal_next, records) = Wal::read_all(&wal_path)?;
        meta.next_lsn = wal_next
            .max(meta.next_lsn)
            .max(meta.checkpoint_lsn.saturating_add(1))
            .max(1);
        let wal = Wal::open(&wal_path, meta.next_lsn)?;
        let mut db = Self {
            dir,
            pool,
            wal,
            meta,
            open: false,
            txn: None,
            bloom: Bloom::new(),
            sync_wal,
            read_only: false,
            versions: Default::default(),
            feed: None,
            _lock: lock,
        };
        db.recover(&records)?;
        BTree::ensure_root(&mut db.pool, &mut db.meta)?;
        db.meta.next_lsn = db.wal.next_lsn();
        db.rebuild_bloom()?;
        db.persist_meta()?;
        db.open = true;
        Ok(db)
    }

    fn load_or_init_meta(pool: &mut BufferPool) -> Result<MetaInfo> {
        let existing = fs::metadata(pool.path())?.len() != 0;
        let page = pool.get_page(MetaInfo::META_PAGE_ID)?;
        let valid = page.magic() == crate::page::MAGIC && page.kind() == PageKind::Meta;
        let meta = if valid {
            MetaInfo::from_page(page)
        } else {
            MetaInfo::fresh_file()
        };
        pool.unpin(MetaInfo::META_PAGE_ID);
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
        let mut mp = Page::zeroed(MetaInfo::META_PAGE_ID, PageKind::Meta);
        self.meta.write_to_page(&mut mp);
        mp.set_lsn(self.wal.next_lsn().saturating_sub(1));
        mp.write_checksum();
        self.pool.put_new_page(mp)
    }

    fn sync_wal(&mut self) -> Result<()> {
        if self.sync_wal {
            self.wal.sync()?;
        }
        Ok(())
    }

    /// Redo das operações confirmadas após o último checkpoint.
    fn recover(&mut self, records: &[WalRecord]) -> Result<()> {
        let ckpt = self.meta.checkpoint_lsn;
        let mut pending: Vec<(Op, u64)> = Vec::new();
        let mut active_txn = None;
        for rec in records.iter().filter(|r| r.lsn() > ckpt) {
            match rec {
                WalRecord::Begin { txn_id, lsn } => {
                    if active_txn.is_some() {
                        return Err(Error::CorruptWal(*lsn));
                    }
                    active_txn = Some(*txn_id);
                    self.meta.next_txn_id = self.meta.next_txn_id.max(txn_id.saturating_add(1));
                    pending.clear();
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
                    self.meta.next_txn_id = self.meta.next_txn_id.max(txn_id.saturating_add(1));
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
            self.wal.append(WalRecord::Abort { lsn: 0, txn_id })?;
            self.sync_wal()?;
        }
        Ok(())
    }

    fn has_value_index(&self) -> bool {
        self.meta.index_root != 0 || self.meta.flags & META_FLAG_VALUE_INDEX != 0
    }

    /// Aplica uma operação já durável às árvores (primária, índice e TTL).
    fn apply(&mut self, op: &Op, lsn: u64) -> Result<()> {
        let (pool, meta) = (&mut self.pool, &mut self.meta);
        match op {
            Op::Put { key, value } => {
                let old = BTree::get(pool, meta, key)?;
                BTree::insert(pool, meta, key, value, lsn)?;
                self.bloom.insert(key);
                if !is_reserved(key)
                    && (meta.index_root != 0 || meta.flags & META_FLAG_VALUE_INDEX != 0)
                {
                    index::upsert_value_index(pool, meta, key, old.as_deref(), value, lsn)?;
                }
                if meta.ttl_root != 0 {
                    BTree::delete_in(pool, meta, TreeId::Ttl, key, lsn)?;
                }
            }
            Op::Delete { key } => {
                if let Some(old) = BTree::get(pool, meta, key)? {
                    BTree::delete(pool, meta, key, lsn)?;
                    if !is_reserved(key) {
                        index::remove_value_index(pool, meta, key, &old, lsn)?;
                    }
                }
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

    fn alloc_txn_id(&mut self) -> u64 {
        let id = self.meta.next_txn_id;
        self.meta.next_txn_id = id.saturating_add(1);
        id
    }

    /// Registra `ops` no WAL (em um frame BEGIN/COMMIT quando há mais de uma
    /// ou quando vêm de uma transação) e só então as aplica.
    ///
    /// Se a aplicação falhar depois do registro durável, o handle é marcado
    /// como fechado: o estado em memória não é mais confiável, e reabrir o
    /// banco refaz as operações a partir do WAL.
    fn log_and_apply(&mut self, ops: &[Op], txn_id: Option<u64>) -> Result<()> {
        if ops.is_empty() {
            return Ok(());
        }
        let framed = match txn_id {
            Some(id) => Some(id),
            None if ops.len() > 1 => Some(self.alloc_txn_id()),
            None => None,
        };
        let logged = (|| {
            if let Some(txn_id) = framed {
                self.wal.append(WalRecord::Begin { lsn: 0, txn_id })?;
            }
            for op in ops {
                self.wal.append(op.record())?;
            }
            if let Some(txn_id) = framed {
                self.wal.append(WalRecord::Commit { lsn: 0, txn_id })?;
            }
            self.sync_wal()
        })();
        if let Err(error) = logged {
            if let Some(txn_id) = framed {
                // Garante que o frame parcial nunca engula registros futuros.
                let _ = self.wal.append(WalRecord::Abort { lsn: 0, txn_id });
            }
            return Err(error);
        }
        self.meta.next_lsn = self.wal.next_lsn();
        let lsn = self.wal.next_lsn().saturating_sub(1);
        if self.versions.recording() {
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
        if let Some(feed) = &mut self.feed {
            feed.push(lsn, ops);
        }
        Ok(())
    }

    /// Guarda o valor anterior de cada chave escrita para os snapshots MVCC.
    fn record_before_images(&mut self, ops: &[Op], lsn: u64) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for op in ops {
            if matches!(op, Op::Expire { .. }) || !seen.insert(op.key()) {
                continue;
            }
            let before = self.stored_visible(op.key())?;
            self.versions.record(op.key(), lsn, before);
        }
        Ok(())
    }

    /// Valor gravado e não expirado (ignora transação aberta).
    pub(crate) fn stored_visible(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match BTree::get(&mut self.pool, &self.meta, key)? {
            Some(value) if !self.is_expired(key)? => Ok(Some(value)),
            _ => Ok(None),
        }
    }

    /// LSN do último registro confirmado (versão do banco para MVCC/replicação).
    pub fn last_lsn(&self) -> u64 {
        self.wal.next_lsn().saturating_sub(1)
    }

    /// Modo somente leitura (réplicas): a API pública recusa escritas.
    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Escrita interna (SQL relacional, replicação): aceita o prefixo reservado
    /// e ignora o modo somente leitura. Atômica como [`Db::write_batch`].
    pub(crate) fn write_internal(&mut self, ops: Vec<Op>) -> Result<()> {
        self.write_ops(ops, true)
    }

    fn validate_op(&self, op: &Op, internal: bool) -> Result<()> {
        validate_key(op.key())?;
        if !internal {
            reject_reserved(op.key())?;
        }
        if let Op::Put { key, value } = op {
            validate_value(value)?;
            if self.has_value_index() && !is_reserved(key) {
                check_index_entry(key, value)?;
            }
        }
        Ok(())
    }

    /// Valida e executa `ops` atomicamente (ou acumula na transação aberta).
    fn write(&mut self, ops: Vec<Op>) -> Result<()> {
        self.write_ops(ops, false)
    }

    fn write_ops(&mut self, ops: Vec<Op>, internal: bool) -> Result<()> {
        self.ensure_open()?;
        if self.read_only && !internal {
            return Err(Error::ReadOnly);
        }
        for op in &ops {
            self.validate_op(op, internal)?;
        }
        match self.txn.as_mut() {
            Some(txn) => {
                txn.ops.extend(ops);
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
        validate_key(key)?;
        reject_reserved(key)?;
        let visible = self.get(key)?.is_some();
        let stored = self.txn.is_some() || BTree::get(&mut self.pool, &self.meta, key)?.is_some();
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
        if ops.len() == 1 && self.txn.is_none() {
            // Mesmo um lote unitário é registrado em frame para ser explícito.
            self.ensure_open()?;
            if self.read_only {
                return Err(Error::ReadOnly);
            }
            self.validate_op(&ops[0], false)?;
            let id = self.alloc_txn_id();
            return self.log_and_apply(&ops, Some(id));
        }
        self.write(ops)
    }

    /// Remove fisicamente as chaves expiradas (registrado no WAL). A leitura já
    /// as esconde; isto libera espaço e mantém o índice por valor enxuto.
    pub fn purge_expired(&mut self) -> Result<usize> {
        self.ensure_open()?;
        if self.txn.is_some() {
            return Err(Error::TxnOpen);
        }
        if self.meta.ttl_root == 0 {
            return Ok(0);
        }
        let now = now_ms();
        let ops: Vec<Op> = BTree::range_in(&mut self.pool, &self.meta, TreeId::Ttl, &[0], None)?
            .into_iter()
            .filter(|(_, at)| decode_at(at).is_some_and(|at| at <= now))
            .map(|(key, _)| Op::Delete { key })
            .collect();
        let purged = ops.len();
        if purged > 0 {
            let id = self.alloc_txn_id();
            self.log_and_apply(&ops, Some(id))?;
        }
        Ok(purged)
    }

    // ------------------------------------------------------------------
    // Leitura
    // ------------------------------------------------------------------

    /// Lê o valor visível para este handle (write-set da transação incluso).
    pub fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        reject_reserved(key)?;
        self.get_raw(key)
    }

    /// Como [`Db::get`], mas também enxerga o prefixo reservado.
    pub(crate) fn get_raw(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.ensure_open()?;
        validate_key(key)?;
        if let Some(txn) = &self.txn {
            let now = now_ms();
            for op in txn.ops.iter().rev().filter(|op| op.key() == key) {
                match op {
                    Op::Put { value, .. } => return Ok(Some(value.clone())),
                    Op::Delete { .. } => return Ok(None),
                    Op::Expire { at, .. } if *at != 0 && *at <= now => return Ok(None),
                    Op::Expire { .. } => {}
                }
            }
        }
        if !self.bloom.may_contain(key) {
            return Ok(None);
        }
        match BTree::get(&mut self.pool, &self.meta, key)? {
            Some(value) if !self.is_expired(key)? => Ok(Some(value)),
            _ => Ok(None),
        }
    }

    /// `true` se a chave existe e está visível.
    pub fn contains(&mut self, key: &[u8]) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// Situação de TTL da chave (ignora o write-set de transação aberta).
    pub fn ttl(&mut self, key: &[u8]) -> Result<KeyTtl> {
        if self.get(key)?.is_none() {
            return Ok(KeyTtl::Missing);
        }
        Ok(match self.expiry_of(key)? {
            None => KeyTtl::Persistent,
            Some(at) => KeyTtl::ExpiresIn(Duration::from_millis(at.saturating_sub(now_ms()))),
        })
    }

    pub(crate) fn expiry_of(&mut self, key: &[u8]) -> Result<Option<u64>> {
        if self.meta.ttl_root == 0 {
            return Ok(None);
        }
        Ok(BTree::get_in(&mut self.pool, &self.meta, TreeId::Ttl, key)?
            .as_deref()
            .and_then(decode_at))
    }

    fn is_expired(&mut self, key: &[u8]) -> Result<bool> {
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
    pub fn iter(&mut self, start: &[u8], end: Option<&[u8]>) -> Result<ScanIter<'_>> {
        // O espaço reservado (0xFF..) fica fora de qualquer faixa pública.
        const LIMIT: &[u8] = &[RESERVED_PREFIX];
        let end = Some(end.map_or(LIMIT, |e| e.min(LIMIT)));
        if start >= LIMIT {
            return self.iter_raw(LIMIT, Some(LIMIT));
        }
        self.iter_raw(start, end)
    }

    /// Iterador sem o corte do prefixo reservado (uso interno).
    pub(crate) fn iter_raw(&mut self, start: &[u8], end: Option<&[u8]>) -> Result<ScanIter<'_>> {
        self.ensure_open()?;
        validate_key(start)?;
        if let Some(end) = end {
            validate_key(end)?;
        }
        if self.txn.is_some() {
            let rows = self.merged_txn_view(start, end)?;
            return Ok(ScanIter::materialized(self, rows));
        }
        let first = BTree::first_leaf(&mut self.pool, &self.meta, TreeId::Primary, start)?;
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
    pub fn scan_prefix(&mut self, prefix: &[u8]) -> Result<ScanIter<'_>> {
        let end = prefix_successor(prefix);
        self.iter(prefix, end.as_deref())
    }

    /// Scan materializado de `[start, end)`.
    pub fn scan(&mut self, start: &[u8], end: Option<&[u8]>) -> Result<Vec<Row>> {
        self.iter(start, end)?.collect()
    }

    /// Conta as chaves visíveis em `[start, end)` sem materializá-las.
    pub fn count(&mut self, start: &[u8], end: Option<&[u8]>) -> Result<u64> {
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
        &mut self,
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

    fn merged_txn_view(&mut self, start: &[u8], end: Option<&[u8]>) -> Result<Vec<Row>> {
        let saved = self.txn.take();
        let base = self
            .iter_raw(start, end)
            .and_then(|it| it.collect::<Result<Vec<_>>>());
        self.txn = saved;
        let ops = self.txn.as_ref().map(|t| t.ops.clone()).unwrap_or_default();
        let mut visible: BTreeMap<Vec<u8>, Vec<u8>> = base?.into_iter().collect();
        let now = now_ms();
        for op in ops {
            let key = op.key();
            if key < start || end.is_some_and(|stop| key >= stop) {
                continue;
            }
            match op {
                Op::Put { key, value } => {
                    visible.insert(key, value);
                }
                Op::Delete { key } => {
                    visible.remove(&key);
                }
                Op::Expire { key, at } if at != 0 && at <= now => {
                    visible.remove(&key);
                }
                Op::Expire { .. } => {}
            }
        }
        Ok(visible.into_iter().collect())
    }

    /// Chaves cujo valor é exatamente `value` (índice quando existe).
    pub fn get_by_value(&mut self, value: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.ensure_open()?;
        let keys = if self.meta.index_root == 0 || self.txn.is_some() {
            self.scan(&[0], None)?
                .into_iter()
                .filter(|(_, v)| v.as_slice() == value)
                .map(|(k, _)| k)
                .collect()
        } else {
            index::find_keys_by_value(&mut self.pool, &self.meta, value)?
        };
        let mut live = Vec::with_capacity(keys.len());
        for key in keys {
            if self.txn.is_some() || !self.is_expired(&key)? {
                live.push(key);
            }
        }
        Ok(live)
    }

    // ------------------------------------------------------------------
    // Transações
    // ------------------------------------------------------------------

    /// Inicia um write-set local ao handle (sem isolamento/MVCC).
    pub fn begin(&mut self) -> Result<u64> {
        self.ensure_open()?;
        if self.txn.is_some() {
            return Err(Error::TxnOpen);
        }
        let id = self.alloc_txn_id();
        self.txn = Some(TxnState {
            id,
            ops: Vec::new(),
        });
        Ok(id)
    }

    /// Grava o write-set em um único frame BEGIN/COMMIT e aplica.
    pub fn commit(&mut self) -> Result<u64> {
        self.ensure_open()?;
        let txn = self.txn.take().ok_or(Error::TxnNotOpen)?;
        self.log_and_apply(&txn.ops, Some(txn.id))?;
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

    /// Publica uma imagem completa de `data.mdb` e trunca o WAL.
    pub fn checkpoint(&mut self) -> Result<()> {
        self.ensure_open()?;
        // Páginas expulsas vivem no spill descartável: publica um checkpoint
        // completo antes de descartar o WAL necessário para recriá-las.
        self.sync_wal()?;
        self.meta.checkpoint_lsn = self.wal.next_lsn().saturating_sub(1);
        self.meta.next_lsn = self.wal.next_lsn();
        self.persist_meta()?;
        self.pool.flush_all()?;
        self.wal.truncate_after_checkpoint(self.meta.next_lsn)
    }

    /// Remove chaves expiradas, reconstrói as árvores a partir das linhas
    /// vivas, publica por checkpoint e encolhe `data.mdb`. Devolve as páginas
    /// em uso.
    ///
    /// A reconstrução acontece em memória/spill; até o checkpoint publicar, um
    /// crash mantém a imagem anterior + WAL. As linhas são materializadas.
    pub fn vacuum(&mut self) -> Result<u32> {
        self.ensure_open()?;
        if self.txn.is_some() {
            return Err(Error::TxnOpen);
        }
        self.purge_expired()?;
        let rows: Vec<Row> = self.iter_raw(&[0], None)?.collect::<Result<_>>()?;
        let ttl_rows = if self.meta.ttl_root == 0 {
            Vec::new()
        } else {
            BTree::range_in(&mut self.pool, &self.meta, TreeId::Ttl, &[0], None)?
        };
        let had_index = self.has_value_index();
        let lsn = self.wal.next_lsn().saturating_sub(1);
        let fresh = MetaInfo::fresh();
        self.meta.root_page = fresh.root_page;
        self.meta.freelist_head = 0;
        self.meta.next_page_id = fresh.next_page_id;
        self.meta.index_root = 0;
        self.meta.ttl_root = 0;
        self.meta.flags &= !META_FLAG_VALUE_INDEX;
        // Vacuum migra arquivos antigos para o formato comprimido.
        self.meta.flags |= crate::page::META_FLAG_COMPRESSED_VALUES;
        self.pool.discard_from(fresh.root_page);
        self.pool
            .put_new_page(Page::zeroed(fresh.root_page, PageKind::Leaf))?;
        let (pool, meta) = (&mut self.pool, &mut self.meta);
        for (key, value) in &rows {
            BTree::insert(pool, meta, key, value, lsn)?;
        }
        if had_index {
            BTree::ensure_tree(pool, meta, TreeId::Secondary)?;
            for (key, value) in rows.iter().filter(|(k, _)| !is_reserved(k)) {
                index::upsert_value_index(pool, meta, key, None, value, lsn)?;
            }
        }
        for (key, at) in &ttl_rows {
            BTree::insert_in(pool, meta, TreeId::Ttl, key, at, lsn)?;
        }
        self.checkpoint()?;
        self.pool.truncate_pages(self.meta.next_page_id)?;
        Ok(self.meta.next_page_id)
    }

    /// Cria o índice por valor e faz backfill com as linhas vivas.
    pub fn create_value_index(&mut self) -> Result<usize> {
        self.ensure_open()?;
        if self.txn.is_some() {
            return Err(Error::TxnOpen);
        }
        let all = self.scan(&[0], None)?;
        for (key, value) in &all {
            check_index_entry(key, value)?;
        }
        BTree::ensure_tree(&mut self.pool, &mut self.meta, TreeId::Secondary)?;
        self.meta.flags |= META_FLAG_VALUE_INDEX;
        let lsn = self.wal.next_lsn();
        for (key, value) in &all {
            index::upsert_value_index(&mut self.pool, &mut self.meta, key, None, value, lsn)?;
        }
        self.checkpoint()?;
        Ok(all.len())
    }

    /// Descarta transação aberta, faz checkpoint e fecha o handle.
    pub fn close(&mut self) -> Result<()> {
        if !self.open {
            return Ok(());
        }
        self.txn = None;
        self.checkpoint()?;
        self.open = false;
        Ok(())
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

    pub fn meta(&self) -> &MetaInfo {
        &self.meta
    }

    /// `false` depois de `close` ou de uma falha que exige reabertura.
    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn stats(&self) -> DbStats {
        DbStats {
            root_page: self.meta.root_page,
            index_root: self.meta.index_root,
            ttl_root: self.meta.ttl_root,
            next_page_id: self.meta.next_page_id,
            checkpoint_lsn: self.meta.checkpoint_lsn,
            next_lsn: self.wal.next_lsn(),
            pool_capacity: self.pool.capacity(),
            next_txn_id: self.meta.next_txn_id,
            value_index: self.has_value_index(),
            txn_open: self.txn.is_some(),
        }
    }

    /// Ocupação das páginas: folhas, internos, livres, vazias e preenchimento.
    pub fn page_stats(&mut self) -> Result<PageStats> {
        self.ensure_open()?;
        inspect::page_stats(&mut self.pool, &self.meta)
    }

    pub fn verify(&mut self) -> Result<verify::VerifyReport> {
        self.ensure_open()?;
        verify::verify_pool(&mut self.pool, &self.meta)
    }

    pub fn inspect_page(&mut self, page_id: u32) -> Result<String> {
        self.ensure_open()?;
        inspect::dump_page(&mut self.pool, page_id)
    }

    pub fn inspect_hex(&mut self, page_id: u32, n: usize) -> Result<String> {
        self.ensure_open()?;
        inspect::hexdump_page(&mut self.pool, page_id, n)
    }

    pub fn inspect_meta_text(&self) -> String {
        inspect::dump_meta(&self.meta)
    }

    pub fn bloom_inserts(&self) -> u64 {
        self.bloom.inserts()
    }

    fn rebuild_bloom(&mut self) -> Result<()> {
        self.bloom = Bloom::new();
        for (k, _) in BTree::range_scan(&mut self.pool, &self.meta, &[0u8], None)? {
            self.bloom.insert(&k);
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
    /// ([`crate::rel`]: `CREATE TABLE`, `JOIN`, `GROUP BY`...).
    pub fn execute_sql(&mut self, sql: &str) -> Result<ExecResult> {
        match parse_sql(sql) {
            Ok(stmt) => self.execute_stmt(stmt),
            Err(legacy) => match crate::rel::execute(self, sql) {
                Err(Error::UnknownTable(t)) if t == "kv" || t == "t" => Err(legacy),
                other => other,
            },
        }
    }

    pub fn execute_stmt(&mut self, stmt: Statement) -> Result<ExecResult> {
        Ok(match stmt {
            Statement::Explain(inner) => ExecResult::Ok(explain(&inner)),
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
        })
    }

    /// Executa o predicado; `limit` (quando a ordem é ascendente) interrompe a
    /// leitura cedo, sem percorrer o restante da árvore.
    fn plan_select(&mut self, pred: Option<Pred>, limit: Option<usize>) -> Result<Vec<Row>> {
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

impl Drop for Db {
    fn drop(&mut self) {
        if self.open {
            let _ = self.close();
        }
    }
}

/// Iterador de [`Db::iter`]: produz `Result<(chave, valor)>` em ordem.
pub struct ScanIter<'a> {
    db: &'a mut Db,
    buffered: VecDeque<Row>,
    next_leaf: u32,
    from: Vec<u8>,
    end: Option<Vec<u8>>,
    check_ttl: bool,
    leaves_left: u32,
    done: bool,
}

impl<'a> ScanIter<'a> {
    fn materialized(db: &'a mut Db, rows: Vec<Row>) -> Self {
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
            match BTree::leaf_rows(&mut self.db.pool, &self.db.meta, self.next_leaf, &self.from) {
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
    pub pool_capacity: usize,
    pub next_txn_id: u64,
    pub value_index: bool,
    pub txn_open: bool,
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

/// Com índice por valor, a chave do índice é `[len:u16][valor][chave]` e
/// precisa caber no limite de chave da árvore.
fn check_index_entry(key: &[u8], value: &[u8]) -> Result<()> {
    let needed = 2 + value.len() + key.len();
    if needed > MAX_KEY_LEN {
        return Err(Error::InvalidInput(format!(
            "com índice por valor, chave + valor + 2 deve ter no máximo {MAX_KEY_LEN} bytes (recebido {needed})"
        )));
    }
    Ok(())
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
