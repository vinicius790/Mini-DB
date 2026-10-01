//! Concorrência: leitores em paralelo, snapshots MVCC e transações otimistas
//! com isolamento de snapshot ou serializável.
//!
//! [`SharedDb`] envolve o [`Db`] em um `RwLock`: quantas threads quiserem leem
//! ao mesmo tempo (`get`, scans, `SELECT`, joins...). Escritores são
//! serializados entre si e seguem três passos: planejam o lote com o lock de
//! leitura, gravam no WAL e fazem `fsync` **ainda com o lock de leitura** (os
//! leitores continuam) e só então pegam o lock exclusivo para aplicar o lote,
//! o que leva microssegundos.
//!
//! O arquivo guarda só a versão mais recente de cada chave. Enquanto existir
//! algum snapshot ativo, cada commit guarda em memória a **imagem anterior**
//! das chaves que alterou (undo em memória, como o undo log do InnoDB). Um
//! snapshot com versão `S` lê o valor atual e, se a chave mudou depois de `S`,
//! usa a imagem anterior da primeira mudança posterior a `S`.
//!
//! [`Txn`] lê do seu snapshot, acumula escritas localmente e valida no commit:
//!
//! - [`Isolation::Snapshot`]: falha com [`Error::Conflict`] se outra transação
//!   alterou alguma chave que esta escreveu (first-committer-wins);
//! - [`Isolation::Serializable`]: também falha se mudou qualquer chave ou faixa
//!   que esta **leu** — elimina write skew (validação otimista de leitura).
//!
//! ```
//! use mini_db::{mvcc::SharedDb, Db};
//! # let dir = std::env::temp_dir().join(format!("minidb-doc-mvcc-{}", std::process::id()));
//! let shared = SharedDb::new(Db::open(&dir)?);
//! shared.put(b"saldo", b"100")?;
//! let snap = shared.snapshot()?;
//! shared.put(b"saldo", b"50")?;
//! assert_eq!(snap.get(b"saldo")?.as_deref(), Some(&b"100"[..])); // visão estável
//!
//! let mut a = shared.begin()?;
//! let mut b = shared.begin()?;
//! a.put(b"saldo", b"10")?;
//! b.put(b"saldo", b"20")?;
//! a.commit()?;
//! assert!(matches!(b.commit(), Err(mini_db::Error::Conflict(_))));
//! # drop(snap); shared.write()?.close()?; drop(shared); std::fs::remove_dir_all(dir).unwrap();
//! # Ok::<(), mini_db::Error>(())
//! ```

use crate::auth::{Principal, Privilege};
use crate::db::{is_reserved, BatchOp, Db, ExecResult, Op, Row, RESERVED_PREFIX};
use crate::error::{Error, Result};
use crate::rel::{Value, Writes};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Bound, Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

type Chain = Vec<(u64, Option<Vec<u8>>)>;

/// Imagens anteriores mantidas enquanto houver snapshots ativos.
#[derive(Default)]
pub struct VersionStore {
    /// versão do snapshot -> quantidade de snapshots nessa versão.
    active: BTreeMap<u64, usize>,
    /// chave -> [(lsn do commit, valor antes do commit)] em ordem crescente.
    chains: BTreeMap<Vec<u8>, Chain>,
    /// lsn -> chaves registradas nesse commit (índice do GC).
    by_lsn: BTreeMap<u64, Vec<Vec<u8>>>,
}

impl VersionStore {
    pub(crate) fn recording(&self) -> bool {
        !self.active.is_empty()
    }

    pub(crate) fn record(&mut self, key: &[u8], lsn: u64, before: Option<Vec<u8>>) {
        self.chains
            .entry(key.to_vec())
            .or_default()
            .push((lsn, before));
        self.by_lsn.entry(lsn).or_default().push(key.to_vec());
    }

    fn register(&mut self, seq: u64) {
        *self.active.entry(seq).or_default() += 1;
    }

    fn release(&mut self, seq: u64) {
        if let Some(n) = self.active.get_mut(&seq) {
            *n -= 1;
            if *n == 0 {
                self.active.remove(&seq);
            }
        }
        let Some(&min) = self.active.keys().next() else {
            self.chains.clear();
            self.by_lsn.clear();
            return;
        };
        // Só commits com lsn > min ainda interessam a algum snapshot. O índice
        // por lsn deixa o GC proporcional ao que é descartado.
        let keep = self.by_lsn.split_off(&(min + 1));
        for (_, keys) in std::mem::replace(&mut self.by_lsn, keep) {
            for key in keys {
                if let Some(chain) = self.chains.get_mut(&key) {
                    chain.retain(|(lsn, _)| *lsn > min);
                    if chain.is_empty() {
                        self.chains.remove(&key);
                    }
                }
            }
        }
    }

    /// Imagem vista por um snapshot `seq`, se a chave mudou depois dele.
    fn as_of(&self, key: &[u8], seq: u64) -> Option<&Option<Vec<u8>>> {
        self.chains
            .get(key)?
            .iter()
            .find(|(lsn, _)| *lsn > seq)
            .map(|(_, before)| before)
    }

    fn changed_after(&self, key: &[u8], seq: u64) -> bool {
        self.chains
            .get(key)
            .is_some_and(|chain| chain.iter().any(|(lsn, _)| *lsn > seq))
    }

    fn range_changed_after(&self, start: &[u8], end: Option<&[u8]>, seq: u64) -> bool {
        let upper = end.map_or(Bound::Unbounded, Bound::Excluded);
        self.chains
            .range::<[u8], _>((Bound::Included(start), upper))
            .any(|(_, chain)| chain.iter().any(|(lsn, _)| *lsn > seq))
    }

    fn overlay(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        seq: u64,
    ) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
        let upper = end.map_or(Bound::Unbounded, Bound::Excluded);
        self.chains
            .range::<[u8], _>((Bound::Included(start), upper))
            .filter_map(|(key, _)| Some((key.clone(), self.as_of(key, seq)?.clone())))
            .collect()
    }

    /// Snapshots ativos e imagens retidas (observabilidade).
    pub fn stats(&self) -> (usize, usize) {
        (
            self.active.values().sum(),
            self.chains.values().map(Vec::len).sum(),
        )
    }
}

fn poisoned<E: std::fmt::Display>(e: E) -> Error {
    Error::Server(format!("lock envenenado: {e}"))
}

struct Shared {
    db: RwLock<Db>,
    /// Serializa escritores (planejamento → WAL → aplicação).
    writer: Mutex<()>,
    versions: Arc<Mutex<VersionStore>>,
    events: Arc<crate::events::EventBus>,
}

/// `Db` compartilhável entre threads, com leitura paralela, snapshots e
/// transações MVCC. Clonar é barato (é um `Arc`).
#[derive(Clone)]
pub struct SharedDb {
    inner: Arc<Shared>,
}

/// Acesso exclusivo: bloqueia outros escritores e leitores.
pub struct WriteGuard<'a> {
    db: RwLockWriteGuard<'a, Db>,
    _writer: MutexGuard<'a, ()>,
}

impl Deref for WriteGuard<'_> {
    type Target = Db;
    fn deref(&self) -> &Db {
        &self.db
    }
}

impl DerefMut for WriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Db {
        &mut self.db
    }
}

impl SharedDb {
    pub fn new(db: Db) -> Self {
        let versions = Arc::clone(&db.versions);
        let events = Arc::clone(&db.events);
        Self {
            inner: Arc::new(Shared {
                db: RwLock::new(db),
                writer: Mutex::new(()),
                versions,
                events,
            }),
        }
    }

    /// Barramento de eventos (mudanças confirmadas, NOTIFY).
    pub fn events(&self) -> &Arc<crate::events::EventBus> {
        &self.inner.events
    }

    /// Leitura compartilhada: várias threads ao mesmo tempo. Falha com
    /// [`Error::Unavailable`] enquanto uma réplica faz ressincronização completa.
    pub fn read(&self) -> Result<RwLockReadGuard<'_, Db>> {
        let db = self.read_unchecked()?;
        if db.repl.resyncing() {
            return Err(Error::Unavailable(
                "réplica em ressincronização completa".into(),
            ));
        }
        Ok(db)
    }

    pub(crate) fn read_unchecked(&self) -> Result<RwLockReadGuard<'_, Db>> {
        self.inner.db.read().map_err(poisoned)
    }

    /// Acesso exclusivo (manutenção, transação no nível do `Db`, legado).
    pub fn write(&self) -> Result<WriteGuard<'_>> {
        // O mutex guarda `()`: um panic de outra thread não deixa estado ruim.
        let writer = self.inner.writer.lock().unwrap_or_else(|e| e.into_inner());
        let db = self.inner.db.write().map_err(poisoned)?;
        Ok(WriteGuard {
            db,
            _writer: writer,
        })
    }

    /// Compatibilidade com a 0.5: equivale a [`SharedDb::write`].
    pub fn lock(&self) -> Result<WriteGuard<'_>> {
        self.write()
    }

    /// Caminho de escrita concorrente: `plan` monta o lote com o banco em
    /// leitura; o lote vai para o WAL sem bloquear leitores e é aplicado com
    /// o lock exclusivo por um instante. Devolve o que `plan` devolver.
    pub(crate) fn commit_with<T>(
        &self,
        plan: impl FnOnce(&Db) -> Result<(Vec<Op>, bool, T)>,
    ) -> Result<(T, u64)> {
        let _writer = self.inner.writer.lock().unwrap_or_else(|e| e.into_inner());
        if self.read_unchecked()?.needs_checkpoint() {
            self.inner
                .db
                .write()
                .map_err(poisoned)?
                .maybe_checkpoint()?;
        }
        let (ops, lsn, out) = {
            let db = self.read_unchecked()?;
            let (ops, internal, out) = plan(&db)?;
            db.validate_ops(&ops, internal)?;
            if ops.is_empty() {
                return Ok((out, db.last_lsn()));
            }
            if db.has_txn() {
                // Transação no nível do `Db` (BEGIN via SQL): o lote entra no
                // write-set dela, como no handle exclusivo.
                drop(db);
                let mut db = self.inner.db.write().map_err(poisoned)?;
                db.write_ops(ops, internal)?;
                let lsn = db.last_lsn();
                return Ok((out, lsn));
            }
            let lsn = db.log(&ops, None)?;
            (ops, lsn, out)
        };
        self.inner
            .db
            .write()
            .map_err(poisoned)?
            .apply_logged(&ops, lsn)?;
        Ok((out, lsn))
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.write_batch(&[BatchOp::Put {
            key: key.to_vec(),
            value: value.to_vec(),
        }])
    }

    pub fn put_with_ttl(&self, key: &[u8], value: &[u8], ttl: Duration) -> Result<()> {
        self.write_batch(&[BatchOp::PutWithTtl {
            key: key.to_vec(),
            value: value.to_vec(),
            ttl,
        }])
    }

    /// Remove a chave; devolve se ela existia.
    pub fn delete(&self, key: &[u8]) -> Result<bool> {
        self.commit_with(|db| {
            let existed = db.get(key)?.is_some();
            let ops = if existed {
                vec![Op::Delete { key: key.to_vec() }]
            } else {
                Vec::new()
            };
            Ok((ops, false, existed))
        })
        .map(|(existed, _)| existed)
    }

    /// Lote atômico (mesma semântica de [`Db::write_batch`]).
    pub fn write_batch(&self, batch: &[BatchOp]) -> Result<()> {
        self.commit_with(|_| Ok((crate::db::batch_to_ops(batch), false, ())))
            .map(|_| ())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.read()?.get(key)
    }

    /// Executa SQL (chave-valor ou relacional). Leituras rodam em paralelo;
    /// escritas relacionais usam o caminho concorrente.
    pub fn sql(&self, sql: &str) -> Result<ExecResult> {
        self.sql_params(sql, &[])
    }

    pub fn sql_params(&self, sql: &str, params: &[Value]) -> Result<ExecResult> {
        use crate::sql::Statement;
        let statements = crate::rel::split_statements(sql).unwrap_or_else(|_| vec![sql]);
        if statements.len() > 1 {
            if !params.is_empty() {
                return Err(Error::Sql(
                    "parâmetros só valem para um comando por vez; scripts não aceitam".into(),
                ));
            }
            // Script: roda numa sessão própria (transação implícita, atômico);
            // uma transação deixada aberta é desfeita.
            let mut session = Session::new(self.clone());
            let result = session.execute(sql)?;
            if session.in_transaction() {
                let _ = session.rollback();
                return Err(Error::Sql(
                    "script terminou com transação aberta: falta COMMIT".into(),
                ));
            }
            return Ok(result);
        }
        let sql = statements.first().copied().unwrap_or(sql);
        if crate::db::is_transaction_control(sql) {
            return Err(Error::Sql(
                "BEGIN/COMMIT/ROLLBACK/SAVEPOINT exigem uma sessão (Session::new(db)) ou uma \
                 conexão TCP; num único pedido, mande o script inteiro: BEGIN; ...; COMMIT"
                    .into(),
            ));
        }
        match crate::sql::parse_sql(sql) {
            Ok(Statement::Select { .. } | Statement::Explain(_)) if params.is_empty() => {
                self.read()?.query(sql)
            }
            Ok(stmt) if params.is_empty() => self.write()?.execute_stmt(stmt),
            Ok(_) => Err(Error::Sql(
                "o dialeto chave-valor (FROM kv) não aceita parâmetros".into(),
            )),
            Err(legacy) => {
                let prepared = self.read()?.cached_plan(sql).map_err(|e| match e {
                    Error::UnknownTable(t) if t == "kv" || t == "t" => {
                        Error::Sql(legacy.to_string())
                    }
                    other => other,
                })?;
                self.execute_prepared(&prepared, params)
            }
        }
    }

    pub fn execute_prepared(
        &self,
        prepared: &crate::rel::Prepared,
        params: &[Value],
    ) -> Result<ExecResult> {
        if prepared.is_read_only() {
            return crate::rel::query_prepared(&*self.read()?, prepared, params);
        }
        let (plan, lsn) = self.commit_with(|db| {
            if db.is_read_only() {
                return Err(Error::ReadOnly);
            }
            let mut plan = crate::rel::plan_write(db, prepared, params)?;
            let ops = std::mem::take(&mut plan.ops);
            Ok((ops, true, plan))
        })?;
        if !plan.changes.is_empty() || !plan.notifications.is_empty() {
            self.inner
                .events
                .publish(lsn, plan.changes, plan.notifications);
        }
        Ok(plan.result)
    }

    /// Sessão SQL com transações explícitas (`BEGIN`/`COMMIT`/`SAVEPOINT`).
    pub fn session(&self) -> Session {
        Session::new(self.clone())
    }

    /// Visão consistente do banco no último commit aplicado.
    pub fn snapshot(&self) -> Result<Snapshot> {
        let db = self.read()?;
        let seq = db.last_lsn();
        self.versions().register(seq);
        Ok(Snapshot {
            shared: self.clone(),
            seq,
        })
    }

    fn versions(&self) -> MutexGuard<'_, VersionStore> {
        self.inner
            .versions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Transação otimista com isolamento de snapshot.
    pub fn begin(&self) -> Result<Txn> {
        self.begin_with(Isolation::Snapshot)
    }

    /// Transação otimista serializável (sem write skew).
    pub fn begin_serializable(&self) -> Result<Txn> {
        self.begin_with(Isolation::Serializable)
    }

    pub fn begin_with(&self, isolation: Isolation) -> Result<Txn> {
        Ok(Txn {
            snap: self.snapshot()?,
            writes: BTreeMap::new(),
            isolation,
            reads: RefCell::default(),
            internal: false,
            changes: Vec::new(),
            notifications: Vec::new(),
        })
    }
}

/// Nível de isolamento de uma [`Txn`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isolation {
    /// Snapshot isolation: conflito só em escrita-escrita.
    Snapshot,
    /// Serializável: conflito também se algo lido mudou antes do commit.
    Serializable,
}

/// Leitura estável: não enxerga commits posteriores à sua criação.
pub struct Snapshot {
    shared: SharedDb,
    seq: u64,
}

/// Visão de um snapshot com o banco em leitura (usada pelo SQL relacional).
/// Enquanto a visão existe, o lock de leitura impede a aplicação de commits;
/// o mutex das versões só é tomado por instantes.
pub(crate) struct SnapshotView<'a> {
    pub(crate) db: &'a Db,
    pub(crate) versions: &'a Mutex<VersionStore>,
    pub(crate) seq: u64,
}

impl SnapshotView<'_> {
    fn versions(&self) -> MutexGuard<'_, VersionStore> {
        self.versions.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(before) = self.versions().as_of(key, self.seq) {
            return Ok(before.clone());
        }
        self.db.stored_visible(key)
    }

    /// Visita `[start, end)` em ordem; `visit` devolve `false` para parar.
    pub(crate) fn scan_raw(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()> {
        let overlay = self.versions().overlay(start, end, self.seq);
        let mut overlay = overlay.into_iter().peekable();
        let mut emit = |key: Vec<u8>, value: Option<Vec<u8>>| match value {
            Some(value) => visit(key, value),
            None => Ok(true),
        };
        for row in self.db.iter_raw(start, end)? {
            let (key, value) = row?;
            while overlay.peek().is_some_and(|(k, _)| *k < key) {
                let (k, v) = overlay.next().expect("peek");
                if !emit(k, v)? {
                    return Ok(());
                }
            }
            let value = match overlay.peek() {
                Some((k, _)) if *k == key => overlay.next().expect("peek").1,
                _ => Some(value),
            };
            if !emit(key, value)? {
                return Ok(());
            }
        }
        for (k, v) in overlay {
            if !emit(k, v)? {
                return Ok(());
            }
        }
        Ok(())
    }
}

impl Snapshot {
    /// Versão (LSN) observada por este snapshot.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub(crate) fn with<T>(&self, f: impl FnOnce(&SnapshotView<'_>) -> Result<T>) -> Result<T> {
        let db = self.shared.read_unchecked()?;
        f(&SnapshotView {
            db: &db,
            versions: &self.shared.inner.versions,
            seq: self.seq,
        })
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        user_key(key)?;
        self.with(|view| view.get_raw(key))
    }

    /// Linhas chave-valor de `[start, end)` como estavam no snapshot.
    pub fn scan(&self, start: &[u8], end: Option<&[u8]>) -> Result<Vec<Row>> {
        const LIMIT: &[u8] = &[RESERVED_PREFIX];
        let end = end.map_or(LIMIT, |e| e.min(LIMIT));
        let mut rows = Vec::new();
        if start < end {
            self.with(|view| {
                view.scan_raw(start, Some(end), &mut |k, v| {
                    rows.push((k, v));
                    Ok(true)
                })
            })?;
        }
        Ok(rows)
    }

    /// Consulta relacional somente leitura sobre o snapshot.
    pub fn query(&self, sql: &str) -> Result<ExecResult> {
        self.query_params(sql, &[])
    }

    pub fn query_params(&self, sql: &str, params: &[Value]) -> Result<ExecResult> {
        let prepared = crate::rel::prepare(sql)?;
        self.with(|view| crate::rel::query_prepared(view, &prepared, params))
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        // Só o mutex das versões: soltar um snapshot nunca espera o lock do
        // banco (nem trava se a thread segura um `WriteGuard`).
        self.shared.versions().release(self.seq);
    }
}

fn user_key(key: &[u8]) -> Result<()> {
    if key.is_empty() || is_reserved(key) {
        return Err(Error::InvalidInput(
            "chave vazia ou no prefixo reservado 0xFF".into(),
        ));
    }
    crate::btree::validate_user_key(key)
}

#[derive(Default)]
struct ReadSet {
    keys: BTreeSet<Vec<u8>>,
    ranges: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    /// Faixas lidas por verificações de integridade (UNIQUE, filhas de um pai):
    /// não podem mudar até o commit, em qualquer nível de isolamento.
    guard_unchanged: Vec<(Vec<u8>, Vec<u8>)>,
    /// Faixas que precisam continuar com alguma entrada até o commit (a linha
    /// pai de uma chave estrangeira).
    guard_present: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Transação otimista: lê do snapshot inicial, escreve no commit.
pub struct Txn {
    snap: Snapshot,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    isolation: Isolation,
    reads: RefCell<ReadSet>,
    /// Tem escritas relacionais (chaves reservadas, validadas pelo motor SQL).
    internal: bool,
    changes: Vec<crate::events::Change>,
    notifications: Vec<(String, String)>,
}

/// Fonte de leitura de uma transação: snapshot + escritas próprias, anotando
/// chaves e faixas lidas para a validação serializável.
struct TxnSource<'a> {
    overlay: crate::rel::Overlay<'a>,
    reads: &'a RefCell<ReadSet>,
}

impl crate::rel::Source for TxnSource<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.reads.borrow_mut().keys.insert(key.to_vec());
        self.overlay.get(key)
    }

    fn scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()> {
        self.reads
            .borrow_mut()
            .ranges
            .push((start.to_vec(), end.map(<[u8]>::to_vec)));
        self.overlay.scan(start, end, visit)
    }

    fn guard_unchanged(&self, start: &[u8], end: &[u8]) {
        let mut reads = self.reads.borrow_mut();
        reads.guard_unchanged.push((start.to_vec(), end.to_vec()));
    }

    fn guard_present(&self, start: &[u8], end: &[u8]) {
        let mut reads = self.reads.borrow_mut();
        reads.guard_present.push((start.to_vec(), end.to_vec()));
    }
}

impl Txn {
    pub fn isolation(&self) -> Isolation {
        self.isolation
    }

    /// SQL relacional dentro da transação: leituras enxergam o snapshot mais
    /// as escritas próprias; escritas ficam pendentes até o `commit`.
    ///
    /// ```
    /// use mini_db::{mvcc::SharedDb, Db, ExecResult};
    /// # let dir = std::env::temp_dir().join(format!("minidb-doc-txn-sql-{}", std::process::id()));
    /// let db = SharedDb::new(Db::open(&dir)?);
    /// db.sql("CREATE TABLE acc (id INT PRIMARY KEY, saldo INT CHECK (saldo >= 0))")?;
    /// db.sql("INSERT INTO acc VALUES (1, 100), (2, 0)")?;
    /// let mut txn = db.begin_serializable()?;
    /// txn.sql("UPDATE acc SET saldo = saldo - 30 WHERE id = 1")?;
    /// txn.sql("UPDATE acc SET saldo = saldo + 30 WHERE id = 2")?;
    /// txn.commit()?;
    /// let ExecResult::Table { rows, .. } = db.sql("SELECT saldo FROM acc ORDER BY id")? else { unreachable!() };
    /// assert_eq!(rows[1][0].to_string(), "30");
    /// # db.write()?.close()?; drop(db); std::fs::remove_dir_all(dir).unwrap();
    /// # Ok::<(), mini_db::Error>(())
    /// ```
    pub fn sql(&mut self, sql: &str) -> Result<ExecResult> {
        self.sql_params(sql, &[])
    }

    pub fn sql_params(&mut self, sql: &str, params: &[Value]) -> Result<ExecResult> {
        let statements = crate::rel::split_statements(sql).unwrap_or_else(|_| vec![sql]);
        if statements.len() > 1 {
            if !params.is_empty() {
                return Err(Error::Sql(
                    "parâmetros só valem para um comando por vez; scripts não aceitam".into(),
                ));
            }
            let mut results = Vec::with_capacity(statements.len());
            for s in statements {
                results.push(self.sql_params(s, &[])?);
            }
            return Ok(ExecResult::Batch(results));
        }
        let sql = statements.first().copied().unwrap_or(sql);
        let prepared = crate::rel::prepare(sql).map_err(|e| match e {
            Error::UnknownTable(t) if t == "kv" || t == "t" => Error::Sql(
                "a tabela chave-valor (kv) não participa de transações SQL: use get/put/delete/scan da Txn".into(),
            ),
            other => other,
        })?;
        self.execute_prepared(&prepared, params)
    }

    pub fn execute_prepared(
        &mut self,
        prepared: &crate::rel::Prepared,
        params: &[Value],
    ) -> Result<ExecResult> {
        if prepared.is_transaction_control() {
            return Err(Error::Sql(
                "BEGIN/COMMIT/SAVEPOINT dentro de Txn: use commit()/rollback() ou uma Session"
                    .into(),
            ));
        }
        let plan = self.snap.with(|view| {
            let src = TxnSource {
                overlay: crate::rel::Overlay {
                    base: view,
                    writes: &self.writes,
                },
                reads: &self.reads,
            };
            if prepared.is_read_only() {
                return Ok(crate::rel::WritePlan {
                    ops: Vec::new(),
                    result: crate::rel::query_prepared(&src, prepared, params)?,
                    changes: Vec::new(),
                    notifications: Vec::new(),
                });
            }
            crate::rel::plan_write(&src, prepared, params)
        })?;
        let result = plan.result;
        self.changes.extend(plan.changes);
        self.notifications.extend(plan.notifications);
        let ops = plan.ops;
        if !ops.is_empty() {
            self.internal = true;
            for op in ops {
                match op {
                    Op::Put { key, value } => self.writes.insert(key, Some(value)),
                    Op::Delete { key } => self.writes.insert(key, None),
                    Op::Expire { .. } => return Err(Error::Other("TTL em transação SQL".into())),
                };
            }
        }
        Ok(result)
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.writes.get(key) {
            Some(own) => Ok(own.clone()),
            None => {
                self.reads.borrow_mut().keys.insert(key.to_vec());
                self.snap.get(key)
            }
        }
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        user_key(key)?;
        crate::btree::validate_value(value)?;
        self.writes.insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        user_key(key)?;
        self.writes.insert(key.to_vec(), None);
        Ok(())
    }

    /// Faixa vista pela transação (snapshot + escritas próprias).
    pub fn scan(&self, start: &[u8], end: Option<&[u8]>) -> Result<Vec<Row>> {
        self.reads
            .borrow_mut()
            .ranges
            .push((start.to_vec(), end.map(<[u8]>::to_vec)));
        let mut rows: BTreeMap<_, _> = self.snap.scan(start, end)?.into_iter().collect();
        for (key, value) in &self.writes {
            if key.as_slice() < start || end.is_some_and(|e| key.as_slice() >= e) {
                continue;
            }
            match value {
                Some(v) => rows.insert(key.clone(), v.clone()),
                None => rows.remove(key),
            };
        }
        Ok(rows.into_iter().collect())
    }

    /// Confirma atomicamente; [`Error::Conflict`] se a validação do nível de
    /// isolamento falhar (repita a transação). Devolve o LSN do commit.
    pub fn commit(self) -> Result<u64> {
        let Txn {
            snap,
            writes,
            isolation,
            reads,
            internal,
            changes,
            notifications,
        } = self;
        let reads = reads.into_inner();
        let shared = snap.shared.clone();
        let seq = snap.seq;
        let lsn = shared
            .commit_with(|db| {
                // Chave estrangeira: a linha pai lida pela verificação precisa
                // existir agora (estado confirmado + escritas desta transação).
                // Atualizar outras colunas do pai não é conflito; apagá-lo é.
                for (start, end) in &reads.guard_present {
                    let mut present = false;
                    let current = crate::rel::Overlay {
                        base: db,
                        writes: &writes,
                    };
                    let end = Some(end.as_slice());
                    crate::rel::Source::scan(&current, start, end, &mut |_, _| {
                        present = true;
                        Ok(false)
                    })?;
                    if !present {
                        return Err(Error::Conflict(
                            "chave estrangeira: linha pai removida por outra transação".into(),
                        ));
                    }
                }
                {
                    let versions = shared.versions();
                    let conflict = writes
                        .keys()
                        .find(|key| versions.changed_after(key, seq))
                        .map(|k| String::from_utf8_lossy(k).into_owned());
                    // UNIQUE e filhas de um pai apagado/alterado: valem em qualquer
                    // nível de isolamento, senão duas transações violam a restrição.
                    let conflict = conflict.or_else(|| {
                        reads
                            .guard_unchanged
                            .iter()
                            .find(|(s, e)| versions.range_changed_after(s, Some(e.as_slice()), seq))
                            .map(|_| "restrição UNIQUE ou chave estrangeira".to_string())
                    });
                    let conflict = conflict.or_else(|| {
                        if isolation != Isolation::Serializable {
                            return None;
                        }
                        reads
                            .keys
                            .iter()
                            .find(|key| versions.changed_after(key, seq))
                            .map(|k| format!("leitura de {}", String::from_utf8_lossy(k)))
                            .or_else(|| {
                                reads
                                    .ranges
                                    .iter()
                                    .find(|(s, e)| {
                                        versions.range_changed_after(s, e.as_deref(), seq)
                                    })
                                    .map(|(s, _)| {
                                        format!("faixa a partir de {}", String::from_utf8_lossy(s))
                                    })
                            })
                    });
                    if let Some(what) = conflict {
                        return Err(Error::Conflict(what));
                    }
                }
                let ops = writes
                    .iter()
                    .map(|(key, value)| match value {
                        Some(value) => Op::Put {
                            key: key.clone(),
                            value: value.clone(),
                        },
                        None => Op::Delete { key: key.clone() },
                    })
                    .collect();
                Ok((ops, internal, ()))
            })
            .map(|((), lsn)| lsn);
        if let Ok(lsn) = lsn {
            if !changes.is_empty() || !notifications.is_empty() {
                shared.inner.events.publish(lsn, changes, notifications);
            }
        }
        drop(snap);
        lsn
    }

    /// Descarta as escritas (equivale a soltar a transação).
    pub fn rollback(self) {}
}

/// Sessão SQL: transações explícitas com `BEGIN [ISOLATION LEVEL
/// SERIALIZABLE]`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`/`RELEASE`/`ROLLBACK TO`
/// e scripts (`a; b; c`) atômicos. Uma por conexão TCP; a API HTTP cria uma
/// por pedido. Fora de transação, cada comando é autocommit.
///
/// ```
/// use mini_db::{mvcc::SharedDb, Db, ExecResult};
/// # let dir = std::env::temp_dir().join(format!("minidb-doc-session-{}", std::process::id()));
/// let db = SharedDb::new(Db::open(&dir)?);
/// let mut s = db.session();
/// s.execute("CREATE TABLE itens (id INT PRIMARY KEY, v TEXT)")?;
/// s.execute("BEGIN")?;
/// s.execute("INSERT INTO itens VALUES (1, 'a')")?;
/// s.execute("SAVEPOINT sp")?;
/// s.execute("INSERT INTO itens VALUES (2, 'b')")?;
/// s.execute("ROLLBACK TO sp")?;
/// s.execute("COMMIT")?;
/// let ExecResult::Table { rows, .. } = db.sql("SELECT COUNT(*) FROM itens")? else { unreachable!() };
/// assert_eq!(rows[0][0].to_string(), "1");
/// # drop(s); db.write()?.close()?; drop(db); std::fs::remove_dir_all(dir).unwrap();
/// # Ok::<(), mini_db::Error>(())
/// ```
pub struct Session {
    db: SharedDb,
    txn: Option<Txn>,
    /// `(nome, escritas, nº de mudanças, nº de notificações)` no momento do savepoint.
    savepoints: Vec<(String, Writes, usize, usize)>,
    /// Ouvinte de `LISTEN` no barramento (criado no primeiro LISTEN).
    listener: Option<u64>,
    /// Quem executa (rede). `None` = sessão confiável (embutida/CLI): sem
    /// verificação de privilégios.
    principal: Option<Principal>,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(id) = self.listener {
            self.db.inner.events.unsubscribe(id);
        }
    }
}

impl Session {
    pub fn new(db: SharedDb) -> Self {
        Self {
            db,
            txn: None,
            savepoints: Vec::new(),
            listener: None,
            principal: None,
        }
    }

    /// Autentica `user`/`password` no catálogo; a sessão passa a obedecer
    /// aos privilégios dele.
    pub fn login(&mut self, user: &str, password: &str) -> Result<()> {
        let guard = self.db.read()?;
        self.principal = Some(crate::auth::authenticate(&*guard, user, password)?);
        Ok(())
    }

    /// Sessão em nome de um principal já autenticado (protocolo PostgreSQL).
    pub fn set_principal(&mut self, principal: Option<Principal>) {
        self.principal = principal;
    }

    pub fn principal(&self) -> Option<&Principal> {
        self.principal.as_ref()
    }

    /// Há usuários cadastrados? Sem nenhum, a rede aceita conexões sem senha.
    pub fn auth_required(&self) -> Result<bool> {
        let guard = self.db.read()?;
        crate::auth::has_users(&*guard)
    }

    /// Confere um privilégio avulso (`kv` para os comandos chave-valor).
    pub fn authorize_object(&self, object: &str, privilege: Privilege) -> Result<()> {
        if self.principal.is_none() {
            return Ok(());
        }
        let guard = self.db.read()?;
        let p = self.current(&guard)?;
        crate::auth::authorize_object(&*guard, &p, object, privilege)
    }

    /// Principal como está agora no catálogo (GRANT/REVOKE/DROP valem na hora).
    fn current(&self, guard: &Db) -> Result<Principal> {
        let p = self.principal.as_ref().ok_or(Error::Unauthorized)?;
        crate::auth::load(guard, &p.name)?
            .filter(|now| now.login)
            .ok_or(Error::Unauthorized)
    }

    fn authorize(&self, sql: &str) -> Result<()> {
        if self.principal.is_none() {
            return Ok(());
        }
        let guard = self.db.read()?;
        let p = &self.current(&guard)?;
        match crate::rel::prepare(sql) {
            Ok(prepared) => crate::auth::authorize(&*guard, p, prepared.stmt()),
            // Dialeto chave-valor (`FROM kv`, CHECKPOINT...): privilégio em `kv`.
            Err(e) => match crate::sql::parse_sql(sql) {
                Ok(crate::sql::Statement::Select { .. } | crate::sql::Statement::Explain(_)) => {
                    crate::auth::authorize_object(&*guard, p, "kv", Privilege::Select)
                }
                Ok(_) => crate::auth::authorize_object(&*guard, p, "kv", Privilege::All),
                Err(_) => Err(e),
            },
        }
    }

    fn listener(&mut self) -> u64 {
        *self
            .listener
            .get_or_insert_with(|| self.db.inner.events.subscribe())
    }

    /// Canais escutados (`LISTEN`).
    pub fn channels(&self) -> Vec<String> {
        self.listener
            .map(|id| self.db.inner.events.channels(id))
            .unwrap_or_default()
    }

    /// Notificações já entregues aos canais escutados; espera até `timeout`
    /// se não houver nenhuma (long-poll).
    pub fn notifications(&self, timeout: Duration) -> Vec<crate::events::Notification> {
        match self.listener {
            Some(id) => self.db.inner.events.poll(id, timeout),
            None => Vec::new(),
        }
    }

    pub fn db(&self) -> &SharedDb {
        &self.db
    }

    pub fn in_transaction(&self) -> bool {
        self.txn.is_some()
    }

    /// Abre uma transação (erro se já há uma aberta).
    pub fn begin(&mut self, serializable: bool) -> Result<()> {
        if self.txn.is_some() {
            return Err(Error::TxnOpen);
        }
        self.txn = Some(self.db.begin_with(if serializable {
            Isolation::Serializable
        } else {
            Isolation::Snapshot
        })?);
        self.savepoints.clear();
        Ok(())
    }

    /// Confirma a transação aberta; devolve o LSN. Em conflito
    /// ([`Error::Conflict`]) a transação é descartada.
    pub fn commit(&mut self) -> Result<u64> {
        let txn = self.txn.take().ok_or(Error::TxnNotOpen)?;
        self.savepoints.clear();
        txn.commit()
    }

    pub fn rollback(&mut self) -> Result<()> {
        self.txn.take().ok_or(Error::TxnNotOpen)?;
        self.savepoints.clear();
        Ok(())
    }

    /// Chave-valor dentro da transação aberta (ou autocommit sem ela).
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.authorize_object("kv", Privilege::Insert)?;
        match &mut self.txn {
            Some(t) => t.put(key, value),
            None => self.db.put(key, value),
        }
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.authorize_object("kv", Privilege::Select)?;
        match &self.txn {
            Some(t) => t.get(key),
            None => self.db.get(key),
        }
    }

    /// Devolve se a chave existia (na transação, se a transação a enxergava).
    pub fn delete(&mut self, key: &[u8]) -> Result<bool> {
        self.authorize_object("kv", Privilege::Delete)?;
        match &mut self.txn {
            Some(t) => {
                let existed = t.get(key)?.is_some();
                t.delete(key)?;
                Ok(existed)
            }
            None => self.db.delete(key),
        }
    }

    /// Um comando ou um script (`;`). Sem `BEGIN` explícito, um script roda
    /// numa transação implícita e qualquer erro desfaz tudo.
    pub fn execute(&mut self, sql: &str) -> Result<ExecResult> {
        self.execute_params(sql, &[])
    }

    pub fn execute_params(&mut self, sql: &str, params: &[Value]) -> Result<ExecResult> {
        let statements = crate::rel::split_statements(sql).unwrap_or_else(|_| vec![sql]);
        if statements.len() <= 1 {
            return self.one(statements.first().copied().unwrap_or(sql), params);
        }
        if !params.is_empty() {
            return Err(Error::Sql(
                "parâmetros só valem para um comando por vez; scripts não aceitam".into(),
            ));
        }
        let had = self.txn.is_some();
        let implicit = !had
            && !statements
                .iter()
                .any(|s| crate::db::is_transaction_control(s));
        if implicit {
            self.begin(false)?;
        }
        let mut results = Vec::with_capacity(statements.len());
        for s in &statements {
            match self.one(s, &[]) {
                Ok(r) => results.push(r),
                Err(e) => {
                    if !had && self.txn.is_some() {
                        let _ = self.rollback();
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

    fn one(&mut self, sql: &str, params: &[Value]) -> Result<ExecResult> {
        self.authorize(sql)?;
        crate::rel::set_current_user(self.principal.as_ref().map(|p| p.name.clone()));
        if crate::db::is_transaction_control(sql) {
            let prepared = crate::rel::prepare(sql)?;
            return self.control(prepared.stmt());
        }
        let first: String = sql
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect::<String>()
            .to_ascii_lowercase();
        if first == "listen" || first == "unlisten" {
            let prepared = crate::rel::prepare(sql)?;
            return Ok(ExecResult::Ok(match prepared.stmt() {
                crate::rel::parser::Stmt::Listen(channel) => {
                    let id = self.listener();
                    self.db.inner.events.listen(id, channel);
                    format!("LISTEN {channel}")
                }
                crate::rel::parser::Stmt::Unlisten(channel) => {
                    if let Some(id) = self.listener {
                        self.db.inner.events.unlisten(id, channel.as_deref());
                    }
                    format!("UNLISTEN {}", channel.clone().unwrap_or_else(|| "*".into()))
                }
                _ => unreachable!(),
            }));
        }
        match &mut self.txn {
            None => self.db.sql_params(sql, params),
            Some(txn) => {
                if crate::sql::parse_sql(sql).is_ok() {
                    return Err(Error::Sql(
                        "o dialeto chave-valor (FROM kv, CHECKPOINT) não roda dentro de uma transação SQL"
                            .into(),
                    ));
                }
                txn.sql_params(sql, params)
            }
        }
    }

    fn control(&mut self, stmt: &crate::rel::parser::Stmt) -> Result<ExecResult> {
        use crate::rel::parser::Stmt;
        Ok(ExecResult::Ok(match stmt {
            Stmt::Begin { serializable } => {
                self.begin(*serializable)?;
                format!(
                    "BEGIN {}",
                    if *serializable {
                        "SERIALIZABLE"
                    } else {
                        "SNAPSHOT"
                    }
                )
            }
            Stmt::Commit => format!("COMMIT lsn={}", self.commit()?),
            Stmt::Rollback { to: None } => {
                self.rollback()?;
                "ROLLBACK".into()
            }
            Stmt::Rollback { to: Some(name) } => {
                let txn = self.txn.as_mut().ok_or(Error::TxnNotOpen)?;
                let pos = self
                    .savepoints
                    .iter()
                    .rposition(|(s, ..)| s == name)
                    .ok_or_else(|| Error::Sql(format!("savepoint {name} não existe")))?;
                txn.writes = self.savepoints[pos].1.clone();
                // Eventos e NOTIFY do trecho desfeito não podem ser publicados no commit.
                txn.changes.truncate(self.savepoints[pos].2);
                txn.notifications.truncate(self.savepoints[pos].3);
                self.savepoints.truncate(pos + 1);
                format!("ROLLBACK TO {name}")
            }
            Stmt::Savepoint(name) => {
                let txn = self.txn.as_ref().ok_or(Error::TxnNotOpen)?;
                self.savepoints.retain(|(s, ..)| s != name);
                self.savepoints.push((
                    name.clone(),
                    txn.writes.clone(),
                    txn.changes.len(),
                    txn.notifications.len(),
                ));
                format!("SAVEPOINT {name}")
            }
            Stmt::Release(name) => {
                self.txn.as_ref().ok_or(Error::TxnNotOpen)?;
                let pos = self
                    .savepoints
                    .iter()
                    .rposition(|(s, ..)| s == name)
                    .ok_or_else(|| Error::Sql(format!("savepoint {name} não existe")))?;
                self.savepoints.truncate(pos);
                format!("RELEASE {name}")
            }
            _ => unreachable!("só controle de transação"),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn shared(tag: &str) -> SharedDb {
        let dir = std::env::temp_dir().join(format!("minidb-mvcc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        SharedDb::new(Db::open(dir).unwrap())
    }

    #[test]
    fn snapshot_scan_ignores_later_commits_and_gc_frees_versions() {
        let db = shared("scan");
        for k in [b"a", b"b", b"c"] {
            db.put(k, b"1").unwrap();
        }
        let snap = db.snapshot().unwrap();
        db.delete(b"a").unwrap();
        db.put(b"b", b"2").unwrap();
        db.put(b"bb", b"new").unwrap();
        let old: Vec<_> = snap.scan(b"a", None).unwrap();
        assert_eq!(
            old,
            vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"1".to_vec()),
                (b"c".to_vec(), b"1".to_vec())
            ]
        );
        assert_eq!(db.read().unwrap().count(b"a", None).unwrap(), 3);
        assert_eq!(db.versions().stats(), (1, 3));
        let snap2 = db.snapshot().unwrap();
        db.put(b"c", b"3").unwrap();
        drop(snap);
        assert_eq!(db.versions().stats(), (1, 1), "GC mantém só o que snap2 vê");
        drop(snap2);
        assert_eq!(db.versions().stats(), (0, 0));
    }

    #[test]
    fn concurrent_counters_never_lose_updates() {
        let db = shared("counter");
        db.put(b"n", b"0").unwrap();
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let db = db.clone();
                thread::spawn(move || {
                    for _ in 0..25 {
                        loop {
                            let mut txn = db.begin().unwrap();
                            let n: u64 = String::from_utf8(txn.get(b"n").unwrap().unwrap())
                                .unwrap()
                                .parse()
                                .unwrap();
                            txn.put(b"n", (n + 1).to_string().as_bytes()).unwrap();
                            match txn.commit() {
                                Ok(_) => break,
                                Err(Error::Conflict(_)) => continue,
                                Err(e) => panic!("{e}"),
                            }
                        }
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
        assert_eq!(db.get(b"n").unwrap().as_deref(), Some(&b"100"[..]));
    }

    #[test]
    fn serializable_prevents_write_skew() {
        // Dois plantonistas: cada um só pode sair se o outro continuar.
        let db = shared("skew");
        db.put(b"on:ana", b"1").unwrap();
        db.put(b"on:bia", b"1").unwrap();
        let run = |iso| {
            let mut a = db.begin_with(iso).unwrap();
            let mut b = db.begin_with(iso).unwrap();
            assert_eq!(a.scan(b"on:", Some(b"on;")).unwrap().len(), 2);
            assert_eq!(b.scan(b"on:", Some(b"on;")).unwrap().len(), 2);
            a.delete(b"on:ana").unwrap();
            b.delete(b"on:bia").unwrap();
            (a.commit(), b.commit())
        };
        let (a, b) = run(Isolation::Serializable);
        assert!(a.is_ok() && matches!(b, Err(Error::Conflict(_))));
        assert_eq!(db.read().unwrap().count(b"on:", Some(b"on;")).unwrap(), 1);
        db.put(b"on:ana", b"1").unwrap();
        let (a, b) = run(Isolation::Snapshot);
        assert!(a.is_ok() && b.is_ok(), "SI permite write skew");
    }

    #[test]
    fn readers_run_while_a_writer_holds_the_wal() {
        let db = shared("parallel");
        for i in 0..200u32 {
            db.put(format!("k{i:03}").as_bytes(), b"v").unwrap();
        }
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let db = db.clone();
                thread::spawn(move || {
                    for _ in 0..50 {
                        assert_eq!(db.read().unwrap().count(b"k", Some(b"l")).unwrap(), 200);
                    }
                })
            })
            .collect();
        for i in 0..50u32 {
            db.put(format!("x{i}").as_bytes(), b"v").unwrap();
        }
        for r in readers {
            r.join().unwrap();
        }
    }
}
