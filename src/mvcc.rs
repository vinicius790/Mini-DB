//! MVCC: snapshots consistentes e transações otimistas entre threads.
//!
//! O banco guarda só a versão mais recente de cada chave. Enquanto existir
//! algum snapshot ativo, cada commit registra a **imagem anterior** das chaves
//! que alterou (undo em memória, como o undo log do InnoDB). Um snapshot com
//! versão `S` lê o valor atual e, se a chave mudou depois de `S`, usa a imagem
//! anterior da primeira mudança posterior a `S`.
//!
//! [`Txn`] implementa *snapshot isolation* com controle otimista: lê do seu
//! snapshot, acumula escritas localmente e, no commit, falha com
//! [`Error::Conflict`] se outra transação alterou alguma das mesmas chaves
//! depois do início (first-committer-wins). Write skew continua possível, como
//! em qualquer SI.
//!
//! ```
//! use mini_db::{mvcc::SharedDb, Db};
//! # let dir = std::env::temp_dir().join(format!("minidb-doc-mvcc-{}", std::process::id()));
//! let shared = SharedDb::new(Db::open(&dir)?);
//! shared.lock()?.put(b"saldo", b"100")?;
//! let snap = shared.snapshot()?;
//! shared.lock()?.put(b"saldo", b"50")?;
//! assert_eq!(snap.get(b"saldo")?.as_deref(), Some(&b"100"[..])); // visão estável
//!
//! let mut a = shared.begin()?;
//! let mut b = shared.begin()?;
//! a.put(b"saldo", b"10")?;
//! b.put(b"saldo", b"20")?;
//! a.commit()?;
//! assert!(matches!(b.commit(), Err(mini_db::Error::Conflict(_))));
//! # drop(snap); shared.lock()?.close()?; drop(shared); std::fs::remove_dir_all(dir).unwrap();
//! # Ok::<(), mini_db::Error>(())
//! ```

use crate::db::{is_reserved, Db, ExecResult, Row, RESERVED_PREFIX};
use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::{Arc, Mutex, MutexGuard};

type Chain = Vec<(u64, Option<Vec<u8>>)>;

/// Imagens anteriores mantidas enquanto houver snapshots ativos.
#[derive(Default)]
pub struct VersionStore {
    /// versão do snapshot -> quantidade de snapshots nessa versão.
    active: BTreeMap<u64, usize>,
    /// chave -> [(lsn do commit, valor antes do commit)] em ordem crescente.
    chains: BTreeMap<Vec<u8>, Chain>,
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
        // ponytail: GC percorre todas as cadeias a cada release; indexar por
        // lsn se houver milhões de versões vivas.
        match self.active.keys().next().copied() {
            None => self.chains.clear(),
            Some(min) => self.chains.retain(|_, chain| {
                chain.retain(|(lsn, _)| *lsn > min);
                !chain.is_empty()
            }),
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

/// `Db` compartilhável entre threads, com snapshots e transações MVCC.
#[derive(Clone)]
pub struct SharedDb {
    db: Arc<Mutex<Db>>,
}

impl SharedDb {
    pub fn new(db: Db) -> Self {
        Self::from_arc(Arc::new(Mutex::new(db)))
    }

    pub fn from_arc(db: Arc<Mutex<Db>>) -> Self {
        Self { db }
    }

    /// Handle bruto (servidores TCP/HTTP usam o mesmo mutex).
    pub fn handle(&self) -> Arc<Mutex<Db>> {
        Arc::clone(&self.db)
    }

    /// Acesso exclusivo ao `Db`: escritas diretas também alimentam o MVCC.
    pub fn lock(&self) -> Result<MutexGuard<'_, Db>> {
        self.db.lock().map_err(|e| Error::Server(e.to_string()))
    }

    /// Visão consistente do banco no último commit.
    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut db = self.lock()?;
        let seq = db.last_lsn();
        db.versions.register(seq);
        Ok(Snapshot {
            shared: self.clone(),
            seq,
        })
    }

    /// Transação otimista com isolamento de snapshot.
    pub fn begin(&self) -> Result<Txn> {
        Ok(Txn {
            snap: self.snapshot()?,
            writes: BTreeMap::new(),
        })
    }

    /// Executa SQL (chave-valor ou relacional) com o banco travado.
    pub fn sql(&self, sql: &str) -> Result<ExecResult> {
        self.lock()?.execute_sql(sql)
    }
}

/// Leitura estável: não enxerga commits posteriores à sua criação.
pub struct Snapshot {
    shared: SharedDb,
    seq: u64,
}

/// Visão de um snapshot com o banco travado (usada pelo SQL relacional).
pub(crate) struct SnapshotView<'a> {
    pub(crate) db: &'a mut Db,
    pub(crate) seq: u64,
}

impl SnapshotView<'_> {
    pub(crate) fn get_raw(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(before) = self.db.versions.as_of(key, self.seq) {
            return Ok(before.clone());
        }
        self.db.stored_visible(key)
    }

    /// Visita `[start, end)` em ordem; `visit` devolve `false` para parar.
    pub(crate) fn scan_raw(
        &mut self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()> {
        let mut overlay = self
            .db
            .versions
            .overlay(start, end, self.seq)
            .into_iter()
            .peekable();
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

    fn with<T>(&self, f: impl FnOnce(&mut SnapshotView<'_>) -> Result<T>) -> Result<T> {
        let mut db = self.shared.lock()?;
        f(&mut SnapshotView {
            db: &mut db,
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

    /// `SELECT` relacional executado sobre o snapshot.
    pub fn query(&self, sql: &str) -> Result<ExecResult> {
        self.with(|view| crate::rel::query_snapshot(view, sql))
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        if let Ok(mut db) = self.shared.db.lock() {
            db.versions.release(self.seq);
        }
    }
}

fn user_key(key: &[u8]) -> Result<()> {
    if key.is_empty() || is_reserved(key) {
        return Err(Error::InvalidInput(
            "chave vazia ou no prefixo reservado 0xFF".into(),
        ));
    }
    Ok(())
}

/// Transação otimista: lê do snapshot inicial, escreve no commit.
pub struct Txn {
    snap: Snapshot,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Txn {
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.writes.get(key) {
            Some(own) => Ok(own.clone()),
            None => self.snap.get(key),
        }
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        user_key(key)?;
        crate::btree::validate_key(key)?;
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

    /// Confirma atomicamente; [`Error::Conflict`] se outra transação escreveu
    /// em alguma das mesmas chaves depois do início desta. Devolve o LSN.
    pub fn commit(self) -> Result<u64> {
        let mut db = self.snap.shared.lock()?;
        let conflict = self.writes.keys().find(|key| {
            db.versions
                .chains
                .get(*key)
                .is_some_and(|chain| chain.iter().any(|(lsn, _)| *lsn > self.snap.seq))
        });
        if let Some(key) = conflict {
            return Err(Error::Conflict(String::from_utf8_lossy(key).into_owned()));
        }
        if self.writes.is_empty() {
            return Ok(db.last_lsn());
        }
        let batch: Vec<_> = self
            .writes
            .iter()
            .map(|(key, value)| match value {
                Some(value) => crate::BatchOp::Put {
                    key: key.clone(),
                    value: value.clone(),
                },
                None => crate::BatchOp::Delete { key: key.clone() },
            })
            .collect();
        db.write_batch(&batch)?;
        Ok(db.last_lsn())
    }

    /// Descarta as escritas (equivale a soltar a transação).
    pub fn rollback(self) {}
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
            db.lock().unwrap().put(k, b"1").unwrap();
        }
        let snap = db.snapshot().unwrap();
        {
            let mut g = db.lock().unwrap();
            g.delete(b"a").unwrap();
            g.put(b"b", b"2").unwrap();
            g.put(b"bb", b"new").unwrap();
        }
        let old: Vec<_> = snap.scan(b"a", None).unwrap();
        assert_eq!(
            old,
            vec![
                (b"a".to_vec(), b"1".to_vec()),
                (b"b".to_vec(), b"1".to_vec()),
                (b"c".to_vec(), b"1".to_vec())
            ]
        );
        assert_eq!(db.lock().unwrap().count(b"a", None).unwrap(), 3);
        assert_eq!(db.lock().unwrap().versions.stats(), (1, 3));
        drop(snap);
        assert_eq!(db.lock().unwrap().versions.stats(), (0, 0));
    }

    #[test]
    fn concurrent_counters_never_lose_updates() {
        let db = shared("counter");
        db.lock().unwrap().put(b"n", b"0").unwrap();
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
        assert_eq!(
            db.lock().unwrap().get(b"n").unwrap().as_deref(),
            Some(&b"100"[..])
        );
    }
}
