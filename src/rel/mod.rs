//! SQL relacional sobre o motor chave-valor.
//!
//! Tabelas tipadas, chave primária, índices secundários (inclusive UNIQUE),
//! `JOIN`/`LEFT JOIN`, `GROUP BY`/`HAVING`, agregados, `ORDER BY`, `LIMIT`/
//! `OFFSET`, `UPDATE`/`DELETE` com `WHERE` arbitrário e `ALTER TABLE ADD
//! COLUMN`. Tudo vive no espaço de chaves reservado `0xFF` da árvore primária,
//! então herda WAL, recuperação, compressão, MVCC e replicação sem código novo.
//!
//! Layout (ids em big-endian para manter a ordem):
//!
//! | chave                                   | valor                     |
//! |-----------------------------------------|---------------------------|
//! | `FF 'c' <nome>`                         | esquema (JSON)            |
//! | `FF 'q'`                                | próximo id de tabela      |
//! | `FF 's' <tid>`                          | próximo rowid             |
//! | `FF 't' <tid> <pk>`                     | linha codificada          |
//! | `FF 'x' <tid> <iid> <valor> <pk>`       | `<pk>`                    |
//!
//! `<pk>` e `<valor>` usam [`value::encode_key`], que preserva a ordem: scans
//! por faixa de chave primária e buscas por igualdade em índice viram scans de
//! prefixo na B+ Tree.
//!
//! ```
//! use mini_db::{Db, ExecResult};
//! # let dir = std::env::temp_dir().join(format!("minidb-doc-rel-{}", std::process::id()));
//! let mut db = Db::open(&dir)?;
//! db.execute_sql("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INT)")?;
//! db.execute_sql("INSERT INTO users (name, age) VALUES ('ana', 31), ('bia', 25)")?;
//! let ExecResult::Table { rows, .. } =
//!     db.execute_sql("SELECT name FROM users WHERE age > 30")? else { unreachable!() };
//! assert_eq!(rows[0][0].to_string(), "ana");
//! # db.close()?; drop(db); std::fs::remove_dir_all(dir).unwrap();
//! # Ok::<(), mini_db::Error>(())
//! ```

mod exec;
pub mod parser;
pub mod value;

pub use value::{Type, Value};

use crate::db::{Db, ExecResult};
use crate::error::{Error, Result};
use crate::mvcc::SnapshotView;

/// Leitura de chaves (banco atual ou snapshot MVCC).
pub(crate) trait Source {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    /// Visita `[start, end)` em ordem; `visit` devolve `false` para parar.
    fn scan(
        &mut self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()>;
}

impl Source for Db {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_raw(key)
    }

    fn scan(
        &mut self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()> {
        for row in self.iter_raw(start, end)? {
            let (k, v) = row?;
            if !visit(k, v)? {
                break;
            }
        }
        Ok(())
    }
}

impl Source for SnapshotView<'_> {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_raw(key)
    }

    fn scan(
        &mut self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()> {
        self.scan_raw(start, end, visit)
    }
}

/// Executa um comando relacional (leitura ou escrita) no banco.
pub fn execute(db: &mut Db, sql: &str) -> Result<ExecResult> {
    let stmt = parser::parse(sql)?;
    exec::run(db, stmt)
}

/// Executa uma consulta somente leitura sobre um snapshot MVCC.
pub(crate) fn query_snapshot(view: &mut SnapshotView<'_>, sql: &str) -> Result<ExecResult> {
    let stmt = parser::parse(sql)?;
    exec::read_only(view, stmt).unwrap_or_else(|| {
        Err(Error::Sql(
            "snapshot aceita só SELECT/SHOW/DESCRIBE/EXPLAIN".into(),
        ))
    })
}
