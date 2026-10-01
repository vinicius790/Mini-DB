//! SQL relacional sobre o motor chave-valor.
//!
//! Tabelas tipadas com chave primária simples ou composta, `NOT NULL`,
//! `DEFAULT <expressão>`, `CHECK`, `UNIQUE`, `AUTOINCREMENT`/`SERIAL` e chaves
//! estrangeiras com `ON DELETE`/`ON UPDATE` (`CASCADE`, `SET NULL`,
//! `SET DEFAULT`, `RESTRICT`); índices secundários simples ou compostos;
//! views; `ALTER TABLE` (adicionar, remover e renomear colunas, renomear a
//! tabela, mudar DEFAULT/NOT NULL); `TRUNCATE`. Consultas com `JOIN` (`INNER`,
//! `LEFT`, `RIGHT`, `FULL`, `CROSS`, `USING`), subconsultas (escalares,
//! `IN`, `ANY`/`ALL`, `EXISTS`, correlacionadas, no `FROM`), `WITH` e
//! `WITH RECURSIVE`, `VALUES`, `UNION`/`INTERSECT`/`EXCEPT`, `GROUP BY`/
//! `HAVING` com agregados estatísticos e `GROUP_CONCAT`, funções de janela
//! (`ROW_NUMBER`, `RANK`, `LAG`/`LEAD`, agregados com moldura), `CASE`,
//! `CAST`/`::`, `ORDER BY ... NULLS FIRST|LAST`, `LIMIT`/`OFFSET` e dezenas de
//! funções de texto, matemática, data/hora e JSON. DML com `INSERT ...
//! VALUES | SELECT | DEFAULT VALUES`, `INSERT OR REPLACE|IGNORE`,
//! `ON CONFLICT` (upsert), `UPDATE`/`DELETE` com qualquer `WHERE`, todos com
//! `RETURNING`; parâmetros (`?`, `?N`, `$N`) com comandos preparados; scripts
//! com vários comandos e transações (`BEGIN`/`COMMIT`/`ROLLBACK`/`SAVEPOINT`)
//! via [`crate::mvcc::Session`]. Tudo vive no espaço de chaves reservado
//! `0xFF` da árvore primária, então herda WAL, recuperação, compressão,
//! overflow, MVCC e replicação sem código novo.
//!
//! Layout (ids em big-endian para manter a ordem):
//!
//! | chave                                   | valor                     |
//! |-----------------------------------------|---------------------------|
//! | `FF 'c' <nome>`                         | esquema da tabela (JSON)  |
//! | `FF 'v' <nome>`                         | view (JSON: consulta)     |
//! | `FF 'q'`                                | próximo id de tabela      |
//! | `FF 's' <tid>`                          | próximo rowid/sequência   |
//! | `FF 't' <tid> <pk>`                     | linha codificada          |
//! | `FF 'x' <tid> <iid> <valores> <pk>`     | `<pk>`                    |
//!
//! `<pk>` e `<valores>` usam [`value::encode_key`], que preserva a ordem e é
//! auto-delimitada: scans por faixa/prefixo de chave primária e buscas por
//! igualdade nas primeiras colunas de um índice viram scans de prefixo na
//! B+ Tree. Valores indexados com mais de 256 bytes são truncados na entrada e
//! conferidos na linha, então o índice aceita textos de qualquer tamanho.
//!
//! ```
//! use mini_db::{Db, ExecResult};
//! # let dir = std::env::temp_dir().join(format!("minidb-doc-rel-{}", std::process::id()));
//! let mut db = Db::open(&dir)?;
//! db.execute_sql("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INT CHECK (age >= 0))")?;
//! db.execute_sql("INSERT INTO users (name, age) VALUES ('ana', 31), ('bia', 25)")?;
//! let ExecResult::Table { rows, .. } = db.execute_sql(
//!     "SELECT name, RANK() OVER (ORDER BY age DESC) FROM users WHERE age > (SELECT AVG(age) FROM users)",
//! )? else { unreachable!() };
//! assert_eq!(rows[0][0].to_string(), "ana");
//! # db.close()?; drop(db); std::fs::remove_dir_all(dir).unwrap();
//! # Ok::<(), mini_db::Error>(())
//! ```

mod exec;
pub mod func;
pub mod parser;
mod pgcatalog;
mod pgmore;
pub mod regex;
pub mod rewrite;
mod search;
pub mod value;
mod window;
mod write;

pub(crate) use write::WritePlan;

pub(crate) use exec::{Overlay, Writes};
pub use exec::{INDEX_VALUE_BYTES, MAX_PK_BYTES, MAX_RECURSION};
pub use func::{parse_datetime, set_conn_info, set_current_user, ConnInfo};
pub use value::{Type, Value};

use crate::db::{Db, ExecResult};
use crate::error::{Error, Result};
use crate::mvcc::SnapshotView;

/// Leitura de chaves (banco atual, snapshot MVCC ou transação).
pub(crate) trait Source {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    /// Visita `[start, end)` em ordem; `visit` devolve `false` para parar.
    fn scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()>;

    /// Uma verificação de integridade (UNIQUE, filhas de uma linha pai) depende
    /// de `[start, end)` não mudar até o commit. Só transações registram: fora
    /// delas o comando já roda sozinho, sob o lock do escritor.
    fn guard_unchanged(&self, _start: &[u8], _end: &[u8]) {}

    /// Uma chave estrangeira depende de `[start, end)` continuar com ao menos
    /// uma entrada até o commit (a linha pai). Só transações registram.
    fn guard_present(&self, _start: &[u8], _end: &[u8]) {}
}

impl Source for Db {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_raw(key)
    }

    fn scan(
        &self,
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
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get_raw(key)
    }

    fn scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()> {
        self.scan_raw(start, end, visit)
    }
}

/// Comando analisado uma vez para executar várias vezes.
#[derive(Clone, Debug)]
pub struct Prepared {
    stmt: parser::Stmt,
    params: usize,
}

impl Prepared {
    /// Quantos parâmetros o comando espera.
    pub fn param_count(&self) -> usize {
        self.params
    }

    /// `SELECT`, `VALUES`, `SHOW ...`, `DESCRIBE` e `EXPLAIN`.
    pub fn is_read_only(&self) -> bool {
        matches!(
            self.stmt,
            parser::Stmt::Query(_)
                | parser::Stmt::ShowTables
                | parser::Stmt::ShowIndexes(_)
                | parser::Stmt::ShowTriggers(_)
                | parser::Stmt::ShowCreate(_)
                | parser::Stmt::Describe(_)
                | parser::Stmt::ShowUsers
                | parser::Stmt::ShowGrants(_)
                | parser::Stmt::Explain(..)
        )
    }

    /// `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `RELEASE`.
    pub fn is_transaction_control(&self) -> bool {
        self.stmt.is_transaction_control()
    }

    pub(crate) fn stmt(&self) -> &parser::Stmt {
        &self.stmt
    }

    fn check(&self, params: &[Value]) -> Result<()> {
        if params.len() != self.params {
            return Err(Error::Sql(format!(
                "o comando espera {} parâmetro(s), recebeu {}",
                self.params,
                params.len()
            )));
        }
        Ok(())
    }
}

pub fn prepare(sql: &str) -> Result<Prepared> {
    let (stmt, params) = parser::parse(sql)?;
    Ok(Prepared { stmt, params })
}

/// Subexpressões diretas de uma expressão (para percorrer a AST).
pub(crate) fn expr_children(e: &parser::Expr) -> Vec<&parser::Expr> {
    exec::children(e)
}

/// Divide um script nos seus comandos (`;`), respeitando aspas e comentários.
pub fn split_statements(sql: &str) -> Result<Vec<&str>> {
    parser::split_statements(sql)
}

/// Executa um comando relacional (leitura ou escrita) no banco.
pub fn execute(db: &mut Db, sql: &str) -> Result<ExecResult> {
    execute_prepared(db, &prepare(sql)?, &[])
}

pub(crate) fn execute_prepared(db: &mut Db, p: &Prepared, params: &[Value]) -> Result<ExecResult> {
    p.check(params)?;
    if let Some(result) = exec::read(db, &p.stmt, params) {
        return result;
    }
    if db.is_read_only() {
        return Err(Error::ReadOnly);
    }
    let plan = write::plan_write(db, &p.stmt, params)?;
    db.write_internal_events(plan.ops, plan.changes, plan.notifications)?;
    Ok(plan.result)
}

/// Executa só leitura sobre qualquer fonte (banco, snapshot ou transação).
pub(crate) fn query_prepared(
    src: &dyn Source,
    p: &Prepared,
    params: &[Value],
) -> Result<ExecResult> {
    p.check(params)?;
    exec::read(src, &p.stmt, params).unwrap_or_else(|| {
        Err(Error::Sql(
            "somente leitura: use execute_sql para escritas".into(),
        ))
    })
}

/// Planeja uma escrita relacional lendo de `src` (banco, snapshot ou
/// transação com escritas próprias sobrepostas).
pub(crate) fn plan_write(src: &dyn Source, p: &Prepared, params: &[Value]) -> Result<WritePlan> {
    p.check(params)?;
    if p.is_read_only() {
        return Err(Error::Sql("comando de leitura".into()));
    }
    write::plan_write(src, &p.stmt, params)
}
