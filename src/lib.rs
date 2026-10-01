//! # Mini-DB
//!
//! Banco de dados embarcado sem dependências externas: SQL relacional com chaves
//! estrangeiras, views, funções de janela, CTEs recursivas e transações
//! ([`rel`], [`mvcc::Session`]), chave-valor com TTL, leitura paralela e
//! MVCC serializável ([`mvcc`]), replicação cifrada com failover
//! ([`replication`]), compressão ([`codec`]) e valores de até 64 MiB sobre páginas
//! de 4 KiB, B+ Tree com overflow, buffer pool e WAL com CRC32 — com adaptadores
//! CLI, TCP, HTTP/JSON (com token) e ABI C.
//!
//! ```
//! use mini_db::{BatchOp, Db};
//! use std::time::Duration;
//! # let dir = std::env::temp_dir().join(format!("minidb-doc-lib-{}", std::process::id()));
//! let mut db = Db::open(&dir)?;
//! db.put(b"user:1", b"ana")?;
//! db.put_with_ttl(b"cache:1", b"tmp", Duration::from_secs(30))?;
//! db.write_batch(&[BatchOp::Put { key: b"user:2".to_vec(), value: b"bia".to_vec() }])?;
//! assert_eq!(db.count(b"user:", Some(b"user;"))?, 2);
//! let users: Vec<_> = db.scan_prefix(b"user:")?.collect::<mini_db::Result<_>>()?;
//! assert_eq!(users.len(), 2);
//! db.close()?;
//! # drop(db); std::fs::remove_dir_all(dir).unwrap();
//! # Ok::<(), mini_db::Error>(())
//! ```

pub mod auth;
pub mod backup;
pub mod bignum;
pub mod bloom;
pub mod btree;
pub mod buffer;
pub mod catalog;
pub mod cmd;
pub mod codec;
pub mod config;
pub mod crypto;
pub mod curve25519;
pub mod db;
pub mod ecc;
pub mod encryption;
pub mod error;
pub mod events;
pub mod ffi;
pub mod http;
pub mod index;
pub mod inspect;
pub mod json;
pub mod metrics;
pub mod mvcc;
pub mod page;
pub mod pg;
pub mod pubkey;
pub mod rel;
pub mod replica;
pub mod replication;
pub mod rsa;
pub mod server;
pub mod sql;
pub mod tls;
pub mod verify;
pub mod wal;
pub mod x509;

pub use config::Config;
pub use db::RESERVED_PREFIX;
pub use db::{
    prefix_successor, simulate_crash_after_wal, BatchOp, Db, DbStats, ExecResult, KeyTtl, Row,
    ScanIter,
};
pub use error::{Error, Result};
pub use inspect::PageStats;
pub use metrics::Metrics;
pub use page::{MetaInfo, MAX_KEY_LEN, MAX_VALUE_LEN, PAGE_SIZE};
pub use sql::{parse_sql, Statement};
pub use verify::VerifyReport;
pub use wal::WalRecord;
