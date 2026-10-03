# Mini-DB

[![ci](https://github.com/vinicius790/Mini-DB/actions/workflows/ci.yml/badge.svg)](https://github.com/vinicius790/Mini-DB/actions/workflows/ci.yml)

*English summary. The full documentation is in Portuguese: [README.md](README.md) and [docs/](docs).*

An embedded database written in Rust from scratch, with **no external Cargo
dependencies**. One engine exposes several faces over the same storage:

- **Relational SQL:** tables with `PRIMARY KEY`, `UNIQUE`, `NOT NULL`, `CHECK`, `DEFAULT`
  and foreign keys with cascading actions; composite indexes, views and materialized
  views, full `ALTER TABLE`; joins (hash join included), correlated subqueries, `WITH
  RECURSIVE`, set operations, `GROUP BY`/`HAVING`, aggregates with `FILTER`, window
  functions, 200+ functions, `RETURNING`, upsert, parameters and prepared statements,
  transactions with savepoints, triggers, `NOTIFY`/`LISTEN`, a change stream (SSE),
  `ANALYZE` with a cost-based planner and `EXPLAIN ANALYZE`.
- **Search:** full-text with BM25 ranking, vector search with HNSW, spatial search with
  a Z-order curve.
- **Security and operations:** users, roles and `GRANT`; SCRAM-SHA-256; encryption at
  rest (ChaCha20, PBKDF2); full and incremental physical backup with point-in-time
  restore.
- **PostgreSQL wire protocol:** `psql` and the PG drivers connect directly (port 5432),
  with native TLS 1.3, its own PKI and mutual TLS, and a virtual `pg_catalog`.
- **Key-value:** `put`/`get`/`scan`, per-key TTL, atomic batches, a value index.

Underneath: 4 KiB pages, a B+ Tree with overflow pages (values up to 64 MiB), a buffer
pool, LZ77 compression, a WAL with CRC32 and journal-based checkpoints, crash recovery,
MVCC (snapshot and serializable isolation) and authenticated, encrypted replication
with semi-synchronous mode, manual promotion and fencing. It ships as a Rust library, a
CLI, TCP and HTTP/JSON servers and a C ABI.

Requires **Rust 1.89+**. Current version: **1.3.0** ([CHANGELOG](CHANGELOG.md), in
Portuguese).

## Quick start

```sh
cargo run --bin minidb -- shell ./data                 # interactive session
cargo run --bin minidb -- exec ./data PUT hero Alucard # one command, then exit
cargo run --bin minidb -- http ./data 127.0.0.1:8080   # HTTP/JSON API
curl http://127.0.0.1:8080/health
```

As a library:

```rust
use mini_db::{BatchOp, Db};
use std::time::Duration;

let mut db = Db::open("./data")?;
db.put(b"user:1", b"ana")?;
db.put_with_ttl(b"session:9", b"token", Duration::from_secs(900))?;
db.write_batch(&[
    BatchOp::Put { key: b"user:2".to_vec(), value: b"bia".to_vec() },
    BatchOp::Delete { key: b"user:0".to_vec() },
])?; // all or nothing, even across a crash
db.execute_sql("CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT NOT NULL)")?;
db.close()?;
```

## Status and limits

Mini-DB is experimental. The network interfaces are development and integration tools,
not a security boundary: see [SECURITY.md](SECURITY.md) (in Portuguese) before exposing
any port.

- With no token and no users the database runs in *open mode*: any local process can
  use the HTTP and TCP APIs. Set `MINIDB_TOKEN` or create users.
- The cryptography (TLS 1.3, X.509, RSA, ECDSA, Ed25519, AES-GCM, ChaCha20-Poly1305) is written
  from scratch and has **not** been externally audited. Where that matters, terminate
  TLS in an audited proxy.
- One writer at a time (like SQLite and LMDB); readers run in parallel.
- `SNAPSHOT` isolation (the default) allows write skew; use `BEGIN ISOLATION LEVEL
  SERIALIZABLE` when that matters. `UNIQUE` and foreign keys are revalidated at commit
  under both levels.
- Failover is manual (`PROMOTE`); there is no consensus protocol.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --locked
```

`make ci` runs the lint, doc and test steps. Fuzz targets live in [`fuzz/`](fuzz).
License: [MIT](LICENSE).
