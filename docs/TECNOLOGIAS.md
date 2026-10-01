# Tecnologias do Mini-DB

## Núcleo (do zero)

- Rust 2021 / rustc 1.89+
- Páginas 4 KiB, B+ Tree (primária, índice por valor e TTL) com overflow, buffer pool LRU
- WAL com CRC32 e checksum de página CRC16, ambos por tabela gerada em `const`
- Iteradores por folha, lotes atômicos, TTL com expiração preguiçosa
- Compressão LZ77 (`src/codec.rs`), MVCC (`src/mvcc.rs`), replicação (`src/replication.rs`)
- SQL relacional próprio (`src/rel/`): parser, planejador por custo, FTS/HNSW/espacial, regex
- Criptografia própria, sem bibliotecas: SHA-2, HMAC, PBKDF2, ChaCha20-Poly1305, X25519,
  Ed25519, ECDSA P-256/P-384, RSA, X.509 e TLS 1.3 (`src/crypto.rs`, `curve25519.rs`,
  `ecc.rs`, `rsa.rs`, `bignum.rs`, `pubkey.rs`, `x509.rs`, `tls.rs`) — sem auditoria externa
- Sem RocksDB, sem SQLite no hot path

## Interfaces (padrões de indústria, implementação própria)

| Padrão | Onde |
| --- | --- |
| HTTP/1.1 + JSON (e HTTPS) | `src/http.rs` |
| Protocolo PostgreSQL v3 (SCRAM-SHA-256, TLS) | `src/pg.rs`, `src/rel/pgcatalog.rs` |
| TCP de linhas | `src/server.rs`, `src/cmd.rs` |
| Prometheus text exposition | `src/metrics.rs` |
| OpenAPI 3 mínimo | `GET /openapi.json` |
| ABI C | `src/ffi.rs`, `include/minidb.h` |
| TOML reduzido + env | `src/config.rs` |
| JSONL backup | `src/backup.rs` |
| Docker / Compose | `Dockerfile`, `docker-compose.yml` |
| GitHub Actions | `.github/workflows/ci.yml` |

Clientes de referência: `clients/minidb_client.py`, `clients/minidb_client.ts`.

Dependências Cargo: nenhuma. O projeto usa apenas a biblioteca padrão e mantém o
núcleo sem dependência de um motor de banco externo ou runtime obrigatório.

A crate também produz `rlib`, `cdylib` e `staticlib` para consumidores Rust e C.

## Qualidade (fora do núcleo)

| Ferramenta | Onde | Observação |
| --- | --- | --- |
| Teste baseado em modelo | `tests/model_based.rs` | PRNG próprio, sem dependências |
| Robustez de decodificadores | `tests/robustness.rs` | Roda no `cargo test` estável |
| libFuzzer via `cargo-fuzz` | `fuzz/` | Crate separado; única dependência externa do repositório |
| Contrato C compilado e executado | `tests/ffi_header.c` | `cc` + `libmini_db.a` |
| Clientes Python/TypeScript | `scripts/clients_smoke.sh` | Servidor real, `tsc --strict` |
| Benchmark com percentis | `src/bin/minidb-bench.rs` | Saída tabela ou `--json` |

Detalhes em [QUALIDADE.md](QUALIDADE.md).
