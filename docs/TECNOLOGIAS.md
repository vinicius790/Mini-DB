# Tecnologias do Mini-DB 0.3

## Núcleo (do zero)

- Rust 2021 / rustc 1.89+
- Páginas 4 KiB, B+ Tree (primária, índice por valor e TTL), buffer pool LRU
- WAL com CRC32 e checksum de página CRC16, ambos por tabela gerada em `const`
- Iteradores por folha, lotes atômicos, TTL com expiração preguiçosa
- Sem RocksDB, sem SQLite no hot path

## Interfaces (padrões de indústria, implementação própria)

| Padrão | Onde |
| --- | --- |
| HTTP/1.1 + JSON | `src/http.rs` |
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
