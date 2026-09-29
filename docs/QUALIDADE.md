# Qualidade e testes

O núcleo não tem dependências; a estratégia de testes também não, exceto o
fuzzing, que vive no crate separado `fuzz/`.

## Camadas de teste

| Camada | Arquivo | O que garante |
| --- | --- | --- |
| Unidade | `src/**` (`#[cfg(test)]`) | Página, CRC (vetores de referência), JSON, SQL, HTTP, TCP, FFI, prefixos |
| Integração | `tests/*.rs` | B+ Tree, scans, WAL, crash, transações, índice, backup, réplica, TTL, lotes |
| Crash real | `tests/crash_regressions.rs` | Subprocesso encerrado com `exit` sem destrutores |
| Estrutura | `tests/delete_structure.rs` | Folhas esvaziadas, `VACUUM`, limite do índice |
| Modelo | `tests/model_based.rs` | Sequências aleatórias equivalem a um `BTreeMap` com crashes, reaberturas, transações, checkpoint, vacuum e TTL |
| Robustez | `tests/robustness.rs` | SQL, JSON, WAL e páginas com entrada arbitrária não entram em pânico; JSON e WAL reencodam idêntico |
| Doctests | `src/lib.rs`, `src/db.rs` | Exemplos da documentação compilam e rodam |
| Contrato C | `tests/ffi_header.c` | Header compila em C11 estrito e o binário linkado roda |
| Clientes | `scripts/clients_smoke.sh` | Python e TypeScript (`tsc --strict`) contra servidor real |
| Demo de crash | `scripts/demo_crash_recover.sh` | `kill -9` real e recovery via CLI |

## Teste baseado em modelo

```sh
cargo test --release --test model_based                          # 4 sementes × 600 passos
MINIDB_MODEL_STEPS=20000 cargo test --release --test model_based # estresse
MINIDB_MODEL_SEED=1337 cargo test --release --test model_based   # reproduz uma semente
```

Pool de 6 frames força expulsões para o spill; o espaço pequeno de chaves força
upserts e folhas que esvaziam e voltam a encher. Uma falha imprime `seed` e
`step`, suficientes para reproduzir.

## Fuzzing

Requer `cargo install cargo-fuzz` e toolchain nightly:

```sh
cd fuzz
cargo +nightly fuzz run sql_parser  -- -max_total_time=60
cargo +nightly fuzz run json_parser -- -max_total_time=60
cargo +nightly fuzz run wal_record  -- -max_total_time=60
cargo +nightly fuzz run page_decode -- -max_total_time=60
```

Propriedades: nenhum pânico; JSON aceito sobrevive a `stringify → parse`; corpo de
WAL aceito é reencodado byte a byte. O teste de robustez estável cobre as mesmas
propriedades a cada `cargo test` (e já encontrou um bug real: floats inteiros como
`3.0` eram serializados como `3`).

## Benchmark

```sh
cargo run --release --bin minidb-bench -- 20000            # com fsync (padrão)
cargo run --release --bin minidb-bench -- 20000 --no-fsync # isola o custo de CPU
cargo run --release --bin minidb-bench -- 20000 --json     # para comparar execuções
```

Cargas: put sequencial, get aleatório (acerto), get ausente (Bloom), lotes de 100,
prefixo, contagem, delete aleatório, checkpoint, vacuum e reabertura com recovery.
Cada carga reporta ops/s, p50, p99 e máximo. Números valem só para a máquina local;
use-os para comparar versões, não para publicar.

## Critério de merge

`cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`,
`cargo test --all-targets --locked`, `cargo test --doc`, `cargo doc` sem avisos,
contrato C e smoke dos clientes. Todo invariante novo entra em
[INVARIANTES.md](INVARIANTES.md) e em um teste.
