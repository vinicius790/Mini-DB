# Mini-DB

[![ci](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

Banco de dados embarcado escrito em Rust, do zero e **sem nenhuma dependência Cargo
externa**. Um único motor oferece duas faces sobre o mesmo armazenamento:

- **Relacional:** tabelas tipadas, chave primária, índices secundários e `UNIQUE`,
  `JOIN`/`LEFT JOIN`, `GROUP BY`/`HAVING`, agregados, `ORDER BY`, `LIMIT`/`OFFSET`,
  `ALTER TABLE` e `EXPLAIN` com planejador que escolhe entre chave primária, faixa e
  índice.
- **Chave-valor:** `put`/`get`/`scan`, TTL por chave, lotes atômicos e índice por valor.

Por baixo: páginas de 4 KiB, B+ Tree, buffer pool LRU, **compressão LZ77 própria**,
WAL com CRC32, checkpoint atômico, recovery após crash, **MVCC** (snapshots e
transações otimistas entre threads) e **replicação primário → réplicas** por streaming
do log de commits. Exposto como biblioteca Rust, CLI, TCP, HTTP/JSON e ABI C.

Requer **Rust 1.89+**. Versão atual: **0.5.0** ([CHANGELOG](CHANGELOG.md)).

## Começar

```sh
cargo run --bin minidb -- shell ./data                 # sessão interativa
cargo run --bin minidb -- exec ./data PUT hero Alucard # um comando e fecha
cargo run --bin minidb -- http ./data 127.0.0.1:8080   # API HTTP/JSON
curl http://127.0.0.1:8080/health
```

```sh
curl -X PUT http://127.0.0.1:8080/v1/kv \
  -H "Content-Type: application/json" \
  -d '{"key":"hero","value":"Alucard"}'
curl --get --data-urlencode "key=hero" http://127.0.0.1:8080/v1/kv
```

Como biblioteca (`cargo run --example quickstart`):

```rust
use mini_db::{BatchOp, Db};
use std::time::Duration;

let mut db = Db::open("./data")?;
db.put(b"user:1", b"ana")?;
db.put_with_ttl(b"session:9", b"token", Duration::from_secs(900))?;
db.write_batch(&[
    BatchOp::Put { key: b"user:2".to_vec(), value: b"bia".to_vec() },
    BatchOp::Delete { key: b"user:0".to_vec() },
])?; // tudo ou nada, mesmo com crash
for row in db.scan_prefix(b"user:")? {   // uma folha por vez
    let (key, value) = row?;
}
let total = db.count(b"user:", Some(b"user;"))?;
db.close()?;
```

## SQL relacional

```sql
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, age INT);
CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INT NOT NULL, total REAL);
CREATE INDEX orders_user ON orders (user_id);
INSERT INTO users (name, email, age) VALUES ('ana', 'ana@x', 31), ('bia', 'bia@x', 25);

SELECT u.name, COUNT(o.id) AS pedidos, SUM(o.total) AS gasto
FROM users u LEFT JOIN orders o ON o.user_id = u.id
WHERE u.age BETWEEN 18 AND 65
GROUP BY u.name HAVING COUNT(o.id) > 0
ORDER BY gasto DESC LIMIT 10;

EXPLAIN SELECT * FROM orders o JOIN users u ON u.id = o.user_id;
-- SCAN orders
-- JOIN users USING LOOKUP ON id (index nested loop)
```

Tipos `INTEGER`, `REAL`, `TEXT`, `BOOLEAN` e `NULL`; restrições `PRIMARY KEY`,
`NOT NULL`, `UNIQUE`, `DEFAULT`; `INTEGER PRIMARY KEY` autoincrementa (tabelas sem PK
ganham rowid oculto). Expressões com `AND/OR/NOT` (lógica de três valores), `LIKE`,
`IN`, `BETWEEN`, `IS NULL`, aritmética, `||` e funções `lower`, `upper`, `length`,
`abs`, `round`, `substr`, `trim`, `coalesce`, `typeof`. Também `SHOW TABLES`,
`DESCRIBE t`, `DROP TABLE/INDEX` e `ALTER TABLE t ADD COLUMN`. Cada comando é atômico
(um frame no WAL) e respeita `BEGIN`/`COMMIT`/`ROLLBACK`. O dialeto chave-valor
(`SELECT … FROM kv`) continua disponível. Detalhes: [MOTOR-0.5](docs/MOTOR-0.5.md).

## Concorrência (MVCC) e replicação

```rust
use mini_db::{mvcc::SharedDb, Db};

let db = SharedDb::new(Db::open("./data")?);        // Clone + Send entre threads
let snap = db.snapshot()?;                           // visão congelada
let mut txn = db.begin()?;                           // snapshot isolation otimista
txn.put(b"saldo", b"90")?;
txn.commit()?;                                       // Err(Conflict) se alguém escreveu antes
snap.query("SELECT SUM(total) FROM orders")?;        // SQL sobre o snapshot
```

```sh
minidb http ./primario 127.0.0.1:8080 --primary 127.0.0.1:9000
minidb http ./replica  127.0.0.1:8081 --replica-of 127.0.0.1:9000   # somente leitura
```

A réplica recebe um snapshot completo quando está atrasada demais e, depois, cada
commit do primário; o LSN aplicado é gravado no mesmo lote atômico dos dados, então
reiniciar a réplica nunca duplica nem pula commits.

## Interfaces

| Interface | Resumo | Referência |
| --- | --- | --- |
| Rust | `mini_db::Db` (SQL relacional via `execute_sql`), `mvcc::SharedDb` (snapshots/transações), `replication`; `put`, `put_with_ttl`, `get`, `delete`, `write_batch`, `iter`, `scan_prefix`, `count`, `scan_page`, TTL, transações, `checkpoint`, `vacuum`, índice por valor, SQL, `verify`, `page_stats` | [INTERFACES.md](docs/INTERFACES.md) |
| CLI | `minidb shell \| exec \| serve \| http \| export \| import`; comandos `SETEX`, `TTL`, `PREFIX`, `COUNT`, `PAGES`… | [INTERFACES.md](docs/INTERFACES.md#cli) |
| TCP | Um comando UTF-8 por linha (mesmo interpretador da CLI), padrão `127.0.0.1:7432` | [INTERFACES.md](docs/INTERFACES.md#tcp) |
| HTTP | `/v1/kv`, `/v1/scan`, `/v1/count`, `/v1/batch`, `/v1/ttl`, `/v1/expire`, `/v1/purge`, `/v1/pages`, `/v1/sql`, `/v1/stats`, `/health`, `/metrics`, `/openapi.json` | [HTTP.md](docs/HTTP.md) |
| C | `rlib`, `cdylib`, `staticlib` + [`include/minidb.h`](include/minidb.h); família `*_bytes` para bytes arbitrários | [INTERFACES.md](docs/INTERFACES.md#abi-c) |
| Clientes | [Python](clients/minidb_client.py) (stdlib) e [TypeScript](clients/minidb_client.ts) (`fetch`) | [INTERFACES.md](docs/INTERFACES.md#clientes-http-de-referência) |

Ferramentas: `minidb-verify` (invariantes), `minidb-inspect` (forense de páginas) e
`minidb-bench` (cargas com p50/p99 e `--json` — números locais, não publicados de propósito).

## Arquitetura em uma página

```
SQL relacional ─┐                          ┌─► MVCC (imagens anteriores p/ snapshots)
CLI/TCP/HTTP/C ─┼─► Db ── commit único ────┼─► Change feed ──► réplicas (TCP)
SharedDb ───────┘   │                      └─► B+ Trees (primária · índice · TTL)
                    ├──► WAL (CRC32, fsync)          │  valores comprimidos (LZ77)
                    └──► Bloom filter                └─► BufferPool LRU ──► data.mdb
```

- **Escrita:** caminho único — validação, registro no WAL (frame atômico para lotes,
  `fsync` por padrão) e só então aplicação às árvores; o recovery usa a mesma função.
- **Leitura:** iteradores descem até a folha inicial e seguem o encadeamento uma folha
  por vez; chaves expiradas nunca aparecem.
- **Checkpoint:** monta `data.mdb.next`, sincroniza, publica por rename e trunca o WAL.
- **Recovery:** refaz as operações confirmadas após o último checkpoint; cauda truncada
  e transações sem `COMMIT` são descartadas.
- **Exclusão:** remove a célula da folha sem reestruturar nós internos; `VACUUM`
  reconstrói as árvores compactas e encolhe o arquivo.

Detalhes: [ARQUITETURA](docs/ARQUITETURA.md) · [formato de página](docs/FORMATO-PAGINA.md) ·
[WAL](docs/WAL.md) · [recovery](docs/RECOVERY.md) · [invariantes](docs/INVARIANTES.md) ·
[índice por valor](docs/INDICE-SECUNDARIO-STUB.md) · [motor 0.5](docs/MOTOR-0.5.md) · [réplica](docs/REPLICA.md) ·
[qualidade e testes](docs/QUALIDADE.md).

## Persistência e backup

O diretório de dados contém `data.mdb`, `wal.log`, `LOCK` e, temporariamente,
`data.mdb.spill`. Apenas um processo escritor local abre o diretório. `fsync = true` é
o padrão; desativá-lo troca durabilidade por desempenho. Metadados corrompidos geram
erro — o arquivo nunca é reinicializado silenciosamente.

`minidb export [dir] [out.jsonl]` grava JSONL `minidb-jsonl/v1` com chave e valor em
hexadecimal (lossless); `minidb import` aceita esse formato e o legado textual, em uma
única transação. Mantenha backups fora do diretório do banco e teste a restauração.

Configuração: [`minidb.toml`](minidb.toml) ou variáveis `MINIDB_PATH`, `MINIDB_HTTP`,
`MINIDB_TCP`, `MINIDB_POOL`, `MINIDB_FSYNC`. Docker: `docker compose up`.

## Limites

- Chaves: 1–128 bytes. Valores (e linhas SQL codificadas): até 1024 bytes lógicos,
  sem páginas de overflow. Com o índice por valor ativo, `chave + valor + 2` também
  deve caber em 128 bytes; entradas de índice SQL também cabem em 128 bytes.
- Chaves iniciadas pelo byte `0xFF` são reservadas ao motor (tabelas SQL, replicação).
- SQL relacional sem subconsultas, `UNION`, chaves compostas, `CASE` ou parâmetros
  preparados; joins são nested loop (com busca por chave/índice quando possível).
- MVCC com mutex global por operação: snapshots nunca bloqueiam escritores por longos
  períodos, mas leituras e escritas não rodam em paralelo de verdade. Snapshot
  isolation permite write skew.
- HTTP e TCP não têm autenticação nem TLS; aceitam até 128 conexões simultâneas cada
  (as excedentes recebem `503`/`ERR server busy`) e serializam o acesso ao banco.
- TTL tem resolução de milissegundos pelo relógio do sistema; chaves expiradas ocupam
  espaço até `PURGE`/`VACUUM`.
- Replicação assíncrona com um único primário, sem eleição nem failover automático;
  o feed de commits fica em memória (réplicas fazem ressincronização completa após
  reiniciar o primário) e o protocolo não tem autenticação. Checksums detectam corrupção
  acidental, não adulteração. Garantias em falha de energia dependem do filesystem.

Veja [SECURITY.md](SECURITY.md) e o desenho da 0.5 em [MOTOR-0.5.md](docs/MOTOR-0.5.md).

## Desenvolvimento

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --locked
cargo test --doc
cc -std=c11 -Wall -Wextra -Werror -fsyntax-only -I include tests/ffi_header.c
bash scripts/demo_crash_recover.sh   # crash real (kill -9) + recovery
bash scripts/clients_smoke.sh        # clientes Python/TypeScript contra servidor real
MINIDB_MODEL_STEPS=20000 cargo test --release --test model_based  # estresse
```

A suíte inclui teste baseado em modelo (operações aleatórias com crashes comparadas a
um `BTreeMap`), robustez de decodificadores, fuzzing em [`fuzz/`](fuzz) e benchmark
com percentis — veja [QUALIDADE.md](docs/QUALIDADE.md).
Atalhos: `make ci`, `make bench`, `python tools/dev.py test|build|bench|smoke|package`.
Contribuições: [CONTRIBUTING.md](CONTRIBUTING.md). Licença: [MIT](LICENSE).
