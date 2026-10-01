# Mini-DB

[![ci](https://github.com/vinicius790/Mini-DB/actions/workflows/ci.yml/badge.svg)](https://github.com/vinicius790/Mini-DB/actions/workflows/ci.yml)

*English summary: [README.en.md](README.en.md).*

Banco de dados embarcado escrito em Rust, do zero e **sem nenhuma dependência Cargo
externa**. Um único motor oferece duas faces sobre o mesmo armazenamento:

- **Relacional:** tabelas com `PRIMARY KEY`, `UNIQUE`, `NOT NULL`, `CHECK`, `DEFAULT`
  com expressão, `AUTOINCREMENT`/`SERIAL` e **chaves estrangeiras** (`ON DELETE`/
  `ON UPDATE` `CASCADE`, `SET NULL`, `SET DEFAULT`, `RESTRICT`); índices compostos,
  **views**, `ALTER TABLE` completo, `TRUNCATE`; consultas com `JOIN` (`INNER`, `LEFT`,
  `RIGHT`, `FULL`, `CROSS`, `USING`) e hash join, subconsultas (correlacionadas, `IN`,
  `ANY`/`ALL`, `EXISTS`), `WITH` e **`WITH RECURSIVE`**, `VALUES`, `UNION`/`INTERSECT`/
  `EXCEPT`, `GROUP BY`/`HAVING` com agregados estatísticos, **funções de janela**
  (`ROW_NUMBER`, `RANK`, `LAG`/`LEAD`, agregados com moldura), `CASE`, `CAST`, mais de 200
  funções (texto, matemática, data/hora, JSON, hash), `RETURNING`, upsert
  (`ON CONFLICT`, `INSERT OR REPLACE`), parâmetros (`?`, `$1`), comandos preparados,
  **scripts** e transações SQL (`BEGIN`/`COMMIT`/`ROLLBACK`/`SAVEPOINT`), **gatilhos**
  (`NEW`/`OLD`, `RAISE`), **views materializadas** (com atualização automática),
  `NOTIFY`/`LISTEN` e **stream de mudanças** (SSE), `ANALYZE` com **planejador por
  custo**, `EXPLAIN ANALYZE`.
- **Busca avançada:** **full-text** com ranking BM25 (`CREATE FULLTEXT INDEX`,
  `MATCH (cols) AGAINST ('termo "frase" pref* -excluído OR outro')`, radicalização
  PT/EN, `fts_highlight`), **vetorial** com HNSW (`CREATE VECTOR INDEX ... WITH (metric
  = 'cosine'|'l2'|'dot')`, `ORDER BY emb <=> '[...]' LIMIT k`, `vec_*`) e **espacial**
  com curva Z 2D/3D (`CREATE SPATIAL INDEX`, caixas `BETWEEN`, `st_dwithin`,
  `st_distance_sphere`).
- **Segurança e operação:** **usuários, papéis e `GRANT`** por tabela (senhas
  SCRAM-SHA-256, privilégios conferidos por comando em TCP, HTTP e PostgreSQL),
  **criptografia em repouso** (ChaCha20, senha → PBKDF2), **backup físico completo e
  incremental** com **restauração a um ponto no tempo** (por LSN ou instante).
- **Protocolo PostgreSQL:** `psql` e os drivers PG conectam direto (`minidb pg`, porta
  5432): consulta simples e estendida, parâmetros, SCRAM-SHA-256, SQLSTATE, **TLS 1.3
  nativo** (certificado autoassinado, ou **PKI própria** — `minidb cert ca|server|client` —
  com cadeia de CA e **certificado de cliente/mTLS** que autentica o usuário do banco;
  chaves **Ed25519, ECDSA P-256/P-384 ou RSA 2048–4096**, inclusive certificados de CAs
  públicas; `sslmode=verify-full`), **`pg_catalog` e `information_schema` virtuais com dados reais**
  (tabelas, índices, restrições, **gatilhos, funções/agregados, operadores, estatísticas do
  `ANALYZE`, papéis, `pg_stat_ssl`**; `\dt`, `\d` com FKs e gatilhos, `\df`, `\do`, `\dx`,
  `\du`... do psql funcionam) e **expressões regulares** (`~`, `regexp_replace`...).
  HTTP também em HTTPS (inclusive com certificado de cliente).
- **Chave-valor:** `put`/`get`/`scan`, TTL por chave, lotes atômicos e índice por valor.

Por baixo: páginas de 4 KiB, B+ Tree com **páginas de overflow** (valores de até
64 MiB, chaves de até 1 KiB), buffer pool com **leitura paralela**, **compressão LZ77
própria**, WAL com CRC32 e **checkpoint por journal** (proporcional ao que mudou),
recovery após crash, **MVCC** (snapshots, transações otimistas com isolamento de
snapshot ou **serializável**) e **replicação** autenticada e cifrada, com retomada pelo
WAL arquivado, modo semi-síncrono, promoção e fencing. Exposto como biblioteca Rust,
CLI, TCP e HTTP/JSON (ambos com token) e ABI C.

Requer **Rust 1.89+**. Versão atual: **1.3.0** ([CHANGELOG](CHANGELOG.md)).

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
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL CHECK (length(name) >= 2),
  email TEXT UNIQUE,
  age INT CHECK (age BETWEEN 0 AND 150),
  created TEXT DEFAULT current_timestamp
);
CREATE TABLE orders (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users ON DELETE CASCADE,
  total REAL CHECK (total >= 0),
  status TEXT DEFAULT 'open'
);
INSERT INTO users (name, email, age) VALUES ('ana', 'ana@x', 31), ('bia', 'bia@x', 25)
RETURNING id, created;

-- agregação, janela e CTE recursiva
SELECT u.name, COUNT(o.id) AS pedidos, SUM(o.total) AS gasto,
       RANK() OVER (ORDER BY SUM(o.total) DESC) AS posicao
FROM users u LEFT JOIN orders o ON o.user_id = u.id
GROUP BY u.name HAVING COUNT(o.id) > 0
ORDER BY posicao LIMIT 10;

WITH RECURSIVE dias(d) AS (
  SELECT date('now', 'start of month') UNION ALL SELECT date(d, '+1 day') FROM dias WHERE d < date('now')
)
SELECT d, (SELECT COUNT(*) FROM users WHERE date(created) = d) AS cadastros FROM dias;

CREATE VIEW resumo AS SELECT user_id, SUM(total) AS total FROM orders GROUP BY user_id;
INSERT INTO totals (user_id, total) SELECT user_id, total FROM resumo
ON CONFLICT (user_id) DO UPDATE SET total = excluded.total;

BEGIN;                                   -- em Session / conexão TCP / script HTTP
UPDATE acc SET saldo = saldo - 30 WHERE id = 1;
UPDATE acc SET saldo = saldo + 30 WHERE id = 2;
COMMIT;
```

```rust
db.execute_sql_params("SELECT * FROM users WHERE email = ?", &[Value::Text(email)])?;
let q = db.prepare("INSERT INTO t VALUES ($1, $2)")?;       // analisa uma vez
db.execute_prepared(&q, &[Value::Int(1), Value::Text("a".into())])?;
db.execute_sql("INSERT INTO a VALUES (1); INSERT INTO b VALUES (1)")?; // script atômico

let shared = SharedDb::new(db);
let mut s = shared.session();                                // transações explícitas
s.execute("BEGIN ISOLATION LEVEL SERIALIZABLE; UPDATE ...; SAVEPOINT p; ...; COMMIT")?;
let mut txn = shared.begin()?;                               // ou SQL direto na Txn
txn.sql("DELETE FROM orders WHERE status = 'cancelled'")?;
txn.commit()?;
```

Tipos `INTEGER`, `REAL`, `TEXT`, `BOOLEAN` (com os sinônimos usuais: `VARCHAR`,
`DOUBLE PRECISION`, `TIMESTAMP`, `JSON`, `SERIAL`...). Integridade: `PRIMARY KEY`
(simples ou composta, autoincremento), `UNIQUE`, `NOT NULL`, `CHECK`, `DEFAULT
<expressão>` e `FOREIGN KEY` com ações referenciais em cascata dentro do mesmo lote.
Esquema: `CREATE/DROP TABLE|INDEX|VIEW`, `ALTER TABLE ... ADD|DROP|RENAME COLUMN,
RENAME TO, ALTER COLUMN SET|DROP DEFAULT|NOT NULL`, `TRUNCATE`, `SHOW TABLES|INDEXES|
CREATE TABLE`, `DESCRIBE`. Cada comando é atômico (um frame no WAL); scripts e
transações SQL ficam atômicos no commit. O dialeto chave-valor (`SELECT … FROM kv`)
continua disponível. Referência completa: [docs/SQL.md](docs/SQL.md).

## Concorrência (MVCC) e replicação

```rust
use mini_db::{mvcc::SharedDb, Db};

let db = SharedDb::new(Db::open("./data")?);        // Clone + Send entre threads
db.read()?.query("SELECT ...")?;                     // leitores rodam em paralelo
let snap = db.snapshot()?;                           // visão congelada
let mut txn = db.begin_serializable()?;              // ou begin() (snapshot isolation)
txn.put(b"saldo", b"90")?;
txn.commit()?;                                       // Err(Conflict) se a validação falhar
snap.query("SELECT SUM(total) FROM orders")?;        // SQL sobre o snapshot
```

```sh
export MINIDB_REPL_SECRET=segredo-longo   # autentica e cifra o canal (ChaCha20 + HMAC)
export MINIDB_TOKEN=token-dos-clientes    # HTTP: Authorization: Bearer · TCP: AUTH
minidb http ./primario 127.0.0.1:8080 --primary 127.0.0.1:9000
minidb http ./replica  127.0.0.1:8081 --replica-of 127.0.0.1:9000 --primary 127.0.0.1:9001
curl -X POST -H "Authorization: Bearer $MINIDB_TOKEN" http://127.0.0.1:8081/v1/replication/promote
```

A réplica recebe um snapshot em pedaços quando é nova e, depois, cada commit do
primário; uma réplica que ficou para trás (inclusive depois de o primário reiniciar)
retoma pelo WAL arquivado. O LSN aplicado é gravado no mesmo lote atômico dos dados,
então reiniciar a réplica nunca duplica nem pula commits. Com `sync_replicas = N`, cada
commit espera `N` réplicas confirmarem. `PROMOTE` transforma uma réplica em primário
com época nova; o primário antigo se isola (somente leitura) ao encontrar a época maior.

## Interfaces

| Interface | Resumo | Referência |
| --- | --- | --- |
| Rust | `mini_db::Db` (SQL relacional via `execute_sql`), `mvcc::SharedDb` (snapshots/transações), `replication`; `put`, `put_with_ttl`, `get`, `delete`, `write_batch`, `iter`, `scan_prefix`, `count`, `scan_page`, TTL, transações, `checkpoint`, `vacuum`, índice por valor, SQL, `verify`, `page_stats` | [INTERFACES.md](docs/INTERFACES.md) |
| CLI | `minidb shell \| exec \| serve \| http \| pg \| backup \| restore \| encrypt \| decrypt \| rekey \| export \| import`; comandos `SETEX`, `TTL`, `PREFIX`, `COUNT`, `PAGES`… | [INTERFACES.md](docs/INTERFACES.md#cli) |
| TCP | Um comando UTF-8 por linha (mesmo interpretador da CLI), padrão `127.0.0.1:7432`; `AUTH usuário senha` | [INTERFACES.md](docs/INTERFACES.md#tcp) |
| PostgreSQL | Protocolo v3 na porta `5432`: `psql`, libpq, node-postgres, psycopg, JDBC; SCRAM-SHA-256 | [INTERFACES.md](docs/INTERFACES.md#protocolo-postgresql) |
| HTTP | `/v1/kv`, `/v1/scan`, `/v1/count`, `/v1/batch`, `/v1/ttl`, `/v1/expire`, `/v1/purge`, `/v1/pages`, `/v1/sql` (com `params`), `/v1/stats`, `/v1/replication`, `/v1/replication/promote`, `/v1/maintain`, `/health`, `/metrics`, `/openapi.json` | [HTTP.md](docs/HTTP.md) |
| C | `rlib`, `cdylib`, `staticlib` + [`include/minidb.h`](include/minidb.h); família `*_bytes` para bytes arbitrários | [INTERFACES.md](docs/INTERFACES.md#abi-c) |
| Clientes | [Python](clients/minidb_client.py) (stdlib) e [TypeScript](clients/minidb_client.ts) (`fetch`) | [INTERFACES.md](docs/INTERFACES.md#clientes-http-de-referência) |

Ferramentas: `minidb-verify` (invariantes), `minidb-inspect` (forense de páginas) e
`minidb-bench` (cargas com p50/p99 e `--json` — números locais, não publicados de propósito).

## Arquitetura em uma página

```
SQL relacional ─┐   leitores (RwLock, em paralelo)  ┌─► MVCC (imagens anteriores)
CLI/TCP/HTTP/C ─┼─► SharedDb ─► Db                  ├─► feed ─► réplicas (cifrado)
                │   escritor: plano ─► WAL+fsync ───┤     └─► WAL arquivado (retomada)
                │   (leitores seguem) ─► aplica ────┴─► B+ Trees (primária · índice · TTL)
                │                                       │ overflow + LZ77
                └─► Bloom filter                        └─► BufferPool ─► journal ─► data.mdb
```

- **Escrita:** caminho único — validação, registro no WAL (frame atômico para lotes,
  `fsync` por padrão) e só então aplicação às árvores; o recovery usa a mesma função.
- **Leitura:** iteradores descem até a folha inicial e seguem o encadeamento uma folha
  por vez; chaves expiradas nunca aparecem.
- **Checkpoint:** grava as páginas alteradas em `data.mdb.journal` (com CRC), sincroniza,
  escreve no lugar e apaga o journal; automático quando o WAL passa de 64 MiB.
- **Recovery:** refaz as operações confirmadas após o último checkpoint; cauda truncada
  e transações sem `COMMIT` são descartadas.
- **Exclusão:** remove a célula da folha sem reestruturar nós internos; páginas de
  overflow voltam à freelist na hora; `VACUUM` reconstrói as árvores em streaming em
  um arquivo novo e troca por rename (a manutenção automática decide quando).

Detalhes: [ARQUITETURA](docs/ARQUITETURA.md) · [formato de página](docs/FORMATO-PAGINA.md) ·
[WAL](docs/WAL.md) · [recovery](docs/RECOVERY.md) · [invariantes](docs/INVARIANTES.md) ·
[índice por valor](docs/INDICE-SECUNDARIO.md) · [motor 0.6](docs/MOTOR-0.6.md) ·
[SQL](docs/SQL.md) ·
[motor 0.5](docs/MOTOR-0.5.md) · [réplica](docs/REPLICA.md) ·
[qualidade e testes](docs/QUALIDADE.md).

## Persistência e backup

O diretório de dados contém `data.mdb`, `wal.log`, `LOCK`, `wal-archive/` (quando há
retenção para réplicas) e, temporariamente, `data.mdb.spill`, `data.mdb.journal` e
`vacuum.mdb`. Apenas um processo escritor local abre o diretório. `fsync = true` é
o padrão; desativá-lo troca durabilidade por desempenho. Metadados corrompidos geram
erro — o arquivo nunca é reinicializado silenciosamente.

`minidb backup [dir] <destino>` faz um **backup físico**: a primeira vez copia a imagem
consistente das páginas (após checkpoint) e o arquivo de chave; as seguintes são
**incrementais** (copiam os segmentos de WAL arquivados desde o completo). `minidb
restore <backup> <dir-novo> [--until-lsn N | --until-time 'AAAA-MM-DD HH:MM:SS']`
reconstrói o banco até o fim ou até um **ponto no tempo** (só transações confirmadas até
ali; marcas de relógio no WAL dão precisão de 1 s). Um banco criptografado restaura com
a mesma senha. `minidb export [dir] [out.jsonl]` grava JSONL `minidb-jsonl/v1` com chave
e valor em hexadecimal (lossless); `minidb import` aceita esse formato e o legado textual,
em uma única transação. Mantenha backups fora do diretório do banco e teste a restauração.

Criptografia em repouso: `passphrase` no `minidb.toml` ou `MINIDB_PASSPHRASE` ao criar o
banco cifra páginas e WAL (ChaCha20; ver [SECURITY.md](SECURITY.md)); a senha é exigida em
toda abertura.

Configuração: [`minidb.toml`](minidb.toml) ou variáveis `MINIDB_*` (caminho, endereços,
pool, fsync, token, senha de criptografia, porta PostgreSQL, conexões, corpo máximo,
segredo e modo síncrono da replicação, retenção de WAL, checkpoint e manutenção
automáticos). Docker: `docker compose up`.

## Limites

Os limites da 0.5 viraram capacidades (tabela completa em
[MOTOR-0.6](docs/MOTOR-0.6.md#o-que-era-limite-e-o-que-virou)). O que resta são
tetos amplos e deliberados, ou garantias que dependem do ambiente:

- Valores (e linhas SQL): até **64 MiB**; chaves: até **1 KiB**; chave primária SQL
  codificada: até 768 bytes (textos indexados podem ter qualquer tamanho). São tetos
  de memória por operação, na mesma faixa de bancos de produção.
- Um escritor por vez (como SQLite e LMDB): transações de várias threads rodam em
  paralelo e só o commit é serializado; o `fsync` não bloqueia leitores.
- SQL: sem procedimentos armazenados e tipo BLOB
  (use TEXT/hex ou a face chave-valor); `ALTER TABLE` não adiciona `CHECK`/`FOREIGN
  KEY` a uma tabela existente (declare no `CREATE TABLE`); views não acompanham
  renomeações. Ver [docs/SQL.md](docs/SQL.md#o-que-não-tem).
- Failover por promoção manual (`PROMOTE`) com fencing por época; eleição automática
  exige um protocolo de consenso (Raft) com três ou mais nós.
- TLS: replicação, protocolo PostgreSQL e HTTP são cifrados (TLS 1.3 nativo, com PKI
  própria e mTLS opcionais). Aceitam chaves/certificados **RSA, ECDSA (P-256/P-384) e
  Ed25519** (inclusive os de CAs públicas, como Let's Encrypt) e só TLS 1.3. O protocolo TCP de linhas
  continua em texto claro — use-o em redes confiáveis ou atrás de um túnel/proxy TLS.
- Chaves iniciadas por `0xFF` são reservadas ao motor. Um processo abre o diretório por
  vez (outros processos usam o servidor). Garantias em falha de energia dependem do
  filesystem honrar o `fsync`; checksums detectam corrupção acidental, não adulteração.

Veja [SECURITY.md](SECURITY.md).

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
