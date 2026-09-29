# Changelog

## 0.5.0

Motor
- **SQL relacional** (`mini_db::rel`): `CREATE/DROP TABLE`, `CREATE [UNIQUE] INDEX`,
  `DROP INDEX`, `ALTER TABLE ADD COLUMN`, `INSERT` multi-linha, `UPDATE`/`DELETE` com
  `WHERE` arbitrário, `SELECT` com `JOIN`/`LEFT JOIN`, `GROUP BY`/`HAVING`, `COUNT/SUM/
  AVG/MIN/MAX` (com `DISTINCT`), `DISTINCT`, `ORDER BY` (expressão, alias ou posição),
  `LIMIT/OFFSET`, `SHOW TABLES`, `DESCRIBE` e `EXPLAIN`. Tipos `INTEGER`, `REAL`,
  `TEXT`, `BOOLEAN`; `PRIMARY KEY` (autoincremento), `NOT NULL`, `UNIQUE`, `DEFAULT`.
  Planejador com busca pontual/faixa na PK, índices e index nested loop em joins.
- **MVCC** (`mini_db::mvcc`): `SharedDb` entre threads, `Snapshot` (leituras e SQL
  congelados) e `Txn` otimista com snapshot isolation e `Error::Conflict`.
- **Replicação lógica** (`mini_db::replication`): primário publica os commits por TCP;
  réplicas somente leitura aplicam snapshot + stream com LSN aplicado atômico e
  reconexão automática. CLI: `--primary ADDR` e `--replica-of ADDR` em `serve`/`http`.
- **Compressão LZ77** própria nos valores da árvore primária (flag na meta; arquivos
  0.4 migram no `VACUUM`).
- Erros `Conflict`, `ReadOnly` e `Constraint` (HTTP 400); `Db::last_lsn`,
  `Db::set_read_only`.

Interfaces
- `/v1/sql`, CLI e TCP executam SQL relacional; resultados tabulares em JSON
  (`columns` + `rows`) e em tabela alinhada na CLI.
- `export`/`import` incluem as tabelas SQL.

Incompatibilidades
- Chaves iniciadas por `0xFF` passam a ser reservadas ao motor.
- `ExecResult` ganhou a variante `Table` e deixou de implementar `Eq` (continua `PartialEq`).

## 0.4.0

Motor
- TTL por chave: `put_with_ttl`, `expire`, `persist`, `ttl`, `purge_expired`; terceira
  B+ Tree (`ttl_root` na página meta) e registro WAL `Expire` (tipo 7). Expiração
  preguiçosa em `get`, iteradores, contagem, índice e SQL.
- `Db::iter`/`ScanIter` leem uma folha por vez; `scan`, `scan_page`, `count`,
  `scan_prefix` e o SQL usam o iterador (paginação e contagem sem materializar).
- `write_batch` atômico em um único frame `BEGIN/COMMIT`.
- Caminho de escrita único (WAL → árvores) compartilhado com o recovery; falha após o
  registro durável fecha o handle em vez de seguir com estado duvidoso; `ABORT`
  automático se o append de um frame falhar no meio. `rollback` não escreve no WAL.
- `page_stats` (folhas vazias, preenchimento, altura) e `verify` com coerência entre
  índice, TTL e árvore primária.
- CRC16/CRC32 por tabela e reconstrução de página com um único checksum:
  `delete` ~4× e `vacuum` ~2,6× mais rápidos no benchmark local.

Interfaces
- SQL: `COUNT(*)`, `key LIKE 'prefixo%'`, `INSERT … TTL n`, `LIMIT` com parada antecipada.
- CLI/TCP: `SETEX`, `EXPIRE`, `TTL`, `PERSIST`, `PURGE`, `EXISTS`, `COUNT`, `PREFIX`, `PAGES`.
- HTTP: `/v1/count`, `/v1/ttl`, `/v1/pages`, `/v1/batch`, `/v1/expire`, `/v1/purge`,
  `prefix` em `/v1/scan`, `ttl_ms` em `/v1/kv`; erros de validação do motor viram 400.
- ABI C: `minidb_put_ttl_bytes`, `minidb_count`. Clientes Python/TS com as novas rotas.
- Métrica `minidb_batch_ops_total`.

Correções
- JSON: floats inteiros (`3.0`) e extremos (`1e300`) eram serializados como inteiros.

Qualidade
- Teste baseado em modelo, robustez de decodificadores, fuzzing (`fuzz/`), smoke dos
  clientes, contrato C linkado e executado, benchmark com p50/p99 e `--json`.
- Removidos `src/crc16.rs` e `src/lsn.rs` (não compilados) e o comparativo com sqlite3.

Compatibilidade: arquivos 0.3 abrem sem migração; faça checkpoint antes de voltar
para 0.3 (o WAL 0.4 pode conter registros `Expire`).

## 0.3.1

- **Correção crítica:** exclusões que esvaziavam uma folha podiam tornar outras chaves
  inalcançáveis (o empréstimo do irmão não atualizava o separador no pai). A exclusão
  agora é local à folha e nunca desalinha separadores.
- B+ Tree: splits sobem pelo caminho registrado na descida, sem varrer a árvore para
  achar o pai; `insert`/`get`/`delete` primários unificados com as variantes por árvore.
- `VACUUM` reconstrói as árvores, publica por checkpoint e encolhe `data.mdb`.
- Índice por valor: erro explícito quando `chave + valor + 2` excede 128 bytes.
- TCP passa a limitar 128 conexões simultâneas, como o HTTP (`ERR server busy`).
- HTTP: `key` preenchido em consultas por `key_hex`; `next_txn_id` em `/v1/stats`;
  `503` documentado na OpenAPI.
- ABI C: funções exportadas marcadas `unsafe` com contrato `# Safety`.
- Build: teste HTTP que não compilava, Clippy `-D warnings` e `rustfmt` limpos;
  CI com `--locked`; `rust-version = 1.89` no manifesto.
- Documentação revisada; `demo_crash_recover.sh` agora faz crash real com `kill -9`;
  `tools/dev.py` focado em Cargo; `.gitignore` cobre `LOCK`, spill e `__pycache__`.

## 0.3.0

- Validação estrita de JSON, incluindo UTF-8 e escapes Unicode
- Servidores HTTP/TCP com limites, timeout e atendimento concorrente
- ABI C binária com consulta de tamanho e detecção de buffer insuficiente
- Validação de tabelas e colunas no subset SQL
- Artefatos `rlib`, `cdylib` e `staticlib`

- Bloom filter em GET
- `VERIFY` / `minidb-verify`
- `INSPECT` / `HEX` / `minidb-inspect`
- Réplica por snapshot + WAL
- Catálogo `__sys/*`
- Documentação de formato de página e WAL

## 0.2.1

- HTTP/JSON, Prometheus, JSONL, ABI C, Docker, CI

## 0.2.0

- DELETE, transações, SQL subset, índice por valor, checksum de página

## 0.1.0

- B+ Tree + WAL + CLI
