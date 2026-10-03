# Motor 0.6: sem os limites da 0.5

A 0.6 remove cada limite listado na 0.5 sem mudar o modelo do motor (um commit
único, WAL lógico, B+ Trees em páginas de 4 KiB) e sem adicionar dependências.

## O que era limite e o que virou

| Limite na 0.5 | Na 0.6 | Onde |
| --- | --- | --- |
| Valores e linhas SQL ≤ 1024 bytes | Até **64 MiB** (páginas de overflow + compressão) | `btree.rs`, `page.rs` |
| Chaves ≤ 128 bytes | Até **1 KiB** | `page.rs` |
| Índice por valor exigia `chave + valor + 2 ≤ 128` | Qualquer valor (entrada = hash de 16 bytes + chave, conferida na leitura) | `index.rs` |
| Textos indexados longos quebravam o índice SQL | Qualquer tamanho (256 bytes na entrada + conferência na linha, UNIQUE exato) | `rel/exec.rs` |
| Split por contagem podia falhar com células grandes | Split por **bytes** com teto de célula de 1/3 da página: sempre cabe | `btree.rs` |
| Checkpoint copiava o arquivo inteiro | **Journal** só com as páginas alteradas | `buffer.rs` |
| WAL crescia até o `close` | Checkpoint automático por tamanho (64 MiB) | `db.rs` |
| `VACUUM` materializava o banco na memória | Reconstrução em **streaming** num arquivo novo + rename | `db.rs` |
| Espaço de valores apagados só voltava no `VACUUM` | Páginas de overflow voltam à **freelist** na hora; manutenção automática | `buffer.rs`, `db.rs` |
| Mutex global: leituras e escritas em fila | Leitores em **paralelo**; o `fsync` do escritor não bloqueia leitores | `mvcc.rs`, `buffer.rs` |
| Snapshot isolation permitia write skew | `begin_serializable`: validação de leituras e faixas | `mvcc.rs` |
| GC de versões O(n) por snapshot | Índice por LSN: custo proporcional ao descartado | `mvcc.rs` |
| SQL sem subconsultas | Escalares, `IN (SELECT)`, `EXISTS`, correlacionadas, no `FROM` | `rel/` |
| Sem `UNION`/CTE | `UNION`/`INTERSECT`/`EXCEPT` (`ALL`), `WITH` | `rel/` |
| Sem chaves compostas | `PRIMARY KEY (a, b)`, índices e `UNIQUE (a, b)` compostos | `rel/` |
| Sem `CASE`/parâmetros | `CASE`, `CAST`, `?`/`?N`/`$N`, comandos preparados | `rel/` |
| Joins só nested loop | Busca por chave/índice, **hash join**, `RIGHT`/`FULL`/`CROSS` | `rel/exec.rs` |
| Sem `INSERT ... SELECT`/upsert | `INSERT ... SELECT`, `ON CONFLICT DO NOTHING / DO UPDATE` | `rel/` |
| HTTP/TCP sem autenticação | Token (`Bearer` / `AUTH`), comparação em tempo constante | `http.rs`, `server.rs` |
| 128 conexões fixas | Configurável (padrão 1024) | `config.rs` |
| Replicação sem autenticação | HMAC-SHA256 + ChaCha20 com chaves por sessão | `replication.rs`, `crypto.rs` |
| Feed só em memória (resync após reinício) | Retomada pelo **WAL arquivado** | `wal.rs`, `replication.rs` |
| Snapshot de replicação em um quadro (memória O(banco)) | Snapshot MVCC em **pedaços**, sem bloquear escritas | `replication.rs` |
| Só assíncrona | **Semi-síncrona** (`sync_replicas`, timeout opcional) | `replication.rs` |
| Sem failover | **Promoção** + época + **fencing** do primário antigo, réplicas em cascata | `replication.rs` |
| Polling de 20 ms no streaming | `Condvar`: acorda no commit | `replication.rs` |

## Armazenamento

**Overflow.** Uma célula de folha nunca passa de 1352 bytes (1/3 do espaço útil). Se
`4 + chave + valor gravado` passa disso, o valor (já comprimido) vai para uma cadeia de
páginas `Overflow` e a célula guarda `[total:u32][primeira:u32]`, marcada pelo bit 15
de `val_len` — arquivos antigos nunca têm esse bit, então abrem como estão. Regravar ou
apagar a chave devolve a cadeia à freelist antes de alocar a nova.

**Split por bytes.** Com toda célula ≤ 1/3 da página, dividir no ponto em que a
metade esquerda passa de 50% dos bytes garante que as duas metades cabem. O split por
contagem da 0.5 podia falhar (quatro células grandes numa metade) depois de o lote já
estar no WAL — o que impediria até a reabertura. O teste
`split_point_balances_bytes_and_never_empties_a_side` cobre o caso.

**Checkpoint por journal.** As páginas alteradas (frames sujos + spill) vão para
`data.mdb.journal` com CRC32 e marcador final; depois de `fsync`, são escritas no lugar
e o journal é apagado. Na abertura, journal completo é reaplicado (idempotente) e
incompleto é descartado. Custo proporcional ao que mudou, não ao tamanho do arquivo.

**VACUUM em streaming.** Após purge + checkpoint, as árvores são reconstruídas folha a
folha em `vacuum.mdb` (outro buffer pool) e o arquivo substitui `data.mdb` por rename.
Um crash antes do rename mantém o original; sobras são removidas na abertura.

## Concorrência

`BufferPool::get_page(&self)` devolve `Arc<Page>` sob um mutex curto; escritas usam
`&mut self` e fazem copy-on-write se um leitor ainda segura a versão anterior. Todas as
leituras do `Db` usam `&self`. O `SharedDb` usa `RwLock<Db>` + um mutex de escritor:

1. planeja o lote (validações, SQL) com o lock de **leitura**;
2. grava no WAL e faz `fsync` ainda com o lock de leitura (o WAL tem mutex próprio);
3. pega o lock de **escrita** só para aplicar o lote (microssegundos).

Transações (`Txn`) de várias threads leem e acumulam escritas em paralelo; só o commit
é serializado. Com `Isolation::Serializable`, o commit falha se alguma chave ou faixa
lida mudou depois do início — sem write skew.

## SQL

Executor com contexto encadeado: colunas não encontradas no escopo atual são buscadas
nas consultas externas (subconsultas correlacionadas). Uma subconsulta é tentada
primeiro sem a linha externa; se funcionar, é não correlacionada e o resultado fica em
cache para o comando inteiro. O planejador escolhe: ponto na PK completa, índice único
completo, lista `IN` na PK, prefixo/faixa da PK composta, prefixo de índice, scan. Joins:
busca por PK/índice por linha externa, hash join em igualdades entre os dois lados, ou
nested loop. `RIGHT`/`FULL` materializam o lado interno e emitem as linhas sem par.

## Replicação

Handshake `MINIDB-REPL 2 <época> <nonce> <auth>` → `SYNC <lsn> <época> <nonce>
<snapshot?> <mac>` → `OK`. Com segredo, as chaves de sessão são
`HMAC(segredo, rótulo ‖ nonce_primário ‖ nonce_réplica)` e cada quadro leva
ChaCha20 + tag HMAC de 16 bytes sobre `direção ‖ contador ‖ cifrado`.

O primário tenta, nesta ordem: feed em memória → histórico dos WALs arquivados +
atual → snapshot MVCC em pedaços. A réplica confirma cada lote durável (`ACK`), o que
alimenta o modo semi-síncrono. Réplica nova, que caiu no meio de uma ressincronização
ou de outra linhagem sempre recebe snapshot.

`PROMOTE` para o seguidor, incrementa a época (chave replicada) e libera escritas. Um
nó que se conecta com época maior faz o primário antigo se isolar (somente leitura); um
nó nunca aceita dados de época menor.

## O que continua sendo teto (por decisão)

- 64 MiB por valor, 1 KiB por chave, 768 bytes de PK codificada: memória por
  operação e tamanho de célula. Aumentar é trocar as constantes em `page.rs`.
- Um escritor por vez (modelo de SQLite/LMDB). Escritores concorrentes com locks por
  linha exigiriam outro motor de transações.
- Eleição automática de líder exige consenso (Raft) com três ou mais nós.
- TLS: a 0.6 não tinha. Desde a 1.1 o protocolo PostgreSQL, o HTTP (`https = true`) e a
  replicação falam TLS 1.3 próprio (veja [../SECURITY.md](../SECURITY.md)). O TCP de
  linhas segue em texto claro (use um túnel/proxy TLS) e o código de TLS não teve
  auditoria externa: onde isso for exigência, termine o TLS num proxy auditado.

## Verificação

`tests/engine_v06.rs` (valores de 5 MiB, chaves de 1 KiB, crash, freelist, vacuum,
splits adversariais, checkpoint automático, TCP com token, replicação cifrada com
segredo errado recusado, retomada após reinício sem snapshot, semi-síncrona, promoção e
fencing), `tests/sql_v06.rs` (todas as construções SQL novas), testes unitários de
SHA-256/HMAC/ChaCha20 com vetores oficiais (FIPS 180-4, RFC 4231, RFC 8439), journal,
split, codec grande, quadros cifrados com replay e adulteração, GC do MVCC, write skew.
