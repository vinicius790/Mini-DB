# Interfaces do Mini-DB

Este documento descreve as interfaces que chamam o mesmo motor `Db`. Não há interface
visual neste repositório. O contrato específico HTTP/JSON está em [HTTP.md](HTTP.md).

## Biblioteca Rust

O pacote Cargo chama-se `minidb`; a biblioteca Rust é importada como `mini_db`.
`Db::open(path)` abre/cria o diretório usando o pool padrão (64 frames) e sincronização
do WAL ativada. `Db::open_with_capacity(path, frames)` altera a capacidade do pool;
`Db::open_with_options(path, frames, sync_wal)` também controla sync por operação.

O handle é mutável (`&mut self`) e deve ter um único dono por vez. A API oferece
`put`, `get`, `delete`, `scan`, `scan_page`, `begin`, `commit`, `rollback`,
`checkpoint`, `vacuum`, `create_value_index`, `get_by_value`, `execute_sql`, `verify`
e operações de inspect. Chaves são bytes não vazios de até 1 KiB; valores são
bytes de até 64 MiB. Leituras usam `&self`; para várias threads, envolva o `Db` em
`mvcc::SharedDb`. `put` é upsert. Scans usam ordem lexicográfica de bytes e
intervalo semiaberto `[start, end)`.

`begin` inicia um write-set em memória, não um snapshot de leitura. Os `put`/`delete`
da transação só ficam visíveis ao próprio handle; `commit` grava o lote e aplica as
operações, e `rollback` o descarta. No handle exclusivo `Db` não há isolamento entre
transações; snapshots e transações otimistas (snapshot ou serializável) vêm de
`mvcc::SharedDb`/`Session`. `vacuum` exige que não haja
transação aberta: reconstrói as árvores, faz checkpoint e encolhe `data.mdb`. O
servidor TCP/HTTP compartilha um único handle sob mutex, serializando as operações.
Chame `close` para observar falhas de checkpoint; deixar `Db` cair também tenta fechar,
mas o erro de `Drop` não pode ser devolvido ao chamador.

### Referência rápida da API Rust (0.4)

| Grupo | Métodos |
| --- | --- |
| Escrita | `put`, `put_with_ttl`, `delete`, `write_batch(&[BatchOp])` (atômico) |
| TTL | `expire`, `persist`, `ttl` → `KeyTtl::{Missing, Persistent, ExpiresIn}`, `purge_expired` |
| Leitura | `get`, `contains`, `get_by_value` |
| Iteração | `iter(start, end)` → `ScanIter` (uma folha por vez), `scan_prefix`, `scan`, `scan_page`, `count` |
| Transação | `begin`, `commit`, `rollback` |
| Manutenção | `checkpoint`, `vacuum`, `create_value_index`, `close` |
| Diagnóstico | `stats`, `page_stats` → `PageStats`, `verify`, `inspect_page`, `inspect_hex`, `is_open` |
| SQL | `execute_sql`, `execute_stmt` → `ExecResult::{Ok, Rows, Value, Count}` |

`ScanIter` produz `Result<(chave, valor)>` e mantém em memória uma folha por vez;
com transação aberta, a visão mesclada é materializada. Chaves expiradas nunca
aparecem. `put` sempre remove um TTL anterior da chave (como `SET` no Redis).
Erros de validação usam `Error::InvalidInput`, `KeyTooLarge` ou `ValueTooLarge`;
`Error::is_client_error()` separa erro de requisição de erro do servidor. Se a
aplicação de uma operação falhar depois do registro no WAL, o handle se fecha
(`is_open() == false`) e reabrir o banco recupera o estado.

## CLI

Executável: `minidb` (`cargo run --bin minidb -- ...`). Sem argumentos, mostra uso e
sai com código 2. Erros fatais do comando saem com código 1.

| Comando | Efeito |
| --- | --- |
| `minidb shell [dir]` | Shell interativo; `open` é alias. O diretório padrão é `./data`. Ao sair, fecha e faz checkpoint. |
| `minidb exec [dir] <comando...>` | Executa um comando e fecha/checkpointa. Se o primeiro argumento depois de `exec` for reconhecido como comando, usa `./data`; caso contrário, trata-o como diretório. |
| `minidb serve [dir] [addr]` | Servidor TCP de linha, padrão `127.0.0.1:7432`. |
| `minidb http [dir] [addr]` | Servidor HTTP, padrão `127.0.0.1:8080`. `serve` e `http` também escutam o protocolo PostgreSQL em `pg_addr`. |
| `minidb pg [dir] [addr]` | Só o protocolo PostgreSQL, padrão `127.0.0.1:5432` (`psql -h 127.0.0.1 -p 5432`). |
| `minidb backup [dir] <destino>` | Backup físico: completo na primeira vez, incremental nas seguintes. |
| `minidb restore <backup> <dir> [--until-lsn N \| --until-time 'AAAA-MM-DD HH:MM:SS']` | Restaura num diretório vazio, até o fim ou até um ponto no tempo (`passphrase` da configuração para bancos cifrados). |
| `minidb export [dir] [out.jsonl]` | Exporta `minidb-jsonl/v1`; destino padrão `backup.jsonl`. |
| `minidb import [dir] [in.jsonl]` | Importa JSONL ou legado textual; origem padrão `backup.jsonl`. |

Em `serve`/`http`, `minidb.toml` e `MINIDB_*` configuram diretório, pool, endereço e
`fsync`; argumentos explícitos de diretório/endereço prevalecem. `exec`, `shell`,
`export` e `import` abrem o banco com as opções padrão. Veja `minidb.toml` para
exemplos.

Comandos compartilhados entre shell/TCP (`HELP` lista todos):

| Grupo | Comandos |
| --- | --- |
| Dados | `PUT`/`INSERT k v`, `GET k`, `DELETE`/`DEL`/`RM k`, `EXISTS k`, `GETVAL`/`BYVALUE v` |
| TTL | `SETEX k segundos v`, `EXPIRE k segundos`, `TTL k`, `PERSIST k`, `PURGE` |
| Leitura | `SCAN [início] [fim]`, `PREFIX p [limite]`, `COUNT [início] [fim]` |
| Transação | `BEGIN [ISOLATION LEVEL SERIALIZABLE]`, `COMMIT`, `ROLLBACK [TO sp]`/`ABORT`, `SAVEPOINT sp`, `RELEASE sp` (transação MVCC da sessão/conexão; `PUT`/`GET`/`DEL` e SQL participam) |
| Manutenção | `CHECKPOINT`/`CKPT`, `VACUUM`, `INDEX`, `VERIFY`, `PAGES`, `STATS`, `CATALOG` |
| Forense | `INSPECT [página]`, `HEX página [bytes]` |

`TTL` responde `ttl_ms=N`, `(persistent)` ou `(missing)`. Argumentos
textuais são UTF-8; a CLI/TCP não fornecem uma sintaxe geral de bytes hex para chaves e
valores arbitrários. Prefira Rust, HTTP `*_hex` ou FFI `*_bytes` para esses dados.

`PUT key value with spaces` junta os argumentos após a chave com espaços. Aspas simples
e duplas agrupam argumentos, mas o parser de comandos não implementa escapes dentro de
aspas; os literais SQL seguem o lexer SQL, não o parser de shell.

O subset SQL aceita `SELECT *`, `SELECT key, value` ou `SELECT COUNT(*)` em `kv`/`t`,
predicados de chave `=`, `>`, `>=`, `<`, `<=`, `LIKE 'prefixo%'` (só curinga final;
`_` é literal), `value = literal`, `ORDER BY key [ASC|DESC]` e `LIMIT`. Em ordem
ascendente o `LIMIT` interrompe a leitura cedo. Também aceita
`INSERT INTO kv [(key, value)] VALUES (k, v) [TTL segundos]`,
`UPDATE value ... WHERE key = ...`, `DELETE ... WHERE key = ...`,
`CREATE INDEX [nome] ON kv (value)`, `EXPLAIN`, controle transacional, `CHECKPOINT`,
`VACUUM`. Esse é só o dialeto chave-valor: joins, parâmetros, scripts e tipos ricos
vêm do SQL relacional ([SQL.md](SQL.md)), que a CLI, o TCP e o HTTP também executam.
Na CLI/TCP, `GRANT`, `REVOKE` e `REINDEX` são reconhecidos como SQL.

## TCP

Uma conexão recebe `minidb 1.3 ready`; em seguida envia um comando UTF-8 por linha.
Cada conexão tem a sua [`Session`](SQL.md#transações-scripts-e-sessões): `BEGIN` abre
uma transação MVCC só daquela conexão (as outras não veem nada até o `COMMIT`), e SQL
com vários comandos na mesma linha (`a; b`) roda atômico. As
respostas são texto, normalmente `OK ...`, `ROW ...`/`END count=...`, valor, `(nil)` ou
`ERR ...`. `QUIT`/`EXIT` responde `OK bye` e fecha. O parser e os comandos são os mesmos
da CLI. Valores devolvidos são formatados com decodificação UTF-8 lossily decoded; TCP
não é transporte binário e pode perder a representação exata de bytes inválidos.

Cada linha, incluindo newline se presente, pode ter o tamanho de um valor máximo; a leitura é limitada
incrementalmente e linhas maiores recebem `ERR comando muito grande` antes do fechamento.
Uma última linha sem newline é processada no EOF. Timeout é 300 s por leitura ociosa,
não duração máxima da conexão. Há uma thread por conexão, com até `max_connections`
conexões simultâneas (excedentes recebem `ERR server busy` e são fechadas); leituras de
conexões diferentes rodam em paralelo. Com `token`, o primeiro comando precisa ser
`AUTH <token>`; com usuários cadastrados (`CREATE USER`), `AUTH <usuário> <senha>` — a
sessão passa a obedecer aos privilégios dele (`GRANT`), inclusive nos comandos
chave-valor (objeto `kv`). Comandos novos: `ROLE`, `PROMOTE`, `MAINTAIN`. Não existe framing para comandos multilinha.

## Protocolo PostgreSQL

`minidb pg [dir] [addr]` (ou `pg_addr` / `MINIDB_PG`, padrão `127.0.0.1:5432`, também
ligado por `serve` e `http`; vazio desliga) fala o protocolo de rede do PostgreSQL v3:

```
psql "host=127.0.0.1 port=5432 user=ana dbname=minidb sslmode=disable"
```

Funciona com `psql` e com os drivers PG (libpq, node-postgres, psycopg, JDBC, pgx):
consulta simples, protocolo estendido (Parse/Bind/Describe/Execute/Sync, parâmetros
`$1` em texto ou binário), tags `INSERT 0 n`, `SELECT n`, erros com SQLSTATE (`42P01`
tabela inexistente, `42501` sem privilégio, `28P01` senha, `40001` conflito), transação
abortada até `ROLLBACK`. Autenticação: **SCRAM-SHA-256** quando há usuários; senha em
claro comparada ao `token` quando só há token; `trust` num banco sem usuários. `SET`,
`RESET`, `DISCARD`, `DEALLOCATE` e `SHOW parâmetro` são aceitos como no-op para os
clientes.

**COPY** (consulta simples, formatos texto e CSV): `COPY tabela [(colunas)] FROM STDIN`,
`COPY tabela [(colunas)] TO STDOUT` e `COPY (SELECT ...) TO STDOUT`, com `[WITH]
[(]FORMAT text|csv, DELIMITER 'x', NULL 'x'[)]`. Texto: delimitador padrão TAB, NULL como
`\N`, escapes `\\ \n \r \t \b \f \v`, `\NNN` e `\xHH`. **CSV** (como no PostgreSQL/psql):
`WITH (FORMAT csv [, HEADER [true|false]] [, DELIMITER 'x'] [, NULL 'x'] [, QUOTE 'x']
[, ESCAPE 'x'])` ou a forma antiga `WITH CSV [HEADER] [QUOTE 'x'] [ESCAPE 'x']`; padrões
`,`, aspa `"`, ESCAPE igual à aspa e NULL = campo vazio **sem** aspas (`""` é texto vazio).
Campos entre aspas podem ter delimitador, aspa dobrada e quebras de linha; `HEADER` descarta
a 1ª linha na entrada e escreve os nomes das colunas na saída, que põe aspas em campos com
delimitador, aspa, `\r`/`\n`, vazios ou iguais ao NULL. Opção desconhecida ou inválida
(delimitador de mais de um caractere, igual à aspa, NULL contendo o delimitador...) é
recusada; linha com número de colunas errado ou aspas sem fechamento dá erro com o número
da linha. Nos dois formatos a linha `\.` encerra os dados e o `CopyInResponse`/
`CopyOutResponse` anuncia formato geral texto (0, como o PostgreSQL faz no CSV). O `FROM
STDIN` exige `INSERT` na tabela e o `TO STDOUT` exige `SELECT` (conferidos como num
`INSERT`/`SELECT` comum); os dados são aplicados por `INSERT` parametrizados de 500
linhas numa única transação (a do cliente, se aberta; senão uma própria): `CopyFail`,
linha malformada ou violação de restrição devolvem `ErrorResponse` e nada fica gravado.
Os valores chegam como texto e o motor converte para o tipo da coluna. Limites por
`COPY FROM`: 256 MiB de dados e 1.000.000 de linhas. Não há BINARY, `FORCE_QUOTE`/
`FORCE_NOT_NULL`, arquivo/`PROGRAM`
nem `COPY` no protocolo estendido; o `COPY` precisa ser o único comando da mensagem
`Query`. Um erro antes do `CopyInResponse` (tabela ou coluna inexistente, sem privilégio)
é devolvido na hora; `CopyData` fora de um `COPY` é ignorado, como no PostgreSQL.

**TLS 1.3 nativo** (1.1): com `tls = true` (padrão) o servidor aceita `SSLRequest` e
negocia TLS 1.3 (X25519, AES-128-GCM ou ChaCha20-Poly1305, Ed25519) sem dependências. Na primeira
execução gera `tls.key` (PKCS#8 Ed25519) e `tls.crt` (X.509 autoassinado, SAN com o
host/IP configurado, `localhost` e `127.0.0.1`) no diretório do banco.
`sslmode=require` funciona direto; `sslmode=verify-full sslrootcert=tls.crt` também.
HTTP em HTTPS com `https = true` (`MINIDB_HTTPS=1`), mesma identidade.

**PKI própria e certificado de cliente** (1.2):

```
minidb cert ca     ./pki                 # ca.key (segredo) + ca.crt (distribua)
minidb cert server ./pki db.exemplo.com  # server.key/.crt com SAN, assinados pela CA
minidb cert client ./pki ana --days 90   # client-ana.key/.crt, CN = usuário do banco
```

```toml
tls_cert = "pki/server.crt"      # pode conter folha + intermediárias
tls_key  = "pki/server.key"      # PKCS#8 Ed25519
tls_ca   = "pki/ca.crt"          # CAs confiáveis para certificados de cliente
tls_client_auth = "required"     # off | optional | required (padrão required com tls_ca)
```

(Também `MINIDB_TLS_CERT`, `MINIDB_TLS_KEY`, `MINIDB_TLS_CA`, `MINIDB_TLS_CLIENT_AUTH`;
caminhos relativos valem a partir do diretório do banco.) Cliente:
`psql "host=db user=ana sslmode=verify-full sslrootcert=pki/ca.crt
sslcert=pki/client-ana.crt sslkey=pki/client-ana.key"` — o certificado autentica `ana`
sem senha; um certificado de outro usuário é recusado (28000). Em `optional`, quem não
apresenta certificado segue para SCRAM. No HTTPS, `curl --cacert pki/ca.crt --cert
pki/client-ana.crt --key pki/client-ana.key` executa como `ana`. Chaves e certificados
podem ser Ed25519, ECDSA P-256/P-384 ou RSA (p. ex. emitidos pela Let's Encrypt ou pelo
OpenSSL); `minidb cert ... --algo ed25519|p256|p384|rsa2048|rsa3072|rsa4096` escolhe o tipo da
PKI própria (padrão: ed25519).

**`pg_catalog` e `information_schema`** (1.1, ampliados na 1.2): tabelas virtuais
sintetizadas do catálogo a cada consulta. Com dados reais: `pg_class`, `pg_namespace`,
`pg_attribute`, `pg_attrdef`, `pg_index`, `pg_constraint` (PK, UNIQUE, FK com ações,
CHECK), `pg_type`, `pg_am` (btree, hnsw, fulltext, zorder), `pg_roles`/`pg_user`/
`pg_authid`, `pg_auth_members`, `pg_database`, `pg_settings`, `pg_tables`, `pg_views`,
`pg_matviews`, `pg_indexes`, **`pg_trigger`**, **`pg_proc`** (funções, agregados e
janelas do motor), `pg_aggregate`, `pg_operator`, `pg_cast`, `pg_opclass`,
`pg_language`, `pg_extension`/`pg_available_extensions` (`minidb_fulltext`,
`minidb_vector`, `minidb_spatial`), `pg_collation`, `pg_ts_config/dict/parser/template`
(simple, portuguese, english), `pg_depend`, `pg_stat_user_tables`/`pg_stat_all_tables`,
`pg_stat_user_indexes`, `pg_stats`/`pg_statistic` (do `ANALYZE`), `pg_stat_activity`,
`pg_stat_ssl`, `pg_stat_database`, `pg_timezone_names` e
`information_schema.tables/columns/table_constraints/key_column_usage/schemata/views/
triggers/referential_constraints/check_constraints/routines`. Recursos que o Mini-DB não
tem (publicações, partições, enums, tabelas estrangeiras, policies, large objects...)
existem como relações vazias, para os clientes não falharem. Funções: `pg_get_userbyid`,
`pg_table_is_visible` e as demais `*_is_visible`, `format_type`, `pg_get_expr`,
`pg_get_indexdef`, `pg_get_constraintdef`, `pg_get_viewdef`, `pg_get_triggerdef`,
`pg_get_function_result/arguments`, `to_regclass`, `x::regclass` (nome ⇄ oid),
`current_setting`, `pg_typeof`, `quote_ident`, `array_to_string`, `generate_series`/
`unnest` (inclusive `WITH ORDINALITY`) no FROM, `x = ANY(array)`, `arr[i]`. Os
metacomandos do psql funcionam: `\dt`, `\d tabela` (colunas, índices, **FKs, "Referenced
by", gatilhos, CHECK**), `\d+`, `\di`, `\dv`, `\du`, `\l`, `\dn`, `\dt+`, `\df`, `\do`,
`\dC`, `\dx`, `\dF`, `\dA`, `\dp`... Não há cursores parciais (`COPY`: ver acima). Vetores, JSON e
datas trafegam como texto. `LISTEN canal` funciona: as notificações (`NOTIFY`) chegam
como `NotificationResponse` junto da resposta do comando seguinte (o psql as mostra como
"Asynchronous notification"); não há envio espontâneo com a conexão ociosa.

## Clientes HTTP de referência

`clients/minidb_client.py` usa somente a biblioteca padrão; `clients/minidb_client.ts`
usa `fetch` (Node 18+ ou browser). Ambos incluem operações textuais e binárias para
KV, prefixo, contagem, lote atômico, TTL, purge e páginas; a variante binária codifica bytes em hex no protocolo e devolve bytes. O scan
binário recebe limites e cursor em bytes e pode receber `limit` para paginação. Em cada
cliente, erro HTTP gera uma exceção com status e mensagem do serviço. Os clientes são
exemplos síncronos/pequenos, não SDKs com retries, autenticação ou controle de taxa.

No browser, o cliente TypeScript envia `Content-Type: application/json`, o que causa
preflight CORS. Por padrão o servidor não envia cabeçalhos CORS e recusa (`403`)
escritas com `Origin` não liberado, então o navegador bloqueia o cliente; libere a
origem do painel com `MINIDB_CORS_ORIGIN`. CORS não autentica nem substitui token ou
usuários. O servidor também recusa (`403`) um `Host` com nome de domínio que não esteja
em `MINIDB_ALLOWED_HOSTS` (defesa contra DNS rebinding); `localhost`, IPs e nomes sem
ponto passam. Para detalhes dos campos, status e comportamento do scan, veja [HTTP.md](HTTP.md).

## ABI C

Inclua `include/minidb.h`; a biblioteca exporta `rlib`, `cdylib` e `staticlib`. Handles
são opacos. `minidb_open` retorna `NULL` quando falha; todas as funções exigem um handle
aberto. O handle deve ser fechado uma única vez e não pode ser usado depois do close.

| Função | Retorno |
| --- | --- |
| Todas | `unsafe extern "C"`: o chamador garante ponteiros válidos e uso exclusivo do handle. |
| `minidb_open` | `void *` não nulo em sucesso; `NULL` em falha. |
| `minidb_close` | Fecha, mas descarta falha de checkpoint por compatibilidade. |
| `minidb_close_checked` | `0` sucesso, `-1` handle nulo, `-2` falha de close; consome o handle mesmo em erro. |
| `minidb_put_bytes` | `0` sucesso, `-1` argumento/chave/valor inválido, `-2` erro do banco. |
| `minidb_get_bytes` | bytes copiados; `0` ausente ou valor vazio; `-1` argumento inválido, `-2` erro do banco, `-3` buffer insuficiente. |
| `minidb_get_size` | Tamanho; `0` ausente ou valor vazio; `-1` argumento inválido, `-2` erro do banco. |
| `minidb_exists` | `1` presente, `0` ausente, `-1` argumento inválido, `-2` erro do banco. |
| `minidb_delete` | `1` removida, `0` ausente, `-1` argumento inválido, `-2` erro do banco. |
| `minidb_put_ttl_bytes` | Como `minidb_put_bytes`, expirando após `ttl_ms` (> 0). |
| `minidb_count` | Contagem em `[start, end)` (`end` pode ser `NULL`); `-1`/`-2` em erro. |
| `minidb_put`, `minidb_get` | Adaptadores NUL-terminated; não suportam NUL embutido em chave/valor. `get` copia bytes sem conversão UTF-8, acrescenta NUL e retorna o tamanho em bytes, excluindo o terminador. |

As constantes `MINIDB_OK`, `MINIDB_ERR_ARGUMENT`, `MINIDB_ERR_DATABASE` e
`MINIDB_ERR_BUFFER_TOO_SMALL` correspondem a `0`, `-1`, `-2` e `-3`; as funções que
retornam `intptr_t` usam os mesmos códigos negativos. Getter por tamanho/cópia retorna
zero tanto para chave ausente quanto para valor vazio: use `minidb_exists` para
separá-los. `minidb_get` com buffer de tamanho 1 pode representar valor vazio como um
único NUL; para valor não vazio, buffer curto retorna `-3`.

A API binária aceita `value == NULL` somente quando `value_len == 0`; a chave precisa
ser não nula e não vazia. Um buffer `out == NULL` só é válido com `out_len == 0`.
Ponteiros e comprimentos devem descrever memória válida no processo. A biblioteca não
pode validar ponteiros arbitrários nem tornar o handle seguro para chamadas
concorrentes; o consumidor deve serializar todas as chamadas sobre o mesmo handle.

O teste de contrato C é `tests/ffi_header.c`; em sistemas com compilador C11, rode:

```sh
cc -std=c11 -Wall -Wextra -Werror -fsyntax-only -I include tests/ffi_header.c
```
