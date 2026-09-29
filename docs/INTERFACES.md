# Interfaces do Mini-DB 0.3

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
e operações de inspect. Chaves são bytes não vazios de até 128 bytes; valores são
bytes de até 1024 bytes (com índice por valor, `chave + valor + 2` ≤ 128 bytes). `put` é upsert. Scans usam ordem lexicográfica de bytes e
intervalo semiaberto `[start, end)`.

`begin` inicia um write-set em memória, não um snapshot de leitura. Os `put`/`delete`
da transação só ficam visíveis ao próprio handle; `commit` grava o lote e aplica as
operações, e `rollback` o descarta. Não há MVCC nem isolamento entre transações. `vacuum` exige que não haja
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
| `minidb http [dir] [addr]` | Servidor HTTP, padrão `127.0.0.1:8080`. |
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
| Transação | `BEGIN`, `COMMIT`, `ROLLBACK`/`ABORT` |
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
`VACUUM`. Não oferece joins, parâmetros preparados, múltiplos statements ou tipos SQL
ricos. `EXPLAIN` descreve a estratégia, não é um executor/planner geral.

## TCP

Uma conexão recebe `minidb 0.4 ready`; em seguida envia um comando UTF-8 por linha. As
respostas são texto, normalmente `OK ...`, `ROW ...`/`END count=...`, valor, `(nil)` ou
`ERR ...`. `QUIT`/`EXIT` responde `OK bye` e fecha. O parser e os comandos são os mesmos
da CLI. Valores devolvidos são formatados com decodificação UTF-8 lossily decoded; TCP
não é transporte binário e pode perder a representação exata de bytes inválidos.

Cada linha, incluindo newline se presente, pode ter até 64 KiB; a leitura é limitada
incrementalmente e linhas maiores recebem `ERR comando muito grande` antes do fechamento.
Uma última linha sem newline é processada no EOF. Timeout é 300 s por leitura ociosa,
não duração máxima da conexão. Há uma thread por conexão, com no máximo 128 conexões simultâneas
(excedentes recebem `ERR server busy` e são fechadas); o `Mutex<Db>` serializa o acesso
ao banco. Não existe framing para comandos multilinha.

## Clientes HTTP de referência

`clients/minidb_client.py` usa somente a biblioteca padrão; `clients/minidb_client.ts`
usa `fetch` (Node 18+ ou browser). Ambos incluem operações textuais e binárias para
KV, prefixo, contagem, lote atômico, TTL, purge e páginas; a variante binária codifica bytes em hex no protocolo e devolve bytes. O scan
binário recebe limites e cursor em bytes e pode receber `limit` para paginação. Em cada
cliente, erro HTTP gera uma exceção com status e mensagem do serviço. Os clientes são
exemplos síncronos/pequenos, não SDKs com retries, autenticação ou controle de taxa.

No browser, o cliente TypeScript envia `Content-Type: application/json`, o que causa
preflight CORS. O servidor permite qualquer origem; isso não concede acesso nem fornece
proteção. Para detalhes dos campos, status e comportamento do scan, veja [HTTP.md](HTTP.md).

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
