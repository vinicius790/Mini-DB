# Motor 0.5: SQL relacional, MVCC, replicação e compressão

> Documento histórico: os limites citados aqui foram superados na 0.6
> ([MOTOR-0.6.md](MOTOR-0.6.md)) e o SQL cresceu muito desde então ([SQL.md](SQL.md)).

A 0.5 transforma o Mini-DB de um armazenamento chave-valor em um banco relacional
embarcado sem acrescentar dependências nem um segundo formato de arquivo. As quatro
peças novas se apoiam no mesmo ponto: **o commit único** (`Db::log_and_apply`), que
já era o caminho de toda escrita e do recovery.

```
comando SQL / put / write_batch / Txn::commit
                 │
                 ▼
     validação ─► WAL (frame BEGIN/COMMIT, fsync) ─► imagens anteriores (se há snapshot)
                                                   ─► aplicação às B+ Trees (valores LZ77)
                                                   ─► change feed (se é primário)
```

## 1. SQL relacional (`src/rel/`)

| Arquivo | Papel |
| --- | --- |
| `value.rs` | `Value`/`Type`, coerção, comparação SQL (NULL = desconhecido), codificação de linha e de chave |
| `parser.rs` | lexer + parser recursivo (precedência `OR < AND < NOT < comparação < + - \|\| < * / % < unário`) |
| `exec.rs` | catálogo, planejador, executor, agregação e `EXPLAIN` |

### Layout no espaço reservado `0xFF`

| Chave | Valor |
| --- | --- |
| `FF 'c' <tabela>` | esquema em JSON (colunas, PK, índices) |
| `FF 'q'` | próximo id de tabela |
| `FF 's' <tid>` | próximo rowid (autoincremento) |
| `FF 't' <tid> <pk>` | linha: `[n:u16]` + por coluna `tag` + payload |
| `FF 'x' <tid> <iid> <valor> <pk>` | `<pk>` |

`<pk>` e `<valor>` usam uma codificação **que preserva a ordem e é auto-delimitada**:
inteiros com o bit de sinal invertido em big-endian, reais com a transformação IEEE
clássica (positivos: inverte o sinal; negativos: inverte tudo), texto com `00` escapado
como `00 FF` e terminado por `00 00`. Consequências:

- `WHERE id BETWEEN a AND b` vira um scan de faixa direto na B+ Tree;
- `WHERE email = 'x'` vira um scan do prefixo `FF 'x' <tid> <iid> enc('x')`, e nenhum
  outro valor pode compartilhar esse prefixo;
- a ordem física das linhas é a ordem da chave primária.

A API chave-valor pública corta faixas em `0xFF` e recusa essas chaves, então tabelas
nunca vazam para `scan`/`count`/`SELECT … FROM kv`. `export`/`import` e `vacuum` usam o
acesso interno e preservam as tabelas.

### Planejador

Para a tabela do `FROM`, os conjuntos `coluna op literal` do `WHERE` (inclusive
`literal op coluna` e `BETWEEN`) escolhem, nesta ordem: busca pontual pela PK, índice
`UNIQUE`, faixa da PK, índice comum, scan completo. O `WHERE` inteiro é **sempre
reaplicado** às linhas candidatas, então o plano só precisa devolver um superconjunto
correto — um erro de planejamento nunca muda o resultado, só o custo.

Cada `JOIN` procura no `ON` uma igualdade `interna.coluna = expressão_externa` sobre a
PK ou uma coluna indexada (index nested loop, uma busca por linha externa). Sem isso, a
tabela interna é lida uma vez e usada em nested loop. `LEFT JOIN` completa com `NULL`.

Sem joins, ordenação, agregação ou `DISTINCT`, o `LIMIT` interrompe o scan assim que
tem linhas suficientes.

### Escritas e restrições

Cada comando acumula escritas em um `Pending` (mapa ordenado chave → valor/remoção) que
também responde às leituras do próprio comando; no fim, vira **um único lote** no WAL.
Por isso um `INSERT` de várias linhas com um valor `UNIQUE` repetido falha inteiro, e um
`UPDATE users SET id = id + 1` não acusa falso conflito: todas as versões antigas saem
antes de as novas entrarem. Com `BEGIN` aberto, o lote entra no write-set da transação
e as leituras seguintes já o enxergam.

`ALTER TABLE ADD COLUMN` só altera o catálogo: linhas antigas são completadas com o
`DEFAULT` na leitura, sem reescrever a tabela.

## 2. MVCC (`src/mvcc.rs`)

O arquivo guarda só a versão atual. Enquanto houver snapshot ativo, cada commit guarda
em memória a **imagem anterior** das chaves que alterou, marcada com o LSN do commit
(o mesmo princípio do undo log do InnoDB). Um snapshot com versão `S` lê o valor atual
e, se a chave mudou depois de `S`, usa a imagem anterior da primeira mudança posterior
a `S`. Scans fazem o merge ordenado entre o iterador da árvore e essas imagens.

- Sem snapshots ativos não há custo nenhum: nada é registrado.
- Ao soltar o snapshot mais antigo, as imagens que ninguém mais enxerga são descartadas.
- `Txn` lê do seu snapshot, acumula escritas e, no commit, falha com `Error::Conflict`
  se alguma chave escrita mudou depois do início (first-committer-wins). É snapshot
  isolation: write skew é possível.
- `Snapshot::query` executa `SELECT`, `SHOW TABLES`, `DESCRIBE` e `EXPLAIN` sobre a
  visão congelada, inclusive com joins e agregados.

Limite conhecido: um mutex global protege o `Db` por operação (o buffer pool é mutável
até em leituras). Snapshots dão consistência sem travar escritores por longos períodos,
mas não paralelismo real de CPU. O próximo passo seria latch por página.

## 3. Replicação (`src/replication.rs`)

Replicação **lógica** por streaming dos commits. O primário mantém um `ChangeFeed` em
memória com os últimos lotes (limitado por número de operações). A réplica envia
`SYNC <lsn>` com o último LSN do primário que já aplicou e recebe quadros
`[len:u32][tipo:u8][lsn:u64][ops]`:

| Tipo | Quando | Efeito na réplica |
| --- | --- | --- |
| `BATCH` | o feed cobre o LSN pedido | aplica o lote + novo LSN aplicado, atômico |
| `SNAPSHOT` | réplica nova, muito atrasada ou primário reiniciado | substitui todo o estado (remove o que sumiu) + LSN, atômico |
| `HEARTBEAT` | ociosidade (1 s) | detecta conexão morta (timeout de 5 s) |

Como o LSN aplicado (`FF 'rlsn'`) é gravado no mesmo lote que os dados, um crash da
réplica em qualquer ponto retoma do lote seguinte, sem duplicar nem pular nada. TTLs
viajam como instantes absolutos. A réplica abre em modo somente leitura
(`Error::ReadOnly`, HTTP 400) e reconecta com backoff exponencial até 5 s.

Fora do escopo: eleição/failover, replicação síncrona, autenticação/TLS no canal e feed
persistente (hoje a réplica faz ressincronização completa após o primário reiniciar).

## 4. Compressão (`src/codec.rs`)

LZ77 próprio com tabela hash de 4096 entradas, janela de 64 KiB, cópias de 4 a 131
bytes e literais de até 128 bytes. Valor gravado na folha da árvore primária:
`[0x00][cru]` ou `[0x01][len:u16][tokens]`, escolhendo o comprimido só quando é menor.
O codificador é determinístico e o decodificador valida todos os limites (entrada
corrompida é erro, nunca pânico).

- Arquivos criados pela 0.5 têm `META_FLAG_COMPRESSED_VALUES` na página meta; arquivos
  0.4 continuam legíveis como estão e passam para o formato comprimido no próximo
  `VACUUM`.
- WAL, índices e TTL continuam com valores lógicos: recovery, replicação e verificação
  não mudam.
- Os limites continuam valendo sobre o valor **lógico** (1024 bytes); a compressão
  reduz disco e I/O (≈3× no teste com JSON repetitivo), não aumenta o tamanho máximo.

## Verificação

`tests/relational.rs` (DDL, DML, restrições, planos, joins, agregação, crash, vacuum),
`tests/engine_v05.rs` (compressão, snapshots concorrentes, conflitos, primário → réplica
por TCP real), testes unitários de codec, parser, codificação de chave, LIKE, feed e
quadros de replicação, e os alvos de fuzz `rel_sql` e `codec`.
