# Arquitetura do Mini-DB

## Camadas

| Camada | Responsabilidade |
| --- | --- |
| `Db` | Dono do handle: validação, caminho único WAL → árvores, transações, TTL, iteradores, SQL, checkpoint e vacuum. |
| `BTree` | Árvores primária, índice por valor e TTL: busca, upsert, splits pelo caminho de descida, exclusão local e scan pelo encadeamento de folhas. |
| `BufferPool` | Pin/unpin, LRU, spill de páginas dirty e publicação atômica no checkpoint. |
| `Wal` | Frames com LSN e CRC32, redo, BEGIN/COMMIT/ABORT e truncamento pós-checkpoint. |
| Adaptadores | CLI/TCP (`cmd`), HTTP/JSON, backup JSONL e ABI C chamam o mesmo `Db`. |
| Diagnóstico | `verify`, `inspect`, métricas Prometheus e binários de suporte. |

Páginas têm 4096 bytes, little-endian, header fixo, diretório de slots e células do fim
para o começo ([FORMATO-PAGINA.md](FORMATO-PAGINA.md)). A página 0 guarda raízes,
freelist, high-water mark, LSNs, próximo id de transação e flags. O índice secundário é
uma segunda B+ Tree com chave `[len][valor][chave primária]`; a expiração é uma terceira
B+ Tree (`ttl_root`) de chave → instante em ms.

## B+ Tree

A inserção desce da raiz registrando o caminho de ancestrais. Se a folha enche, ela é
dividida ao meio e o separador sobe por esse caminho; nós internos cheios também se
dividem e promovem a chave do meio, e uma nova raiz é criada quando o caminho acaba.
Não há busca pelo pai a partir da raiz.

A exclusão remove a célula e compacta a folha, sem tocar nos nós internos. Uma folha
pode ficar vazia e continua no encadeamento: leituras e scans a atravessam, e novas
inserções na mesma faixa a reutilizam. Isso mantém os separadores sempre coerentes com
o conteúdo. O `VACUUM` reconstrói as árvores a partir das linhas vivas, publica a nova
imagem por checkpoint e encolhe `data.mdb`.

## Caminho de escrita

Toda escrita vira uma lista de operações lógicas (`Put`, `Delete`, `Expire`) que
passa por um único caminho: validação → registro no WAL (frame `BEGIN/COMMIT`
quando há mais de uma) → `fsync` → aplicação nas três árvores. O recovery usa a
mesma função de aplicação, então o estado reconstruído é idêntico ao que existia em
memória. Se a aplicação falhar depois do registro durável, o handle se fecha e
reabrir recupera pelo WAL — o motor nunca continua com estado em memória duvidoso.

## TTL

`put_with_ttl` grava `Put` + `Expire` no mesmo frame. A leitura esconde a chave
assim que o instante passa (verificação preguiçosa em `get`, iteradores, contagem,
índice e SQL); `PURGE` a remove fisicamente pelo WAL e o `VACUUM` purga antes de
reconstruir. `put` sem TTL remove a expiração anterior; `delete` também.

## Iteradores

`Db::iter` desce até a primeira folha e carrega uma folha por vez seguindo o
encadeamento (`BTree::leaf_rows`), com limite de folhas visitadas contra ciclos.
`scan`, `scan_page`, `count`, `scan_prefix` e o SQL (`LIMIT` ascendente, `COUNT(*)`,
`LIKE 'p%'`) usam o iterador, então paginação e contagem não materializam o banco.

## Escrita e recuperação

No autocommit, `Db` valida e acrescenta a operação ao WAL antes de alterar a árvore;
com `fsync=true`, sincroniza por operação. Em transação, o write-set fica em memória
até o commit escrever `BEGIN`, operações e `COMMIT`. A recuperação refaz as operações
confirmadas após o checkpoint e descarta transações incompletas (fechando-as com
`ABORT` no WAL).

O pool expulsa páginas dirty para o spill, nunca para `data.mdb`. O checkpoint monta
`data.mdb.next`, sincroniza, publica por rename e trunca o WAL. Ordem de escrita e
limites de crash: [RECOVERY.md](RECOVERY.md) e [WAL.md](WAL.md).

## Adaptadores e concorrência

CLI e TCP compartilham o interpretador de comandos. HTTP implementa HTTP/1.1 simples
com JSON e CORS; a ABI C oferece formas NUL-terminated e binárias. Cada servidor cria
uma thread por conexão (limite configurável) sobre um `SharedDb`: leitores em paralelo
(`RwLock`), escritor único cujo `fsync` acontece sem bloquear leitores. Os clientes Python/TypeScript são
exemplos sobre HTTP.

A configuração vem de `minidb.toml` e pode ser substituída por `MINIDB_*`. O `LOCK` é
local e exclusivo. `ship_snapshot` é uma cópia fria após checkpoint, não streaming nem
failover ([REPLICA.md](REPLICA.md)).

## Limites deliberados

Os limites deliberados das versões anteriores (SQL, concorrência, replicação,
tamanhos) foram removidos na 0.6: veja [MOTOR-0.6.md](MOTOR-0.6.md). O SQL da 0.7
(integridade referencial, views, janelas, CTEs recursivas, sessões) está em
[SQL.md](SQL.md); o código vive em `src/rel/` (`parser.rs`, `exec.rs` consultas e
planejador, `write.rs` DDL/DML e integridade, `window.rs`, `func.rs`). Histórico:
[0.5](MOTOR-0.5.md), [0.4](ESCOPO-0.4.md), [0.3](ESCOPO-0.3.md).
