# Escopo fechado do Mini-DB 0.3

> Documento histórico. O escopo vigente está em [ESCOPO-0.4.md](ESCOPO-0.4.md).

Este documento define o que significa "concluído" para a versão 0.3. O projeto é um
motor KV embutido didático, não um SGBD distribuído de produção.

## Entregue

- Persistência em páginas de 4 KiB com B+ Tree, buffer pool e checksum.
- WAL com CRC, transações de escrita, checkpoint e recovery após crash.
- GET, PUT, DELETE, scans, paginação por cursor e índice secundário por valor.
- Subset SQL documentado: SELECT, INSERT, UPDATE, DELETE, EXPLAIN, BEGIN, COMMIT,
  ROLLBACK, CHECKPOINT, VACUUM e CREATE INDEX.
- CLI, servidor TCP linha-orientado, HTTP/JSON, métricas Prometheus e ABI C.
- Backup/import JSONL com bytes em hexadecimal.
- ABI C textual compatível e API C binária para bytes arbitrários.
- Snapshot frio de réplica por `data.mdb` + `wal.log`.
- Verificação de invariantes, inspect de páginas e ferramentas auxiliares.
- Testes Rust de unidade, integração, recovery, crash, WAL, SQL, paginação e produto.

## Critério de conclusão

A versão 0.3 está concluída quando `cargo test --all-targets --locked`, doctests e os
builds de bins/biblioteca passam. O CI executa também fmt, Clippy e verificação sintática
do header C quando essas ferramentas estão disponíveis no runner.

## Não objetivos da versão 0.3

Os itens abaixo não são pendências desta versão e não devem ser implementados como
correções incrementais:

- MVCC ou isolamento transacional avançado.
- JOIN, plano SQL completo ou tipos SQL ricos.
- Autenticação, autorização e TLS incorporados.
- Cluster, consenso, eleição, failover ou replicação contínua.
- Vacuum/compactação online avançada.
- Garantias de falha de energia independentes do sistema de arquivos.
- Concorrência distribuída ou múltiplos escritores no mesmo diretório.

Esses recursos só devem entrar em uma versão futura com mudança explícita de escopo,
formato on-disk, documentação, testes e compatibilidade.
