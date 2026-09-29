# Escopo da versão 0.4

A 0.4 amplia o motor e a estratégia de qualidade mantendo o núcleo sem
dependências e o formato em disco compatível com a 0.3.

## Entregue

- TTL por chave (`put_with_ttl`, `expire`, `persist`, `ttl`, `purge_expired`) com
  terceira B+ Tree, registro WAL `Expire` e expiração preguiçosa em todas as leituras.
- Iterador por folha (`iter`, `scan_prefix`), `count`, paginação sem materializar.
- Lote atômico `write_batch` em um frame `BEGIN/COMMIT`.
- SQL: `COUNT(*)`, `LIKE 'prefixo%'`, `INSERT ... TTL n`, `LIMIT` com parada antecipada.
- CLI/TCP: `SETEX`, `EXPIRE`, `TTL`, `PERSIST`, `PURGE`, `EXISTS`, `COUNT`, `PREFIX`, `PAGES`.
- HTTP: `/v1/count`, `/v1/ttl`, `/v1/pages`, `/v1/batch`, `/v1/expire`, `/v1/purge`,
  `prefix` em `/v1/scan`, `ttl_ms` em `/v1/kv`; OpenAPI atualizada.
- ABI C: `minidb_put_ttl_bytes`, `minidb_count`.
- `page_stats`, `verify` com coerência entre árvores, caminho de escrita único com
  fechamento do handle em falha pós-WAL, CRCs por tabela.
- Testes baseados em modelo, robustez, fuzzing (`fuzz/`), smoke dos clientes e
  benchmark com percentis.

## Critério de conclusão

Os comandos de [QUALIDADE.md](QUALIDADE.md#critério-de-merge) passam no CI em Linux,
macOS e Windows.

## Não objetivos

Continuam fora: MVCC e isolamento entre transações concorrentes, JOIN e tipos SQL,
autenticação/TLS embutidos, replicação contínua/failover, múltiplos escritores,
compressão de valores (valores ≤ 1 KiB não compensam o custo) e garantias de
energia independentes do filesystem.
