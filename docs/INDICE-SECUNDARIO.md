# Índice secundário por valor

Implementado em `src/index.rs` como uma segunda B+ Tree (face chave-valor; os índices
do SQL relacional estão em [SQL.md](SQL.md)).

- Chave do índice: `[sha256(valor)[..16]][chave primária]`; valor da entrada: vazio.
  A busca por valor calcula o hash e varre o prefixo, depois confere o valor real.
- Raiz: `meta.index_root` (`TreeId::Secondary`), flags `META_FLAG_VALUE_INDEX` e
  `META_FLAG_INDEX_V2` (formato por hash; bancos antigos são reconstruídos uma vez).
- Criação e backfill: `CREATE INDEX ON kv (value)`, comando `INDEX` ou
  `Db::create_value_index` (faz checkpoint ao final).
- Manutenção automática em `put`, `delete`, `commit` e recovery; `VACUUM` reconstrói.
- Consulta: `GETVAL`, `Db::get_by_value` ou `SELECT * FROM kv WHERE value = ...`.
  Com transação aberta, a consulta usa scan completo para enxergar o write-set.

## Tamanho

Como a chave do índice tem tamanho fixo (hash + chave primária), valores de qualquer
tamanho (até 64 MiB) podem ser indexados; `put` nunca rejeita um par por causa do índice.

Escopo: um único índice (valor → chaves), sem índices compostos nem `UNIQUE`.
