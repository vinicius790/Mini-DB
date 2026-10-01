# Índice secundário por valor

Implementado em `src/index.rs` como uma segunda B+ Tree.

- Chave do índice: `[val_len:u16][value][primary_key]`; valor: a chave primária.
- Raiz: `meta.index_root` (`TreeId::Secondary`), flag `META_FLAG_VALUE_INDEX`.
- Criação e backfill: `CREATE INDEX ON kv (value)`, comando `INDEX` ou
  `Db::create_value_index` (faz checkpoint ao final).
- Manutenção automática em `put`, `delete`, `commit` e recovery; `VACUUM` reconstrói.
- Consulta: `GETVAL`, `Db::get_by_value` ou `SELECT * FROM kv WHERE value = ...`.
  Com transação aberta, a consulta usa scan completo para enxergar o write-set.

## Limite de tamanho

Como a chave do índice precisa caber no limite de chave da árvore (128 bytes), com o
índice ativo cada par deve satisfazer `2 + len(valor) + len(chave) ≤ 128`. `put` e
`create_value_index` rejeitam pares maiores com uma mensagem explícita, antes de
escrever no WAL. Para valores grandes, não crie o índice.

Escopo honesto: um único índice (valor → chaves), sem índices compostos nem `UNIQUE`.
