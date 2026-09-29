# Invariantes que o `VERIFY` exige

1. Toda página `0 .. next_page_id` tem magic `MDB1` e CRC16 válido.
2. `root_page` ∈ `(0, next_page_id)`.
3. Range scan da árvore primária devolve chaves estritamente crescentes.
4. Não há chave duplicada no encadeamento de folhas.
5. Insert é upsert: mesma chave substitui o valor.
6. Delete remove a chave; GET seguinte devolve `None`.
7. Após crash sem checkpoint, recover reproduz os PUTs cujo WAL foi `fsync`.
8. Transação sem COMMIT não fica visível após reopen.
9. Bloom **não** gera falso negativo para chave presente (falso positivo é legal).
10. Índice secundário, quando existe, encontra as chaves com aquele valor.
11. Exclusão nunca torna inalcançável outra chave, mesmo esvaziando folhas inteiras.
12. `VACUUM` preserva todas as linhas vivas, o índice e os TTLs, e reduz o arquivo.
13. Toda entrada da árvore de TTL corresponde a uma chave da árvore primária.
14. Toda entrada do índice por valor aponta para uma chave com exatamente aquele valor.
15. Chave expirada é invisível em `get`, scans, contagem, índice e SQL, mesmo antes do `PURGE`.
16. Um lote (`write_batch`, `put_with_ttl`, commit) sobrevive inteiro ou não sobrevive a um crash.
17. Qualquer sequência de operações equivale a um `BTreeMap` de referência (`tests/model_based.rs`).

`VERIFY`/`minidb-verify` checam 1–4, 13 e 14 no arquivo aberto e saem com código 1
se algum falhar; os demais são cobertos por testes.
