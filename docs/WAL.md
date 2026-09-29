# WAL — write-ahead log

Arquivo `wal.log`. Prefixo do arquivo: magic `MWAL` + version u32 = 1.

## Frame

```
payload_len u32     tamanho de (lsn + type + payload)
crc32       u32     IEEE sobre (lsn + type + payload)
lsn         u64
type        u8
payload     [payload_len-9]
```

Leitura para no frame truncado. CRC errado → `CorruptWal`.

## Tipos (`type`)

| id | nome | payload |
|---|---|---|
| 1 | Insert | key_len u32, key, val_len u32, val |
| 2 | Delete | key_len u32, key |
| 3 | Checkpoint | root u32, freelist u32, next_page u32, checkpoint_lsn u64 |
| 4 | Begin | txn_id u64 |
| 5 | Commit | txn_id u64 |
| 6 | Abort | txn_id u64 |
| 7 | Expire | key_len u32, key, expires_at u64 (ms desde a época; 0 remove o TTL) |

## Recover

1. Lê frames válidos.
2. Descarta LSN ≤ `meta.checkpoint_lsn`.
3. Fora de txn: aplica na hora (autocommit).
4. Begin…Commit aplica o lote; Abort descarta; EOF no meio = abort.

## Escrita

- Uma operação isolada (PUT, DELETE, EXPIRE) é um frame avulso.
- `put_with_ttl`, `write_batch`, `purge_expired` e `commit` gravam
  `BEGIN … COMMIT`: ou todo o grupo é refeito no recovery, ou nada.
- Sequência: append → `fsync` (padrão) → aplicação nas árvores. Se o append
  falhar no meio de um frame, um `ABORT` é tentado para fechá-lo.
- Se a aplicação falhar depois do registro durável, o handle é fechado; ao
  reabrir, o recovery refaz a operação a partir do WAL.
- Recovery usa a mesma função de aplicação da escrita normal.

Compatibilidade: o tipo 7 surgiu na 0.4. Um WAL com registros `Expire` não
é lido por binários 0.3 (que o tratam como fim do log); faça checkpoint antes
de voltar de versão.
`data.mdb` só recebe páginas no eviction ou no checkpoint.
