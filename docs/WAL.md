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

Leitura para no último frame truncado ou com CRC ruim (escrita interrompida: a cauda é
ignorada e removida). Um frame com CRC ruim **seguido de mais dados** é corrupção no
meio do log e dá `CorruptWal`. Com criptografia em repouso o CRC cobre o texto
cifrado, e o formato do payload vem da versão do `data.mdb.key` (nunca do conteúdo do
arquivo):

- **v2 e v3 (bancos cifrados; chave de versão 2 ou 3)**: `nonce(12) ‖ ChaCha20-Poly1305(payload) ‖ etiqueta(16)`,
  com uma subchave só do WAL (HMAC da chave do banco) e nonce aleatório: um LSN pode
  voltar a ser usado com outro conteúdo (cauda descartada no recovery, restauração até
  um ponto), então o nonce não deriva dele. O AAD é `"minidb wal v2" ‖ lsn do frame
  anterior no arquivo (0 no primeiro) ‖ lsn ‖ type`: cada frame fica preso ao anterior.
  Um frame inteiro (CRC confere) cuja etiqueta não confere, ou cujo LSN não avança,
  dá `CorruptWal` em qualquer posição, inclusive no fim: byte alterado, tipo ou LSN
  trocados, frame removido, repetido ou fora de ordem. Frame truncado ou com CRC ruim
  no fim continua sendo cauda de escrita interrompida e é descartado; como no fim do
  arquivo um frame rasgado e um adulterado com o CRC quebrado são indistinguíveis,
  quem altera o arquivo consegue **cortar o fim do log** (perder as últimas
  transações), mas não alterar, reordenar ou remover o que fica antes. Trocar o
  arquivo inteiro por outro WAL válido do mesmo banco (cópia antiga, segmento
  arquivado) também não é detectado: equivale a cortar o fim do log ou a voltar o
  diretório inteiro a uma cópia anterior (`docs/RECOVERY.md`).
- **v1 (legado)**: `sal(4) ‖ ChaCha20(payload)` (nonce = sal ‖ lsn), sem etiqueta: só o
  CRC, que quem tem o arquivo refaz. Bancos v1 são migrados na primeira abertura com a
  senha, e os segmentos arquivados são regravados no formato autenticado.

Cada arquivo (o `wal.log` atual e cada segmento de `wal-archive/`) começa uma cadeia
nova, então é sempre lido inteiro, do início.

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
| 8 | Time | unix_ms u64 (marca de relógio, no máximo uma por segundo; base do restore por instante) |

O tipo 3 (Checkpoint) é decodificado, mas o motor atual não o escreve: o estado do
checkpoint vive na página meta.

## Recover

1. Lê frames válidos.
2. Descarta LSN ≤ `meta.checkpoint_lsn`.
3. Fora de txn: aplica na hora (autocommit).
4. Begin…Commit aplica o lote; Abort descarta; EOF no meio = abort; um `Begin` que
   chega com outra transação aberta descarta a anterior (nunca confirmou).

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
`data.mdb` só recebe páginas no checkpoint (o eviction do pool vai para `.spill`).
Depois de um checkpoint o WAL é arquivado em `wal-archive/` (se há retenção) ou truncado.
