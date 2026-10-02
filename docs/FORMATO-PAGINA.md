# Formato on-disk — página 4096 bytes

Endianness: little-endian. Magic: `MDB1`.

```
offset  size  campo
0       4     magic
4       4     page_id
8       1     kind   0=Free 1=Meta 2=Internal 3=Leaf 4=Overflow
9       1     flags
10      2     n_slots
12      2     cell_end
14      4     right_sibling (folha) / próximo free
18      4     extra / leftmost_child
22      8     lsn
30      2     checksum CRC16-CCITT (bytes 30-31 zerados no cálculo)
32      …     slot directory + células
```

Slot directory: a partir do byte 32, `n_slots` × `u16` (offset da célula).
Células crescem do fim da página para o início.

Célula folha: `[key_len u16][val_len u16][key][val]`
Célula interna: `[key_len u16][child u32][key]`

Página 0 (Meta), payload após o header 32 B:

```
root_page u32 | freelist_head u32 | next_page_id u32
checkpoint_lsn u64 | next_lsn u64 | index_root u32
next_txn_id u64 | flags u32 | ttl_root u32   (0.4+; zero em arquivos 0.3)
```

Árvores: `root_page` (primária, chave → valor), `index_root` (índice por
valor, `[len u16][valor][chave]` → chave) e `ttl_root` (expiração, chave →
`expires_at` u64 big-endian em ms). As três usam o mesmo formato de página.

Nota: em bancos cifrados no formato v2 o cabeçalho é cifrado e autenticado (ver
`docs/RECOVERY.md`); o que segue descreve o formato em claro e o v1.

Checksum: CRC16-CCITT-FALSE (poly 0x1021, init 0xFFFF; vetor `"123456789"` →
`0x29B1`) calculado por tabela, com os bytes 30-31 tratados como zero.

Compatibilidade: arquivos 0.3 abrem na 0.4 sem migração (`ttl_root` = 0).

Limites (0.6): chave ≤ 1 KiB (chaves internas de índice ≤ 1088 B), valor ≤ 64 MiB.
Nenhuma célula passa de 1/3 da página (1352 B + slot); valores maiores vão para
páginas `Overflow` (tipo 4): a célula guarda `[total:u32][primeira:u32]` com o bit 15
de `val_len` ligado, e cada página de overflow usa `right_sibling` como próxima e
`extra` como bytes úteis. Páginas liberadas entram na freelist (`freelist_head`).
Flags da meta: `1` índice por valor, `2` valores comprimidos, `4` índice por hash.
