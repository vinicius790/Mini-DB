# Recuperação e checkpoint

Cada alteração confirmada é registrada no WAL antes de ser considerada persistida e só
depois aplicada às árvores. O buffer pool pode despejar páginas modificadas para
`data.mdb.spill`, nunca para `data.mdb`.

## Checkpoint

1. Sincroniza o WAL e grava o `checkpoint_lsn` na página meta.
2. Grava as páginas alteradas em `data.mdb.journal` (com CRC e marca de fim) e o
   `fsync`.
3. Escreve as páginas no lugar em `data.mdb` e faz `fsync`.
4. Apaga o journal e arquiva o WAL em `wal-archive/` (com retenção para réplicas e
   backups incrementais) ou o trunca.

Ao abrir, um journal completo é reaplicado (idempotente) e um journal incompleto é
descartado: `data.mdb` fica sempre na imagem anterior ou na nova, nunca pela metade.
O custo é proporcional às páginas alteradas, não ao tamanho do banco. O checkpoint
automático dispara quando o WAL passa de `auto_checkpoint_mb` (padrão 64).

## Recovery

O bloqueio `LOCK` impede duas instâncias locais de abrir o mesmo diretório. Na abertura
o WAL é lido e os registros com LSN ≤ `checkpoint_lsn` são ignorados; autocommits são
aplicados na hora, `BEGIN … COMMIT` aplica o lote e `ABORT` o descarta. Uma transação
sem `COMMIT` (inclusive um `BEGIN` seguido de outro `BEGIN` porque o `ABORT` não chegou
ao disco) é descartada.

- **Cauda incompleta** (último frame truncado ou com CRC ruim, sem nada depois): é
  ignorada e removida, como num crash no meio da escrita.
- **Corrupção no meio do log** (frame com CRC ruim seguido de mais dados): a abertura
  falha com `CorruptWal`, em vez de descartar em silêncio transações já confirmadas.
  Restaure de um backup ou use `minidb restore --until-lsn`.
- Um cabeçalho de banco danificado causa erro, nunca reinicialização silenciosa.

## Durabilidade

Por padrão, cada operação confirmada sincroniza o WAL. `fsync = false`
(`MINIDB_FSYNC=false`; também `0`, `no` e `off`) desativa essa sincronização por commit,
trocando durabilidade por desempenho; checkpoints continuam sincronizando a imagem
publicada. Em sistemas não Unix o `fsync` do diretório é um no-op, então a ordem de
publicação por rename depende do sistema de arquivos.

## Integridade com criptografia em repouso

Em bancos cifrados criados a partir desta versão (`data.mdb.key` de versão 3), cada página
de `data.mdb`, do journal e do spill é um ChaCha20-Poly1305 com a etiqueta inteira de 128
bits e AAD com a posição. A imagem é `etiqueta(16) ‖ campos do cabeçalho(14) ‖ 2 bytes ‖
corpo`, cifrada: a página continua com 4096 bytes. O nonce de cada página **não** fica
nela: fica no mapa de páginas `data.mdb.pages`, um arquivo com o nonce atual de cada
página e um HMAC-SHA256 (subchave do banco) sobre tudo. Cada checkpoint sela as páginas
alteradas com nonces novos; o journal leva as imagens e o mapa novo, e o mapa é publicado
por temporário + fsync + rename depois das páginas. O mapa novo guarda o MAC do anterior:
na abertura um journal só é reaplicado se o mapa dele descende do mapa instalado (ou já é
ele), então um journal antigo deixado no diretório é descartado sem tocar em nada. Trocas
do arquivo de dados (`VACUUM`, `encrypt`/`rekey`/`decrypt`, migração) publicam o mapa
novo como `data.mdb.pages.next` e o instalam depois do rename do arquivo; uma queda entre
os dois é resolvida na abertura (vale o mapa com que a página 0 abre).

O que dá `CorruptPage` na leitura: byte alterado, página movida de lugar, cabeçalho
adulterado, **versão antiga e válida de uma página** (*replay*: o mapa já aponta para o
nonce novo), mapa antigo, adulterado ou apagado, e arquivo de dados truncado (o mapa
conhece páginas que sumiram).

Os frames do WAL desses bancos também são autenticados (ChaCha20-Poly1305 encadeado
pelo LSN do frame anterior; formato em `docs/WAL.md`): frame alterado, removido,
repetido ou fora de ordem dá `CorruptWal`, mesmo no fim do arquivo quando o CRC confere.
Um frame truncado ou com CRC ruim no fim continua sendo tratado como escrita
interrompida, então quem altera o arquivo pode cortar as últimas transações do WAL, mas
não mudar as que ficam.

Bancos de formatos anteriores (chave v1: CRC16 em claro; chave v2: etiqueta de 80 bits,
sem mapa) são migrados para v3 automaticamente na primeira abertura com a senha, com a
**mesma chave** (só o byte de versão do `data.mdb.key` muda): réplicas, WAL arquivado e
backups continuam valendo (os segmentos arquivados de um banco v1 são regravados com
frames autenticados). A migração reescreve `data.mdb` num temporário (precisa do espaço
de uma cópia) e é desfeita ou concluída por `recover_convert` se cair no meio; se falhar
(disco cheio, diretório só de leitura), o banco abre no formato antigo e a próxima
abertura tenta de novo. O primeiro backup depois de uma troca de chave ou de formato é
completo (a base antiga não abriria os segmentos novos).

O que continua fora: voltar o **diretório inteiro** a uma cópia anterior coerente (todas
as páginas, o mapa e o WAL juntos, como restaurar um backup) não é detectável sem um
contador guardado fora do disco.
O modelo coberto é o de quem lê ou altera os arquivos sem a senha: não lê os dados, não
forja nem edita páginas ou registros e não volta páginas isoladas no tempo; voltar o
banco inteiro a um estado antigo que ele mesmo gravou fica fora.

## VACUUM

`VACUUM` remove as chaves expiradas, faz checkpoint e reconstrói as árvores em streaming
(uma folha por vez) num arquivo novo, `vacuum.mdb`; a troca é um `rename` atômico sobre
`data.mdb`. Um crash antes do rename mantém a imagem anterior e o WAL; sobras de
`vacuum.mdb` são removidas na abertura.

## Backup e restauração

Veja o README: `minidb backup` (completo e incremental) e `minidb restore` (até o fim,
`--until-lsn` ou `--until-time`). A restauração avisa se faltar algum LSN entre os
segmentos (por exemplo, segmento apagado pela retenção).

Os testes cobrem término abrupto do processo e arquivos truncados. Garantias em quedas
de energia dependem também das semânticas de sincronização e rename do sistema de
arquivos; não houve matriz de ensaios por sistema operacional ou dispositivo. Faça
cópias externas e valide a restauração antes de usar dados importantes.
