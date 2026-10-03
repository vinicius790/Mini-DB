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

Em bancos cifrados criados a partir desta versão (`data.mdb.key` de versão 2), cada página
de `data.mdb`, do journal e do spill leva uma etiqueta Poly1305 de 80 bits (ChaCha20-Poly1305,
nonce `id ‖ 8 bytes aleatórios`, AAD com a posição). A etiqueta substitui o magic, o id, o
LSN e o CRC16 do cabeçalho de 32 bytes, então a página continua com 4096 bytes, sem arquivo
lateral e sem mexer no journal: a etiqueta viaja com a página e a recuperação do journal
continua uma cópia de bytes. Alterar um byte, mover uma página de lugar ou adulterar o
cabeçalho dá `CorruptPage` na leitura. Bancos de chave versão 1 mantêm o formato antigo
(CRC16 em claro, que quem tem o arquivo refaz ou zera) e migram com `encrypt`/`rekey`.
Os frames do WAL desses bancos também são autenticados (ChaCha20-Poly1305 encadeado
pelo LSN do frame anterior; formato em `docs/WAL.md`): frame alterado, removido,
repetido ou fora de ordem dá `CorruptWal`, mesmo no fim do arquivo quando o CRC confere.
Um frame truncado ou com CRC ruim no fim continua sendo tratado como escrita
interrompida, então quem altera o arquivo pode cortar as últimas transações do WAL, mas
não mudar as que ficam.

Não há proteção contra *replay* (devolver uma versão antiga e válida da mesma página, ou
o banco inteiro numa cópia anterior). Fechar isso exigiria guardar a versão atual de
cada página num lugar autenticado: um contador de geração no AAD obrigaria a regravar
todas as páginas a cada checkpoint, e uma tabela de etiquetas ou árvore de Merkle muda o
formato, o journal, o spill, o `VACUUM` e o `convert`. Mesmo assim a volta do diretório
inteiro a uma cópia anterior coerente só seria detectada com um contador fora do disco.
O modelo coberto é o de quem lê ou altera os arquivos sem a senha: não lê os dados e não
forja nem edita páginas ou registros; voltar o banco (ou uma página) a um estado antigo
que ele mesmo gravou fica fora.

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
