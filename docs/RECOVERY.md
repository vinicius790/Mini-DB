# Recuperação e checkpoint

Cada alteração confirmada é registrada no WAL antes de ser considerada persistida. O buffer pool pode despejar páginas modificadas para `.mdb.spill`, sem alterar `data.mdb`. O checkpoint prepara uma imagem completa em `data.mdb.next`, sincroniza os dados, publica a imagem e somente então trunca o WAL. Um checkpoint interrompido antes da publicação permite recuperar a imagem anterior com o WAL. Depois da publicação, o WAL antigo ainda pode ser repetido de modo idempotente.

O bloqueio `LOCK` impede duas instâncias locais de abrir simultaneamente o mesmo diretório. O WAL verifica integridade dos frames e ignora uma cauda incompleta; uma transação sem commit é descartada. Um cabeçalho de banco danificado causa erro em vez de reinicialização silenciosa.

Por padrão, cada operação confirmada sincroniza o WAL. A configuração `fsync = false`
(ou `MINIDB_FSYNC=false`) desativa essa sincronização por commit nos modos HTTP/TCP,
reduzindo a garantia de durabilidade em troca de desempenho; checkpoints continuam
sincronizando a imagem publicada e o diretório para preservar a ordem de publicação.

`VACUUM` reconstrói as árvores em memória/spill sem gravar no WAL (as linhas não
mudam) e publica o resultado pelo mesmo checkpoint atômico; só depois encolhe
`data.mdb`, removendo páginas além do high-water mark. Um crash antes da publicação
mantém a imagem anterior e o WAL.

Os testes cobrem término abrupto do processo e arquivos truncados. Garantias em quedas de energia dependem também das semânticas de sincronização e rename do sistema de arquivos; não houve matriz de ensaios por sistema operacional ou dispositivo. Faça cópias externas e valide a restauração antes de usar dados importantes.
