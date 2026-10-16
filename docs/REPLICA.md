# Réplica por WAL shipping

> Para replicação **contínua** (primário → réplicas por streaming), veja
> [MOTOR-0.5.md](MOTOR-0.5.md#3-replicação-srcreplicationrs). Este módulo cobre só a
> cópia fria de arquivos.

`mini_db::replica::ship_snapshot(src, dst)` copia `data.mdb` + `wal.log`.
`open_standby(dst)` reabre e o recover aplica o log.

O shipping adquire o lock do primário, executa checkpoint e fecha o banco antes
da cópia. Se o primário já estiver aberto por outro processo ou handle, a operação
falha em vez de produzir um snapshot potencialmente inconsistente. O destino recebe
cada arquivo por cópia temporária e rename.

Isso é warm standby, não cluster. Sem eleição, sem lag metric além do LSN
da meta. Serve para:

- backup consistente a frio (feche ou checkpoint no primário antes)
- teste de recover em outro diretório
- drill de desastre

Para alta disponibilidade use a replicação contínua (`replication.rs`: streaming
autenticado e cifrado, semi-síncrona, promoção manual com época e fencing; veja
[MOTOR-0.6.md](MOTOR-0.6.md)). `ship_snapshot` não abre bancos criptografados nem copia
`data.mdb.key`: para esses, use `minidb backup`.

## Failover automático (modo cluster, opcional)

Desligado por padrão. Liga quando `cluster_peers` não está vazio em `minidb.toml`
(ou `MINIDB_CLUSTER_PEERS`), e então `--primary ADDR` passa a ser o endereço de
replicação **deste nó** (réplicas e pares chegam por ele); `--replica-of` não combina
com o modo cluster. Sem `cluster_peers`, nada muda: a replicação é a descrita acima,
com `PROMOTE` manual.

```toml
cluster_id = 1                                   # id deste nó (> 0, único)
cluster_peers = "2@10.0.0.2:7001,3@10.0.0.3:7001" # id@endereço de replicação dos outros
election_timeout_ms = 1500                       # base; cada nó sorteia entre 1x e 2x
repl_secret = "..."                              # obrigatório no modo cluster
```

`cluster_peers` é a configuração **inicial**: vale até a primeira troca de membros
(veja abaixo); depois, cada nó usa a configuração gravada no próprio banco. A lista
pode incluir o próprio nó (`1@10.0.0.1:7001`): esse é o endereço que o líder anuncia
aos outros quando grava uma configuração nova; sem ele, vale o `--primary`, que então
precisa ser alcançável pelos outros (não `0.0.0.0`).

### O que é

Eleição de líder **no estilo Raft** (`src/raft.rs`) por cima da replicação lógica
existente, com commit por maioria, PreVote e troca de um membro por vez. Não é um Raft
completo (veja "O que não é").

- **Termo = época.** O vencedor do termo `T` é promovido pelo mesmo caminho de
  `PROMOTE`, com época `T`. O fencing que já existe (um primário que encontra época
  maior fica somente leitura; uma réplica nunca segue época menor) passa a recusar o
  líder antigo.
- **Estado persistente** por nó em `raft-state` no diretório do banco (termo atual e
  voto nesse termo), gravado com arquivo temporário + fsync + rename antes de qualquer
  mensagem sair. Um nó reiniciado não vota duas vezes no mesmo termo.
- **RPCs** pelo canal de replicação autenticado e cifrado (`MINIDB_REPL_SECRET`;
  handshake `RAFT <nonce> <mac>` em vez de `SYNC`): `PreVote`, `RequestVote(termo,
  candidato, posição do log)` e `Heartbeat(termo, líder)`, com respostas. Sem segredo o
  modo cluster recusa subir.
- **Regras:** um voto por termo; só vota em candidato cujo log é pelo menos tão
  atualizado quanto o próprio (compara época dos dados, depois LSN); líder com
  **maioria estrita dos membros da configuração em vigor** (`n/2 + 1`, contando ele
  mesmo se for membro); quem vê termo maior vira seguidor.
- **PreVote.** Seguidor sem batimento por um timeout de eleição (sorteado em
  `[base, 2·base)`; batimentos a `base/5`) primeiro pergunta aos membros se votariam
  nele no termo + 1, **sem subir o próprio termo**. Quem ouviu um líder há menos de um
  timeout de eleição, ou tem log mais atualizado, diz não. Só com a maioria dos
  pré-votos ele sobe o termo e pede votos de verdade. Um nó que ficou isolado continua
  no termo em que estava e, ao voltar, passa a seguir o líder sem forçar eleição.
- **Ao ganhar**, o nó para de seguir quem seguia, é promovido com época = termo e cada
  commit espera a confirmação durável da maioria dos membros (sem timeout). Cada nó
  conta uma vez: o seguidor manda o seu id no `SYNC` (coberto pelo MAC), e réplicas
  comuns ligadas ao líder (`--replica-of`) recebem os dados mas **não contam** para a
  maioria. Os demais passam a segui-lo (a réplica do cluster troca de upstream em
  execução; como a linhagem mudou, a primeira sincronização com o novo líder é por
  snapshot completo).
- **Líder isolado:** sem resposta da maioria por um timeout de eleição, o líder para de
  aceitar escritas (somente leitura) antes de os outros poderem eleger alguém. Os
  commits que ainda esperavam confirmações voltam com erro (veja "O que é garantido").
- **Configuração de membros** = um registro do próprio log replicado (chave reservada
  no banco): durável no WAL de cada nó, replicada como qualquer escrita e incluída nos
  snapshots. Como no Raft, cada nó usa a configuração mais recente que tem nos dados; um
  nó reiniciado volta com a que estava no seu banco (o `cluster_peers` do arquivo só
  vale enquanto não houve troca nenhuma).
- **Trocar membros** (um por vez, só no líder; com usuários cadastrados exige
  superusuário, como o `PROMOTE` exige privilégio total; sem usuários, vale o token):
  - TCP: `CLUSTER` (mostra `índice id@endereço,...`), `CLUSTER ADD <id> <endereço>`,
    `CLUSTER REMOVE <id>`.
  - SQL: `SHOW CLUSTER` (mostra nós, ID, endereços, papel e estado do cluster) e `SHOW PEERS` (mostra réplicas conectadas, LSN e latência).
  - HTTP: `GET /v1/cluster`, `POST /v1/cluster/add` com `{"id": 4, "addr": "..."}`,
    `POST /v1/cluster/remove` com `{"id": 3}`.
  - API: `replication::change_membership(&db, raft::Change::Add(id, addr))` e
    `replication::membership(&db)`.

  O líder (1) confirma, pela maioria da configuração em uso, um registro do termo
  atual; (2) grava a configuração nova, que passa a valer **no líder** para a maioria
  dos commits seguintes (e do próprio registro) assim que entra no log, e em cada
  seguidor assim que ele a aplica; (3) responde OK só quando a **maioria da
  configuração nova** confirmou. Outra troca é recusada enquanto essa não termina.
  Durante a troca o líder já manda batimentos ao nó que está entrando, que passa a
  segui-lo e recebe os dados (por snapshot, se for novo).
- **Adicionar:** suba o nó novo com `cluster_id` próprio e `cluster_peers` listando os
  membros atuais, e rode `CLUSTER ADD` no líder. Antes da troca ele não conta para
  ninguém e os pré-votos dele são recusados (o log dele está atrás).
- **Remover:** o nó removido deixa de se candidatar quando aplica a configuração nova,
  o voto dele deixa de contar para os outros, o líder para de mandar-lhe batimentos e
  ele fica somente leitura (`fenced`); pode ser desligado. **Remover o líder:** ele
  continua liderando até a configuração nova ser confirmada e então deixa de liderar;
  os que ficam elegem outro (há um intervalo sem líder, como em qualquer eleição).
- **Ressincronização completa:** um nó recebendo snapshot não se candidata, mas
  **vota** com a posição do log que tinha antes de começar (gravada na marca da
  ressincronização, também numa retomada depois de queda).
- `ROLE`/`/v1/replication`: líder = `primary`; seguidor = `replica of <líder>`; nó sem
  líder conhecido (ou removido) = `fenced`. `PROMOTE` manual é recusado no modo cluster.

### O que é garantido

- No máximo um líder por termo: maioria estrita da configuração e um voto por termo,
  persistido. Configurações vizinhas diferem em um único nó, então uma maioria de uma
  e uma maioria da outra sempre têm um nó em comum; e uma troca só começa depois de a
  anterior ter sido confirmada e de um registro do termo atual ter sido confirmado
  (a correção conhecida do "single-server change" do Raft).
- Uma escrita **confirmada ao cliente** pelo líder está gravada de forma durável na
  maioria dos membros da configuração em vigor nele (ele próprio, se for membro, mais
  confirmações de outros membros, uma por nó). Um novo líder só é eleito com a maioria
  dos votos e só recebe voto de quem não tem log mais atualizado; as maiorias se
  cruzam, então a escrita confirmada sobrevive à eleição.
- **Commit sem a maioria nunca volta como sucesso.** Se o líder perde a liderança
  (sem contato com a maioria, termo maior, removido ou desligado) enquanto um commit
  espera confirmações, esse commit volta ao cliente com o erro `indisponível no
  momento: commit não confirmado pela maioria do cluster: resultado incerto, o líder
  perdeu a maioria` — TCP `ERR ...`, HTTP 503, protocolo PostgreSQL SQLSTATE `57P03`,
  API embutida `Error::Unavailable` — e conta em `sync_timeouts`. Vale para todo
  caminho de commit (autocommit, `COMMIT` de transação SQL/MVCC, lotes, `Db`
  exclusivo); os eventos de mudança (`LISTEN`/`/v1/changes`) desse commit não são
  publicados.
- Um seguidor que viu um termo maior (ou começou uma pré-votação) não aplica nem
  confirma mais nada do líder antigo.
- Uma troca de membros só é dada como concluída depois de confirmada pela maioria da
  configuração nova; nunca há duas trocas pendentes no mesmo líder.
- Um nó isolado não sobe o termo (PreVote) e, ao voltar, não derruba um líder que a
  maioria ainda ouve.
- O voto de um nó em ressincronização usa a posição de antes dela, que é a de tudo o
  que ele já confirmou a algum líder (durante o snapshot ele não confirma nada); por
  isso ele nunca vota em quem não tem uma escrita confirmada que passou por ele.
- `sync_replicas`/`sync_timeout_ms` do arquivo são ignorados no modo cluster (vale a
  maioria, sem timeout), para não existir confirmação assíncrona que se perca. Fora do
  modo cluster eles funcionam como sempre (o timeout libera o commit sem erro).

### O que não é garantido (limites conhecidos)

- **Resultado incerto.** O commit que volta com o erro acima já está no WAL do líder
  antigo e aplicado nele: pode ter chegado à maioria (e sobreviver no novo líder) ou
  não (e sumir quando aquele nó se ressincronizar). O cliente precisa conferir antes de
  repetir uma escrita que não seja idempotente. A mesma incerteza vale para uma troca
  de membros que volta com erro depois de gravada (`CLUSTER` mostra o que valeu).
- Leituras em seguidores podem estar atrasadas (não há leitura linearizável); no líder
  deposto, um commit "incerto" fica visível até ele se ressincronizar.
- Um nó em ressincronização completa não se candidata. Se o líder cair e todos os nós
  fora de ressincronização juntos não formarem maioria, ninguém se elege até um deles
  terminar de sincronizar com algum líder, o que pode exigir intervenção (reiniciar o
  nó com os dados mais recentes sem `cluster_peers` e promovê-lo).
- O nó que entra vota assim que a configuração nova vale, sem fase de "aprendiz": se ele
  não estiver no ar, a maioria passa a precisar de um nó a mais. Adicione nós que já
  estão rodando; com membros fora do ar, uma troca pode ficar esperando (como qualquer
  commit, sem timeout) e travar as escritas até a maioria nova responder.
- O endereço de cada membro é o da configuração gravada: para mudar o endereço de um
  nó, remova-o e adicione-o de novo.
- Todos os nós do cluster precisam desta versão (pré-votos e id de nó no `SYNC`).

### O que não é

- Não há AppendEntries próprio, snapshots do log do Raft nem `commitIndex`: o "log" é a
  replicação lógica existente, e a posição de um nó é `(época, LSN aplicado)`. A
  configuração de membros é um registro desse log, não um arquivo à parte: um arquivo
  separado poderia divergir do log (por exemplo, depois de uma ressincronização que
  descarta um registro não confirmado) e quebrar a garantia de um líder por termo.
- Não há "joint consensus": a troca é de um membro por vez.
- Não há leitura linearizável em seguidores, redirecionamento de escritas nem
  transferência de liderança: o cliente precisa escrever no líder (`ROLE` diz quem é).
- A validação do protocolo foi por testes determinísticos da máquina de estados
  (`src/raft.rs`: 3, 4 e 5 nós simulados, PreVote, entrada e saída de membros, saída
  do próprio líder, troca concorrente recusada) e testes de integração com nós reais
  (`tests/review_raft.rs`: failover, commit incerto, entrada e saída de membros), não
  por verificação formal.
