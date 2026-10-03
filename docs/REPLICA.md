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

### O que é

Eleição de líder **no estilo Raft** (`src/raft.rs`) por cima da replicação lógica
existente, com commit por maioria. Não é um Raft completo (veja "O que não é").

- **Termo = época.** O vencedor do termo `T` é promovido pelo mesmo caminho de
  `PROMOTE`, com época `T`. O fencing que já existe (um primário que encontra época
  maior fica somente leitura; uma réplica nunca segue época menor) passa a recusar o
  líder antigo.
- **Estado persistente** por nó em `raft-state` no diretório do banco (termo atual e
  voto nesse termo), gravado com arquivo temporário + fsync + rename antes de qualquer
  mensagem sair. Um nó reiniciado não vota duas vezes no mesmo termo.
- **RPCs** pelo canal de replicação autenticado e cifrado (`MINIDB_REPL_SECRET`;
  handshake `RAFT <nonce> <mac>` em vez de `SYNC`): `RequestVote(termo, candidato,
  posição do log)` e `Heartbeat(termo, líder)`, com respostas. Sem segredo o modo
  cluster recusa subir.
- **Regras:** um voto por termo; só vota em candidato cujo log é pelo menos tão
  atualizado quanto o próprio (compara época dos dados, depois LSN); líder com
  **maioria estrita** (`n/2 + 1`, contando ele mesmo); quem vê termo maior vira
  seguidor; seguidor sem batimento por um timeout de eleição vira candidato com
  termo + 1 (timeout sorteado em `[base, 2·base)`, batimentos a `base/5`).
- **Ao ganhar**, o nó para de seguir quem seguia, é promovido com época = termo e exige
  `sync_replicas = n/2` (maioria − 1, sem timeout) em cada commit. Os demais passam a
  segui-lo (a réplica do cluster troca de upstream em execução; como a linhagem mudou,
  a primeira sincronização com o novo líder é por snapshot completo, como hoje).
- **Líder isolado:** sem resposta da maioria por um timeout de eleição, o líder para de
  aceitar escritas (somente leitura) antes de os outros poderem eleger alguém.
- `ROLE`/`/v1/replication`: líder = `primary`; seguidor = `replica of <líder>`; nó sem
  líder conhecido = `fenced`. `PROMOTE` manual é recusado no modo cluster.

### O que é garantido

- No máximo um líder por termo (maioria estrita e um voto por termo, persistido).
- Uma escrita **confirmada ao cliente** pelo líder está em pelo menos `n/2 + 1` nós
  (ela própria mais `n/2` confirmações duráveis). Um novo líder só é eleito com a
  maioria dos votos e só recebe voto de quem não tem log mais atualizado; as duas
  maiorias se cruzam, então a escrita confirmada sobrevive à eleição.
- Um seguidor que viu um termo maior não aplica nem confirma mais nada do líder antigo.
- `sync_replicas`/`sync_timeout_ms` do arquivo são ignorados no modo cluster (vale a
  maioria, sem timeout), para não existir confirmação assíncrona que se perca.

### O que não é garantido (limites conhecidos)

- **Janela de deposição.** Um commit que já estava esperando confirmações quando o
  líder perdeu a maioria é liberado (conta em `sync_timeouts`) e volta ao cliente sem
  erro, embora possa não estar na maioria; ele fica no WAL do líder antigo e pode ser
  perdido quando esse nó se ressincroniza com o novo líder. Tudo o que foi confirmado
  **antes** da perda de contato está na maioria.
- Leituras em seguidores podem estar atrasadas (não há leitura linearizável).
- Nó em ressincronização completa (snapshot) não vota nem se candidata. Se o líder cair
  enquanto a maioria dos seguidores ainda recebe o snapshot, não há quórum até que um
  deles termine de sincronizar com algum líder, o que pode exigir intervenção
  (reiniciar o nó com os dados mais recentes sem `cluster_peers` e promovê-lo).
- Sem PreVote: um nó que ficou isolado volta com termo alto e força uma eleição.

### O que não é

- Não há AppendEntries próprio, snapshots do log do Raft nem `commitIndex`: o "log" é a
  replicação lógica existente, e a posição de um nó é `(época, LSN aplicado)`.
- Não há mudança de membros em execução: `cluster_peers` é fixo na subida.
- Não há leitura linearizável em seguidores nem redirecionamento de escritas: o cliente
  precisa escrever no líder (`ROLE` diz quem é).
- A validação do protocolo foi por testes determinísticos da máquina de estados
  (`src/raft.rs`, 3 e 5 nós simulados) e um teste de integração com 3 nós reais
  (`tests/review_raft.rs`), não por verificação formal.
