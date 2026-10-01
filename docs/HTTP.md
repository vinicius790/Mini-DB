# API HTTP

Inicie o servidor com `minidb http [dir] [addr]`. O endereço padrão é
`127.0.0.1:8080`; configuração por arquivo/ambiente e argumentos da CLI está descrita
no README. O serviço implementa HTTP/1.1 de conexão curta: uma requisição por conexão,
seguida de `Connection: close`.

## Rotas

| Método e rota | Contrato |
| --- | --- |
| `GET /health` (`/v1/health`) | Liveness; retorna `{"ok":true,"service":"minidb"}`. Não verifica se uma operação de escrita pode completar. |
| `GET /metrics` (`/v1/metrics`) | Contadores Prometheus em texto. Contadores são locais ao processo e reiniciam com ele. |
| `GET /openapi.json` (`/v1/openapi.json`) | Descrição OpenAPI mínima mantida no código. |
| `GET /v1/stats` | Raízes, high-water mark, LSNs, próximo id de transação, capacidade do pool, estado do índice e da transação. |
| `GET /v1/kv?key=...` ou `?key_hex=...` | Busca uma chave. Se ambos forem fornecidos, `key_hex` tem precedência. |
| `PUT /v1/kv` ou `POST /v1/kv` | Upsert JSON com `key`/`value` ou `key_hex`/`value_hex` e `ttl_ms` opcional. O par hex tem precedência quando presente. |
| `DELETE /v1/kv?key=...` ou `?key_hex=...` | Remove a chave; o JSON informa `deleted: true` ou `false`. |
| `GET /v1/scan` | Scan ordenado, intervalo `[start, end)`; parâmetros hex disponíveis para bytes arbitrários. |
| `GET /v1/count` | Contagem em `start`/`end` ou `prefix` (e variantes `*_hex`): `{"ok":true,"count":N}`. |
| `GET /v1/ttl?key=` | `{"state":"missing"\|"persistent"\|"expires","ttl_ms":N\|null}`. |
| `GET /v1/pages` | Ocupação: páginas, folhas, folhas vazias, internos, livres, bytes vivos, % de preenchimento e altura. |
| `POST /v1/batch` | Lote atômico `{"ops":[{"op":"put","key":...,"value":...,"ttl_ms"?:N},{"op":"delete","key":...}]}` (1–10000 itens, formas `*_hex` aceitas). |
| `POST /v1/expire` | `{"key":...,"ttl_ms":N}` define TTL; `"ttl_ms":null` remove. Responde `updated`. |
| `POST /v1/purge` | Remove fisicamente chaves expiradas; responde `purged`. |
| `GET /v1/changes?since=LSN[&table=t][&limit=n][&timeout=s][&once=1]` | Stream de mudanças confirmadas (SSE `event: change`, `data: {lsn,table,kind,old,new}`); com `once=1` devolve JSON com o lote atual e `last_lsn`. `since` omitido = só o que vier. `410` quando o LSN saiu do anel. |
| `GET /v1/listen?channel=a[&channel=b][&timeout=s]` | Notificações `NOTIFY` dos canais, em SSE (`event: notify`). |
| `POST /v1/sql` | Executa SQL a partir de `{"sql":"...","params":[...]}`: um comando, ou um script (`a; b; c`) atômico, com `BEGIN ... COMMIT` opcional dentro do mesmo pedido. Scripts devolvem `{"ok":true,"results":[...]}`, um resultado por comando. |
| `OPTIONS <rota>` | Resposta preflight CORS `204` apenas para rotas conhecidas; `Allow`/`Access-Control-Allow-Methods` é específico da rota e o header permitido é `Content-Type`. |

## Dados e respostas

Chaves e valores do motor são bytes. Campos textuais são codificados como UTF-8. Em
`/v1/kv`, o corpo de escrita aceita:

```json
{"key":"hero","value":"Alucard"}
```

ou, para bytes arbitrários:

```json
{"key_hex":"00ff","value_hex":"800a"}
```

Hexadecimal deve ter número par de dígitos. Chaves vazias não são válidas; chave e
valor respeitam os limites do motor (1 KiB e 64 MiB, respectivamente). Em consultas
e deleções, use `key_hex`; em scans, use os parâmetros `start_hex`, `end_hex` e
`after_hex`. Se a forma textual e hex da mesma posição forem enviadas, a forma hex
vence.

Respostas KV incluem `key`/`key_hex` e `value`/`value_hex`; `key` é preenchido também
quando a consulta usa `key_hex`. As formas textuais são
representações UTF-8 lossily decoded e não são reversíveis para bytes inválidos; os
campos hex são a fonte exata. Em cache miss, `value` e `value_hex` são `null`. Um valor
vazio é diferente de miss: nesse caso o campo hex é a string vazia (`""`). DELETE
retorna `{"ok":true,"deleted":...}`.

Cada linha de scan contém `key`, `key_hex`, `value` e `value_hex`. O endpoint devolve
as linhas já materializadas numa resposta JSON; não é streaming. Sem `limit`, o scan
pode devolver todo o conjunto e consumir memória proporcional ao resultado.

## Scan e paginação

Parâmetros textuais: `start`, `end`, `after`, `prefix` (`prefix` não combina com
`start`/`end`). Parâmetros binários equivalentes:
`start_hex`, `end_hex`, `after_hex`. Por padrão `start` é o byte zero, que é o menor
byte permitido numa chave. `end` é exclusivo. `limit` deve ser inteiro entre 1 e
10000. Cursor é exclusivo: envie a última chave recebida em `after` ou `after_hex`;
cursor só é aceito junto com `limit`.

```sh
curl 'http://127.0.0.1:8080/v1/scan?start=player%3A&limit=100'
curl 'http://127.0.0.1:8080/v1/scan?start_hex=00ff&after_hex=00ff01&limit=50'
```

Paginar reduz o tamanho de cada resposta e evita repetir a fronteira; o algoritmo atual
lê folha a folha e para ao preencher `limit` (memória proporcional ao limite, não
ao banco). Não há snapshot consistente entre páginas. Escritas concorrentes podem
alterar o conjunto entre requisições.

Percent-encoding de query é validado e `+` representa espaço. Se um parâmetro conhecido
for repetido, a primeira ocorrência é usada. Parâmetros desconhecidos válidos são
ignorados. Hex é a forma recomendada para chaves não textuais.

## SQL

O endpoint executa o SQL relacional completo ([SQL.md](SQL.md)) e também o dialeto
chave-valor (`SELECT ... FROM kv`). Aceita `params` e scripts (ver abaixo). Consultas
relacionais retornam `{"ok":true,"columns":[...],"rows":[[...]]}`; no dialeto
chave-valor, `{"ok":true,"rows":[{"key":"...","value":"..."}]}` e `COUNT(*)` retorna
`{"ok":true,"count":N}`; valores em SQL são textuais e
essa resposta não é um transporte binário. Números não finitos (`inf`, `NaN`) saem como
`null`. A sintaxe inválida, argumentos inválidos e
estado transacional incompatível retornam 400. Erros de I/O, corrupção e falhas internas
retornam 500.

## Transporte, status e CORS

Cabeçalhos têm limite de 32 KiB; corpos, de `max_body_bytes` (padrão: o bastante para
um valor máximo em hexadecimal, ~129 MiB); ambos são medidos separadamente. O
servidor usa `Content-Length` para determinar o corpo, rejeita cabeçalhos
`Content-Length` duplicados e combinações com `Transfer-Encoding`, aceita
`Transfer-Encoding: identity` sem framing adicional e não suporta chunked. O corpo é
UTF-8 (JSON para rotas com corpo). Cada leitura bloqueante tem
timeout de 30 s; isso é timeout ocioso por leitura, não prazo total. O servidor cria uma
thread por conexão e aceita até `max_connections` (padrão 1024) conexões simultâneas;
as excedentes recebem `503` com `{"ok":false,"error":"server busy"}` e são fechadas.
As threads compartilham um `SharedDb`: leituras rodam em paralelo e escritas usam o
caminho concorrente (o `fsync` não bloqueia leitores).

Com `token` configurado, toda rota exceto `/health` e `OPTIONS` exige
`Authorization: Bearer <token>` (senão `401`). `/v1/sql` aceita `params` (array de
null, bool, número ou texto) para `?`, `?N` e `$N` (só com um comando por pedido). Cada
pedido é uma sessão própria: um `BEGIN` sem `COMMIT` no mesmo pedido é desfeito e
responde `400`; para transações longas use a conexão TCP. Rotas de replicação:
`GET /v1/replication` (papel, época, LSNs, réplicas conectadas, modo síncrono) e
`POST /v1/replication/promote`; manutenção: `POST /v1/maintain`.

Por padrão **não há cabeçalhos CORS**: uma página web qualquer não consegue ler nem
escrever na API pelo navegador (com `Access-Control-Allow-Origin: *`, qualquer site
visitado poderia atacar um servidor em `127.0.0.1` sem token). Para um painel web
legítimo, defina `MINIDB_CORS_ORIGIN=https://origem.exemplo` (uma só origem): as
respostas passam a incluir `Access-Control-Allow-Origin` e `Vary: Origin`. Preflight
`OPTIONS` em rota conhecida retorna 204 e anuncia os métodos aceitos naquela rota, além
de autorizar `Content-Type` e `Authorization`. Preflight para rota inexistente retorna
404. Não há suporte a credentials. CORS não é autenticação e não impede acesso por
clientes não-browser; sem token nem usuários a API continua aberta a qualquer processo
local, então defina `token` ou crie usuários.

Status usados: `200` para operações concluídas, `400` também para erros de
validação vindos do motor (ex.: restrição violada), `401` sem token válido, `403`
para escrita em réplica somente leitura, `409` para conflito de transação, `204` para
preflight, `400` para
requisição inválida (incluindo SQL inválido e chave/valor fora do limite), `404` para
rota não reconhecida, `405` para método não suportado numa rota conhecida (`Allow`
informa os métodos aceitos), `500` para falha interna e `503` quando o limite de
conexões foi atingido ou a réplica está em ressincronização. Erros JSON têm forma
`{"ok":false,"error":"..."}`. `/health` confirma liveness, não prontidão ou durabilidade.

Não exponha esta API diretamente a uma rede não confiável sem TLS: com `https = true`
o servidor fala HTTPS (TLS 1.3 próprio); sem isso o token trafega em texto claro. Não
há rate limiting: use proxy/firewall e restrinja o bind a loopback quando adequado;
consulte [../SECURITY.md](../SECURITY.md). `GET /v1/changes` e `GET /v1/listen`
mostram linhas de todas as tabelas e por isso exigem `SELECT` em `*` para usuários
sem superprivilégio.
