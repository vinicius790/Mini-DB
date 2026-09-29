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
| `POST /v1/sql` | Executa um statement do subset SQL a partir de `{"sql":"..."}`. |
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
valor respeitam os limites do motor (128 e 1024 bytes, respectivamente); com índice
por valor, `chave + valor + 2` deve caber em 128 bytes. Em consultas
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

O endpoint compartilha `parse_sql` com a API Rust e aceita somente o subset descrito no
README: comandos KV, SELECT, CREATE INDEX e operações de manutenção/transação. Não é
um SQL geral e não oferece parâmetros preparados. Sucesso com linhas retorna
`{"ok":true,"rows":[{"key":"...","value":"..."}]}`; `COUNT(*)` retorna
`{"ok":true,"count":N}`; valores em SQL são textuais e
essa resposta não é um transporte binário. A sintaxe inválida, argumentos inválidos e
estado transacional incompatível retornam 400. Erros de I/O, corrupção e falhas internas
retornam 500.

## Transporte, status e CORS

Cabeçalhos têm limite de 32 KiB, corpos de 8 MiB; ambos são medidos separadamente. O
servidor usa `Content-Length` para determinar o corpo, rejeita cabeçalhos
`Content-Length` duplicados e combinações com `Transfer-Encoding`, aceita
`Transfer-Encoding: identity` sem framing adicional e não suporta chunked. O corpo é
UTF-8 (JSON para rotas com corpo). Cada leitura bloqueante tem
timeout de 5 s; isso é timeout ocioso por leitura, não prazo total. O servidor cria uma
thread por conexão e aceita no máximo 128 conexões simultâneas; as excedentes recebem
`503` com `{"ok":false,"error":"server busy"}` e são fechadas. As threads
compartilham um `Db` sob mutex, portanto as operações de banco são serializadas.

Para facilitar o cliente TypeScript em browser, todas as respostas incluem
`Access-Control-Allow-Origin: *`; preflight `OPTIONS` em rota conhecida retorna 204 e
anuncia os métodos aceitos naquela rota, além de autorizar `Content-Type`. Preflight
para rota inexistente retorna 404. Não há allowlist de origens nem suporte a
credentials. CORS não é autenticação e não impede acesso por clientes não-browser.

Status usados: `200` para operações concluídas, `400` também para erros de
validação vindos do motor (ex.: limite do índice por valor), `204` para preflight, `400` para
requisição inválida (incluindo SQL inválido e chave/valor fora do limite), `404` para
rota não reconhecida, `405` para método não suportado numa rota conhecida (`Allow`
informa os métodos aceitos), `500` para falha interna e `503` quando o limite de
conexões foi atingido. Erros JSON têm forma
`{"ok":false,"error":"..."}`. `/health` confirma liveness, não prontidão ou durabilidade.

Não exponha esta API diretamente a uma rede não confiável: não há autenticação, TLS,
rate limiting; o limite de 128 conexões não substitui um proxy. Use proxy/firewall e restrinja o bind a
loopback quando adequado; consulte [../SECURITY.md](../SECURITY.md).
