# Changelog

## Não lançado (correções pós-1.3.0)

TLS
- TLS 1.3 passa a suportar também `TLS_AES_128_GCM_SHA256` (0x1301, a suíte obrigatória do
  RFC 8446 e a primeira que clientes comuns oferecem), além de `TLS_CHACHA20_POLY1305_SHA256`;
  o servidor escolhe a primeira suíte da lista do cliente que ele suporta. Só o AEAD do
  registro muda (chave de 16 bytes, mesmo hash SHA-256 e mesma agenda de chaves).
  `src/crypto.rs` ganhou AES-128 (S-box gerada em tempo de compilação), GHASH sem desvios
  e `aes128_gcm_seal`/`aes128_gcm_open`, com os vetores do NIST (Test Cases 1 a 4) e teste
  de integração contra `openssl s_client` (`tests/review_aesgcm.rs`). Limite conhecido: a
  consulta à S-box não é em tempo constante estrito (risco de temporização de cache).

COPY
- PostgreSQL: `COPY tabela [(colunas)] FROM STDIN`, `COPY tabela [(colunas)] TO STDOUT` e
  `COPY (SELECT ...) TO STDOUT` no formato texto (`DELIMITER`, `NULL`, escapes, `\.`),
  com `CopyInResponse`/`CopyOutResponse`/`CopyData`/`CopyDone`/`CopyFail`. O `FROM` aplica
  tudo numa transação só, com os privilégios de `INSERT` (e `SELECT` no `TO`); limite de
  256 MiB e 1.000.000 de linhas por `COPY FROM`. `CopyData` solto fora de um `COPY` passou
  a ser ignorado (antes dava erro). CSV e BINARY seguem fora.

Segurança
- HTTP não envia mais `Access-Control-Allow-Origin: *`; `MINIDB_CORS_ORIGIN` libera uma
  origem. O TCP de linhas encerra a conexão ao receber uma requisição HTTP e volta a
  exigir login se o primeiro usuário for criado depois da conexão.
- Autorização: subconsultas em `INSERT ... VALUES`, `ON CONFLICT`, `RETURNING` e
  `NOTIFY` são conferidas; `CREATE TRIGGER` exige os privilégios do corpo; `HEX`/
  `INSPECT`/`VERIFY`/`CATALOG` e `/v1/changes`/`/v1/listen` exigem privilégio em `*`.
- Login: usuário inexistente custa o mesmo PBKDF2; sal SCRAM fictício estável por nome.
- PostgreSQL: bytes em claro junto do `SSLRequest` derrubam a conexão; vaga de
  conexão devolvida mesmo com panic; startup limitado a 10 000 bytes; conexão em claro
  recusada com `tls_client_auth = required`.
- `tls.key` autogerado com 0600; `random_bytes` usa `BCryptGenRandom` no Windows;
  redução módulo L do Ed25519 sem desvios dependentes de segredo.
- HTTP recusa (`403`) `POST`/`PUT`/`DELETE` com `Origin` diferente da origem liberada:
  uma página qualquer não escreve mais na API local por `POST` sem preflight.
- HTTP confere o cabeçalho `Host` contra DNS rebinding (leituras por `GET` incluídas):
  aceita ausente, IP literal, nomes sem ponto, `localhost`/`*.localhost` e os de
  `MINIDB_ALLOWED_HOSTS` (`*` desliga); outro nome recebe `403`, exceto em `/health` e
  `/v1/health`. Atrás de proxy ou com domínio próprio, liste o nome na variável.
- Autorização: subconsulta em `LIMIT`/`OFFSET` é conferida; `RETURNING` exige `SELECT`
  na tabela; `ALL` dividido entre concessão direta e papel é somado.
- PostgreSQL: mensagens antes da autenticação limitadas a 64 KiB; conexão aberta sem
  usuários é encerrada quando o primeiro usuário é criado; erro de TLS aborta a subida
  em vez de cair para texto claro.
- Regex: profundidade da busca limitada (grupo repetido muitas vezes dá "não casa" em
  vez de estourar a pilha); `.*` e `\w+` não gastam pilha por caractere.
- Criptografia em repouso: estado de conversão incompleto não apaga mais a chave; a
  chave nova é gravada com `fsync`. Chave privada TLS recebe 0600 antes da escrita.
- SCRAM: o sal fictício de usuário inexistente sai de um segredo do processo; o
  cliente não consegue mais recalculá-lo para descobrir quem existe.
- Parser: uma expressão aceita até 1 000 operadores encadeados (`1 + 1 + ...`,
  `a OR b OR ...`) e um comando até 500 `UNION`/`INTERSECT`/`EXCEPT`; acima disso é
  erro. O executor avalia essas cadeias em laço: 999 operadores cabem numa pilha de
  2 MiB em build de depuração (medido no CI); antes, 250 já a estouravam.
- Regex: orçamento total de passos por varredura, além do limite por posição inicial.
- `encrypt`/`decrypt`/`rekey` seguram o lock do diretório do início ao fim e recusam
  um banco aberto.

Correções
- WAL: `Begin` com operações pendentes de outra transação volta a ser erro (não
  descarta em silêncio); se nem o `Abort` de um frame interrompido couber no disco, o
  WAL recusa escritas até a reabertura.
- Hash join com chave de texto numérico e número (`'05' = 5`) não perde mais linhas.
- Transação que apaga o pai que ela mesma referenciou não dá mais conflito falso de
  chave estrangeira; `TRUNCATE` do pai em transação protege contra filha concorrente.
- WAL: CRC ruim seguido só de zeros é cauda de escrita interrompida (queda de energia),
  não corrupção; `restore --until-lsn` não avisa de lacuna depois do alvo.
- `EXPLAIN` mostra o `SORT` de `ORDER BY ... NULLS`; join por índice com coluna de
  texto e valor numérico (`'05' = 5`) não perde linhas; `EXPLAIN EXPLAIN ...` entra no
  limite de aninhamento; `sum() FILTER (...)` sem argumento é erro.
- Datas: modificadores e `date_diff` fora do intervalo dão erro em vez de estouro;
  `printf('%05d', -42)` devolve `-0042`.
- Configuração: comentário depois de valor entre aspas é ignorado; booleano
  desconhecido mantém o padrão em vez de desligar `tls`/`fsync`.
- Servidores: vaga de conexão devolvida quando a thread não nasce; consulta vazia no
  protocolo PostgreSQL entrega as notificações; `minidb-inspect` nunca faz checkpoint.
- `DEFAULT 1e999` (infinito) corrompia o catálogo: o lexer recusa números fora do
  intervalo e o JSON escreve `null` para não finitos.
- Regex `[[:]` causava panic; texto/aninhamento limitados; um panic em escrita não
  envenena mais o mutex do escritor. Parser SQL com limite de aninhamento; threads de
  conexão com pilha de 64 MiB.
- `ROLLBACK TO` descarta também eventos e `NOTIFY` do trecho desfeito.
- Join por índice só usa índices B-tree; `NULLS FIRST/LAST` respeitado com índice;
  `coluna_texto = número` não usa índice; `CREATE INDEX` em view materializada recusado;
  gatilhos sem colisão no cache de subconsultas; FTS só com termos excluídos não casa.
- Tipos `DATE`, `DATETIME`, `JSON`, `UUID`, `TINYINT` aceitos em `CREATE TABLE`.
- `lpad`/`rpad`/`printf` com teto; estouros em `substr`, `generate_series`, molduras de
  janela, `array_get` e `parse_time` tratados.
- WAL: corrupção no meio do log dá `CorruptWal` (antes truncava em silêncio); `Begin`
  sem `Abort` anterior não impede mais a abertura; a época da réplica sobrevive a uma
  ressincronização interrompida; o stream de mudanças não corta um commit no meio.
- `restore` avisa sobre lacuna de LSN. `minidb-inspect --hex` usa o tamanho certo.
  `shell`/`exec`/`export`/`import`/`inspect`/`verify` abrem banco cifrado
  (`MINIDB_PASSPHRASE`). Booleanos de configuração aceitam `yes`/`on`.

Novidades
- Integridade entre transações: `UNIQUE` e chaves estrangeiras são revalidadas no
  commit também em `SNAPSHOT`. Antes, duas transações concorrentes podiam gravar o mesmo
  valor único ou deixar uma filha sem pai; agora a segunda recebe `Error::Conflict`.
- SQL: `agregado(x) FILTER (WHERE condição)` (reescrito para `CASE WHEN`).
- Protocolo PostgreSQL: `LISTEN`/`NOTIFY` entregam `NotificationResponse` ao cliente
  (antes o `LISTEN` era aceito e nada chegava).
- Filtro bloom escalável: cresce em camadas em vez de saturar com 4 KiB fixos (com
  50 mil chaves, ~5 % de falsos positivos em vez de ~99 %).
- mTLS: certificado de cliente com `extendedKeyUsage` sem `clientAuth` (por exemplo um
  certificado de servidor da mesma CA) é recusado.
- `encrypt`/`decrypt`/`rekey` à prova de crash: uma conversão interrompida é desfeita
  ou concluída na abertura seguinte.
- `minidb-verify` e `minidb-inspect` não fazem checkpoint ao sair (não reescrevem
  `data.mdb`).
- OpenAPI com `/v1/changes`, `/v1/listen`, replicação, manutenção e `params`.

Projeto
- CI único em `.github/workflows` (lint, matriz Linux/macOS/Windows, stress, contratos,
  fuzz, cobertura); testes rodam mesmo se o lint falhar. Workflow de release (tags
  `v*`): binários para Linux, macOS e Windows e imagem em `ghcr.io`.
- Dockerfile com `/data` gravável e sem porta morta; `.dockerignore`.
- Clientes Python/TypeScript com token/Basic e `params`; docs atualizadas;
  resumo em inglês (`README.en.md`).
- Alvos de fuzz `regex` e `x509`; testes de robustez para regex e decodificadores
  PEM/X.509; testes unitários do limite de aninhamento do parser e do filtro bloom.

## 1.3.0

- TLS/X.509 com **RSA, ECDSA (P-256/P-384) e Ed25519** em servidor, cadeias e mTLS:
  inteiros grandes com Montgomery (`src/bignum.rs`), curvas NIST (`src/ecc.rs`), RSA
  PKCS#1 v1.5/PSS com CRT (`src/rsa.rs`), SHA-384, chaves PEM PKCS#8/PKCS#1/SEC1 e SPKI
  (`src/pubkey.rs`). O handshake negocia `signature_algorithms` (ed25519, ecdsa_secp256r1/
  secp384r1, rsa_pss_rsae_*) e recusa só o que a chave não pode assinar.
  `minidb cert ... --algo ed25519|p256|p384|rsa2048|rsa3072|rsa4096` (geração de primos
  com Miller–Rabin; chaves passam em `openssl pkey -check`). Validado com `psql
  sslmode=verify-full`, `curl --cert`, `openssl s_client`/`verify`, cadeias RSA/EC geradas
  pelo OpenSSL (`tests/fixtures/pki`).
- Operações com chave privada em tempo constante: Montgomery sem desvios dependentes de
  dados, `pow_ct` em janela fixa, fórmulas completas (Renes–Costello–Batina) e escalar de
  tamanho fixo no ECDSA, nonce uniforme por rejeição; RSA com CRT, blinding e conferência
  contra falhas. RSA-PSS-SHA512 só é oferecido quando cabe na chave.
- Correção: alertas depois do ServerHello agora vão cifrados (antes o cliente via
  "bad record type" em vez de `unknown_ca`/`certificate_required`), e o servidor lê o voo
  inteiro do cliente antes de recusar o certificado (sem RST que apagava o alerta).
- Compatibilidade: `x509::create_ca`/`issue` mantêm a assinatura da 1.2 (Ed25519);
  `create_ca_with`/`issue_with` escolhem o algoritmo. `ed25519_key_pem`,
  `parse_ed25519_key_pem` e `OID_ED25519` continuam disponíveis e chaves `tls.key` da 1.2
  carregam sem mudança. Mudaram de tipo, para aceitar RSA/ECDSA: `Cert::public`
  (`PublicKey`), `x509::build` (`&PrivateKey`, `&PublicKey`) e `Identity::public_key()`
  (`PublicKey`); `Identity::from_key` aceita `Ed25519Key` ou `PrivateKey`.

## 1.2.0

- PKI própria e mTLS (`src/x509.rs`, `src/tls.rs`): `minidb cert ca|server|client`
  emite CA, certificado de servidor (SAN) e de cliente (CN = usuário) Ed25519; o servidor
  aceita cadeia (folha + intermediárias) via `tls_cert`/`tls_key` e verifica
  certificados de cliente contra `tls_ca` (`tls_client_auth = off|optional|required`):
  cadeia, nomes, validade, `CA:TRUE`, CertificateVerify. No PostgreSQL o CN autentica o
  usuário sem senha (CN ≠ usuário → 28000); no HTTPS o CN vira o usuário. Erros claros
  para chaves/certificados RSA/ECDSA (só Ed25519). Validado com OpenSSL (`openssl
  verify`), `psql sslcert/sslkey`, `curl --cert`.
- `pg_catalog`/`information_schema` com dados reais (`src/rel/pgmore.rs`): `pg_proc`,
  `pg_aggregate`, `pg_operator`, `pg_cast`, `pg_opclass`, `pg_language`, `pg_extension`,
  `pg_collation`, `pg_ts_*`, `pg_trigger`, `pg_depend`, `pg_auth_members`, `pg_matviews`,
  estatísticas (`pg_stat_user_tables`, `pg_stat_user_indexes`, `pg_stats`,
  `pg_statistic`), sessão (`pg_stat_activity`, `pg_stat_ssl`, `pg_backend_pid` por
  conexão), `information_schema.triggers/referential_constraints/check_constraints/
  routines`. `pg_constraint` ganhou `conparentid`, `confupdtype`, `confdeltype`...;
  `pg_get_triggerdef`, `pg_get_function_result/arguments`; `x::regclass` converte
  nome ⇄ oid; `format_type(oid, NULL)`; `FROM função() WITH ORDINALITY`.
  Com isso `\d` mostra FKs, "Referenced by" e gatilhos, e `\df`, `\do`, `\dC`, `\dx`,
  `\dF`, `\dL`, `\dA`, `\drds`, `\des`, `\dew` funcionam no psql real.
- Funções `ssl_is_used()`, `ssl_version()`, `ssl_cipher()`, `ssl_client_dn()`.
- Índices aparecem em `pg_class`/`pg_am` com o método certo (btree, hnsw, fulltext, zorder).

## 1.1.0

- TLS 1.3 nativo (`src/tls.rs`, `src/curve25519.rs`): X25519, Ed25519, SHA-512,
  Poly1305/ChaCha20-Poly1305, HKDF, certificado X.509 autoassinado (`tls.key`/`tls.crt`
  gerados; par Ed25519 próprio aceito). Protocolo PostgreSQL responde `S` ao
  `SSLRequest` (`tls = true` por padrão); HTTP em HTTPS com `https = true`. Testado com
  libpq/psql (`sslmode=require` e `verify-full`) e curl.
- `pg_catalog`/`information_schema` virtuais + funções `pg_*` e de sessão: os
  metacomandos do psql (`\dt`, `\d`, `\d+`, `\di`, `\dv`, `\du`, `\l`, `\dn`) e as
  consultas de ORMs funcionam. Sintaxe extra: `esquema.tabela`, `pg_catalog.função()`,
  `OPERATOR(pg_catalog.~)`, `COLLATE`, `E'...'`, `x::regclass` (tipos do catálogo não
  convertem), `array[...]`, `array(subconsulta)`, `arr[i]`, `x = ANY(array)`, funções de
  tabela `generate_series`/`unnest`, identificadores entre aspas mantêm maiúsculas.
- Expressões regulares próprias: operadores `~ ~* !~ !~*` e `regexp_like/replace/substr/
  count/matches/split_to_array`.
- `minidb encrypt|decrypt|rekey`: converte a criptografia em repouso no lugar.
- Colunas de função no resultado levam o nome da função (`version`, não `version(...)`);
  texto numérico compara com números (`oid = '16384'`).

## 1.0.0

Segurança
- Usuários e papéis: `CREATE USER nome [WITH] PASSWORD 'x' [SUPERUSER]`, `CREATE ROLE`,
  `ALTER USER ... PASSWORD | SUPERUSER | NOSUPERUSER`, `DROP USER|ROLE`, `GRANT
  SELECT|INSERT|UPDATE|DELETE|CREATE|ALL ON [TABLE] t|kv|* TO ...`, `GRANT papel TO usuário`,
  `REVOKE ... FROM`, `SHOW USERS`, `SHOW GRANTS [FOR nome]`. Credenciais SCRAM-SHA-256 no
  catálogo (`FF 'u' nome`); o primeiro usuário precisa ser superusuário; sem usuários a
  rede fica em modo aberto (compatível).
- Autorização por comando na `Session` (rede): tabelas lidas (inclusive subconsultas,
  CTEs e views), alvo de INSERT/UPDATE/DELETE, DDL (`CREATE` na tabela ou em `*`),
  administração de usuários só para superusuário; comandos chave-valor usam o objeto
  `kv`. `Error::Forbidden` → HTTP 403, SQLSTATE 42501.
- TCP `AUTH <usuário> <senha>` (além de `AUTH <token>`); HTTP `Authorization: Basic`.
- Criptografia em repouso: `Db::open_encrypted` / `passphrase` / `MINIDB_PASSPHRASE`.
  Páginas (corpo) e frames do WAL cifrados com ChaCha20, nonce aleatório por imagem,
  chave por PBKDF2-HMAC-SHA256; `data.mdb.key` com sal e verificador; VACUUM, journal,
  spill e arquivo de WAL mantêm a cifra; réplicas leem o histórico com a chave.

Operação
- `minidb backup [dir] <destino>`: completo (imagem após checkpoint + chave) e depois
  incremental (segmentos do WAL arquivado + WAL atual). Servidores passam a arquivar o
  WAL sempre que `wal_retention_mb > 0`.
- `minidb restore <backup> <dir> [--until-lsn N | --until-time '...']`: reconstrói o WAL
  a partir dos segmentos e deixa a recuperação aplicar só transações confirmadas; marcas
  de relógio (`REC_TIME`, no máximo uma por segundo) permitem restaurar a um instante.
- `Db::backup`/`restore` na API; `Db::cipher()`, `Db::is_encrypted()`.

Protocolo PostgreSQL
- `minidb pg [dir] [addr]` e `pg_addr`/`MINIDB_PG` (padrão `127.0.0.1:5432`, também em
  `serve`/`http`): startup v3 (SSL/GSS recusados), SCRAM-SHA-256 (usuários), senha em
  claro = token, ou trust; consulta simples com várias instruções; protocolo estendido
  (Parse/Bind/Describe/Execute/Close/Sync/Flush) com parâmetros em texto e binário
  (int2/4/8, float4/8, bool, text); RowDescription com OIDs inferidos; tags
  `INSERT 0 n`/`SELECT n`; SQLSTATE por erro; transação abortada até ROLLBACK; `SET`,
  `RESET`, `DISCARD`, `DEALLOCATE`, `SHOW parâmetro` como no-op. Testado com `psql`
  (inclusive `\bind`). Sem SSL, COPY e `pg_catalog`.

Outros
- Conversões de atribuição como no PostgreSQL: número/booleano → TEXT e texto
  numérico/booleano → INTEGER/REAL/BOOLEAN (parâmetros de drivers chegam como texto).
- Formato `minidb-1.0` (arquivos 0.8/0.9 abrem sem conversão); banner TCP `minidb 1.0 ready`.

## 0.9.0

Busca avançada (índices especiais, mantidos em cada INSERT/UPDATE/DELETE, dentro da
mesma transação; `REINDEX nome` reconstrói um índice ou todos os da tabela).
- Full-text: `CREATE FULLTEXT INDEX nome ON t (a, b)` guarda postings por termo
  (`FF 'x' tid iid 'p' termo 0 pk` → posições) com radicalização leve PT/EN, sem
  acentos. `MATCH (a, b) AGAINST ('consulta')` devolve a pontuação BM25 (0 = não
  casa): termos obrigatórios, `OR`, `-termo`/`NOT`, `"frase exata"`, `prefixo*`. Com
  índice nas mesmas colunas o planejador lê só os candidatos (`SEARCH ... USING FULLTEXT
  INDEX`); sem índice avalia linha a linha. `fts_tokens`, `fts_highlight`.
- Vetorial: `CREATE VECTOR INDEX nome ON t (emb) WITH (metric = 'cosine'|'l2'|'dot',
  m = 16, ef_construction = 100, dims = N)` — grafo HNSW persistido nas chaves do
  índice. `ORDER BY emb <=> '[0.1, ...]' LIMIT k` (`<->` L2, `<=>` cosseno, `<#>`
  produto interno negativo; ou `vec_distance(emb, v [, métrica])`) usa o índice quando a
  métrica coincide (`SEARCH ... USING VECTOR INDEX`), com 4× candidatos se houver
  filtro. Funções `vec_l2`, `vec_cosine`, `vec_dot`, `vec_distance`, `vec_dims`,
  `vec_norm`, `vec_normalize`, `vec_add`, `vec_sub`.
- Espacial: `CREATE SPATIAL INDEX nome ON t (x, y [, z])` com códigos Morton (curva
  Z, 31 bits por eixo em 2D, 21 em 3D, faixa ±1 000 000). Caixas fechadas em todas as
  colunas (`BETWEEN`, `>=`/`<=`, `st_dwithin(x, y, cx, cy, raio)`) viram até 64 faixas
  de código (`SEARCH ... USING SPATIAL INDEX ranges=N`) mais o filtro exato.
  `st_distance`, `st_distance_sphere` (metros, haversine), `st_dwithin`.
- `SHOW INDEXES` ganha a coluna `kind`; `SHOW CREATE TABLE` reproduz `FULLTEXT`/
  `VECTOR`/`SPATIAL` e `WITH (...)`; formato `minidb-0.9` (arquivos 0.8 abrem sem
  conversão).

## 0.8.0

Otimizador e desempenho
- `ANALYZE [tabela]`: linhas, distintos, nulos, mínimo e máximo por coluna, no
  catálogo (`FF 'a'`); `EXPLAIN` mostra `est. rows≈N`.
- Planejador por custo: entre chave primária, faixas e índices escolhe o caminho com
  menos linhas estimadas (seletividade por distintos e interpolação min/max); sem
  estatísticas vale a heurística anterior.
- `ORDER BY` satisfeito pelo acesso (PK ou índice, ASC com parada antecipada, DESC por
  inversão) e escolha de índice que já entrega a ordem pedida; Top-N (`ORDER BY ...
  LIMIT`) em O(n) + ordenação só dos n escolhidos.
- Join: `LOOKUP` vira `HASH` quando a relação externa é muito maior que a interna
  (estatísticas).
- Cache de comandos analisados por texto (`Db`/`SharedDb`); `EXPLAIN ANALYZE` executa
  e mostra linhas lidas/devolvidas e tempo por etapa.

Automação e tempo real
- Gatilhos: `CREATE TRIGGER nome BEFORE|AFTER INSERT|UPDATE [OF cols]|DELETE ON t
  [WHEN (cond)] BEGIN cmd; ... END` com `NEW.c`/`OLD.c`, `RAISE(ABORT|FAIL|ROLLBACK,
  msg)` e `RAISE(IGNORE)`; corpos veem as escritas pendentes do comando, disparam em
  cascatas e têm limite de profundidade; `DROP TRIGGER`, `SHOW TRIGGERS`, DDL em
  `SHOW CREATE TABLE`.
- Views materializadas: `CREATE MATERIALIZED VIEW mv [(cols)] [WITH AUTO REFRESH] AS
  consulta`, `REFRESH MATERIALIZED VIEW`, `DROP MATERIALIZED VIEW`; com `AUTO REFRESH`
  a view é recalculada no mesmo lote de cada escrita nas tabelas que ela lê.
- `NOTIFY canal [, payload]` entregue no commit a quem fez `LISTEN canal` (`Session`,
  conexão TCP com `WAIT [s]` e notificações anexadas às respostas, HTTP
  `GET /v1/listen?channel=...` em Server-Sent Events).
- Stream de mudanças: toda linha inserida/alterada/apagada vira evento (LSN, tabela,
  antes/depois) num anel em memória (`Db::events()`, capacidade configurável);
  `GET /v1/changes?since=LSN[&table=t]` em SSE ou JSON (`once=1`); LSN antigo demais
  responde `410` com o primeiro disponível.

## 0.7.0

SQL de alto nível (compatível com bancos da 0.6: catálogo migrado na leitura)
- Integridade: `CHECK` (coluna e tabela, com nome), `DEFAULT <expressão>` avaliado a
  cada linha (`now()`, `uuid()`, `random()`, `(a + 1)`), `AUTOINCREMENT`/`SERIAL`/
  `GENERATED AS IDENTITY`, `FOREIGN KEY`/`REFERENCES` com `ON DELETE`/`ON UPDATE`
  `CASCADE`, `SET NULL`, `SET DEFAULT`, `RESTRICT`/`NO ACTION`, autorreferência e
  chaves compostas; ações em cascata (várias tabelas, vários níveis) no mesmo lote
  atômico; índice automático nas colunas da FK; `DROP TABLE`/`TRUNCATE` protegidos.
- Esquema: `ALTER TABLE ... DROP COLUMN` (reescreve linhas, remove índices e CHECKs da
  coluna), `RENAME COLUMN` (atualiza CHECKs e FKs das filhas), `RENAME TO` (atualiza
  FKs), `ALTER COLUMN SET|DROP DEFAULT`, `SET|DROP NOT NULL`; `CREATE [OR REPLACE]
  VIEW`/`DROP VIEW` (views expandidas como subconsultas, aninháveis, sem ciclos);
  `TRUNCATE`; `SHOW INDEXES`, `SHOW CREATE TABLE|VIEW` (DDL reexecutável), `SHOW
  TABLES` com tipo, `DESCRIBE` com referências; sinônimos de tipos (`VARCHAR`,
  `DOUBLE PRECISION`, `TIMESTAMP`, `JSON`, `UUID`, `SERIAL`...), `IF [NOT] EXISTS` em
  tudo, comentários `/* */`, identificadores entre aspas/crases/colchetes.
- Consultas: funções de janela (`ROW_NUMBER`, `RANK`, `DENSE_RANK`, `PERCENT_RANK`,
  `CUME_DIST`, `NTILE`, `LAG`, `LEAD`, `FIRST_VALUE`, `LAST_VALUE`, `NTH_VALUE` e
  todo agregado com `OVER (PARTITION BY ... ORDER BY ... ROWS|RANGE ...)`, acumulação
  incremental para molduras que começam no início); `WITH RECURSIVE` (UNION e UNION
  ALL, colunas nomeadas, limite de iterações); `VALUES` como consulta, no `FROM` e em
  CTE; `x op ANY|SOME|ALL (subconsulta)`; `IS [NOT] DISTINCT FROM`; `IS TRUE/FALSE`;
  `GLOB` com classes `[a-z]`; operadores bit a bit (`&`, `|`, `<<`, `>>`, `~`);
  `x::tipo`; `ORDER BY ... NULLS FIRST|LAST`; `JOIN ... USING`; `LIMIT a, b`,
  `OFFSET n ROWS`, `FETCH FIRST n ROWS ONLY`; `GROUP BY` por alias; `IN ()` vazio.
- Agregados: `GROUP_CONCAT`/`STRING_AGG`, `TOTAL`, `BOOL_AND`/`EVERY`, `BOOL_OR`,
  `STDDEV[_POP|_SAMP]`, `VARIANCE`/`VAR_POP`/`VAR_SAMP`.
- Funções (~90): texto (`initcap`, `ltrim`/`rtrim` com caracteres, `left`/`right`,
  `reverse`, `repeat`, `lpad`/`rpad`, `starts_with`, `contains`, `split_part`,
  `position`, `char`/`unicode`, `hex`, `quote`, `printf`/`format`, `concat[_ws]`),
  matemática (`floor`, `ceil`, `sqrt`, `power`, `exp`, `ln`/`log`, `trunc`, `sign`,
  `mod`, trigonometria, `pi`, `random`), condicionais (`iif`, `greatest`, `least`,
  `nvl`), data/hora em UTC (`now`, `current_*`, `date`, `time`, `datetime`,
  `strftime`, `unixepoch`, `julianday`, modificadores `+N days`/`start of month`,
  `year`...`second`, `date_add`/`date_sub`/`date_diff`), JSON (`json_extract`,
  `json_type`, `json_array_length`, `json_object`, `json_array`, `json_valid`),
  `sha256`, `uuid`.
- DML: `RETURNING` em `INSERT`/`UPDATE`/`DELETE`; `INSERT OR REPLACE|IGNORE`,
  `REPLACE INTO`, `INSERT ... DEFAULT VALUES`; chaves estrangeiras conferidas ao fim
  do comando (linhas do mesmo lote podem se referenciar).
- Transações e scripts: vários comandos em um texto (`a; b; c`) rodam atômicos
  (`ExecResult::Batch`); `Session` (uma por conexão TCP, uma por pedido HTTP) com
  `BEGIN [ISOLATION LEVEL SERIALIZABLE]`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`,
  `RELEASE`, `ROLLBACK TO`; `Txn::sql` (SQL dentro de transações MVCC, com validação
  serializável das leituras); `Db` ganha `SAVEPOINT` e scripts; `PUT`/`GET`/`DEL` do
  TCP participam da transação da conexão.
- Correções: `BEGIN` via `SharedDb::sql` não abre mais uma transação global no `Db`
  compartilhado (agora exige sessão); leituras dentro de transações do `Db` deixaram
  de ser lineares no tamanho do write-set.

## 0.6.0

Armazenamento
- Páginas de overflow: valores de até 64 MiB (antes 1 KiB); chaves de até 1 KiB
  (antes 128 B). Páginas liberadas voltam à freelist.
- Split de B+ Tree por bytes (corrige falha rara com células grandes após o registro
  no WAL); busca binária em folhas e nós internos.
- Checkpoint por journal (proporcional às páginas alteradas), checkpoint automático
  pelo tamanho do WAL, VACUUM em streaming num arquivo novo, `Db::maintain`.
- Índice por valor por hash: qualquer tamanho de valor (reconstruído na abertura de
  bancos antigos). Compressão com cabeçalho de 32 bits para valores grandes.

Concorrência
- `SharedDb` com `RwLock`: leitores em paralelo; `fsync` do escritor sem bloquear
  leitores; `Db` com leituras `&self`.
- `begin_serializable` / `Isolation::Serializable`; GC de versões indexado por LSN.

SQL
- Subconsultas (escalares, `IN`, `EXISTS`, correlacionadas, no `FROM`), `WITH`,
  `UNION`/`INTERSECT`/`EXCEPT` (`ALL`), `CASE`, `CAST`, `nullif`, `replace`, `instr`.
- Chaves primárias, índices e `UNIQUE` compostos; textos indexados de qualquer tamanho.
- Parâmetros `?`/`?N`/`$N`, `prepare`/`execute_prepared`, `query`/`query_params`
  (somente leitura com `&self`), `params` no `/v1/sql`.
- `RIGHT`/`FULL`/`CROSS JOIN`, vírgula no `FROM`, hash join; `INSERT ... SELECT`;
  `ON CONFLICT DO NOTHING | DO UPDATE SET ... [WHERE]` com `excluded`.

Replicação
- Canal autenticado (HMAC-SHA256) e cifrado (ChaCha20) com segredo compartilhado.
- Retomada pelo WAL arquivado (`set_wal_retention`), snapshot MVCC em pedaços,
  ressincronização segura (réplica indisponível até terminar), `Condvar` no feed.
- Semi-síncrona (`set_sync_replicas`), `promote` com época e fencing, réplicas em
  cascata (`--replica-of` + `--primary`), `status`/`ROLE`, `/v1/replication`.

Servidores e operação
- Token em HTTP (`Bearer`) e TCP (`AUTH`); limites de conexões e corpo configuráveis;
  status 401/403/409/503; manutenção periódica; novas variáveis `MINIDB_*`.
- `crypto`: SHA-256, HMAC-SHA256, ChaCha20 com vetores oficiais nos testes.

Incompatibilidades
- `Db::iter`/`get`/`scan`... agora recebem `&self`; `cmd::apply`, `server::serve`,
  `http::serve_http` e `replication::run_replica` recebem `SharedDb`.
- `rel::parser::parse` devolve `(Stmt, parâmetros)`; `Error` ganhou `Unavailable` e
  `Unauthorized`; `VerifyReport`/`PageStats`/`DbStats` ganharam campos.
- Formato: arquivos 0.5 abrem normalmente; o índice por valor é refeito uma vez.

## 0.5.0

Motor
- **SQL relacional** (`mini_db::rel`): `CREATE/DROP TABLE`, `CREATE [UNIQUE] INDEX`,
  `DROP INDEX`, `ALTER TABLE ADD COLUMN`, `INSERT` multi-linha, `UPDATE`/`DELETE` com
  `WHERE` arbitrário, `SELECT` com `JOIN`/`LEFT JOIN`, `GROUP BY`/`HAVING`, `COUNT/SUM/
  AVG/MIN/MAX` (com `DISTINCT`), `DISTINCT`, `ORDER BY` (expressão, alias ou posição),
  `LIMIT/OFFSET`, `SHOW TABLES`, `DESCRIBE` e `EXPLAIN`. Tipos `INTEGER`, `REAL`,
  `TEXT`, `BOOLEAN`; `PRIMARY KEY` (autoincremento), `NOT NULL`, `UNIQUE`, `DEFAULT`.
  Planejador com busca pontual/faixa na PK, índices e index nested loop em joins.
- **MVCC** (`mini_db::mvcc`): `SharedDb` entre threads, `Snapshot` (leituras e SQL
  congelados) e `Txn` otimista com snapshot isolation e `Error::Conflict`.
- **Replicação lógica** (`mini_db::replication`): primário publica os commits por TCP;
  réplicas somente leitura aplicam snapshot + stream com LSN aplicado atômico e
  reconexão automática. CLI: `--primary ADDR` e `--replica-of ADDR` em `serve`/`http`.
- **Compressão LZ77** própria nos valores da árvore primária (flag na meta; arquivos
  0.4 migram no `VACUUM`).
- Erros `Conflict`, `ReadOnly` e `Constraint` (HTTP 400); `Db::last_lsn`,
  `Db::set_read_only`.

Interfaces
- `/v1/sql`, CLI e TCP executam SQL relacional; resultados tabulares em JSON
  (`columns` + `rows`) e em tabela alinhada na CLI.
- `export`/`import` incluem as tabelas SQL.

Incompatibilidades
- Chaves iniciadas por `0xFF` passam a ser reservadas ao motor.
- `ExecResult` ganhou a variante `Table` e deixou de implementar `Eq` (continua `PartialEq`).

## 0.4.0

Motor
- TTL por chave: `put_with_ttl`, `expire`, `persist`, `ttl`, `purge_expired`; terceira
  B+ Tree (`ttl_root` na página meta) e registro WAL `Expire` (tipo 7). Expiração
  preguiçosa em `get`, iteradores, contagem, índice e SQL.
- `Db::iter`/`ScanIter` leem uma folha por vez; `scan`, `scan_page`, `count`,
  `scan_prefix` e o SQL usam o iterador (paginação e contagem sem materializar).
- `write_batch` atômico em um único frame `BEGIN/COMMIT`.
- Caminho de escrita único (WAL → árvores) compartilhado com o recovery; falha após o
  registro durável fecha o handle em vez de seguir com estado duvidoso; `ABORT`
  automático se o append de um frame falhar no meio. `rollback` não escreve no WAL.
- `page_stats` (folhas vazias, preenchimento, altura) e `verify` com coerência entre
  índice, TTL e árvore primária.
- CRC16/CRC32 por tabela e reconstrução de página com um único checksum:
  `delete` ~4× e `vacuum` ~2,6× mais rápidos no benchmark local.

Interfaces
- SQL: `COUNT(*)`, `key LIKE 'prefixo%'`, `INSERT … TTL n`, `LIMIT` com parada antecipada.
- CLI/TCP: `SETEX`, `EXPIRE`, `TTL`, `PERSIST`, `PURGE`, `EXISTS`, `COUNT`, `PREFIX`, `PAGES`.
- HTTP: `/v1/count`, `/v1/ttl`, `/v1/pages`, `/v1/batch`, `/v1/expire`, `/v1/purge`,
  `prefix` em `/v1/scan`, `ttl_ms` em `/v1/kv`; erros de validação do motor viram 400.
- ABI C: `minidb_put_ttl_bytes`, `minidb_count`. Clientes Python/TS com as novas rotas.
- Métrica `minidb_batch_ops_total`.

Correções
- JSON: floats inteiros (`3.0`) e extremos (`1e300`) eram serializados como inteiros.

Qualidade
- Teste baseado em modelo, robustez de decodificadores, fuzzing (`fuzz/`), smoke dos
  clientes, contrato C linkado e executado, benchmark com p50/p99 e `--json`.
- Removidos `src/crc16.rs` e `src/lsn.rs` (não compilados) e o comparativo com sqlite3.

Compatibilidade: arquivos 0.3 abrem sem migração; faça checkpoint antes de voltar
para 0.3 (o WAL 0.4 pode conter registros `Expire`).

## 0.3.1

- **Correção crítica:** exclusões que esvaziavam uma folha podiam tornar outras chaves
  inalcançáveis (o empréstimo do irmão não atualizava o separador no pai). A exclusão
  agora é local à folha e nunca desalinha separadores.
- B+ Tree: splits sobem pelo caminho registrado na descida, sem varrer a árvore para
  achar o pai; `insert`/`get`/`delete` primários unificados com as variantes por árvore.
- `VACUUM` reconstrói as árvores, publica por checkpoint e encolhe `data.mdb`.
- Índice por valor: erro explícito quando `chave + valor + 2` excede 128 bytes.
- TCP passa a limitar 128 conexões simultâneas, como o HTTP (`ERR server busy`).
- HTTP: `key` preenchido em consultas por `key_hex`; `next_txn_id` em `/v1/stats`;
  `503` documentado na OpenAPI.
- ABI C: funções exportadas marcadas `unsafe` com contrato `# Safety`.
- Build: teste HTTP que não compilava, Clippy `-D warnings` e `rustfmt` limpos;
  CI com `--locked`; `rust-version = 1.89` no manifesto.
- Documentação revisada; `demo_crash_recover.sh` agora faz crash real com `kill -9`;
  `tools/dev.py` focado em Cargo; `.gitignore` cobre `LOCK`, spill e `__pycache__`.

## 0.3.0

- Validação estrita de JSON, incluindo UTF-8 e escapes Unicode
- Servidores HTTP/TCP com limites, timeout e atendimento concorrente
- ABI C binária com consulta de tamanho e detecção de buffer insuficiente
- Validação de tabelas e colunas no subset SQL
- Artefatos `rlib`, `cdylib` e `staticlib`

- Bloom filter em GET
- `VERIFY` / `minidb-verify`
- `INSPECT` / `HEX` / `minidb-inspect`
- Réplica por snapshot + WAL
- Catálogo `__sys/*`
- Documentação de formato de página e WAL

## 0.2.1

- HTTP/JSON, Prometheus, JSONL, ABI C, Docker, CI

## 0.2.0

- DELETE, transações, SQL subset, índice por valor, checksum de página

## 0.1.0

- B+ Tree + WAL + CLI
