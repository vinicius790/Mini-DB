# Segurança e modelo de ameaça

Mini-DB é experimental e deve ser usado em ambiente controlado. As interfaces de rede
são ferramentas de desenvolvimento/integração, não uma fronteira de segurança.

## Rede

- **Usuários, papéis e privilégios** (1.0): `CREATE USER nome PASSWORD '...'
  [SUPERUSER]`, `CREATE ROLE`, `GRANT SELECT|INSERT|UPDATE|DELETE|CREATE|ALL ON tabela|kv|*
  TO ...`, `GRANT papel TO usuário`, `REVOKE`, `SHOW USERS`, `SHOW GRANTS`. Senhas são
  guardadas como credenciais SCRAM-SHA-256 (sal + PBKDF2 4096 iterações + chaves
  derivadas), nunca em claro. Enquanto não existe nenhum usuário, o banco está em *modo
  aberto*; o primeiro usuário precisa ser `SUPERUSER`. Cada comando de uma sessão
  autenticada é conferido contra os privilégios atuais (GRANT/REVOKE valem na hora),
  inclusive subconsultas em `INSERT ... VALUES`, `ON CONFLICT`, `RETURNING` e
  `NOTIFY`. `HEX`/`INSPECT`/`VERIFY`/`CATALOG` e os streams `/v1/changes` e
  `/v1/listen` exigem privilégio em `*`. `SHOW`, `DESCRIBE` e `LISTEN` valem para
  qualquer usuário autenticado (DDL e `SHOW GRANTS` ficam visíveis) e as funções
  `has_*_privilege` do catálogo PostgreSQL sempre respondem `true`.
  A API Rust embutida e a CLI local são confiáveis (sem verificação).
- HTTP e TCP aceitam um **token** (`token` / `MINIDB_TOKEN`) e, com usuários, credenciais:
  HTTP `Authorization: Basic base64(usuário:senha)` (401 sem credencial válida, 403 sem
  privilégio) ou `Bearer <token>`; TCP `AUTH <usuário> <senha>` ou `AUTH <token>` antes de
  qualquer comando (credencial errada fecha a conexão). O protocolo PostgreSQL autentica
  com SCRAM-SHA-256 (a senha não trafega). Comparações em tempo constante.
- **TLS 1.3 nativo** (1.1; PKI e mTLS na 1.2): protocolo PostgreSQL (`tls = true`,
  padrão) e HTTP (`https = true`) com implementação própria, sem dependências: X25519,
  AES-128-GCM ou ChaCha20-Poly1305, HKDF-SHA256 e assinatura Ed25519. Três formas de identidade: (1)
  certificado autoassinado gerado na primeira execução (`tls.key`/`tls.crt`); (2) **PKI
  própria**: `minidb cert ca <dir>`, `cert server <dir> <host>` e `cert client <dir>
  <usuário>` emitem CA, certificado de servidor (SAN) e certificados de cliente (CN =
  usuário) assinados pela CA, e `tls_cert`/`tls_key` apontam o servidor para eles
  (`tls.crt` pode ter folha + intermediárias); (3) par/cadeia Ed25519 de outra CA.
  **Certificado de cliente (mTLS)**: com `tls_ca` (PEM das CAs confiáveis) e
  `tls_client_auth = required|optional` o servidor exige/aceita certificado de cliente,
  valida a cadeia (assinaturas, nomes, validade, `CA:TRUE` nos emissores) e a posse da
  chave (CertificateVerify). No PostgreSQL o CN válido autentica o usuário do banco sem
  senha (CN ≠ usuário pedido → recusado, SQLSTATE 28000); no HTTP o CN vira o usuário
  da requisição. `pg_stat_ssl`, `ssl_is_used()` e `ssl_client_dn()` mostram a sessão.
  Só TLS 1.3, sem retomada/0-RTT. Chaves e certificados **Ed25519, ECDSA (P-256/P-384) e
  RSA** (PKCS#8, PKCS#1, SEC1; RSA assina com PSS no handshake e PKCS#1 v1.5/PSS nas
  cadeias, inclusive de CAs públicas); clientes sem AES-128-GCM e ChaCha20-Poly1305 ou sem esquema de
  assinatura compatível com a chave recebem `handshake_failure`; recusas depois do
  ServerHello (certificado de cliente de outra CA, vencido, ausente) vão como alerta
  cifrado (`unknown_ca`, `certificate_expired`, `certificate_required`). A aritmética de
  inteiros grandes, ECDSA e RSA (`bignum`, `ecc`, `rsa`) é própria e validada contra
  OpenSSL; nas operações com segredo ela é de tempo constante (Montgomery sem desvios,
  exponenciação em janela fixa com leitura de tabela por máscara, fórmulas completas de
  soma de pontos, escalar percorrido em todos os bits) e o RSA usa blinding novo a cada
  assinatura mais conferência `s^e = m`. A multiplicação escalar do Ed25519 é de tempo
  constante e a redução módulo L também (por máscara). O nonce do ECDSA é aleatório
  uniforme (sem RFC 6979); `random_bytes` usa `BCryptGenRandom` (Windows) ou
  `/dev/urandom` e só cai num gerador semeado pelo processo se ambos falharem. A
  verificação X.509 confere cadeia, validade, `CA:TRUE`, assinaturas e, no certificado de
  cliente, o `extendedKeyUsage` (se presente, precisa incluir `clientAuth`), mas **não**
  `keyUsage`, `pathLenConstraint`, nameConstraints nem revogação, e a identidade do
  cliente é só o CN: emita certificados de cliente de uma CA dedicada. É código sem auditoria externa
  nem verificação formal: onde isso for exigência, termine o TLS num proxy auditado.
  Chaves privadas geradas (inclusive o `tls.key` autogerado) ficam com modo 0600, e
  `ca.key` deve ficar fora do servidor. Verificado com OpenSSL/libpq (`psql
  sslmode=verify-full sslcert= sslkey=`, `curl --cert`, `openssl verify`). Não há quotas
  nem rate limiting: use um proxy/firewall na borda.
- **Criptografia em repouso** (1.0): com `passphrase` (`MINIDB_PASSPHRASE`) o banco novo
  cifra páginas (`data.mdb`, journal, spill) e frames do WAL/arquivo com ChaCha20; a
  chave vem de PBKDF2-HMAC-SHA256 (20 000 iterações) da senha e `data.mdb.key` guarda só
  sal e verificador. Cabeçalhos de página (32 bytes: id, tipo, contadores) e o tipo de
  cada registro do WAL ficam em claro. Senha errada é recusada na abertura. Não há
  autenticação criptográfica das páginas (o checksum detecta corrupção acidental) e um
  `minidb encrypt|decrypt|rekey [dir]` (senhas em `MINIDB_PASSPHRASE` /
  `MINIDB_NEW_PASSPHRASE`) converte um banco fechado no lugar, reescrevendo as páginas
  após checkpoint (o WAL arquivado antigo é descartado). Se a conversão for
  interrompida, a abertura seguinte a desfaz (banco e chave originais) ou a conclui.
- A replicação com `repl_secret` / `MINIDB_REPL_SECRET` é autenticada (HMAC-SHA256 com
  nonces dos dois lados) e cifrada (ChaCha20 + HMAC por quadro, chaves por sessão,
  contador contra replay). Um lado com segredo recusa o outro sem. O segredo é usado
  direto como chave HMAC (sem KDF): use um segredo longo e aleatório. Sem segredo, o
  canal é texto claro e aceita qualquer réplica: ela recebe um snapshot completo
  (inclusive as credenciais SCRAM dos usuários), pode confirmar LSNs arbitrários
  (simulando a durabilidade semi-síncrona) e, ao anunciar uma época maior, isola o
  primário (somente leitura até reiniciar; o isolamento não é persistido). O
  failover é manual, sem quórum. `sync_timeout_ms = 0` (padrão) espera réplicas para
  sempre e, sem nenhuma réplica, bloqueia as escritas.
- **Tokens e privilégios:** a credencial de token (HTTP `Bearer`, TCP `AUTH <token>`,
  senha do PostgreSQL = token) vale como superusuário e ignora os `GRANT`s. Gatilhos
  executam o corpo sem nova checagem; `CREATE TRIGGER` exige os privilégios do corpo.
  Sem usuários o banco está em modo aberto; apagar o último usuário de login volta a esse
  modo. `UNIQUE` e chaves estrangeiras são revalidadas no commit em qualquer nível de
  isolamento (veja [docs/SQL.md](docs/SQL.md)).
- **PostgreSQL e TLS:** o TLS é opcional para o cliente. Com `tls_client_auth = required`
  uma conexão em claro é recusada; sem isso, ela funciona com senha (SCRAM). Bytes em
  claro enviados junto do `SSLRequest` derrubam a conexão (nunca viram dados da sessão
  TLS). `MINIDB_PG_TRACE` registra todo SQL, inclusive senhas de `CREATE USER`: não
  use em produção.
- O padrão é loopback (`127.0.0.1`); `0.0.0.0` expõe a porta na rede. Não faça isso sem
  um proxy/firewall que autentique, limite taxa e aplique timeouts.
- HTTP não envia cabeçalhos CORS por padrão: o navegador não deixa um site visitado ler
  as respostas da API local nem enviar pedidos com preflight. Pedidos que não sejam
  `GET`/`HEAD`/`OPTIONS` e tragam um cabeçalho `Origin` diferente da origem liberada
  recebem `403`, o que barra também o `POST` "simples" (formulário, `fetch` sem
  preflight). `MINIDB_CORS_ORIGIN` libera uma única origem (`*` libera todas). Isso não
  impede clientes diretos (sem `Origin`) e não autentica: **sem `token` nem usuários o
  banco está em modo aberto**, e qualquer processo local acessa a API. Contra DNS
  rebinding (uma página que aponta um nome dela para `127.0.0.1` e lê por `GET`), o
  servidor confere o cabeçalho `Host` em toda rota, exceto `/health` e `/v1/health`:
  aceita ausente, IP literal, nomes sem ponto (`localhost`, serviço do docker-compose),
  `*.localhost` e os de `MINIDB_ALLOWED_HOSTS` (lista separada por vírgula; `*` desliga
  a checagem); outro nome recebe `403`. Atrás de proxy reverso ou com domínio próprio,
  liste o nome em `MINIDB_ALLOWED_HOSTS`. Defina token ou usuários sempre que o bind não for estritamente local. O TCP de
  linhas encerra a conexão ao receber uma linha de requisição HTTP (`MÉTODO alvo
  HTTP/1.x`; um navegador não consegue usá-lo como transporte de comandos).
- HTTP limita cabeçalho a 32 KiB, corpo a `max_body_bytes` (padrão: o suficiente para
  um valor máximo em hexadecimal) e cada leitura bloqueante a 30 s; TCP limita linhas
  ao tamanho de um valor máximo e usa timeout de leitura de 300 s. São timeouts de leitura
  ociosa, não prazo total da requisição.
- Cada servidor aceita no máximo `max_connections` (padrão 1024) conexões simultâneas
  (uma thread por conexão);
  excedentes recebem `503 server busy` (HTTP) ou `ERR server busy` (TCP). O limite
  protege contra exaustão de threads, não contra negação de serviço distribuída.
- HTTP suporta apenas `Content-Length` (ou `Transfer-Encoding: identity`); chunked não é
  suportado e cabeçalhos de framing ambíguos são rejeitados. Uma resposta por conexão.

## Dados e semântica

- Chaves são bytes não vazios de até 1 KiB; valores têm até 64 MiB. Os campos
  textuais HTTP/TCP/SQL não substituem os campos `*_hex` do HTTP nem a API C binária.
- Use parâmetros (`?`, `$1`; `params` no `/v1/sql`; `execute_sql_params`/`prepare`)
  para qualquer dado externo: valores nunca são interpolados no texto SQL.
- `/v1/batch` aceita até 10000 operações por requisição (o corpo continua limitado a
  `max_body_bytes`); o lote inteiro fica em memória até o commit.
- O import JSONL é lossless, mas mantém o write-set em memória até o commit.
- Backups e snapshots não são cifrados. Controle permissões de diretórios e transporte.
- Apenas um escritor local abre o diretório. O `LOCK` não coordena hosts e não é
  fencing distribuído.
- `fsync=false` deixa de sincronizar o WAL por commit e pode perder operações recentes
  em crash ou queda de energia.

## ABI C

- Todas as funções exportadas são `unsafe`: pressupõem ponteiros e comprimentos válidos.
  Um handle não pode ser usado concorrentemente sem sincronização externa.
- Não use um handle depois de fechado nem feche duas vezes. Use `*_bytes` para dados
  com NUL embutido.
- `minidb_close` descarta erro de fechamento; `minidb_close_checked` o retorna.
  `minidb_get_size`/`minidb_get_bytes` retornam zero para ausência e para valor vazio;
  use `minidb_exists` para distinguir.

## Integridade

CRC16 de página e CRC32 do WAL detectam corrupção acidental; não são hashes
criptográficos. Criptografia em repouso existe (veja acima) mas sem autenticação das
páginas. O engine não oferece isolamento entre tenants.

## Como reportar

Abra uma issue com versão, sistema operacional, passos reproduzíveis, resultado
esperado/observado e a saída de `minidb-verify`. Revise um `data.mdb` antes de anexá-lo:
ele pode conter dados sensíveis.
