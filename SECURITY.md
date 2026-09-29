# Segurança e modelo de ameaça

Mini-DB é experimental e deve ser usado em ambiente controlado. As interfaces de rede
são ferramentas de desenvolvimento/integração, não uma fronteira de segurança.

## Rede

- HTTP e TCP não implementam autenticação, autorização, TLS, quotas ou rate limiting.
- O padrão é loopback (`127.0.0.1`); `0.0.0.0` expõe a porta na rede. Não faça isso sem
  um proxy/firewall que autentique, limite taxa e aplique timeouts.
- HTTP responde `Access-Control-Allow-Origin: *`. CORS controla scripts em browsers,
  não impede clientes diretos e não autentica. Não há suporte a credentials.
- HTTP limita cabeçalho a 32 KiB, corpo a 8 MiB e cada leitura bloqueante a 5 s; TCP
  limita linhas a 64 KiB e usa timeout de leitura de 300 s. São timeouts de leitura
  ociosa, não prazo total da requisição.
- Cada servidor aceita no máximo 128 conexões simultâneas (uma thread por conexão);
  excedentes recebem `503 server busy` (HTTP) ou `ERR server busy` (TCP). O limite
  protege contra exaustão de threads, não contra negação de serviço distribuída.
- HTTP suporta apenas `Content-Length` (ou `Transfer-Encoding: identity`); chunked não é
  suportado e cabeçalhos de framing ambíguos são rejeitados. Uma resposta por conexão.

## Dados e semântica

- Chaves são bytes não vazios de até 128 bytes; valores têm até 1024 bytes. Os campos
  textuais HTTP/TCP/SQL não substituem os campos `*_hex` do HTTP nem a API C binária.
- O parser SQL é um subset próprio, sem parâmetros preparados. Não concatene entrada
  não confiável em comandos SQL; prefira os métodos KV para dados externos.
- `/v1/batch` aceita até 10000 operações por requisição (o corpo continua limitado a
  8 MiB); o lote inteiro fica em memória até o commit.
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
criptográficos. O engine não oferece criptografia nem isolamento entre tenants.

## Como reportar

Abra uma issue com versão, sistema operacional, passos reproduzíveis, resultado
esperado/observado e a saída de `minidb-verify`. Revise um `data.mdb` antes de anexá-lo:
ele pode conter dados sensíveis.
