# SQL: referência do dialeto

O SQL relacional roda sobre a árvore primária do motor (chaves reservadas `0xFF`) e
herda WAL, recuperação, compressão, MVCC e replicação. Este documento é a referência
do que o parser e o executor aceitam. Identificadores são convertidos para minúsculas
(entre aspas duplas, crases ou colchetes mantêm espaços e símbolos); palavras-chave
não diferenciam caixa; textos usam aspas simples (`''` escapa); comentários `--` e
`/* */`.

## Tipos

| Tipo | Sinônimos aceitos | Observações |
| --- | --- | --- |
| `INTEGER` | `INT`, `BIGINT`, `SMALLINT`, `TINYINT`, `SERIAL`, `BIGSERIAL`, `SMALLSERIAL` | 64 bits com sinal; `SERIAL` = `INTEGER` + `AUTOINCREMENT` |
| `REAL` | `FLOAT`, `DOUBLE [PRECISION]`, `NUMERIC`, `DECIMAL` | 64 bits; nunca NaN |
| `TEXT` | `VARCHAR(n)`, `CHAR`, `CHARACTER VARYING`, `STRING`, `DATE`, `TIME`, `TIMESTAMP`, `DATETIME`, `JSON`, `UUID` | UTF-8, até 64 MiB (o tamanho declarado é ignorado) |
| `BOOLEAN` | `BOOL` | `true`/`false`; `0`/`1` são aceitos |

Inteiros viram `REAL` quando a coluna é `REAL`; `REAL` sem parte fracionária vira
`INTEGER`; `1 = 1.0`. Datas e horas são `TEXT` ISO 8601 (`YYYY-MM-DD HH:MM:SS`, UTC)
ou `INTEGER` em segundos Unix; as funções de data aceitam os dois. Não há tipo BLOB:
guarde bytes como texto hex/base64 ou na face chave-valor.

## Tabelas

```sql
CREATE TABLE [IF NOT EXISTS] nome (
  coluna TIPO [PRIMARY KEY [AUTOINCREMENT]] [NOT NULL] [UNIQUE]
         [DEFAULT expressão] [CHECK (expressão)]
         [REFERENCES pai [(colunas)] [ON DELETE ação] [ON UPDATE ação]]
         [GENERATED ALWAYS AS IDENTITY] [COLLATE x],
  ...,
  [CONSTRAINT nome] PRIMARY KEY (a, b),
  [CONSTRAINT nome] UNIQUE (a, b),
  [CONSTRAINT nome] CHECK (expressão),
  [CONSTRAINT nome] FOREIGN KEY (a, b) REFERENCES pai (x, y) [ON DELETE ação] [ON UPDATE ação]
);
```

- **Chave primária**: simples ou composta; sem PK a tabela ganha um `rowid` oculto.
  `INTEGER PRIMARY KEY` (e qualquer coluna `AUTOINCREMENT`/`SERIAL`/`IDENTITY`) recebe
  o próximo valor da sequência da tabela quando vem `NULL`; valores explícitos maiores
  avançam a sequência. Chave codificada de até 768 bytes.
- **`DEFAULT`**: literal ou expressão constante (`now()`, `uuid()`, `random()`,
  `(1 + 2)`), avaliada a cada linha inserida. Sem referência a colunas nem subconsulta.
- **`CHECK`**: qualquer expressão sobre as colunas da própria linha (sem subconsulta,
  agregado ou janela); `NULL` passa. Guardada como texto e reavaliada em `INSERT`/
  `UPDATE`, inclusive nas linhas alteradas por cascata.
- **`UNIQUE`**: vira índice único; `NULL` não conflita.
- **`FOREIGN KEY`**: as colunas referenciadas precisam ser a chave primária ou um
  `UNIQUE` da tabela pai, com os mesmos tipos. `REFERENCES pai` sem colunas usa a PK do
  pai. A tabela pode referenciar a si mesma (árvores). Um índice nas colunas da FK é
  criado automaticamente (`<tabela>_<cols>_fkey_idx`) para as verificações no pai.
  Ações: `NO ACTION` (padrão) e `RESTRICT` bloqueiam; `CASCADE` apaga/atualiza as
  filhas; `SET NULL`; `SET DEFAULT`. As ações propagam em cadeia por quantas tabelas
  e níveis houver, dentro do mesmo lote atômico, e todas as chaves de uma mesma linha
  filha são aplicadas juntas. As verificações do lado filho ocorrem no fim do comando:
  linhas do mesmo `INSERT` podem se referenciar em qualquer ordem. `DROP TABLE` e
  `TRUNCATE` de um pai referenciado são recusados (remova/esvazie as filhas antes).

```sql
DROP TABLE [IF EXISTS] nome;
TRUNCATE [TABLE] nome;                       -- apaga tudo e zera a sequência
ALTER TABLE t ADD [COLUMN] c TIPO [restrições de coluna];   -- linhas antigas recebem o DEFAULT
ALTER TABLE t DROP [COLUMN] [IF EXISTS] c;   -- reescreve as linhas; derruba índices e CHECKs da coluna
ALTER TABLE t RENAME [COLUMN] a TO b;        -- atualiza CHECKs e as FKs que apontam para a coluna
ALTER TABLE t RENAME TO t2;                  -- atualiza as FKs das filhas
ALTER TABLE t ALTER [COLUMN] c SET DEFAULT expressão | DROP DEFAULT | SET NOT NULL | DROP NOT NULL;
CREATE [UNIQUE] INDEX [IF NOT EXISTS] nome ON t (a, b);
CREATE FULLTEXT | VECTOR | SPATIAL INDEX nome ON t (...) [WITH (opção = valor, ...)];  -- ver Busca avançada
DROP INDEX [IF EXISTS] nome;  REINDEX nome_do_índice | tabela;
CREATE [OR REPLACE] VIEW [IF NOT EXISTS] v [(colunas)] AS consulta;
DROP VIEW [IF EXISTS] v;
SHOW TABLES;                                 -- name, kind (table/view), columns, indexes
SHOW INDEXES [FROM t];                       -- table, index, columns, unique, auto, kind
SHOW CREATE TABLE t;  SHOW CREATE VIEW v;    -- DDL reexecutável
DESCRIBE t;  SHOW COLUMNS FROM t;            -- column, type, pk, not_null, default, index, references
EXPLAIN comando;
```

`DROP COLUMN` recusa colunas da chave primária, de uma chave estrangeira ou
referenciadas por outra tabela. `ADD COLUMN` aceita `NOT NULL` só com `DEFAULT`, e não
aceita `PRIMARY KEY`/`UNIQUE` (crie um índice único depois). Views são expandidas
como subconsultas a cada uso (podem usar outras views; referência circular é
recusada), são somente leitura e não acompanham renomeações de tabelas ou colunas
(recrie-as com `CREATE OR REPLACE VIEW`). Tabelas, views e o nome `kv` compartilham o
mesmo espaço de nomes.

## Consultas

```sql
[WITH [RECURSIVE] cte [(cols)] AS (consulta), ...]
SELECT [DISTINCT] item, ...                  -- *, t.*, expressão [AS alias]
[FROM fonte [AS alias [(cols)]] [junções]]
[WHERE condição]
[GROUP BY expressão | posição | alias, ...] [HAVING condição]
[UNION [ALL] | INTERSECT [ALL] | EXCEPT [ALL] consulta]
[ORDER BY expressão | posição | alias [ASC | DESC] [NULLS FIRST | LAST], ...]
[LIMIT n [OFFSET m] | LIMIT m, n | OFFSET m ROWS | FETCH FIRST n ROWS ONLY];

VALUES (1, 'a'), (2, 'b');                   -- consulta com colunas column1, column2...
```

- **Fontes**: tabelas, views, CTEs, subconsultas `(SELECT ...) AS x (a, b)`, `(VALUES
  ...) AS v (a, b)`.
- **Junções**: `[INNER] JOIN ... ON`, `LEFT|RIGHT|FULL [OUTER] JOIN ... ON`, `CROSS
  JOIN`, vírgula, `JOIN ... USING (cols)` (a coluna do lado direito fica oculta sem
  qualificador e não aparece em `*`). O planejador escolhe busca por chave/índice por
  linha externa, hash join em igualdades ou nested loop; `EXPLAIN` mostra.
- **Subconsultas**: escalares, `IN (SELECT ...)`, `EXISTS`, `x op ANY|SOME|ALL (SELECT
  ...)`, no `FROM`; correlacionadas enxergam as colunas externas. As não
  correlacionadas rodam uma vez por comando (cache).
- **CTEs**: `WITH` normal (materializada uma vez) e `WITH RECURSIVE nome(cols) AS
  (termo base UNION [ALL] passo)`: o passo roda repetidamente sobre as linhas novas até
  não produzir nenhuma (com `UNION`, linhas repetidas encerram ciclos). Há um teto de
  100 000 iterações; geradores infinitos precisam de `WHERE` ou de `LIMIT` dentro da
  CTE.
- **Agregados**: `COUNT(*|x|DISTINCT x)`, `SUM`, `AVG`, `MIN`, `MAX`, `TOTAL`,
  `GROUP_CONCAT(x [, sep])`/`STRING_AGG`, `BOOL_AND`/`EVERY`, `BOOL_OR`,
  `STDDEV`/`STDDEV_POP`/`STDDEV_SAMP`, `VARIANCE`/`VAR_POP`/`VAR_SAMP`; `DISTINCT` em
  qualquer um. `agregado(x) FILTER (WHERE condição)` agrega só as linhas em que a
  condição vale (equivale a `agregado(CASE WHEN condição THEN x END)`). `GROUP BY` aceita expressões, posições (`GROUP BY 1`) e aliases da
  saída; `HAVING` filtra grupos.
- **Funções de janela**: `função(args) OVER ([PARTITION BY e, ...] [ORDER BY e [ASC|DESC]
  [NULLS FIRST|LAST], ...] [ROWS | RANGE moldura])` em `SELECT` e `ORDER BY`
  (não em `WHERE`/`HAVING`; use uma subconsulta). Funções: `ROW_NUMBER()`, `RANK()`,
  `DENSE_RANK()`, `PERCENT_RANK()`, `CUME_DIST()`, `NTILE(n)`, `LAG(x [, off [,
  padrão]])`, `LEAD(...)`, `FIRST_VALUE(x)`, `LAST_VALUE(x)`, `NTH_VALUE(x, n)` e
  qualquer agregado. Moldura: `BETWEEN UNBOUNDED PRECEDING | n PRECEDING | CURRENT ROW
  | n FOLLOWING AND ...` (ou só o início, com fim `CURRENT ROW`). Sem moldura: a
  partição inteira quando não há `ORDER BY`; com `ORDER BY`, do início até os pares da
  linha corrente (acumulado). `RANGE` com deslocamento exige um único `ORDER BY`
  numérico. Molduras que começam no início da partição são acumuladas incrementalmente.
- **Conjuntos**: `UNION`, `INTERSECT`, `EXCEPT` (com `ALL`), associativos à esquerda;
  `ORDER BY` no fim usa nome ou posição da coluna.

## Expressões

Precedência (da mais baixa): `OR`; `AND`; `NOT`; comparações (`=`, `<>`/`!=`, `<`,
`<=`, `>`, `>=`, `IS [NOT] NULL`, `IS [NOT] TRUE|FALSE`, `IS [NOT] DISTINCT FROM`,
`[NOT] LIKE`/`ILIKE`, `[NOT] GLOB`, `[NOT] IN (lista | subconsulta)`, `[NOT] BETWEEN a
AND b`, `op ANY|ALL (subconsulta)`); bit a bit (`&`, `|`, `<<`, `>>`); `+`, `-`, `||`;
`*`, `/`, `%`; unários `-`, `+`, `~`; `x::tipo`; primários (literais, colunas, `?`/
`?N`/`$N`, `CASE`, `CAST(x AS tipo)`, `EXISTS`, subconsultas, funções). Lógica de três
valores: `NULL` propaga, `AND`/`OR` seguem a tabela SQL. `LIKE` não distingue caixa
(`%`, `_`); `GLOB` distingue (`*`, `?`, `[a-z]`, `[^x]`). Divisão por zero dá `NULL`;
estouro de inteiro dá erro.

### Funções

| Grupo | Funções |
| --- | --- |
| Condicionais | `coalesce`/`ifnull`/`nvl`, `nullif`, `iif`/`if`, `greatest`, `least`, `typeof` |
| Texto | `lower`, `upper`, `initcap`, `length`/`char_length`, `octet_length`, `trim`/`ltrim`/`rtrim([, chars])`, `replace`, `instr`/`strpos`/`position`, `substr`/`substring`/`mid` (início negativo conta do fim), `left`, `right`, `reverse`, `repeat`, `lpad`, `rpad`, `starts_with`, `ends_with`, `contains`, `split_part`, `concat`, `concat_ws`, `char`/`chr`, `unicode`/`ascii`, `hex`, `quote`, `printf`/`format` (`%s %d %f %x %e %%`, largura/precisão), `sha256` |
| Matemática | `abs`, `sign`, `round(x [, casas])`, `trunc`, `floor`, `ceil`/`ceiling`, `sqrt`, `cbrt`, `power`/`pow`, `exp`, `ln`, `log([base,] x)`, `log2`, `log10`, `mod`, `sin`, `cos`, `tan`, `asin`, `acos`, `atan`, `atan2`, `degrees`, `radians`, `pi`, `random`, `to_number` |
| Data/hora (UTC) | `now()`/`current_timestamp`, `current_date`, `current_time`, `date(t [, mods])`, `time(...)`, `datetime(...)`, `strftime(fmt, t [, mods])`, `unixepoch(...)`, `julianday(...)`, `year`, `month`, `day`, `hour`, `minute`, `second`, `weekday` (0 = domingo), `dayofyear`, `quarter`, `date_add(t, '+1 day')`, `date_sub`, `date_diff(a, b [, 'day'\|'hour'\|'minute'\|'second'\|'week'])` |
| JSON | `json_extract(doc, '$.a.b[0]')`/`json_value`, `json_type`, `json_array_length`, `json_object(k, v, ...)`, `json_array(...)`, `json_valid`, `json` (normaliza) |
| Busca | `fts_tokens(texto)`, `fts_highlight(texto, consulta [, abre, fecha])`, `vec_l2`/`vec_cosine`/`vec_dot(a, b)`, `vec_distance(a, b [, 'cosine'\|'l2'\|'dot'])`, `vec_dims`, `vec_norm`, `vec_normalize`, `vec_add`, `vec_sub`, `st_distance(x1, y1, x2, y2)`, `st_distance_sphere(lat1, lon1, lat2, lon2)` (metros), `st_dwithin(x, y, cx, cy, raio)` |
| Outras | `uuid()`/`gen_random_uuid()`, `sha256`, `hex`, `random()` |

Modificadores de data (estilo SQLite): `'+N days|hours|minutes|seconds|weeks|months|years'`
(negativos também), `'start of day|month|year'`, `'weekday N'`. `strftime` aceita
`%Y %m %d %e %H %M %S %f %s %j %w %u %F %T %%`. Momentos aceitos: `YYYY-MM-DD`,
`YYYY-MM-DD[T ]HH:MM[:SS[.fff]][Z|±HH:MM]`, `now`, inteiros (segundos Unix).

## Escrita

```sql
INSERT [OR REPLACE | OR IGNORE] INTO t [(cols)] VALUES (...), (...) | consulta | DEFAULT VALUES
  [ON CONFLICT [(cols)] DO NOTHING | DO UPDATE SET c = expr, ... [WHERE cond]]
  [RETURNING * | expr [AS alias], ...];
REPLACE INTO t ...;
UPDATE t SET c = expr, ... [WHERE cond] [RETURNING ...];
DELETE FROM t [WHERE cond] [RETURNING ...];
```

`ON CONFLICT` detecta conflitos de chave primária e de qualquer índice único (o alvo
entre parênteses é aceito e ignorado); em `DO UPDATE`, colunas sem prefixo são a linha
existente e `excluded.c` é a linha proposta. `OR REPLACE`/`REPLACE INTO` apagam todas as
linhas em conflito e inserem a nova (com as ações referenciais das apagadas). `RETURNING`
devolve as linhas inseridas/atualizadas (valores finais, com defaults e autoincremento)
ou apagadas. Cada comando é um lote atômico no WAL.

## Transações, scripts e sessões

Vários comandos no mesmo texto (`a; b; c`) formam um **script**: devolve
`ExecResult::Batch` (HTTP: `results`) e, sem `BEGIN` explícito, roda numa transação
implícita: um erro em qualquer comando desfaz todos. Parâmetros só valem para um
comando por vez.

| Onde | Como |
| --- | --- |
| `Db` (handle exclusivo) | `BEGIN`/`COMMIT`/`ROLLBACK`, `SAVEPOINT s`, `ROLLBACK TO s`, `RELEASE s`; write-set local, leituras veem as próprias escritas |
| `SharedDb::session()` / `Session` | `BEGIN [ISOLATION LEVEL SERIALIZABLE \| SNAPSHOT]`, `COMMIT`, `ROLLBACK`, savepoints; transação MVCC otimista: outras sessões não veem nada até o commit, que falha com `Error::Conflict` se houve conflito (repita a transação). `put`/`get`/`delete` participam |
| `Txn::sql` | SQL direto numa transação MVCC (`begin()`/`begin_serializable()`), com as leituras registradas para a validação serializável |
| TCP | uma `Session` por conexão: `BEGIN`, comandos, `COMMIT`; `PUT`/`GET`/`DEL` também entram |
| HTTP `POST /v1/sql` | uma sessão por pedido: mande o script inteiro (`BEGIN; ...; COMMIT` opcional); transação deixada aberta é desfeita com `400` |
| `SharedDb::sql` | autocommit por comando; scripts rodam numa sessão temporária; `BEGIN` isolado é recusado (use sessão) |

O dialeto chave-valor (`SELECT ... FROM kv`, `CHECKPOINT`) não roda dentro de uma
transação SQL de sessão; use as tabelas relacionais ou os comandos `PUT`/`GET`/`DEL`.

## Gatilhos

```sql
CREATE TRIGGER [IF NOT EXISTS] nome BEFORE | AFTER INSERT | UPDATE [OF a, b] | DELETE ON t
  [FOR EACH ROW] [WHEN (condição)]
BEGIN
  comando; ...          -- INSERT/UPDATE/DELETE/NOTIFY, ou SELECT RAISE(...) [WHERE ...]
END;
DROP TRIGGER [IF EXISTS] nome;
SHOW TRIGGERS [FROM t];
```

Por linha. `NEW.c` (INSERT/UPDATE) e `OLD.c` (UPDATE/DELETE) são substituídos pelos
valores da linha antes de cada comando do corpo executar. `RAISE(ABORT | FAIL |
ROLLBACK, 'mensagem')` cancela o comando inteiro (nada é gravado); `RAISE(IGNORE)` num
gatilho BEFORE pula a linha em silêncio (o autoincremento não é consumido). `UPDATE OF`
dispara só quando alguma das colunas listadas mudou. Os comandos do corpo enxergam as
escritas já feitas pelo comando (inclusive a linha nova, em AFTER) e podem disparar
outros gatilhos; a profundidade é limitada a 16 (laços dão erro). Gatilhos disparam
também nas linhas alteradas por cascatas de chave estrangeira. Um gatilho por
evento (crie vários para INSERT e UPDATE). Não há `INSTEAD OF` nem `FOR EACH STATEMENT`.

## Views materializadas

```sql
CREATE [OR REPLACE] MATERIALIZED VIEW [IF NOT EXISTS] mv [(cols)] [WITH AUTO REFRESH] AS consulta;
REFRESH MATERIALIZED VIEW mv;
DROP MATERIALIZED VIEW [IF EXISTS] mv;
```

As linhas ficam numa tabela somente leitura (tipos inferidos do primeiro resultado),
consultável como qualquer outra; índices (`CREATE INDEX` é recusado) e gatilhos não se
aplicam a ela. O tipo de cada coluna é o do primeiro valor não nulo do primeiro
resultado (tudo nulo vira TEXT): um valor incompatível num `REFRESH` posterior dá erro.
`REFRESH` recalcula tudo; com `WITH AUTO REFRESH` a view é
recalculada dentro do mesmo lote atômico de cada comando que altera uma tabela que
ela lê (bom para agregados de tabelas pequenas ou médias; para tabelas grandes, use
`REFRESH` agendado).

## Estatísticas e planejador

`ANALYZE [tabela]` percorre a tabela e guarda linhas, distintos, nulos, mínimo e
máximo por coluna. Com estatísticas o planejador estima as linhas de cada caminho
(igualdade = linhas ÷ distintos; faixas por interpolação min/max) e escolhe o mais
barato; `EXPLAIN` mostra `est. rows≈N`. Sem estatísticas vale a heurística "mais
colunas de igualdade casadas". `EXPLAIN ANALYZE consulta` executa e mostra, por
etapa, linhas lidas e devolvidas e o tempo. Estatísticas somem em `DROP COLUMN` e
acompanham `RENAME TO`; rode `ANALYZE` de novo depois de grandes cargas.

Ordenação: se o acesso já entrega na ordem pedida (chave primária, ou as colunas
restantes de um índice usado por igualdade, seguidas da PK), não há sort; em ASC a
consulta para no `LIMIT`. O planejador prefere um índice que forneça a ordem quando
custa até o dobro do melhor. `ORDER BY ... LIMIT n` sem índice usa seleção Top-N.

## Notificações e mudanças

```sql
LISTEN canal;  UNLISTEN canal | *;      -- só em Session / conexão TCP
NOTIFY canal [, 'payload'];             -- entregue no COMMIT (descartado no ROLLBACK)
```

Sessões TCP recebem `NOTIFY canal payload` anexado à próxima resposta ou com
`WAIT [segundos]` (long-poll). HTTP: `GET /v1/listen?channel=a&channel=b` (SSE,
`event: notify`). Toda linha inserida, alterada ou apagada por SQL vira um evento
`{lsn, table, kind, old, new}` no anel de mudanças (`Db::events()`,
`GET /v1/changes?since=LSN[&table=t][&once=1]`); o anel tem capacidade limitada
(padrão 10 000): um `since` antigo demais devolve `TooOld`/`410` com o primeiro LSN
disponível, e o cliente relê as tabelas.

## Busca avançada

Três tipos de índice além do B-tree, mantidos em cada escrita (na mesma transação) e
reconstruíveis com `REINDEX nome` (um índice) ou `REINDEX tabela` (todos).

```sql
-- Texto completo: postings por termo, radicalização leve PT/EN, sem acentos/caixa.
CREATE FULLTEXT INDEX docs_fts ON docs (title, body);
SELECT id, MATCH (title, body) AGAINST ('motor física') AS score
FROM docs WHERE MATCH (title, body) AGAINST ('motor física') ORDER BY score DESC;
-- consulta: termos obrigatórios | a OR b | -termo / NOT termo | "frase exata" | prefixo*
SELECT fts_highlight(body, 'motor', '<b>', '</b>') FROM docs;

-- Vetorial: HNSW (m, ef_construction), métrica cosine | l2 | dot; vetores em TEXT '[0.1, 0.2]'.
CREATE VECTOR INDEX items_emb ON items (emb) WITH (metric = 'cosine', dims = 384);
SELECT id FROM items ORDER BY emb <=> '[0.1, 0.9, ...]' LIMIT 10;     -- <-> L2, <=> cosseno, <#> -produto
SELECT id FROM items WHERE tag = 'arma' ORDER BY vec_distance(emb, ?, 'cosine') LIMIT 5;

-- Espacial: curva Z (Morton) 2D/3D, coordenadas em [-1 000 000, 1 000 000].
CREATE SPATIAL INDEX pts_xy ON pts (x, y);
SELECT * FROM pts WHERE x BETWEEN 10 AND 20 AND y BETWEEN -5 AND 5;
SELECT * FROM pts WHERE st_dwithin(x, y, 12.5, 0, 3) ORDER BY st_distance(x, y, 12.5, 0);
```

`MATCH ... AGAINST` vale 0 quando não casa e a pontuação BM25 (k1 = 1,2; b = 0,75)
quando casa; com índice nas mesmas colunas (qualquer ordem) o planejador lê só os
candidatos e usa df/tamanho médio reais; sem índice a expressão é avaliada linha a
linha (mesmo resultado, pontuação só por frequência). A busca vetorial usa o índice
quando a consulta é `ORDER BY distância(coluna, vetor) LIMIT k` ascendente, sem
`GROUP BY`/`DISTINCT`/`JOIN`, e a métrica do operador/função é a do índice; é
aproximada (HNSW) — com `WHERE` busca 4k candidatos e filtra depois, podendo devolver
menos que k. Linhas apagadas viram lápides no grafo; `REINDEX` compacta. O índice
espacial atende caixas fechadas em todas as colunas (`BETWEEN`, `>=` e `<=`, ou
`st_dwithin`): até 64 faixas de código Morton, depois o filtro exato.

## Expressões regulares

Motor próprio (subconjunto POSIX/PCRE): literais, `.`, `^`/`$`, classes `[a-z]`,
`[^...]`, `[[:alpha:]]`, `\d \w \s \b`, quantificadores `* + ? {n,m}` (e preguiçosos
`*?`), grupos com captura, `(?:...)`, alternância `|`, sinalizador `i`. Operadores
`~`, `~*`, `!~`, `!~*` (e `OPERATOR(pg_catalog.~)`); funções `regexp_like(s, p[, flags])`,
`regexp_replace(s, p, r[, 'g'])` (`\1`/`$1` nas capturas), `regexp_substr(s, p[, pos,
grupo])`, `regexp_count`, `regexp_matches` (array JSON), `regexp_split_to_array`.
Padrões patológicos são interrompidos por limite de passos (erro, não travamento).

## Usuários, papéis e privilégios

```sql
CREATE USER root PASSWORD 'r00t' SUPERUSER;      -- o primeiro usuário precisa ser SUPERUSER
CREATE USER ana WITH PASSWORD 'ana123';
CREATE ROLE leitores;
GRANT SELECT ON jogos TO leitores;               -- objeto: tabela/view, kv (chave-valor) ou *
GRANT leitores TO ana;                           -- papéis herdam (recursivo)
GRANT INSERT, UPDATE ON TABLE jogos TO ana;
GRANT CREATE ON * TO ana;                        -- DDL no banco; CREATE em t = alterar/apagar t
REVOKE UPDATE ON jogos FROM ana;  REVOKE leitores FROM ana;
ALTER USER ana PASSWORD 'nova' NOSUPERUSER;  DROP USER ana;  DROP ROLE leitores;
SHOW USERS;  SHOW GRANTS [FOR ana];
```

Privilégios: `SELECT` (ler, inclusive em subconsultas/views), `INSERT`, `UPDATE`,
`DELETE` (também `TRUNCATE`), `CREATE` (DDL, `ANALYZE`, `REINDEX`, `REFRESH`), `ALL`.
Administração de usuários e `GRANT`/`REVOKE` são só de superusuário. As verificações
acontecem em sessões autenticadas (TCP `AUTH`, HTTP Basic, protocolo PostgreSQL) a cada
comando, com o catálogo atual; a API Rust embutida e a CLI local não verificam. Sem
nenhum usuário o banco está em modo aberto.

## Planejador

`EXPLAIN` mostra, por relação: `SCAN t`, `SEARCH t USING PRIMARY KEY (...)`, `... IN n
values`, `... PRIMARY KEY RANGE`, `... INDEX nome`, `... FULLTEXT INDEX nome terms=n`,
`... VECTOR INDEX nome (métrica) dims=d k=n`, `... SPATIAL INDEX nome ranges=n`; joins `LOOKUP ON coluna`, `HASH
JOIN` ou `SCAN (nested loop)`; `AGGREGATE`, `WINDOW`, `SUBQUERY`, `COMPOUND`, `CTE`
(`RECURSIVE`), `SORT`, `LIMIT/OFFSET`; para `DELETE`/`UPDATE`, as tabelas filhas
verificadas (`FOREIGN KEY CHECK`). Igualdades e faixas em prefixos da chave primária
ou de índices viram buscas; `IN` de até 1024 valores na PK vira lista de buscas.
Consultas simples com `LIMIT` param cedo.

## O que não tem

- Procedimentos armazenados, `INSTEAD OF`/`FOR EACH STATEMENT`, `MERGE`, `UPDATE ... FROM`, `LATERAL`,
  `LIKE ... ESCAPE`, `ORDER BY` dentro de `GROUP_CONCAT` (ordene na
  subconsulta), `WINDOW w AS (...)` nomeada, `EXCLUDE` em moldura, `GROUPING SETS`/
  `ROLLUP`.
- `ALTER TABLE ... ADD CONSTRAINT` (declare `CHECK`/`FOREIGN KEY` no `CREATE TABLE`;
  para uma tabela existente, crie a nova, copie com `INSERT ... SELECT`, apague a antiga
  e renomeie), `ALTER COLUMN ... TYPE`, restrições `DEFERRABLE`.
- Tipo BLOB, `COLLATE` (aceito e ignorado), fuso horário (tudo em UTC).
- Índices sobre expressões, índices parciais, reordenação de joins (o planejador usa
  estatísticas do `ANALYZE` só para escolher caminho de acesso e estratégia de join).

## Limites de comportamento

- **Isolamento `SNAPSHOT` (padrão do `BEGIN`)**: escritas na mesma chave conflitam, e as
  restrições valem entre transações concorrentes: gravar o mesmo valor `UNIQUE`,
  inserir filha de um pai que outra sessão apagou, ou apagar/alterar um pai que ganhou
  filhas dá `Error::Conflict` no `COMMIT` de quem chegar depois (repita a transação).
  Atualizar outras colunas do pai não conflita. Outras anomalias de leitura (write
  skew) só são barradas em `BEGIN ISOLATION LEVEL SERIALIZABLE`. `READ COMMITTED`,
  `READ UNCOMMITTED` e `REPEATABLE READ` são aceitos e executam como `SNAPSHOT`.
- Molduras `GROUPS` são aceitas e tratadas como `RANGE`.
- Regex: texto acima de 50 000 caracteres não casa (a busca é recursiva); grupos
  aninhados até 100; expressões e subconsultas SQL aninhadas até ~100 níveis.
- Consulta full-text só com termos excluídos (`-x`) não casa nada.
- Gatilhos rodam sem nova checagem de privilégios: quem cria o gatilho precisa dos
  privilégios do corpo (`CREATE TRIGGER` confere isso).
- `ALTER TABLE ... RENAME` não reescreve views, views materializadas, gatilhos nem
  `GRANT`s que citam o nome antigo.
- `DROP TABLE` e `TRUNCATE` não geram eventos de mudança.
