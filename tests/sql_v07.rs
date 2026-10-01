//! SQL 0.7: integridade (CHECK, FOREIGN KEY com ações, DEFAULT com expressão,
//! AUTOINCREMENT), ALTER TABLE completo, views, funções de janela, CTEs
//! recursivas, VALUES, ANY/ALL, RETURNING, upsert estendido, funções
//! escalares, scripts e transações (Db, Txn, Session, TCP).
use mini_db::mvcc::SharedDb;
use mini_db::rel::Value;
use mini_db::{Db, Error, ExecResult};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("minidb-sql07-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn rows_of(res: ExecResult, sql: &str) -> Vec<String> {
    match res {
        ExecResult::Table { rows, .. } => rows
            .iter()
            .map(|r| {
                r.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .collect(),
        other => panic!("{sql}: {other:?}"),
    }
}

fn q(db: &mut Db, sql: &str) -> Vec<String> {
    rows_of(
        db.execute_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}")),
        sql,
    )
}

fn ok(db: &mut Db, sql: &str) -> String {
    match db.execute_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}")) {
        ExecResult::Ok(s) => s,
        other => panic!("{sql}: {other:?}"),
    }
}

fn err(db: &mut Db, sql: &str) -> String {
    match db.execute_sql(sql) {
        Err(e) => e.to_string(),
        Ok(r) => panic!("{sql} devia falhar, devolveu {r:?}"),
    }
}

fn school(tag: &str) -> Db {
    school_at(&tmpdir(tag))
}

fn school_at(dir: &std::path::Path) -> Db {
    let mut db = Db::open(dir).unwrap();
    ok(
        &mut db,
        "CREATE TABLE dept (id INT PRIMARY KEY, name TEXT NOT NULL UNIQUE)",
    );
    ok(
        &mut db,
        "CREATE TABLE emp (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            dept INT REFERENCES dept(id) ON DELETE CASCADE ON UPDATE CASCADE,
            boss INT REFERENCES emp,
            salary REAL CHECK (salary > 0),
            since TEXT DEFAULT (date('2024-01-01')),
            CONSTRAINT nome_ok CHECK (length(name) >= 2)
        )",
    );
    ok(
        &mut db,
        "INSERT INTO dept VALUES (1, 'eng'), (2, 'ops'), (3, 'hr')",
    );
    ok(
        &mut db,
        "INSERT INTO emp (name, dept, boss, salary) VALUES
            ('ana', 1, NULL, 300), ('bia', 1, 1, 200), ('caio', 2, 1, 150),
            ('duda', 2, 3, 120), ('eva', 3, NULL, 100), ('fabio', 1, 2, 180)",
    );
    db
}

#[test]
fn checks_defaults_and_autoincrement() {
    let mut db = school("checks");
    assert_eq!(
        q(&mut db, "SELECT id, since FROM emp WHERE name = 'ana'"),
        ["1|2024-01-01"]
    );
    assert!(err(&mut db, "INSERT INTO emp (name, salary) VALUES ('x', 10)").contains("nome_ok"));
    assert!(err(
        &mut db,
        "INSERT INTO emp (name, salary) VALUES ('zeca', -1)"
    )
    .contains("CHECK"));
    assert!(err(&mut db, "UPDATE emp SET salary = 0 WHERE id = 1").contains("CHECK"));
    // Autoincremento continua após o maior id, inclusive explícito.
    ok(
        &mut db,
        "INSERT INTO emp (id, name, salary) VALUES (50, 'gil', 10)",
    );
    ok(
        &mut db,
        "INSERT INTO emp (name, salary) VALUES ('hugo', 10)",
    );
    assert_eq!(q(&mut db, "SELECT id FROM emp WHERE name = 'hugo'"), ["51"]);
    ok(&mut db, "CREATE TABLE ev (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT DEFAULT current_timestamp, tag TEXT DEFAULT uuid(), n INT DEFAULT (1 + 2))");
    ok(&mut db, "INSERT INTO ev DEFAULT VALUES");
    ok(&mut db, "INSERT INTO ev DEFAULT VALUES");
    let rows = q(
        &mut db,
        "SELECT id, length(at), length(tag), n FROM ev ORDER BY id",
    );
    assert_eq!(rows, ["1|19|36|3", "2|19|36|3"]);
    assert_ne!(
        q(&mut db, "SELECT tag FROM ev WHERE id = 1"),
        q(&mut db, "SELECT tag FROM ev WHERE id = 2")
    );
    assert!(err(&mut db, "CREATE TABLE bad (a TEXT AUTOINCREMENT)").contains("INTEGER"));
    assert!(err(&mut db, "CREATE TABLE bad (a INT CHECK (b > 0))").contains("coluna desconhecida"));
    assert!(err(&mut db, "CREATE TABLE bad (a INT DEFAULT ((SELECT 1)))").contains("DEFAULT"));
}

#[test]
fn foreign_keys_enforce_and_cascade() {
    let mut db = school("fk");
    assert!(err(
        &mut db,
        "INSERT INTO emp (name, dept, salary) VALUES ('novo', 9, 1)"
    )
    .contains("FOREIGN KEY"));
    assert!(err(&mut db, "UPDATE emp SET boss = 999 WHERE id = 2").contains("FOREIGN KEY"));
    // Autorreferência: apagar chefe sem ação bloqueia.
    assert!(err(&mut db, "DELETE FROM emp WHERE id = 1").contains("referenciam"));
    // ON UPDATE CASCADE no departamento.
    ok(&mut db, "UPDATE dept SET id = 10 WHERE id = 1");
    assert_eq!(
        q(&mut db, "SELECT COUNT(*) FROM emp WHERE dept = 10"),
        ["3"]
    );
    // ON DELETE CASCADE apaga os funcionários do departamento; os que tinham
    // esses funcionários como chefe bloqueariam, então primeiro solta o vínculo.
    assert!(err(&mut db, "DELETE FROM dept WHERE id = 10").contains("referenciam"));
    ok(
        &mut db,
        "UPDATE emp SET boss = NULL WHERE boss IN (SELECT id FROM emp WHERE dept = 10)",
    );
    ok(&mut db, "DELETE FROM dept WHERE id = 10");
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM emp"), ["3"]);
    assert_eq!(
        q(&mut db, "SELECT name FROM emp ORDER BY id"),
        ["caio", "duda", "eva"]
    );
    // DROP/TRUNCATE do pai referenciado é bloqueado.
    assert!(err(&mut db, "DROP TABLE dept").contains("referenciada"));
    assert!(err(&mut db, "TRUNCATE dept").contains("bloqueado"));
    // SET NULL e SET DEFAULT.
    ok(&mut db, "CREATE TABLE tag (id INT PRIMARY KEY)");
    ok(&mut db, "CREATE TABLE item (id INT PRIMARY KEY, tag INT DEFAULT 1 REFERENCES tag ON DELETE SET DEFAULT, alt INT REFERENCES tag(id) ON DELETE SET NULL)");
    ok(&mut db, "INSERT INTO tag VALUES (1), (2), (3)");
    ok(&mut db, "INSERT INTO item VALUES (1, 2, 3), (2, 3, 3)");
    ok(&mut db, "DELETE FROM tag WHERE id = 3");
    assert_eq!(
        q(&mut db, "SELECT id, tag, alt FROM item ORDER BY id"),
        ["1|2|NULL", "2|1|NULL"]
    );
    // Cascata em cadeia (avô → pai → filho) num único lote.
    ok(&mut db, "CREATE TABLE a (id INT PRIMARY KEY)");
    ok(
        &mut db,
        "CREATE TABLE b (id INT PRIMARY KEY, a INT REFERENCES a ON DELETE CASCADE)",
    );
    ok(
        &mut db,
        "CREATE TABLE c (id INT PRIMARY KEY, b INT REFERENCES b ON DELETE CASCADE)",
    );
    db.execute_sql("INSERT INTO a VALUES (1), (2); INSERT INTO b VALUES (1, 1), (2, 1), (3, 2); INSERT INTO c VALUES (1, 1), (2, 3)").unwrap();
    ok(&mut db, "DELETE FROM a WHERE id = 1");
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM b"), ["1"]);
    assert_eq!(q(&mut db, "SELECT id FROM c"), ["2"]);
    // Chave composta referenciada por UNIQUE.
    ok(
        &mut db,
        "CREATE TABLE p (x INT, y INT, v TEXT, PRIMARY KEY (x, y))",
    );
    ok(&mut db, "CREATE TABLE f (id INT PRIMARY KEY, px INT, py INT, FOREIGN KEY (px, py) REFERENCES p (x, y) ON DELETE RESTRICT)");
    ok(&mut db, "INSERT INTO p VALUES (1, 1, 'a'), (1, 2, 'b')");
    ok(&mut db, "INSERT INTO f VALUES (1, 1, 2), (2, NULL, 5)");
    assert!(err(&mut db, "INSERT INTO f VALUES (3, 2, 2)").contains("FOREIGN KEY"));
    assert!(err(&mut db, "DELETE FROM p WHERE y = 2").contains("bloqueado"));
    ok(&mut db, "DELETE FROM p WHERE y = 1");
    assert!(err(
        &mut db,
        "CREATE TABLE g (id INT PRIMARY KEY, v TEXT REFERENCES p(v))"
    )
    .contains("UNIQUE"));
    assert!(err(
        &mut db,
        "CREATE TABLE g (id INT PRIMARY KEY, v TEXT REFERENCES dept(id))"
    )
    .contains("TEXT"));
    assert!(q(&mut db, "SHOW INDEXES FROM emp")
        .iter()
        .any(|r| r.contains("fkey_idx")));
    assert!(ok(&mut db, "EXPLAIN DELETE FROM dept WHERE id = 2").contains("FOREIGN KEY CHECK emp"));
    db.close().unwrap();
}

#[test]
fn alter_table_everything() {
    let mut db = school("alter");
    ok(&mut db, "CREATE INDEX emp_salary ON emp (salary)");
    ok(
        &mut db,
        "ALTER TABLE emp ADD COLUMN bonus REAL CHECK (bonus IS NULL OR bonus < salary)",
    );
    assert!(err(&mut db, "UPDATE emp SET bonus = 1000 WHERE id = 1").contains("CHECK"));
    ok(&mut db, "ALTER TABLE emp DROP COLUMN bonus");
    // DROP COLUMN reescreve as linhas e derruba índices e CHECKs da coluna.
    ok(&mut db, "ALTER TABLE emp DROP COLUMN salary");
    assert!(err(&mut db, "SELECT salary FROM emp").contains("coluna desconhecida"));
    assert!(!q(&mut db, "SHOW INDEXES FROM emp")
        .iter()
        .any(|r| r.contains("emp_salary")));
    assert!(!q(&mut db, "SHOW CREATE TABLE emp")[0].contains("salary"));
    assert_eq!(
        q(&mut db, "SELECT name, dept FROM emp WHERE id = 6"),
        ["fabio|1"]
    );
    assert!(err(&mut db, "ALTER TABLE emp DROP COLUMN id").contains("PRIMARY KEY"));
    assert!(err(&mut db, "ALTER TABLE emp DROP COLUMN dept").contains("FOREIGN KEY"));
    assert!(err(&mut db, "ALTER TABLE dept DROP COLUMN id").contains("PRIMARY KEY"));
    // RENAME COLUMN atualiza CHECK e as FKs das filhas; RENAME TABLE idem.
    ok(&mut db, "ALTER TABLE emp RENAME COLUMN name TO nome");
    assert!(err(&mut db, "INSERT INTO emp (nome) VALUES ('x')").contains("length(nome)"));
    ok(&mut db, "ALTER TABLE dept RENAME COLUMN id TO codigo");
    ok(&mut db, "ALTER TABLE dept RENAME TO departamento");
    assert!(
        err(&mut db, "INSERT INTO emp (nome, dept) VALUES ('zz', 77)").contains("departamento")
    );
    assert!(q(&mut db, "SHOW CREATE TABLE emp")[0].contains("REFERENCES departamento (codigo)"));
    ok(&mut db, "DELETE FROM departamento WHERE codigo = 3");
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM emp"), ["5"]);
    // ALTER COLUMN.
    ok(
        &mut db,
        "ALTER TABLE emp ALTER COLUMN since SET DEFAULT 'sempre'",
    );
    ok(&mut db, "INSERT INTO emp (nome) VALUES ('novo')");
    assert_eq!(
        q(&mut db, "SELECT since FROM emp WHERE nome = 'novo'"),
        ["sempre"]
    );
    assert!(err(&mut db, "ALTER TABLE emp ALTER COLUMN boss SET NOT NULL").contains("NULL"));
    ok(&mut db, "UPDATE emp SET boss = 1 WHERE boss IS NULL");
    ok(&mut db, "ALTER TABLE emp ALTER COLUMN boss SET NOT NULL");
    assert!(err(&mut db, "INSERT INTO emp (nome) VALUES ('sem chefe')").contains("NOT NULL"));
    ok(&mut db, "ALTER TABLE emp ALTER COLUMN boss DROP NOT NULL");
    ok(&mut db, "ALTER TABLE emp ALTER COLUMN since DROP DEFAULT");
    ok(&mut db, "ALTER TABLE emp ADD COLUMN nivel INT NOT NULL DEFAULT (1 + 1) CHECK (nivel BETWEEN 1 AND 5)");
    assert_eq!(q(&mut db, "SELECT DISTINCT nivel FROM emp"), ["2"]);
    assert!(err(&mut db, "INSERT INTO emp (nome, nivel) VALUES ('x9', 9)").contains("CHECK"));
    ok(
        &mut db,
        "ALTER TABLE emp ADD COLUMN depto2 INT REFERENCES departamento(codigo)",
    );
    assert!(
        err(&mut db, "INSERT INTO emp (nome, depto2) VALUES ('x9', 99)").contains("FOREIGN KEY")
    );
    let ddl = q(&mut db, "SHOW CREATE TABLE emp")[0].clone();
    assert!(ddl.contains("CREATE TABLE emp") && ddl.contains("CHECK (length(nome) >= 2)"));
    // O DDL gerado é aceito de volta.
    ok(&mut db, "ALTER TABLE emp RENAME TO emp_old");
    let ddl = q(&mut db, "SHOW CREATE TABLE emp_old")[0].clone();
    let create = ddl
        .split("|")
        .last()
        .unwrap()
        .replace("emp_old", "emp_novo");
    ok(&mut db, &create);
    assert!(q(&mut db, "DESCRIBE emp_novo").len() >= 6);
}

#[test]
fn views_and_catalog_commands() {
    let mut db = school("views");
    ok(&mut db, "CREATE VIEW rich AS SELECT e.name, d.name AS dept, e.salary FROM emp e JOIN dept d ON d.id = e.dept WHERE e.salary >= 150");
    assert_eq!(
        q(&mut db, "SELECT name, dept FROM rich ORDER BY salary DESC"),
        ["ana|eng", "bia|eng", "fabio|eng", "caio|ops"]
    );
    ok(&mut db, "CREATE VIEW por_dept (dept, total, media) AS SELECT dept, COUNT(*), AVG(salary) FROM emp GROUP BY dept");
    assert_eq!(
        q(
            &mut db,
            "SELECT dept, total FROM por_dept WHERE media > 130 ORDER BY dept"
        ),
        ["1|3", "2|2"]
    );
    // View sobre view, com join.
    ok(&mut db, "CREATE VIEW resumo AS SELECT r.name, p.total FROM rich r JOIN emp e ON e.name = r.name JOIN por_dept p ON p.dept = e.dept");
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM resumo"), ["4"]);
    assert!(err(&mut db, "INSERT INTO rich VALUES ('x', 'y', 1)").contains("somente leitura"));
    assert!(err(&mut db, "CREATE TABLE rich (id INT)").contains("view"));
    assert!(err(&mut db, "CREATE VIEW rich AS SELECT 1").contains("já existe"));
    ok(
        &mut db,
        "CREATE OR REPLACE VIEW rich AS SELECT name FROM emp WHERE salary > 250",
    );
    assert_eq!(q(&mut db, "SELECT * FROM rich"), ["ana"]);
    assert!(
        err(&mut db, "CREATE VIEW ruim AS SELECT nada FROM emp").contains("coluna desconhecida")
    );
    assert!(err(&mut db, "DROP TABLE rich").contains("DROP VIEW"));
    let tables = q(&mut db, "SHOW TABLES");
    assert!(
        tables.iter().any(|r| r.starts_with("rich|view"))
            && tables.iter().any(|r| r.starts_with("emp|table"))
    );
    assert_eq!(q(&mut db, "DESCRIBE por_dept").len(), 3);
    assert!(q(&mut db, "SHOW CREATE TABLE por_dept")[0]
        .contains("CREATE VIEW por_dept (dept, total, media) AS SELECT"));
    assert!(q(&mut db, "DESCRIBE emp")
        .iter()
        .any(|r| r.starts_with("dept|INTEGER|false|false|NULL|emp_dept_fkey_idx|dept(id)")));
    ok(&mut db, "DROP VIEW resumo");
    ok(&mut db, "DROP VIEW IF EXISTS resumo");
    assert!(err(&mut db, "SELECT * FROM resumo").contains("resumo"));
    // View recursiva/circular é recusada com erro, não com estouro de pilha.
    ok(&mut db, "CREATE VIEW v1 AS SELECT 1 AS x");
    assert!(err(&mut db, "CREATE OR REPLACE VIEW v1 AS SELECT x FROM v1").contains("v1"));
}

#[test]
fn window_functions() {
    let mut db = school("win");
    assert_eq!(
        q(&mut db, "SELECT name, row_number() OVER (ORDER BY salary DESC), rank() OVER (PARTITION BY dept ORDER BY salary DESC), dense_rank() OVER (ORDER BY dept) FROM emp ORDER BY 2"),
        ["ana|1|1|1", "bia|2|2|1", "fabio|3|3|1", "caio|4|1|2", "duda|5|2|2", "eva|6|1|3"]
    );
    // Soma acumulada (moldura padrão) e soma por partição (sem ORDER BY).
    assert_eq!(
        q(&mut db, "SELECT name, SUM(salary) OVER (ORDER BY id), SUM(salary) OVER (PARTITION BY dept), COUNT(*) OVER () FROM emp ORDER BY id"),
        ["ana|300.0|680.0|6", "bia|500.0|680.0|6", "caio|650.0|270.0|6", "duda|770.0|270.0|6", "eva|870.0|100.0|6", "fabio|1050.0|680.0|6"]
    );
    assert_eq!(
        q(&mut db, "SELECT name, lag(name) OVER (ORDER BY id), lead(name, 2, 'fim') OVER (ORDER BY id), first_value(name) OVER (PARTITION BY dept ORDER BY salary DESC), last_value(name) OVER (PARTITION BY dept ORDER BY salary DESC ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) FROM emp ORDER BY id"),
        ["ana|NULL|caio|ana|fabio", "bia|ana|duda|ana|fabio", "caio|bia|eva|caio|duda", "duda|caio|fabio|caio|duda", "eva|duda|fim|eva|eva", "fabio|eva|fim|ana|fabio"]
    );
    // Média móvel de 3 (ROWS), ntile, percent_rank, cume_dist, RANGE.
    assert_eq!(
        q(&mut db, "SELECT id, round(AVG(salary) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING), 1), ntile(2) OVER (ORDER BY id), round(percent_rank() OVER (ORDER BY salary), 2), round(cume_dist() OVER (ORDER BY salary), 2) FROM emp ORDER BY id"),
        ["1|250.0|1|1.0|1.0", "2|216.7|1|0.8|0.83", "3|156.7|1|0.4|0.5", "4|123.3|2|0.2|0.33", "5|133.3|2|0.0|0.17", "6|140.0|2|0.6|0.67"]
    );
    assert_eq!(
        q(&mut db, "SELECT id, COUNT(*) OVER (ORDER BY salary RANGE BETWEEN 50 PRECEDING AND 50 FOLLOWING), SUM(salary) OVER (ORDER BY salary DESC ROWS UNBOUNDED PRECEDING) FROM emp ORDER BY id"),
        ["1|1|300.0", "2|3|500.0", "3|5|830.0", "4|3|950.0", "5|3|1050.0", "6|3|680.0"]
    );
    // Janela sobre agregação, e ORDER BY em função de janela.
    assert_eq!(
        q(&mut db, "SELECT dept, SUM(salary) AS s, rank() OVER (ORDER BY SUM(salary) DESC) AS r FROM emp GROUP BY dept ORDER BY r"),
        ["1|680.0|1", "2|270.0|2", "3|100.0|3"]
    );
    assert_eq!(
        q(&mut db, "SELECT name FROM (SELECT name, row_number() OVER (PARTITION BY dept ORDER BY salary DESC) AS rn FROM emp) t WHERE rn = 1 ORDER BY name"),
        ["ana", "caio", "eva"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT group_concat(name, '+') OVER (ORDER BY id) FROM emp ORDER BY id LIMIT 3"
        ),
        ["ana", "ana+bia", "ana+bia+caio"]
    );
    assert!(err(&mut db, "SELECT * FROM emp WHERE row_number() OVER () = 1").contains("WHERE"));
    assert!(err(&mut db, "SELECT row_number() FROM emp").contains("OVER"));
    assert!(ok(&mut db, "EXPLAIN SELECT rank() OVER (ORDER BY id) FROM emp").contains("WINDOW"));
}

#[test]
fn recursive_ctes_values_quantified_and_operators() {
    let mut db = school("rec");
    assert_eq!(
        q(&mut db, "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 5) SELECT SUM(x), COUNT(*) FROM n"),
        ["15|5"]
    );
    // Hierarquia: subordinados de ana em qualquer nível, com profundidade.
    assert_eq!(
        q(
            &mut db,
            "WITH RECURSIVE sub AS (
                SELECT id, name, 0 AS depth FROM emp WHERE name = 'ana'
                UNION ALL
                SELECT e.id, e.name, s.depth + 1 FROM emp e JOIN sub s ON e.boss = s.id
            ) SELECT name, depth FROM sub WHERE depth > 0 ORDER BY depth, name"
        ),
        ["bia|1", "caio|1", "duda|2", "fabio|2"]
    );
    // UNION (distinto) termina mesmo com ciclo.
    ok(&mut db, "CREATE TABLE g (src INT, dst INT)");
    ok(
        &mut db,
        "INSERT INTO g VALUES (1, 2), (2, 3), (3, 1), (3, 4)",
    );
    assert_eq!(
        q(&mut db, "WITH RECURSIVE r(n) AS (SELECT 1 UNION SELECT dst FROM g JOIN r ON g.src = r.n) SELECT n FROM r ORDER BY n"),
        ["1", "2", "3", "4"]
    );
    assert!(err(&mut db, "WITH RECURSIVE inf(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM inf) SELECT COUNT(*) FROM inf").contains("iterações"));
    // LIMIT dentro da CTE encerra geradores infinitos.
    assert_eq!(
        q(&mut db, "WITH RECURSIVE inf(x) AS (SELECT 1 UNION ALL SELECT x * 2 FROM inf LIMIT 6) SELECT x FROM inf ORDER BY x DESC LIMIT 1"),
        ["32"]
    );
    // VALUES como consulta, no FROM e com colunas nomeadas.
    assert_eq!(q(&mut db, "VALUES (1, 'a'), (2, 'b')"), ["1|a", "2|b"]);
    assert_eq!(
        q(
            &mut db,
            "SELECT v.n * 10, v.s FROM (VALUES (1, 'x'), (2, 'y')) AS v (n, s) ORDER BY 1 DESC"
        ),
        ["20|y", "10|x"]
    );
    assert_eq!(
        q(&mut db, "WITH cores(nome, hex) AS (VALUES ('azul', '00f'), ('verde', '0f0')) SELECT nome FROM cores WHERE hex LIKE '0%' ORDER BY nome"),
        ["azul", "verde"]
    );
    // ANY/ALL, IS DISTINCT FROM, GLOB, bit a bit, ::cast, NULLS FIRST/LAST, USING.
    assert_eq!(
        q(&mut db, "SELECT name FROM emp WHERE salary > ALL (SELECT salary FROM emp WHERE dept = 2) ORDER BY name"),
        ["ana", "bia", "fabio"]
    );
    assert_eq!(
        q(&mut db, "SELECT name FROM emp WHERE dept = ANY (SELECT id FROM dept WHERE name <> 'eng') AND name GLOB '[cd]*' ORDER BY name"),
        ["caio", "duda"]
    );
    assert_eq!(
        q(&mut db, "SELECT COUNT(*) FROM emp e1 JOIN emp e2 ON e1.boss IS NOT DISTINCT FROM e2.boss AND e1.id < e2.id"),
        ["2"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT 6 & 3, 6 | 3, 1 << 4, 256 >> 2, ~0, '42'::INT + 1, 7::REAL / 2"
        ),
        ["2|7|16|64|-1|43|3.5"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT name FROM emp ORDER BY boss NULLS LAST, id LIMIT 3"
        ),
        ["bia", "caio", "fabio"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT name FROM emp ORDER BY boss DESC NULLS FIRST, id LIMIT 3"
        ),
        ["ana", "eva", "duda"]
    );
    ok(
        &mut db,
        "CREATE TABLE dept2 (id INT PRIMARY KEY, floor INT)",
    );
    ok(&mut db, "INSERT INTO dept2 VALUES (1, 3), (2, 5)");
    assert_eq!(
        q(
            &mut db,
            "SELECT d.name, d2.floor FROM dept d JOIN dept2 d2 USING (id) ORDER BY id"
        ),
        ["eng|3", "ops|5"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT 1 WHERE 1 IS TRUE AND NULL IS NOT TRUE AND 0 IS FALSE"
        ),
        ["1"]
    );
}

#[test]
fn aggregates_and_scalar_functions() {
    let mut db = school("funcs");
    assert_eq!(
        q(&mut db, "SELECT dept, group_concat(name, ', '), round(stddev_pop(salary), 2), round(variance(salary), 2), bool_and(salary > 100), bool_or(boss IS NULL), total(boss) FROM emp GROUP BY dept ORDER BY dept"),
        ["1|ana, bia, fabio|52.49|4133.33|true|true|3.0", "2|caio, duda|15.0|450.0|true|false|4.0", "3|eva|0.0|NULL|false|true|0.0"]
    );
    assert_eq!(
        q(&mut db, "SELECT upper(left(name, 1)) || substr(name, 2) AS cap, lpad(id::TEXT, 3, '0'), reverse(name), split_part('a-b-c', '-', 2), printf('%05.1f', salary) FROM emp WHERE id = 1"),
        ["Ana|001|ana|b|300.0"]
    );
    assert_eq!(
        q(&mut db, "SELECT floor(2.7), ceil(2.1), power(2, 10), round(sqrt(2), 3), sign(-3), mod(17, 5), abs(-2.5), trunc(2.987, 2), greatest(1, 9, 4), least('b', 'a'), coalesce(NULL, NULL, 'x'), nullif(3, 3), iif(1 > 2, 'a', 'b')"),
        ["2|3|1024.0|1.414|-1|2|2.5|2.98|9|a|x|NULL|b"]
    );
    assert_eq!(
        q(&mut db, "SELECT date('2024-01-31', '+1 month'), datetime(0), strftime('%Y/%m', '2024-03-05'), unixepoch('1970-01-02'), year('2024-03-05'), date_diff('2024-03-05', '2024-03-01'), date_add('2024-12-31 23:00:00', '+2 hours'), time('2024-01-01T10:20:30Z')"),
        ["2024-03-02|1970-01-01 00:00:00|2024/03|86400|2024|4|2025-01-01 01:00:00|10:20:30"]
    );
    assert_eq!(
        q(
            &mut db,
            r#"SELECT json_extract('{"a":{"b":[10,20]}}', '$.a.b[1]'), json_type('[1]'), json_array_length('[1,2,3]'), json_object('k', 1, 'v', 'x'), json_valid('{'), json_extract(json_array(1, 'a'), '$[1]')"#
        ),
        [r#"20|array|3|{"k":1,"v":"x"}|false|a"#]
    );
    assert_eq!(q(&mut db, "SELECT length(sha256('a')), typeof(random()), length(uuid()), hex('AB'), quote('it''s'), concat_ws('-', 'a', NULL, 'b'), instr('banana', 'nan'), contains('abc', 'b'), initcap('ola mundo')"),
        ["64|integer|36|4142|'it''s'|a-b|3|true|Ola Mundo"]);
    assert_eq!(q(&mut db, "SELECT now() IS NOT NULL, length(current_date), length(current_time), CURRENT_TIMESTAMP > '2020-01-01'"), ["true|10|8|true"]);
    assert!(err(&mut db, "SELECT nada(1)").contains("função desconhecida"));
    assert!(err(&mut db, "SELECT regexp_like('a', '(')").contains("regular"));
    assert!(err(&mut db, "SELECT date('2024-13-01')").contains("inválida"));
}

#[test]
fn returning_replace_ignore_and_upsert() {
    let mut db = school("ret");
    assert_eq!(
        q(&mut db, "INSERT INTO emp (name, dept, salary) VALUES ('gil', 3, 90), ('hana', 3, 95) RETURNING id, name, since"),
        ["7|gil|2024-01-01", "8|hana|2024-01-01"]
    );
    assert_eq!(
        q(
            &mut db,
            "UPDATE emp SET salary = salary * 2 WHERE dept = 3 RETURNING name, salary"
        ),
        ["eva|200.0", "gil|180.0", "hana|190.0"]
    );
    assert_eq!(
        q(
            &mut db,
            "DELETE FROM emp WHERE id >= 7 RETURNING *, id * 10 AS dez"
        ),
        [
            "7|gil|3|NULL|180.0|2024-01-01|70",
            "8|hana|3|NULL|190.0|2024-01-01|80"
        ]
    );
    ok(
        &mut db,
        "CREATE TABLE kv2 (k TEXT PRIMARY KEY, v INT, u TEXT UNIQUE)",
    );
    ok(
        &mut db,
        "INSERT INTO kv2 VALUES ('a', 1, 'x'), ('b', 2, 'y')",
    );
    assert_eq!(
        ok(
            &mut db,
            "INSERT OR IGNORE INTO kv2 VALUES ('a', 99, 'zz'), ('c', 3, 'w')"
        ),
        "INSERT 1 UPDATE 0"
    );
    assert_eq!(q(&mut db, "SELECT v FROM kv2 WHERE k = 'a'"), ["1"]);
    // REPLACE remove todas as linhas em conflito (PK de uma, UNIQUE de outra).
    assert_eq!(
        ok(&mut db, "REPLACE INTO kv2 VALUES ('a', 5, 'y')"),
        "INSERT 1 UPDATE 0"
    );
    assert_eq!(
        q(&mut db, "SELECT k, v, u FROM kv2 ORDER BY k"),
        ["a|5|y", "c|3|w"]
    );
    assert_eq!(
        q(&mut db, "INSERT INTO kv2 VALUES ('a', 1, 'q') ON CONFLICT DO UPDATE SET v = kv2.v + excluded.v RETURNING k, v"),
        ["a|6"]
    );
    assert_eq!(
        q(
            &mut db,
            "INSERT OR REPLACE INTO kv2 VALUES ('c', 30, 'w') RETURNING v"
        ),
        ["30"]
    );
}

#[test]
fn scripts_and_savepoints_on_db_handle() {
    let dir = tmpdir("script");
    let mut db = school_at(&dir);
    let res = db
        .execute_sql("INSERT INTO dept VALUES (4, 'fin'); SELECT COUNT(*) FROM dept; UPDATE dept SET name = 'finance' WHERE id = 4")
        .unwrap();
    let ExecResult::Batch(results) = res else {
        panic!("{res:?}")
    };
    assert_eq!(results.len(), 3);
    assert_eq!(rows_of(results[1].clone(), "count"), ["4"]);
    // Erro no meio desfaz tudo.
    assert!(db
        .execute_sql("INSERT INTO dept VALUES (5, 'x'); INSERT INTO dept VALUES (5, 'y')")
        .is_err());
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM dept"), ["4"]);
    // Transação explícita com savepoints.
    ok(&mut db, "BEGIN");
    ok(&mut db, "INSERT INTO dept VALUES (6, 'a')");
    ok(&mut db, "SAVEPOINT s1");
    ok(&mut db, "INSERT INTO dept VALUES (7, 'b')");
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM dept"), ["6"]);
    ok(&mut db, "ROLLBACK TO s1");
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM dept"), ["5"]);
    ok(&mut db, "INSERT INTO dept VALUES (8, 'c')");
    ok(&mut db, "RELEASE SAVEPOINT s1");
    assert!(err(&mut db, "ROLLBACK TO s1").contains("não existe"));
    ok(&mut db, "COMMIT");
    assert_eq!(
        q(&mut db, "SELECT name FROM dept WHERE id > 5 ORDER BY id"),
        ["a", "c"]
    );
    // Script com BEGIN/COMMIT próprios e reabertura consistente.
    db.execute_sql("BEGIN; INSERT INTO dept VALUES (9, 'd'); COMMIT")
        .unwrap();
    db.execute_sql("BEGIN; INSERT INTO dept VALUES (10, 'e')")
        .unwrap();
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM dept"), ["8"]);
    ok(&mut db, "ROLLBACK");
    db.close().unwrap();
    drop(db);
    let mut db = Db::open(&dir).unwrap();
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM dept"), ["7"]);
    assert!(
        err(&mut db, "SELECT 1; SELECT ?").contains("parâmetros")
            || db
                .execute_sql_params("SELECT 1; SELECT ?", &[Value::Int(1)])
                .is_err()
    );
}

#[test]
fn sessions_txn_sql_and_isolation() {
    let db = SharedDb::new(Db::open(tmpdir("session")).unwrap());
    db.sql("CREATE TABLE acc (id INT PRIMARY KEY, saldo INT CHECK (saldo >= 0), tag TEXT)")
        .unwrap();
    db.sql("INSERT INTO acc VALUES (1, 100, 'a'), (2, 50, 'b')")
        .unwrap();
    // Script atômico pelo SharedDb (sessão implícita).
    let res = db.sql("UPDATE acc SET saldo = saldo - 10 WHERE id = 1; UPDATE acc SET saldo = saldo + 10 WHERE id = 2; SELECT saldo FROM acc ORDER BY id").unwrap();
    let ExecResult::Batch(r) = res else { panic!() };
    assert_eq!(rows_of(r[2].clone(), "sel"), ["90", "60"]);
    assert!(db.sql("UPDATE acc SET saldo = saldo - 500 WHERE id = 1; UPDATE acc SET saldo = 1 WHERE id = 2").is_err());
    assert_eq!(
        rows_of(db.sql("SELECT saldo FROM acc ORDER BY id").unwrap(), "s"),
        ["90", "60"]
    );
    assert!(db.sql("BEGIN").unwrap_err().to_string().contains("sessão"));
    assert!(db
        .sql("BEGIN; INSERT INTO acc VALUES (9, 1, 'x')")
        .unwrap_err()
        .to_string()
        .contains("falta COMMIT"));
    assert_eq!(
        rows_of(db.sql("SELECT COUNT(*) FROM acc").unwrap(), "c"),
        ["2"]
    );
    // Sessão: transação aberta não é vista por fora até o COMMIT.
    let mut s = db.session();
    s.execute("BEGIN").unwrap();
    s.execute("INSERT INTO acc VALUES (3, 7, 'c')").unwrap();
    assert_eq!(
        rows_of(s.execute("SELECT COUNT(*) FROM acc").unwrap(), "in"),
        ["3"]
    );
    assert_eq!(
        rows_of(db.sql("SELECT COUNT(*) FROM acc").unwrap(), "out"),
        ["2"]
    );
    s.execute("SAVEPOINT a; UPDATE acc SET tag = 'zz' WHERE id = 3; ROLLBACK TO a")
        .unwrap();
    assert_eq!(
        rows_of(
            s.execute("SELECT tag FROM acc WHERE id = 3").unwrap(),
            "tag"
        ),
        ["c"]
    );
    s.execute("COMMIT").unwrap();
    assert_eq!(
        rows_of(db.sql("SELECT COUNT(*) FROM acc").unwrap(), "out"),
        ["3"]
    );
    // ROLLBACK descarta; erro dentro da transação não a fecha.
    s.execute("BEGIN; DELETE FROM acc").unwrap();
    assert!(s.execute("INSERT INTO acc VALUES (1, -5, 'x')").is_err());
    assert!(s.in_transaction());
    s.execute("ROLLBACK").unwrap();
    assert_eq!(
        rows_of(db.sql("SELECT COUNT(*) FROM acc").unwrap(), "out"),
        ["3"]
    );
    // Serializável: conflito de escrita-escrita detectado no COMMIT.
    let mut s1 = db.session();
    let mut s2 = db.session();
    s1.execute("BEGIN ISOLATION LEVEL SERIALIZABLE").unwrap();
    s2.execute("BEGIN").unwrap();
    s1.execute("UPDATE acc SET saldo = saldo + 1 WHERE id = 1")
        .unwrap();
    s2.execute("UPDATE acc SET saldo = saldo + 2 WHERE id = 1")
        .unwrap();
    s2.execute("COMMIT").unwrap();
    assert!(matches!(s1.execute("COMMIT"), Err(Error::Conflict(_))));
    assert!(!s1.in_transaction());
    assert_eq!(
        rows_of(db.sql("SELECT saldo FROM acc WHERE id = 1").unwrap(), "s"),
        ["92"]
    );
    // Txn direta com SQL (write skew barrado no serializável).
    let mut t1 = db.begin_serializable().unwrap();
    let mut t2 = db.begin_serializable().unwrap();
    let total = |t: &mut mini_db::mvcc::Txn| {
        rows_of(t.sql("SELECT SUM(saldo) FROM acc").unwrap(), "sum")[0].clone()
    };
    assert_eq!(total(&mut t1), total(&mut t2));
    t1.sql("UPDATE acc SET saldo = saldo - 60 WHERE id = 1")
        .unwrap();
    t2.sql("UPDATE acc SET saldo = saldo - 60 WHERE id = 2")
        .unwrap();
    t1.commit().unwrap();
    assert!(matches!(t2.commit(), Err(Error::Conflict(_))));
    // kv dentro de sessão com transação.
    let mut s3 = db.session();
    s3.execute("BEGIN").unwrap();
    s3.put(b"k1", b"v1").unwrap();
    assert_eq!(s3.get(b"k1").unwrap(), Some(b"v1".to_vec()));
    assert_eq!(db.get(b"k1").unwrap(), None);
    assert!(s3.execute("SELECT * FROM kv").is_err());
    s3.execute("COMMIT").unwrap();
    assert_eq!(db.get(b"k1").unwrap(), Some(b"v1".to_vec()));
    drop((s, s1, s2, s3));
    db.write().unwrap().close().unwrap();
}

#[test]
fn snapshot_transactions_cannot_break_unique_or_foreign_keys() {
    let db = SharedDb::new(Db::open(tmpdir("guards")).unwrap());
    // Chaves primárias de texto: nenhuma sequência compartilhada mascara o conflito.
    db.sql("CREATE TABLE u (id TEXT PRIMARY KEY, email TEXT UNIQUE)")
        .unwrap();
    db.sql("CREATE TABLE p (id INT PRIMARY KEY, nome TEXT)")
        .unwrap();
    db.sql("CREATE TABLE c (id TEXT PRIMARY KEY, p_id INT REFERENCES p)")
        .unwrap();
    db.sql("INSERT INTO p (id) VALUES (1), (2), (3)").unwrap();
    let mut a = db.session();
    let mut b = db.session();

    // UNIQUE: o mesmo valor único gravado com chaves primárias diferentes.
    a.execute("BEGIN").unwrap();
    b.execute("BEGIN").unwrap();
    a.execute("INSERT INTO u VALUES ('a', 'x@y')").unwrap();
    b.execute("INSERT INTO u VALUES ('b', 'x@y')").unwrap();
    a.execute("COMMIT").unwrap();
    assert!(matches!(b.execute("COMMIT"), Err(Error::Conflict(_))));

    // Valores únicos diferentes não conflitam.
    a.execute("BEGIN").unwrap();
    b.execute("BEGIN").unwrap();
    a.execute("INSERT INTO u VALUES ('c', 'm@n')").unwrap();
    b.execute("INSERT INTO u VALUES ('d', 'o@p')").unwrap();
    a.execute("COMMIT").unwrap();
    b.execute("COMMIT").unwrap();
    assert_eq!(
        rows_of(db.sql("SELECT COUNT(*) FROM u").unwrap(), "u"),
        ["3"]
    );

    // Filha inserida enquanto outra sessão apaga o pai.
    a.execute("BEGIN").unwrap();
    a.execute("INSERT INTO c VALUES ('k', 1)").unwrap();
    db.sql("DELETE FROM p WHERE id = 1").unwrap();
    assert!(matches!(a.execute("COMMIT"), Err(Error::Conflict(_))));

    // Pai apagado enquanto outra sessão insere uma filha dele.
    a.execute("BEGIN").unwrap();
    a.execute("DELETE FROM p WHERE id = 2").unwrap();
    db.sql("INSERT INTO c VALUES ('z', 2)").unwrap();
    assert!(matches!(a.execute("COMMIT"), Err(Error::Conflict(_))));

    // Atualizar o pai sem tocar na chave não derruba a inserção da filha.
    a.execute("BEGIN").unwrap();
    a.execute("INSERT INTO c VALUES ('w', 3)").unwrap();
    db.sql("UPDATE p SET nome = 'novo' WHERE id = 3").unwrap();
    a.execute("COMMIT").unwrap();

    assert_eq!(
        rows_of(db.sql("SELECT id FROM c ORDER BY id").unwrap(), "c"),
        ["w", "z"]
    );
    drop((a, b));
    db.write().unwrap().close().unwrap();
}

#[test]
fn tcp_connections_have_their_own_transactions() {
    let dir = tmpdir("tcp-txn");
    let db = SharedDb::new(Db::open(&dir).unwrap());
    db.sql("CREATE TABLE t7 (id INT PRIMARY KEY, v TEXT)")
        .unwrap();
    let addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    {
        let (db, addr) = (db.clone(), addr.clone());
        thread::spawn(move || mini_db::server::serve(db, &addr));
    }
    let connect = || {
        let start = Instant::now();
        loop {
            match TcpStream::connect(&addr) {
                Ok(s) => break s,
                Err(_) if start.elapsed() < Duration::from_secs(5) => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(e) => panic!("{e}"),
            }
        }
    };
    let open = || {
        let stream = connect();
        let out = stream.try_clone().unwrap();
        let mut lines = BufReader::new(stream).lines();
        lines.next().unwrap().unwrap();
        (out, lines)
    };
    let (mut o1, mut l1) = open();
    let (mut o2, mut l2) = open();
    let ask = |out: &mut TcpStream, lines: &mut std::io::Lines<BufReader<TcpStream>>, cmd: &str| {
        writeln!(out, "{cmd}").unwrap();
        lines.next().unwrap().unwrap()
    };
    assert!(ask(&mut o1, &mut l1, "BEGIN").starts_with("OK BEGIN"));
    assert!(ask(&mut o1, &mut l1, "INSERT INTO t7 VALUES (1, 'a')").starts_with("OK INSERT 1"));
    assert!(ask(&mut o1, &mut l1, "PUT chave valor").starts_with("OK"));
    // A outra conexão (e o processo) não veem nada até o COMMIT.
    assert_eq!(ask(&mut o2, &mut l2, "GET chave"), "(nil)");
    assert_eq!(
        rows_of(db.sql("SELECT COUNT(*) FROM t7").unwrap(), "c"),
        ["0"]
    );
    assert!(ask(&mut o1, &mut l1, "COMMIT").starts_with("OK COMMIT"));
    assert_eq!(ask(&mut o2, &mut l2, "GET chave"), "valor");
    assert_eq!(
        rows_of(db.sql("SELECT COUNT(*) FROM t7").unwrap(), "c"),
        ["1"]
    );
    // Erro de sintaxe SQL não derruba a conexão.
    assert!(ask(&mut o2, &mut l2, "SELEC 1").starts_with("ERR"));
    assert!(ask(&mut o2, &mut l2, "ROLLBACK").starts_with("ERR"));
    drop((o1, o2, l1, l2));
}
