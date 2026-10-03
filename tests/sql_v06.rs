//! SQL 0.6: subconsultas (inclusive correlacionadas), CTEs, operações de
//! conjunto, CASE/CAST, chaves e índices compostos, parâmetros, joins
//! RIGHT/FULL/CROSS e hash join, INSERT ... SELECT, upsert e linhas grandes.
use mini_db::rel::Value;
use mini_db::{Db, Error, ExecResult};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("minidb-sql06-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn q(db: &mut Db, sql: &str) -> Vec<String> {
    match db.execute_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}")) {
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

fn ok(db: &mut Db, sql: &str) -> String {
    match db.execute_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}")) {
        ExecResult::Ok(s) => s,
        other => panic!("{sql}: {other:?}"),
    }
}

fn shop(tag: &str) -> Db {
    let mut db = Db::open(tmpdir(tag)).unwrap();
    ok(
        &mut db,
        "CREATE TABLE c (id INT PRIMARY KEY, name TEXT, city TEXT)",
    );
    ok(
        &mut db,
        "CREATE TABLE o (id INT PRIMARY KEY, cid INT, total REAL)",
    );
    ok(
        &mut db,
        "INSERT INTO c VALUES (1, 'ana', 'rio'), (2, 'bia', 'sp'), (3, 'caio', 'rio'), (4, 'duda', NULL)",
    );
    ok(
        &mut db,
        "INSERT INTO o VALUES (10, 1, 50), (11, 1, 150), (12, 2, 20), (13, 9, 99)",
    );
    db
}

#[test]
fn subqueries_scalar_in_exists_and_correlated() {
    let mut db = shop("sub");
    assert_eq!(
        q(
            &mut db,
            "SELECT name FROM c WHERE id IN (SELECT cid FROM o) ORDER BY name"
        ),
        ["ana", "bia"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT name FROM c WHERE id NOT IN (SELECT cid FROM o) ORDER BY 1"
        ),
        ["caio", "duda"]
    );
    // Correlacionadas: enxergam a linha externa.
    assert_eq!(
        q(
            &mut db,
            "SELECT name, (SELECT SUM(total) FROM o WHERE o.cid = c.id) AS gasto FROM c ORDER BY id"
        ),
        ["ana|200.0", "bia|20.0", "caio|NULL", "duda|NULL"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT name FROM c WHERE EXISTS (SELECT 1 FROM o WHERE o.cid = c.id AND o.total > 100)"
        ),
        ["ana"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT name FROM c WHERE NOT EXISTS (SELECT 1 FROM o WHERE o.cid = c.id) ORDER BY 1"
        ),
        ["caio", "duda"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT (SELECT MAX(total) FROM o) - (SELECT MIN(total) FROM o)"
        ),
        ["130.0"]
    );
    assert!(db
        .execute_sql("SELECT (SELECT id FROM c) FROM c")
        .unwrap_err()
        .to_string()
        .contains("linhas"));
    // UPDATE/DELETE com subconsulta.
    ok(&mut db, "DELETE FROM o WHERE cid NOT IN (SELECT id FROM c)");
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM o"), ["3"]);
    ok(
        &mut db,
        "UPDATE c SET city = (SELECT city FROM c WHERE id = 1) WHERE city IS NULL",
    );
    assert_eq!(q(&mut db, "SELECT city FROM c WHERE id = 4"), ["rio"]);
}

#[test]
fn ctes_derived_tables_and_set_operations() {
    let mut db = shop("sets");
    assert_eq!(
        q(
            &mut db,
            "WITH gastos AS (SELECT cid, SUM(total) AS t FROM o GROUP BY cid) \
             SELECT c.name, g.t FROM c JOIN gastos g ON g.cid = c.id WHERE g.t > 30"
        ),
        ["ana|200.0"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT x.city, x.n FROM (SELECT city, COUNT(*) AS n FROM c GROUP BY city) AS x \
             WHERE x.n > 1"
        ),
        ["rio|2"]
    );
    assert_eq!(
        q(&mut db, "SELECT city FROM c UNION SELECT 'bh' ORDER BY 1"),
        ["NULL", "bh", "rio", "sp"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT city FROM c UNION ALL SELECT city FROM c WHERE id = 1"
        )
        .len(),
        5
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM c INTERSECT SELECT cid FROM o ORDER BY id"
        ),
        ["1", "2"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM c EXCEPT SELECT cid FROM o ORDER BY id DESC"
        ),
        ["4", "3"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT cid FROM o EXCEPT ALL SELECT id FROM c ORDER BY 1"
        ),
        ["1", "9"]
    );
    assert!(db
        .execute_sql("SELECT id, name FROM c UNION SELECT id FROM o")
        .is_err());
}

#[test]
fn case_cast_and_functions() {
    let mut db = shop("case");
    assert_eq!(
        q(
            &mut db,
            "SELECT name, CASE WHEN city = 'rio' THEN 'carioca' WHEN city IS NULL THEN '?' ELSE 'outro' END \
             FROM c ORDER BY id"
        ),
        ["ana|carioca", "bia|outro", "caio|carioca", "duda|?"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT CASE id WHEN 1 THEN 'um' WHEN 2 THEN 'dois' END FROM c ORDER BY id LIMIT 3"
        ),
        ["um", "dois", "NULL"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT CAST('42' AS INT) + 1, CAST(3.9 AS INTEGER), CAST(7 AS TEXT) || '!', \
             CAST('true' AS BOOLEAN), nullif(1, 1), replace('a-b', '-', '+'), instr('banana', 'na')"
        ),
        ["43|3|7!|true|NULL|a+b|3"]
    );
    assert!(db.execute_sql("SELECT CAST('x' AS INT)").is_err());
}

#[test]
fn composite_keys_and_indexes_are_planned_and_enforced() {
    let mut db = Db::open(tmpdir("composite")).unwrap();
    ok(
        &mut db,
        "CREATE TABLE ev (tenant TEXT, day INT, seq INT, kind TEXT, PRIMARY KEY (tenant, day, seq), UNIQUE (tenant, kind))",
    );
    ok(&mut db, "CREATE INDEX ev_kind_day ON ev (kind, day)");
    for t in ["a", "b"] {
        for day in 1..=5 {
            for seq in 1..=3 {
                db.execute_sql_params(
                    "INSERT INTO ev VALUES (?, ?, ?, ?)",
                    &[
                        Value::Text(t.into()),
                        Value::Int(day),
                        Value::Int(seq),
                        Value::Text(format!("k{day}{seq}")),
                    ],
                )
                .unwrap();
            }
        }
    }
    let plan = |db: &mut Db, sql: &str| ok(db, &format!("EXPLAIN {sql}"));
    assert!(plan(
        &mut db,
        "SELECT * FROM ev WHERE tenant = 'a' AND day = 2 AND seq = 3"
    )
    .contains("PRIMARY KEY (tenant, day, seq)=(a, 2, 3)"));
    assert!(plan(
        &mut db,
        "SELECT * FROM ev WHERE tenant = 'a' AND day BETWEEN 2 AND 3"
    )
    .contains("PRIMARY KEY RANGE"));
    assert!(plan(&mut db, "SELECT * FROM ev WHERE kind = 'k11' AND day = 1").contains("INDEX"));
    assert_eq!(
        q(
            &mut db,
            "SELECT COUNT(*) FROM ev WHERE tenant = 'a' AND day BETWEEN 2 AND 3"
        ),
        ["6"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT seq FROM ev WHERE tenant = 'b' AND day = 4 ORDER BY seq DESC"
        ),
        ["3", "2", "1"]
    );
    assert_eq!(
        q(&mut db, "SELECT COUNT(*) FROM ev WHERE kind = 'k23'"),
        ["2"]
    );
    let dup = db
        .execute_sql("INSERT INTO ev VALUES ('a', 1, 1, 'zz')")
        .unwrap_err();
    assert!(matches!(dup, Error::Constraint(_)), "{dup}");
    let uniq = db
        .execute_sql("INSERT INTO ev VALUES ('a', 9, 9, 'k11')")
        .unwrap_err();
    assert!(uniq.to_string().contains("UNIQUE"), "{uniq}");
    db.verify().unwrap();
}

#[test]
fn joins_right_full_cross_and_hash() {
    let mut db = shop("joins");
    assert!(ok(&mut db, "EXPLAIN SELECT * FROM o JOIN c ON c.id = o.cid").contains("LOOKUP"));
    assert!(ok(&mut db, "EXPLAIN SELECT * FROM c JOIN o ON o.cid = c.id").contains("HASH JOIN"));
    assert_eq!(
        q(
            &mut db,
            "SELECT c.name, o.id FROM c JOIN o ON o.cid = c.id ORDER BY o.id"
        ),
        ["ana|10", "ana|11", "bia|12"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT c.name, o.id FROM c RIGHT JOIN o ON o.cid = c.id ORDER BY o.id"
        ),
        ["ana|10", "ana|11", "bia|12", "NULL|13"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT c.id, o.id FROM c FULL JOIN o ON o.cid = c.id ORDER BY c.id, o.id"
        ),
        ["NULL|13", "1|10", "1|11", "2|12", "3|NULL", "4|NULL"]
    );
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM c CROSS JOIN o"), ["16"]);
    assert_eq!(
        q(&mut db, "SELECT COUNT(*) FROM c, o WHERE c.id = o.cid"),
        ["3"]
    );
}

#[test]
fn insert_select_upsert_params_and_prepared() {
    let mut db = shop("upsert");
    ok(
        &mut db,
        "CREATE TABLE totals (cid INT PRIMARY KEY, total REAL, n INT DEFAULT 1)",
    );
    assert_eq!(
        ok(
            &mut db,
            "INSERT INTO totals (cid, total) SELECT cid, SUM(total) FROM o GROUP BY cid"
        ),
        "INSERT 3"
    );
    assert_eq!(
        ok(
            &mut db,
            "INSERT INTO totals (cid, total) VALUES (1, 5), (7, 70) \
             ON CONFLICT (cid) DO UPDATE SET total = total + excluded.total, n = n + 1"
        ),
        "INSERT 1 UPDATE 1"
    );
    assert_eq!(
        q(&mut db, "SELECT cid, total, n FROM totals ORDER BY cid"),
        ["1|205.0|2", "2|20.0|1", "7|70.0|1", "9|99.0|1"]
    );
    assert_eq!(
        ok(
            &mut db,
            "INSERT INTO totals (cid, total) VALUES (2, 1) ON CONFLICT DO NOTHING"
        ),
        "INSERT 0 UPDATE 0"
    );
    let insert = db
        .prepare("INSERT INTO totals (cid, total) VALUES (?1, ?2)")
        .unwrap();
    assert_eq!(insert.param_count(), 2);
    for i in 100..110 {
        db.execute_prepared(&insert, &[Value::Int(i), Value::Real(i as f64 / 2.0)])
            .unwrap();
    }
    let select = db
        .prepare("SELECT total FROM totals WHERE cid = $1")
        .unwrap();
    assert!(select.is_read_only());
    match db.execute_prepared(&select, &[Value::Int(105)]).unwrap() {
        ExecResult::Table { rows, .. } => assert_eq!(rows[0][0], Value::Real(52.5)),
        other => panic!("{other:?}"),
    }
    // Parâmetros nunca viram SQL: aspas e ponto-e-vírgula são só texto.
    let evil = "x'); DROP TABLE totals; --";
    db.execute_sql_params(
        "INSERT INTO c VALUES (99, ?, ?)",
        &[Value::Text(evil.into()), Value::Null],
    )
    .unwrap();
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM totals"), ["14"]);
    assert!(
        db.execute_prepared(&select, &[]).is_err(),
        "falta parâmetro"
    );
    assert_eq!(
        db.query_params("SELECT name FROM c WHERE id = ?", &[Value::Int(99)])
            .unwrap(),
        ExecResult::Table {
            columns: vec!["name".into()],
            rows: vec![vec![Value::Text(evil.into())]]
        }
    );
    assert!(db.query("DELETE FROM c").is_err(), "query é só leitura");
}

#[test]
fn large_rows_and_long_indexed_text() {
    let mut db = Db::open(tmpdir("bigrows")).unwrap();
    ok(
        &mut db,
        "CREATE TABLE doc (id INT PRIMARY KEY, title TEXT UNIQUE, body TEXT)",
    );
    ok(&mut db, "CREATE INDEX doc_body ON doc (body)");
    let long = |c: char, n: usize| c.to_string().repeat(n);
    // Títulos com 300 bytes iguais no começo: o índice guarda só 256 bytes e
    // mesmo assim distingue os valores.
    let t1 = format!("{}{}", long('t', 300), "fim-1");
    let t2 = format!("{}{}", long('t', 300), "fim-2");
    let body = long('b', 2 << 20);
    for (i, t) in [(1, &t1), (2, &t2)] {
        db.execute_sql_params(
            "INSERT INTO doc VALUES (?, ?, ?)",
            &[
                Value::Int(i),
                Value::Text(t.clone()),
                Value::Text(body.clone()),
            ],
        )
        .unwrap();
    }
    let dup = db.execute_sql_params(
        "INSERT INTO doc VALUES (3, ?, 'x')",
        &[Value::Text(t2.clone())],
    );
    assert!(
        matches!(dup, Err(Error::Constraint(_))),
        "UNIQUE confere o valor inteiro"
    );
    match db
        .execute_sql_params(
            "SELECT id, length(body) FROM doc WHERE title = ?",
            &[Value::Text(t2)],
        )
        .unwrap()
    {
        ExecResult::Table { rows, .. } => {
            assert_eq!(rows, vec![vec![Value::Int(2), Value::Int(2 << 20)]])
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        q(&mut db, "SELECT COUNT(*) FROM doc WHERE body LIKE 'bbb%'"),
        ["2"]
    );
    db.verify().unwrap();
}
