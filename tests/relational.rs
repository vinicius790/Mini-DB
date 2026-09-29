//! SQL relacional: DDL, DML, restrições, planos, JOIN, agregação e durabilidade.
use mini_db::rel::Value;
use mini_db::{Db, Error, ExecResult};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("minidb-rel-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn q(db: &mut Db, sql: &str) -> Vec<Vec<Value>> {
    match db.execute_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}")) {
        ExecResult::Table { rows, .. } => rows,
        other => panic!("{sql}: {other:?}"),
    }
}

fn ok(db: &mut Db, sql: &str) -> String {
    match db.execute_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}")) {
        ExecResult::Ok(s) => s,
        other => panic!("{sql}: {other:?}"),
    }
}

fn text(rows: &[Vec<Value>]) -> Vec<String> {
    rows.iter()
        .map(|r| {
            r.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("|")
        })
        .collect()
}

fn setup(db: &mut Db) {
    ok(db, "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE, age INT, active BOOLEAN DEFAULT TRUE)");
    ok(db, "CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INT NOT NULL, total REAL, status TEXT DEFAULT 'open')");
    ok(db, "CREATE INDEX orders_user ON orders (user_id)");
    ok(db, "INSERT INTO users (name, email, age) VALUES ('ana', 'ana@x', 31), ('bia', 'bia@x', 25), ('caio', NULL, 40), ('duda', 'duda@x', NULL)");
    ok(db, "INSERT INTO orders (user_id, total) VALUES (1, 10.5), (1, 20), (2, 7.25), (3, 100), (3, 1)");
}

#[test]
fn crud_constraints_and_autoincrement() {
    let mut db = Db::open(tmpdir("crud")).unwrap();
    setup(&mut db);
    assert_eq!(
        text(&q(&mut db, "SELECT id, name FROM users ORDER BY id")),
        ["1|ana", "2|bia", "3|caio", "4|duda"]
    );
    for (bad, kind) in [
        (
            "INSERT INTO users (id, name) VALUES (1, 'dup')",
            "duplicada",
        ),
        (
            "INSERT INTO users (name, email) VALUES ('x', 'ana@x')",
            "UNIQUE",
        ),
        ("INSERT INTO users (email) VALUES ('z@x')", "NOT NULL"),
        (
            "INSERT INTO users (name, age) VALUES ('x', 'velho')",
            "incompatível",
        ),
    ] {
        let err = db.execute_sql(bad).unwrap_err();
        assert!(
            matches!(err, Error::Constraint(_)) && err.to_string().contains(kind),
            "{bad}: {err}"
        );
    }
    // Um INSERT de várias linhas é atômico: a duplicata derruba o comando inteiro.
    assert!(db
        .execute_sql("INSERT INTO users (name, email) VALUES ('e', 'e@x'), ('f', 'e@x')")
        .is_err());
    assert_eq!(
        q(&mut db, "SELECT COUNT(*) FROM users")[0][0],
        Value::Int(4)
    );
    assert_eq!(
        ok(
            &mut db,
            "UPDATE users SET age = age + 1 WHERE age IS NOT NULL"
        ),
        "UPDATE 3"
    );
    assert_eq!(
        text(&q(&mut db, "SELECT age FROM users WHERE name = 'ana'")),
        ["32"]
    );
    // Deslocar todas as PKs no mesmo UPDATE não é falso conflito.
    assert_eq!(ok(&mut db, "UPDATE users SET id = id + 1"), "UPDATE 4");
    assert_eq!(
        text(&q(&mut db, "SELECT id FROM users")),
        ["2", "3", "4", "5"]
    );
    assert!(
        db.execute_sql("UPDATE users SET email = 'ana@x'").is_err(),
        "UNIQUE no UPDATE"
    );
    assert_eq!(
        ok(&mut db, "DELETE FROM users WHERE email IS NULL"),
        "DELETE 1"
    );
    ok(&mut db, "INSERT INTO users (name) VALUES ('novo')");
    assert_eq!(
        text(&q(&mut db, "SELECT id FROM users WHERE name = 'novo'")),
        ["6"],
        "autoincremento segue o maior id"
    );
}

#[test]
fn where_like_in_between_null_logic() {
    let mut db = Db::open(tmpdir("where")).unwrap();
    setup(&mut db);
    let names = |db: &mut Db, w: &str| {
        text(&q(
            db,
            &format!("SELECT name FROM users WHERE {w} ORDER BY name"),
        ))
    };
    assert_eq!(names(&mut db, "name LIKE '_i%'"), ["bia"]);
    assert_eq!(names(&mut db, "age BETWEEN 25 AND 31"), ["ana", "bia"]);
    assert_eq!(names(&mut db, "id IN (1, 3, 99)"), ["ana", "caio"]);
    assert_eq!(names(&mut db, "age > 30 OR email IS NULL"), ["ana", "caio"]);
    assert_eq!(
        names(&mut db, "NOT (age > 30)"),
        ["bia"],
        "NULL não entra em NOT"
    );
    assert_eq!(names(&mut db, "age NOT IN (25, 31)"), ["caio"]);
    assert_eq!(
        text(&q(&mut db, "SELECT upper(name) || '!', length(name), coalesce(age, -1) * 2 FROM users WHERE id = 4")),
        ["DUDA!|4|-2"]
    );
}

#[test]
fn planner_uses_primary_key_and_indexes() {
    let mut db = Db::open(tmpdir("plan")).unwrap();
    setup(&mut db);
    let plan = |db: &mut Db, sql: &str| ok(db, &format!("EXPLAIN {sql}"));
    assert!(plan(&mut db, "SELECT * FROM users WHERE id = 2").contains("USING PRIMARY KEY (id=2)"));
    assert!(
        plan(&mut db, "SELECT * FROM users WHERE id >= 2 AND id < 4").contains("PRIMARY KEY RANGE")
    );
    assert!(plan(&mut db, "SELECT * FROM users WHERE email = 'bia@x'")
        .contains("UNIQUE INDEX users_email_key"));
    assert!(plan(&mut db, "SELECT * FROM orders WHERE user_id = 3").contains("INDEX orders_user"));
    assert!(plan(&mut db, "SELECT * FROM users WHERE age = 3").starts_with("SCAN users"));
    let j = plan(
        &mut db,
        "SELECT * FROM orders o JOIN users u ON u.id = o.user_id",
    );
    assert!(j.contains("LOOKUP ON id"), "{j}");
    // O plano nunca muda o resultado: faixa + filtro residual.
    assert_eq!(
        text(&q(
            &mut db,
            "SELECT id FROM users WHERE id > 1 AND id <= 3 AND name <> 'bia'"
        )),
        ["3"]
    );
    assert_eq!(
        text(&q(&mut db, "SELECT id FROM users WHERE 2 < id")),
        ["3", "4"]
    );
    assert_eq!(
        text(&q(
            &mut db,
            "SELECT id FROM orders WHERE user_id = 3.0 ORDER BY id"
        )),
        ["4", "5"]
    );
}

#[test]
fn joins_group_by_having_order_limit() {
    let mut db = Db::open(tmpdir("join")).unwrap();
    setup(&mut db);
    let rows = q(
        &mut db,
        "SELECT u.name, COUNT(o.id) AS n, SUM(o.total) AS spent, AVG(o.total) \
         FROM users u LEFT JOIN orders o ON o.user_id = u.id \
         GROUP BY u.name ORDER BY spent DESC",
    );
    assert_eq!(
        text(&rows),
        [
            "caio|2|101.0|50.5",
            "ana|2|30.5|15.25",
            "bia|1|7.25|7.25",
            "duda|0|NULL|NULL"
        ]
    );
    let inner = q(&mut db, "SELECT u.name, o.total FROM orders o JOIN users u ON u.id = o.user_id WHERE o.total > 9 ORDER BY 2");
    assert_eq!(text(&inner), ["ana|10.5", "ana|20.0", "caio|100.0"]);
    let having = q(&mut db, "SELECT user_id, MAX(total) FROM orders GROUP BY user_id HAVING COUNT(*) > 1 ORDER BY user_id");
    assert_eq!(text(&having), ["1|20.0", "3|100.0"]);
    assert_eq!(
        text(&q(
            &mut db,
            "SELECT COUNT(*), MIN(age), MAX(name) FROM users WHERE id > 100"
        )),
        ["0|NULL|NULL"]
    );
    assert_eq!(
        text(&q(
            &mut db,
            "SELECT DISTINCT user_id FROM orders ORDER BY user_id DESC LIMIT 2 OFFSET 1"
        )),
        ["2", "1"]
    );
    assert_eq!(
        text(&q(&mut db, "SELECT COUNT(DISTINCT user_id) FROM orders")),
        ["3"]
    );
    assert_eq!(
        text(&q(&mut db, "SELECT name FROM users LIMIT 2")),
        ["ana", "bia"]
    );
    assert!(db
        .execute_sql("SELECT name FROM users WHERE COUNT(*) > 1")
        .is_err());
    assert!(
        db.execute_sql("SELECT id FROM users u JOIN orders o ON o.user_id = u.id")
            .is_err(),
        "id ambíguo"
    );
}

#[test]
fn ddl_alter_drop_and_catalog() {
    let mut db = Db::open(tmpdir("ddl")).unwrap();
    setup(&mut db);
    ok(
        &mut db,
        "ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'",
    );
    assert_eq!(
        text(&q(&mut db, "SELECT plan FROM users WHERE id = 1")),
        ["free"]
    );
    ok(
        &mut db,
        "INSERT INTO users (name, plan) VALUES ('eva', 'pro')",
    );
    assert_eq!(
        q(&mut db, "SELECT COUNT(*) FROM users WHERE plan = 'pro'")[0][0],
        Value::Int(1)
    );
    assert_eq!(
        text(&q(&mut db, "SHOW TABLES")),
        ["orders|4|1", "users|6|1"]
    );
    assert!(text(&q(&mut db, "DESCRIBE users"))[0].starts_with("id|INTEGER|true|true"));
    assert!(db.execute_sql("CREATE TABLE users (id INT)").is_err());
    ok(&mut db, "CREATE TABLE IF NOT EXISTS users (id INT)");
    assert!(
        db.execute_sql("CREATE UNIQUE INDEX dup ON orders (user_id)")
            .is_err(),
        "valores repetidos"
    );
    ok(&mut db, "DROP INDEX orders_user");
    assert!(ok(&mut db, "EXPLAIN SELECT * FROM orders WHERE user_id = 1").starts_with("SCAN"));
    ok(&mut db, "DROP TABLE orders");
    assert!(matches!(
        db.execute_sql("SELECT * FROM orders"),
        Err(Error::UnknownTable(_))
    ));
    // Sem PRIMARY KEY: rowid oculto.
    ok(&mut db, "CREATE TABLE log (msg TEXT)");
    ok(&mut db, "INSERT INTO log VALUES ('a'), ('b')");
    assert_eq!(text(&q(&mut db, "SELECT * FROM log")), ["a", "b"]);
    // As tabelas não vazam para a API chave-valor.
    assert_eq!(db.count(b"\0", None).unwrap(), 0);
    assert!(db.put(&[0xFF, b'x'], b"v").is_err());
    db.verify().unwrap();
}

#[test]
fn survives_crash_vacuum_and_coexists_with_kv_sql() {
    let dir = tmpdir("durable");
    let mut db = Db::open(&dir).unwrap();
    setup(&mut db);
    db.put(b"k", b"v").unwrap();
    db.execute_sql("BEGIN").unwrap();
    ok(&mut db, "INSERT INTO users (name) VALUES ('txn')");
    assert_eq!(
        q(&mut db, "SELECT COUNT(*) FROM users")[0][0],
        Value::Int(5),
        "lê o próprio write-set"
    );
    db.execute_sql("ROLLBACK").unwrap();
    db.drop_without_checkpoint();
    let mut db = Db::open(&dir).unwrap();
    assert_eq!(
        q(&mut db, "SELECT COUNT(*) FROM users")[0][0],
        Value::Int(4)
    );
    db.vacuum().unwrap();
    assert_eq!(
        text(&q(&mut db, "SELECT name FROM users WHERE email = 'bia@x'")),
        ["bia"]
    );
    assert_eq!(
        db.execute_sql("SELECT COUNT(*) FROM kv").unwrap(),
        ExecResult::Count(1)
    );
    assert!(db.execute_sql("SELECT * FROM kv WHERE value > 1").is_err());
    db.verify().unwrap();
}
