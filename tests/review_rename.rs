//! `ALTER TABLE ... RENAME`: GRANTs acompanham a tabela; views e gatilhos (guardados
//! como texto SQL) recusam o rename em vez de ficarem apontando para o nome antigo.

use mini_db::{Db, ExecResult};

/// Sufixo único por processo: só pid + relógio colide entre testes paralelos.
static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmpdir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-test-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn ok(db: &mut Db, sql: &str) {
    match db.execute_sql(sql) {
        Ok(ExecResult::Ok(_)) => {}
        other => panic!("{sql}: {other:?}"),
    }
}

fn err(db: &mut Db, sql: &str) -> String {
    match db.execute_sql(sql) {
        Err(e) => e.to_string(),
        Ok(r) => panic!("{sql} devia falhar, devolveu {r:?}"),
    }
}

fn rows(db: &mut Db, sql: &str) -> Vec<String> {
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

fn open() -> Db {
    let mut db = Db::open(tmpdir().as_path()).unwrap();
    ok(&mut db, "CREATE TABLE jogo (id INT PRIMARY KEY, name TEXT)");
    ok(&mut db, "INSERT INTO jogo VALUES (1, 'a')");
    db
}

#[test]
fn rename_without_dependents_works() {
    let mut db = open();
    ok(&mut db, "ALTER TABLE jogo RENAME COLUMN name TO nome");
    ok(&mut db, "ALTER TABLE jogo RENAME TO jogo2");
    assert_eq!(rows(&mut db, "SELECT nome FROM jogo2"), ["a"]);
}

#[test]
fn rename_migrates_grants() {
    let mut db = open();
    // O primeiro usuário precisa ser superusuário.
    ok(&mut db, "CREATE USER root PASSWORD 'r' SUPERUSER");
    ok(&mut db, "CREATE USER ana PASSWORD 'x'");
    ok(&mut db, "GRANT SELECT, INSERT ON jogo TO ana");
    ok(&mut db, "ALTER TABLE jogo RENAME TO jogo2");
    let grants = rows(&mut db, "SHOW GRANTS FOR ana");
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert!(grants[0].starts_with("ana|jogo2|"), "{grants:?}");
    assert!(grants[0].contains("SELECT") && grants[0].contains("INSERT"));
    // Um GRANT órfão no nome novo (de uma tabela apagada) não vale para a tabela renomeada.
    ok(&mut db, "CREATE TABLE velha (id INT PRIMARY KEY)");
    ok(&mut db, "GRANT DELETE ON velha TO ana");
    ok(&mut db, "DROP TABLE velha");
    ok(&mut db, "CREATE TABLE nova (id INT PRIMARY KEY)");
    ok(&mut db, "ALTER TABLE nova RENAME TO velha");
    let grants = rows(&mut db, "SHOW GRANTS FOR ana");
    assert!(!grants.iter().any(|g| g.contains("DELETE")), "{grants:?}");
}

#[test]
fn rename_table_is_refused_while_a_view_uses_it() {
    let mut db = open();
    ok(&mut db, "CREATE VIEW v AS SELECT id, name FROM jogo");
    let e = err(&mut db, "ALTER TABLE jogo RENAME TO jogo2");
    assert!(e.contains("é usada pela view v"), "{e}");
    // Nada mudou: a view ainda funciona.
    assert_eq!(rows(&mut db, "SELECT name FROM v"), ["a"]);
    ok(&mut db, "DROP VIEW v");
    ok(&mut db, "ALTER TABLE jogo RENAME TO jogo2");
    ok(&mut db, "CREATE VIEW v AS SELECT id, name FROM jogo2");
    assert_eq!(rows(&mut db, "SELECT name FROM v"), ["a"]);
}

#[test]
fn rename_column_is_refused_only_when_a_view_names_it() {
    let mut db = open();
    ok(&mut db, "CREATE VIEW vid AS SELECT id FROM jogo");
    ok(&mut db, "CREATE VIEW vname AS SELECT name FROM jogo");
    let e = err(&mut db, "ALTER TABLE jogo RENAME COLUMN name TO nome");
    assert!(e.contains("é usada pela view vname"), "{e}");
    ok(&mut db, "DROP VIEW vname");
    ok(&mut db, "ALTER TABLE jogo RENAME COLUMN name TO nome");
    assert_eq!(rows(&mut db, "SELECT id FROM vid"), ["1"]);
}

#[test]
fn rename_is_refused_while_a_trigger_uses_it() {
    let mut db = open();
    ok(&mut db, "CREATE TABLE audit (n INT)");
    ok(
        &mut db,
        "CREATE TRIGGER tg AFTER INSERT ON jogo BEGIN INSERT INTO audit (n) VALUES (NEW.id); END",
    );
    // A tabela do corpo do gatilho e a coluna que ele lê não podem mudar de nome.
    let e = err(&mut db, "ALTER TABLE audit RENAME TO audit2");
    assert!(e.contains("é usada pelo gatilho tg"), "{e}");
    let e = err(&mut db, "ALTER TABLE jogo RENAME COLUMN id TO codigo");
    assert!(e.contains("jogo.id é usada pelo gatilho tg"), "{e}");
    // A tabela do gatilho e uma coluna que ele não menciona podem.
    ok(&mut db, "ALTER TABLE jogo RENAME COLUMN name TO nome");
    ok(&mut db, "ALTER TABLE jogo RENAME TO jogo2");
    ok(&mut db, "INSERT INTO jogo2 VALUES (2, 'b')");
    assert_eq!(rows(&mut db, "SELECT n FROM audit"), ["2"]);
}
