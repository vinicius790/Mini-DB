//! 0.8: otimizador (ANALYZE, custo, ordem por índice, top-N, EXPLAIN ANALYZE),
//! gatilhos, views materializadas, NOTIFY/LISTEN e stream de mudanças.
use mini_db::events::ChangeKind;
use mini_db::mvcc::SharedDb;
use mini_db::{Db, ExecResult};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("minidb-sql08-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn rows_of(res: ExecResult) -> Vec<String> {
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
        other => panic!("{other:?}"),
    }
}

fn q(db: &mut Db, sql: &str) -> Vec<String> {
    rows_of(db.execute_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}")))
}

fn ok(db: &mut Db, sql: &str) -> String {
    match db.execute_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}")) {
        ExecResult::Ok(s) => s,
        ExecResult::Batch(_) => String::new(),
        other => panic!("{sql}: {other:?}"),
    }
}

fn err(db: &mut Db, sql: &str) -> String {
    match db.execute_sql(sql) {
        Err(e) => e.to_string(),
        Ok(r) => panic!("{sql} devia falhar, devolveu {r:?}"),
    }
}

fn big(tag: &str) -> Db {
    let mut db = Db::open(tmpdir(tag)).unwrap();
    ok(
        &mut db,
        "CREATE TABLE ev (id INT PRIMARY KEY, kind INT, user INT, v INT)",
    );
    ok(&mut db, "CREATE INDEX ev_kind ON ev (kind)");
    ok(&mut db, "CREATE INDEX ev_user ON ev (user)");
    let mut sql = String::from("INSERT INTO ev VALUES ");
    for i in 0..2000 {
        if i > 0 {
            sql.push(',');
        }
        sql.push_str(&format!(
            "({i}, {}, {}, {})",
            i % 3,
            i % 500,
            (i * 7919) % 1000
        ));
    }
    ok(&mut db, &sql);
    db
}

#[test]
fn analyze_drives_index_choice_and_explain_analyze_measures() {
    let mut db = big("stats");
    // Sem estatísticas os dois índices empatam (uma coluna de igualdade cada).
    ok(&mut db, "ANALYZE ev");
    let plan = ok(
        &mut db,
        "EXPLAIN SELECT * FROM ev WHERE kind = 1 AND user = 7",
    );
    assert!(plan.contains("INDEX ev_user"), "{plan}");
    assert!(plan.contains("est. rows≈4"), "{plan}");
    let plan = ok(&mut db, "EXPLAIN SELECT * FROM ev WHERE kind = 1");
    assert!(
        plan.contains("INDEX ev_kind") && plan.contains("est. rows≈667"),
        "{plan}"
    );
    // Faixa na PK estimada pelo min/max.
    let plan = ok(
        &mut db,
        "EXPLAIN SELECT * FROM ev WHERE id BETWEEN 100 AND 199 AND kind = 2",
    );
    assert!(plan.contains("PRIMARY KEY RANGE"), "{plan}");
    let plan = ok(
        &mut db,
        "EXPLAIN ANALYZE SELECT * FROM ev WHERE kind = 1 AND user = 7",
    );
    assert!(
        plan.contains("rows_read=4") && plan.contains("TOTAL rows=2"),
        "{plan}"
    );
    assert!(plan.contains("time="));
    // Estatísticas sobrevivem a RENAME e somem em DROP COLUMN.
    ok(&mut db, "ALTER TABLE ev RENAME TO events");
    assert!(ok(&mut db, "EXPLAIN SELECT * FROM events WHERE kind = 1").contains("est. rows"));
    ok(&mut db, "ALTER TABLE events DROP COLUMN v");
    assert!(!ok(&mut db, "EXPLAIN SELECT * FROM events WHERE kind = 1").contains("est. rows"));
}

#[test]
fn order_by_uses_access_order_and_top_n() {
    let mut db = big("order");
    let plan = ok(
        &mut db,
        "EXPLAIN ANALYZE SELECT id FROM ev ORDER BY id LIMIT 3",
    );
    assert!(
        plan.contains("rows_read=3") && plan.contains("no sort"),
        "{plan}"
    );
    assert_eq!(
        q(&mut db, "SELECT id FROM ev ORDER BY id LIMIT 3"),
        ["0", "1", "2"]
    );
    assert_eq!(
        q(&mut db, "SELECT id FROM ev ORDER BY id DESC LIMIT 2"),
        ["1999", "1998"]
    );
    // Índice simples entrega (kind, id); um composto (kind, user) entrega
    // (user, id) e é preferido quando a consulta pede essa ordem.
    let plan = ok(
        &mut db,
        "EXPLAIN ANALYZE SELECT id FROM ev WHERE kind = 0 ORDER BY id LIMIT 2",
    );
    assert!(
        plan.contains("INDEX ev_kind") && plan.contains("no sort") && plan.contains("rows_read=2"),
        "{plan}"
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM ev WHERE kind = 0 ORDER BY id LIMIT 2"
        ),
        ["0", "3"]
    );
    ok(&mut db, "CREATE INDEX ev_ku ON ev (kind, user)");
    let plan = ok(
        &mut db,
        "EXPLAIN ANALYZE SELECT id FROM ev WHERE kind = 0 ORDER BY user, id LIMIT 2",
    );
    assert!(
        plan.contains("INDEX ev_ku") && plan.contains("no sort"),
        "{plan}"
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM ev WHERE kind = 0 ORDER BY user, id LIMIT 2"
        ),
        ["0", "1500"]
    );
    ok(&mut db, "ANALYZE ev");
    let plan = ok(
        &mut db,
        "EXPLAIN SELECT id FROM ev WHERE kind = 0 ORDER BY user DESC, id DESC",
    );
    assert!(plan.contains("INDEX ev_ku"), "{plan}");
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM ev WHERE kind = 0 ORDER BY user DESC, id DESC LIMIT 2"
        ),
        ["999", "1998"]
    );
    // Top-N sem índice.
    let plan = ok(
        &mut db,
        "EXPLAIN ANALYZE SELECT id, v FROM ev ORDER BY v, id LIMIT 3",
    );
    assert!(plan.contains("TOP-N"), "{plan}");
    assert_eq!(
        q(&mut db, "SELECT v FROM ev ORDER BY v, id LIMIT 3"),
        ["0", "0", "1"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT v FROM ev ORDER BY v DESC, id LIMIT 2 OFFSET 1"
        ),
        ["999", "998"]
    );
    // Com filtro que não usa a ordem, o resultado continua correto.
    assert_eq!(
        q(
            &mut db,
            "SELECT id FROM ev WHERE v > 990 ORDER BY id LIMIT 2"
        ),
        ["247", "284"]
    );
}

#[test]
fn join_switches_to_hash_when_outer_is_large() {
    let mut db = big("join");
    ok(
        &mut db,
        "CREATE TABLE kinds (kind INT PRIMARY KEY, name TEXT)",
    );
    ok(
        &mut db,
        "INSERT INTO kinds VALUES (0, 'a'), (1, 'b'), (2, 'c')",
    );
    let before = ok(
        &mut db,
        "EXPLAIN ANALYZE SELECT k.name FROM ev e JOIN kinds k ON k.kind = e.kind",
    );
    assert!(before.contains("USING LOOKUP"), "{before}");
    ok(&mut db, "ANALYZE");
    let after = ok(
        &mut db,
        "EXPLAIN ANALYZE SELECT k.name FROM ev e JOIN kinds k ON k.kind = e.kind",
    );
    assert!(
        after.contains("USING HASH") && after.contains("rows_out=2000"),
        "{after}"
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT COUNT(*) FROM ev e JOIN kinds k ON k.kind = e.kind WHERE k.name = 'b'"
        ),
        ["667"]
    );
}

#[test]
fn triggers_before_after_when_and_raise() {
    let dir = tmpdir("trig");
    let mut db = Db::open(&dir).unwrap();
    ok(
        &mut db,
        "CREATE TABLE acc (id SERIAL PRIMARY KEY, owner TEXT, saldo INT)",
    );
    ok(&mut db, "CREATE TABLE audit (id SERIAL PRIMARY KEY, what TEXT, acc INT, delta INT, at TEXT DEFAULT now())");
    ok(&mut db, "CREATE TRIGGER no_negative BEFORE INSERT ON acc WHEN (NEW.saldo < 0) BEGIN SELECT RAISE(ABORT, 'saldo negativo'); END");
    ok(&mut db, "CREATE TRIGGER skip_test BEFORE INSERT ON acc WHEN NEW.owner = 'teste' BEGIN SELECT RAISE(IGNORE); END");
    ok(&mut db, "CREATE TRIGGER log_ins AFTER INSERT ON acc BEGIN INSERT INTO audit (what, acc, delta) VALUES ('ins', NEW.id, NEW.saldo); END");
    ok(&mut db, "CREATE TRIGGER log_upd AFTER UPDATE OF saldo ON acc WHEN OLD.saldo <> NEW.saldo BEGIN INSERT INTO audit (what, acc, delta) VALUES ('upd', NEW.id, NEW.saldo - OLD.saldo); END");
    ok(&mut db, "CREATE TRIGGER log_del AFTER DELETE ON acc BEGIN INSERT INTO audit (what, acc, delta) VALUES ('del', OLD.id, -OLD.saldo); END");
    assert!(
        err(&mut db, "INSERT INTO acc (owner, saldo) VALUES ('ana', -5)")
            .contains("saldo negativo")
    );
    assert_eq!(
        ok(
            &mut db,
            "INSERT INTO acc (owner, saldo) VALUES ('ana', 10), ('teste', 1), ('bia', 20)"
        ),
        "INSERT 2"
    );
    assert_eq!(
        q(&mut db, "SELECT owner FROM acc ORDER BY id"),
        ["ana", "bia"]
    );
    ok(
        &mut db,
        "UPDATE acc SET saldo = saldo + 5 WHERE owner = 'ana'",
    );
    ok(&mut db, "UPDATE acc SET owner = 'BIA' WHERE owner = 'bia'"); // não muda saldo: sem log
    ok(&mut db, "DELETE FROM acc WHERE owner = 'BIA'");
    assert_eq!(
        q(&mut db, "SELECT what, acc, delta FROM audit ORDER BY id"),
        ["ins|1|10", "ins|2|20", "upd|1|5", "del|2|-20"]
    );
    assert_eq!(
        q(&mut db, "SELECT COUNT(*) FROM audit WHERE length(at) = 19"),
        ["4"]
    );
    // Gatilho que dispara a si mesmo é interrompido pelo limite de profundidade.
    ok(&mut db, "CREATE TABLE loop (n INT)");
    ok(
        &mut db,
        "CREATE TRIGGER again AFTER INSERT ON loop BEGIN INSERT INTO loop VALUES (NEW.n + 1); END",
    );
    assert!(err(&mut db, "INSERT INTO loop VALUES (1)").contains("aninhados"));
    assert_eq!(q(&mut db, "SELECT COUNT(*) FROM loop"), ["0"]);
    // Cascata dispara gatilhos das filhas; catálogo e DDL.
    ok(
        &mut db,
        "CREATE TABLE child (id INT PRIMARY KEY, acc INT REFERENCES acc ON DELETE CASCADE)",
    );
    ok(&mut db, "CREATE TRIGGER child_gone AFTER DELETE ON child BEGIN INSERT INTO audit (what, acc, delta) VALUES ('child', OLD.acc, 0); END");
    ok(&mut db, "INSERT INTO child VALUES (1, 1)");
    ok(&mut db, "DELETE FROM acc WHERE id = 1");
    assert_eq!(
        q(
            &mut db,
            "SELECT what FROM audit WHERE what IN ('child', 'del') ORDER BY id"
        ),
        ["del", "del", "child"]
    );
    let shown = q(&mut db, "SHOW TRIGGERS FROM acc");
    assert_eq!(shown.len(), 5);
    assert!(shown[0].starts_with("no_negative|acc|BEFORE|INSERT|NEW.saldo < 0|1"));
    let ddl = q(&mut db, "SHOW CREATE TABLE acc")[0].clone();
    assert!(ddl.contains("CREATE TRIGGER log_upd AFTER UPDATE OF saldo ON acc WHEN (OLD.saldo <> NEW.saldo) BEGIN"), "{ddl}");
    assert!(err(&mut db, "CREATE TRIGGER x AFTER INSERT ON acc BEGIN INSERT INTO audit (what) VALUES (NEW.nada); END").contains("coluna desconhecida"));
    assert!(err(&mut db, "CREATE TRIGGER x AFTER INSERT ON acc BEGIN INSERT INTO audit (what) VALUES (OLD.owner); END").contains("OLD.owner"));
    ok(&mut db, "DROP TRIGGER log_ins");
    assert_eq!(q(&mut db, "SHOW TRIGGERS FROM acc").len(), 4);
    assert!(err(&mut db, "DROP TRIGGER log_ins").contains("não existe"));
    ok(&mut db, "DROP TRIGGER IF EXISTS log_ins");
    assert!(ok(&mut db, "EXPLAIN DELETE FROM acc WHERE id = 9").contains("TRIGGERS"));
    // Reabertura preserva os gatilhos.
    db.close().unwrap();
    drop(db);
    let mut db = Db::open(&dir).unwrap();
    assert!(
        err(&mut db, "INSERT INTO acc (owner, saldo) VALUES ('x', -1)").contains("saldo negativo")
    );
}

#[test]
fn materialized_views_manual_and_auto() {
    let mut db = Db::open(tmpdir("mv")).unwrap();
    ok(
        &mut db,
        "CREATE TABLE sales (id SERIAL PRIMARY KEY, region TEXT, amount REAL)",
    );
    ok(
        &mut db,
        "INSERT INTO sales (region, amount) VALUES ('n', 10), ('n', 5), ('s', 7)",
    );
    assert_eq!(
        ok(&mut db, "CREATE MATERIALIZED VIEW by_region AS SELECT region, SUM(amount) AS total, COUNT(*) AS n FROM sales GROUP BY region"),
        "CREATE MATERIALIZED VIEW by_region rows=2"
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT region, total, n FROM by_region ORDER BY region"
        ),
        ["n|15.0|2", "s|7.0|1"]
    );
    ok(
        &mut db,
        "INSERT INTO sales (region, amount) VALUES ('s', 1)",
    );
    assert_eq!(
        q(&mut db, "SELECT total FROM by_region WHERE region = 's'"),
        ["7.0"]
    );
    assert_eq!(
        ok(&mut db, "REFRESH MATERIALIZED VIEW by_region"),
        "REFRESH MATERIALIZED VIEW by_region rows=2"
    );
    assert_eq!(
        q(&mut db, "SELECT total FROM by_region WHERE region = 's'"),
        ["8.0"]
    );
    assert!(err(&mut db, "INSERT INTO by_region VALUES ('x', 1, 1)").contains("REFRESH"));
    assert!(err(&mut db, "DROP TABLE by_region").contains("DROP MATERIALIZED VIEW"));
    ok(&mut db, "CREATE MATERIALIZED VIEW live WITH AUTO REFRESH AS SELECT COUNT(*) AS n, MAX(amount) AS top FROM sales");
    assert_eq!(q(&mut db, "SELECT n, top FROM live"), ["4|10.0"]);
    ok(
        &mut db,
        "INSERT INTO sales (region, amount) VALUES ('n', 99)",
    );
    assert_eq!(q(&mut db, "SELECT n, top FROM live"), ["5|99.0"]);
    ok(&mut db, "DELETE FROM sales WHERE amount = 99");
    assert_eq!(q(&mut db, "SELECT n, top FROM live"), ["4|10.0"]);
    assert!(q(&mut db, "SHOW TABLES")
        .iter()
        .any(|r| r.starts_with("live|materialized view")));
    assert!(
        q(&mut db, "SHOW CREATE TABLE live")[0].contains("WITH AUTO REFRESH AS SELECT COUNT(*)")
    );
    // Em transação, o refresh automático entra no mesmo lote.
    ok(&mut db, "BEGIN");
    ok(
        &mut db,
        "INSERT INTO sales (region, amount) VALUES ('s', 3)",
    );
    assert_eq!(q(&mut db, "SELECT n FROM live"), ["5"]);
    ok(&mut db, "ROLLBACK");
    assert_eq!(q(&mut db, "SELECT n FROM live"), ["4"]);
    ok(&mut db, "DROP MATERIALIZED VIEW live");
    ok(&mut db, "DROP MATERIALIZED VIEW IF EXISTS live");
    assert!(err(&mut db, "SELECT * FROM live").contains("live"));
    ok(&mut db, "CREATE OR REPLACE MATERIALIZED VIEW by_region (r, t, c) AS SELECT region, SUM(amount), COUNT(*) FROM sales GROUP BY region");
    assert_eq!(
        q(&mut db, "SELECT r, c FROM by_region ORDER BY r"),
        ["n|2", "s|2"]
    );
}

#[test]
fn notify_listen_and_change_stream() {
    let db = SharedDb::new(Db::open(tmpdir("events")).unwrap());
    db.sql("CREATE TABLE t8 (id INT PRIMARY KEY, v TEXT)")
        .unwrap();
    let bus = db.events();
    let start = bus.head_lsn();
    let mut a = db.session();
    let mut b = db.session();
    a.execute("LISTEN jogo").unwrap();
    assert_eq!(a.channels(), ["jogo"]);
    // Dentro de transação, a notificação só sai no COMMIT.
    b.execute("BEGIN; INSERT INTO t8 VALUES (1, 'a'); NOTIFY jogo, 'inserido ' || (SELECT COUNT(*) FROM t8)").unwrap();
    assert!(a.notifications(Duration::from_millis(50)).is_empty());
    b.execute("COMMIT").unwrap();
    let got = a.notifications(Duration::from_secs(2));
    assert_eq!(got.len(), 1);
    assert_eq!(
        (got[0].channel.as_str(), got[0].payload.as_str()),
        ("jogo", "inserido 1")
    );
    // ROLLBACK descarta a notificação; canal não escutado não chega.
    b.execute("BEGIN; NOTIFY jogo, 'nunca'; ROLLBACK").unwrap();
    b.execute("NOTIFY outro, 'x'").unwrap();
    assert!(a.notifications(Duration::from_millis(50)).is_empty());
    db.sql("NOTIFY jogo, 'direto'").unwrap();
    assert_eq!(a.notifications(Duration::from_secs(2))[0].payload, "direto");
    a.execute("UNLISTEN jogo").unwrap();
    db.sql("NOTIFY jogo, 'perdido'").unwrap();
    assert!(a.notifications(Duration::from_millis(50)).is_empty());
    // Stream de mudanças com old/new.
    db.sql("UPDATE t8 SET v = 'b' WHERE id = 1; DELETE FROM t8 WHERE id = 1")
        .unwrap();
    let changes = bus.changes_since(start, 100, Duration::ZERO).unwrap();
    let kinds: Vec<ChangeKind> = changes.iter().map(|c| c.kind).collect();
    assert_eq!(
        kinds,
        [ChangeKind::Insert, ChangeKind::Update, ChangeKind::Delete]
    );
    assert_eq!(changes[1].old.as_ref().unwrap()[1].to_string(), "a");
    assert_eq!(changes[1].new.as_ref().unwrap()[1].to_string(), "b");
    assert!(changes[2].new.is_none() && changes[0].old.is_none());
    assert!(changes[0].lsn <= changes[1].lsn);
    assert_eq!(changes[0].columns, ["id", "v"]);
    // Gatilho e cascata geram eventos também; a capacidade limita o anel.
    bus.set_capacity(2);
    db.sql("INSERT INTO t8 VALUES (2, 'x'), (3, 'y'), (4, 'z')")
        .unwrap();
    assert!(matches!(
        bus.changes_since(start, 100, Duration::ZERO),
        Err(mini_db::events::ChangeError::TooOld { .. })
    ));
    let head = bus.head_lsn();
    let waiter = {
        let db = db.clone();
        thread::spawn(move || db.events().changes_since(head, 10, Duration::from_secs(5)))
    };
    thread::sleep(Duration::from_millis(30));
    db.sql("INSERT INTO t8 VALUES (5, 'w')").unwrap();
    let got = waiter.join().unwrap().unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].new.as_ref().unwrap()[0].to_string(), "5");
    drop((a, b));
    db.write().unwrap().close().unwrap();
}

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

fn connect(addr: &str) -> TcpStream {
    let start = Instant::now();
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => return s,
            Err(_) if start.elapsed() < Duration::from_secs(5) => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(e) => panic!("{e}"),
        }
    }
}

#[test]
fn tcp_listen_wait_and_http_streams() {
    let db = SharedDb::new(Db::open(tmpdir("tcp-events")).unwrap());
    db.sql("CREATE TABLE t9 (id INT PRIMARY KEY, v TEXT)")
        .unwrap();
    let tcp = free_addr();
    let http = free_addr();
    {
        let (db, addr) = (db.clone(), tcp.clone());
        thread::spawn(move || mini_db::server::serve(db, &addr));
    }
    {
        let (db, addr) = (db.clone(), http.clone());
        let metrics = std::sync::Arc::new(mini_db::Metrics::new());
        thread::spawn(move || mini_db::http::serve_http(db, metrics, &addr));
    }
    let open = |addr: &str| {
        let stream = connect(addr);
        let out = stream.try_clone().unwrap();
        let mut lines = BufReader::new(stream).lines();
        lines.next().unwrap().unwrap();
        (out, lines)
    };
    let (mut o1, mut l1) = open(&tcp);
    let (mut o2, mut l2) = open(&tcp);
    let ask = |out: &mut TcpStream, lines: &mut std::io::Lines<BufReader<TcpStream>>, cmd: &str| {
        writeln!(out, "{cmd}").unwrap();
        lines.next().unwrap().unwrap()
    };
    assert_eq!(ask(&mut o1, &mut l1, "LISTEN partida"), "OK LISTEN partida");
    assert_eq!(ask(&mut o1, &mut l1, "WAIT 1"), "(timeout)");
    assert_eq!(
        ask(&mut o2, &mut l2, "NOTIFY partida, 'p1 entrou'"),
        "OK NOTIFY partida"
    );
    assert_eq!(ask(&mut o1, &mut l1, "WAIT 5"), "NOTIFY partida p1 entrou");
    // Notificações também vêm anexadas à próxima resposta.
    assert_eq!(
        ask(&mut o2, &mut l2, "NOTIFY partida, 'p2'"),
        "OK NOTIFY partida"
    );
    thread::sleep(Duration::from_millis(50));
    assert!(ask(&mut o1, &mut l1, "INSERT INTO t9 VALUES (1, 'a')").starts_with("OK INSERT 1"));
    assert_eq!(l1.next().unwrap().unwrap(), "NOTIFY partida p2");
    // HTTP: mudanças em JSON (once) e SSE.
    let head = db.events().head_lsn();
    db.sql("INSERT INTO t9 VALUES (2, 'b')").unwrap();
    let mut s = connect(&http);
    write!(
        s,
        "GET /v1/changes?since={head}&once=1 HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    .unwrap();
    let mut body = String::new();
    s.read_to_string(&mut body).unwrap();
    assert!(
        body.contains("\"kind\":\"insert\"") && body.contains("\"new\":{\"id\":2,\"v\":\"b\"}"),
        "{body}"
    );
    let mut sse = connect(&http);
    write!(
        sse,
        "GET /v1/listen?channel=partida&timeout=10 HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    .unwrap();
    sse.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    thread::sleep(Duration::from_millis(100));
    db.sql("NOTIFY partida, 'via http'").unwrap();
    let mut reader = BufReader::new(sse);
    let mut seen = String::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !seen.contains("via http") && Instant::now() < deadline {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        seen.push_str(&line);
    }
    assert!(
        seen.contains("text/event-stream")
            && seen.contains("event: notify")
            && seen.contains("via http"),
        "{seen}"
    );
    let mut sse2 = connect(&http);
    write!(
        sse2,
        "GET /v1/changes?since={head}&table=t9&timeout=5 HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    .unwrap();
    sse2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader = BufReader::new(sse2);
    let mut seen = String::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !seen.contains("\"table\":\"t9\"") && Instant::now() < deadline {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        seen.push_str(&line);
    }
    assert!(
        seen.contains("event: change") && seen.contains("\"table\":\"t9\""),
        "{seen}"
    );
    drop((o1, o2, l1, l2));
}
