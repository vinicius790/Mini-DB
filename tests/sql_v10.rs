//! 1.0: usuários/papéis/GRANT, autenticação (TCP, HTTP, PostgreSQL SCRAM),
//! protocolo PostgreSQL, criptografia em repouso, backup incremental e PITR.
use mini_db::auth::Privilege;
use mini_db::backup::{self, RestoreTarget};
use mini_db::config::NetOptions;
use mini_db::crypto;
use mini_db::mvcc::SharedDb;
use mini_db::pubkey::{KeyAlgo, PrivateKey};
use mini_db::{Db, Error, ExecResult};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("minidb-sql10-{tag}-{}", std::process::id()));
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

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

fn connect(addr: &str) -> TcpStream {
    let start = Instant::now();
    loop {
        if let Ok(s) = TcpStream::connect(addr) {
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            return s;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "servidor não subiu"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn users_db(tag: &str) -> Db {
    let mut db = Db::open(tmpdir(tag)).unwrap();
    ok(
        &mut db,
        "CREATE TABLE jogos (id INT PRIMARY KEY, nome TEXT, preco REAL)",
    );
    ok(
        &mut db,
        "CREATE TABLE segredos (id INT PRIMARY KEY, valor TEXT)",
    );
    ok(
        &mut db,
        "INSERT INTO jogos VALUES (1, 'Nebula', 59.9), (2, 'Ruínas', 29.9)",
    );
    ok(&mut db, "INSERT INTO segredos VALUES (1, 'chave-api')");
    db
}

#[test]
fn users_roles_and_grants_govern_sessions() {
    let mut db = users_db("users");
    assert!(matches!(
        db.execute_sql("CREATE USER ana PASSWORD 'x'"),
        Err(Error::Sql(m)) if m.contains("SUPERUSER")
    ));
    ok(&mut db, "CREATE USER root PASSWORD 'r00t' SUPERUSER");
    ok(&mut db, "CREATE USER ana WITH PASSWORD 'ana123'");
    ok(&mut db, "CREATE ROLE leitores");
    ok(&mut db, "GRANT SELECT ON jogos TO leitores");
    ok(&mut db, "GRANT leitores TO ana");
    ok(&mut db, "GRANT INSERT, UPDATE ON TABLE jogos TO ana");
    assert_eq!(
        q(&mut db, "SHOW USERS"),
        [
            "ana|user|false|leitores",
            "leitores|role|false|",
            "root|user|true|"
        ]
    );
    let grants = q(&mut db, "SHOW GRANTS FOR ana");
    assert!(
        grants.contains(&"ana|jogos|INSERT, UPDATE|direct".to_string()),
        "{grants:?}"
    );
    assert!(
        grants.contains(&"ana|leitores|MEMBER|role".to_string()),
        "{grants:?}"
    );

    let shared = SharedDb::new(db);
    let mut s = shared.session();
    assert!(s.login("ana", "errada").is_err());
    assert!(s.login("ninguem", "x").is_err());
    s.login("ana", "ana123").unwrap();
    assert_eq!(
        rows_of(s.execute("SELECT count(*) FROM jogos").unwrap()),
        ["2"]
    );
    s.execute("INSERT INTO jogos VALUES (3, 'Órbita', 9.9)")
        .unwrap();
    s.execute("UPDATE jogos SET preco = 8.9 WHERE id = 3")
        .unwrap();
    let denied = |s: &mut mini_db::mvcc::Session, sql: &str| match s.execute(sql) {
        Err(Error::Forbidden(m)) => m,
        other => panic!("{sql}: {other:?}"),
    };
    assert!(denied(&mut s, "DELETE FROM jogos WHERE id = 3").contains("DELETE"));
    assert!(denied(&mut s, "SELECT * FROM segredos").contains("segredos"));
    assert!(denied(
        &mut s,
        "SELECT j.id FROM jogos j WHERE j.id IN (SELECT id FROM segredos)"
    )
    .contains("segredos"));
    assert!(denied(&mut s, "CREATE TABLE x (id INT)").contains("CREATE"));
    assert!(denied(&mut s, "DROP TABLE jogos").contains("CREATE"));
    assert!(denied(&mut s, "CREATE USER hacker PASSWORD 'h'").contains("superusuário"));
    assert!(denied(&mut s, "GRANT ALL ON * TO ana").contains("superusuário"));
    assert!(matches!(s.get(b"k"), Err(Error::Forbidden(_))));
    // Transação com privilégio parcial.
    s.execute("BEGIN").unwrap();
    s.execute("INSERT INTO jogos VALUES (4, 'Eco', 1.0)")
        .unwrap();
    assert!(matches!(
        s.execute("DELETE FROM segredos"),
        Err(Error::Forbidden(_))
    ));
    s.execute("COMMIT").unwrap();
    // Superusuário faz tudo; revogar e apagar usuário.
    let mut r = shared.session();
    r.login("root", "r00t").unwrap();
    r.execute("REVOKE leitores FROM ana").unwrap();
    assert!(matches!(
        s.execute("SELECT * FROM jogos"),
        Err(Error::Forbidden(_))
    ));
    r.execute("GRANT ALL ON * TO ana").unwrap();
    s.execute("SELECT * FROM segredos").unwrap();
    s.execute("CREATE TABLE ok (id INT)").unwrap();
    r.execute("ALTER USER ana PASSWORD 'nova' NOSUPERUSER")
        .unwrap();
    assert!(shared.session().login("ana", "ana123").is_err());
    shared.session().login("ana", "nova").unwrap();
    r.execute("DROP ROLE leitores").unwrap();
    r.execute("DROP USER ana").unwrap();
    assert!(shared.session().login("ana", "nova").is_err());
    assert_eq!(
        rows_of(r.execute("SHOW USERS").unwrap()),
        ["root|user|true|"]
    );
    // Sessões embutidas (sem principal) continuam livres.
    shared.session().execute("SELECT * FROM segredos").unwrap();
    // Privilégio avulso na API.
    let guard = shared.read().unwrap();
    assert!(mini_db::auth::Privilege::parse("select").is_some());
    assert_eq!(Privilege::All.bits(), 31);
    drop(guard);
}

#[test]
fn tcp_requires_user_login_when_users_exist() {
    let mut db = Db::open(tmpdir("tcp-auth")).unwrap();
    ok(&mut db, "CREATE TABLE tb (id INT PRIMARY KEY)");
    ok(&mut db, "CREATE USER admin PASSWORD 'adm' SUPERUSER");
    ok(&mut db, "CREATE USER leitor PASSWORD 'ler'");
    ok(&mut db, "GRANT SELECT ON tb TO leitor");
    let shared = SharedDb::new(db);
    let addr = free_addr();
    {
        let (db, addr) = (shared.clone(), addr.clone());
        thread::spawn(move || mini_db::server::serve_with(db, &addr, NetOptions::default()));
    }
    let talk = |lines: &[&str]| -> Vec<String> {
        let mut s = connect(&addr);
        let mut r = BufReader::new(s.try_clone().unwrap());
        let mut banner = String::new();
        r.read_line(&mut banner).unwrap();
        assert!(banner.starts_with("minidb 1.3 ready"), "{banner}");
        let mut out = Vec::new();
        for l in lines {
            writeln!(s, "{l}").unwrap();
            let mut resp = String::new();
            r.read_line(&mut resp).unwrap();
            out.push(resp.trim_end().to_string());
        }
        out
    };
    let out = talk(&["SELECT 1", "AUTH leitor errada"]);
    assert!(out[0].starts_with("ERR autenticação exigida"), "{out:?}");
    assert!(out[1].starts_with("ERR credenciais"), "{out:?}");
    let out = talk(&[
        "AUTH leitor ler",
        "SQL INSERT INTO tb VALUES (1)",
        "PUT k v",
        "GET k",
    ]);
    assert_eq!(out[0], "OK authenticated");
    assert!(out[1].starts_with("ERR permissão negada"), "{out:?}");
    assert!(out[2].starts_with("ERR permissão negada"), "{out:?}");
    assert!(out[3].starts_with("ERR permissão negada"), "{out:?}");
    let out = talk(&["AUTH admin adm", "SQL INSERT INTO tb VALUES (1)", "PUT k v"]);
    assert_eq!(out[0], "OK authenticated");
    assert!(!out[1].starts_with("ERR"), "{out:?}");
    assert!(out[2].starts_with("OK"), "{out:?}");
}

// --- Cliente PostgreSQL mínimo ---------------------------------------------

struct Pg {
    s: TcpStream,
}

impl Pg {
    fn msg(&mut self, ty: u8, body: &[u8]) {
        self.s.write_all(&[ty]).unwrap();
        self.s
            .write_all(&((body.len() + 4) as u32).to_be_bytes())
            .unwrap();
        self.s.write_all(body).unwrap();
    }

    fn read(&mut self) -> (u8, Vec<u8>) {
        let mut ty = [0u8; 1];
        self.s.read_exact(&mut ty).unwrap();
        let mut len = [0u8; 4];
        self.s.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize - 4];
        self.s.read_exact(&mut body).unwrap();
        (ty[0], body)
    }

    /// Lê até ReadyForQuery; devolve as mensagens.
    fn until_ready(&mut self) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        loop {
            let m = self.read();
            let done = m.0 == b'Z';
            out.push(m);
            if done {
                return out;
            }
        }
    }

    fn startup(addr: &str, user: &str) -> Self {
        let mut s = connect(addr);
        // SSLRequest recusado.
        s.write_all(&8u32.to_be_bytes()).unwrap();
        s.write_all(&80877103u32.to_be_bytes()).unwrap();
        let mut n = [0u8; 1];
        s.read_exact(&mut n).unwrap();
        assert_eq!(n[0], b'N');
        let mut body = 196608u32.to_be_bytes().to_vec();
        for (k, v) in [
            ("user", user),
            ("database", "minidb"),
            ("application_name", "teste"),
        ] {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        s.write_all(&((body.len() + 4) as u32).to_be_bytes())
            .unwrap();
        s.write_all(&body).unwrap();
        Self { s }
    }

    fn scram(&mut self, user: &str, password: &str) -> Result<(), String> {
        let (ty, body) = self.read();
        assert_eq!(ty, b'R');
        assert_eq!(&body[..4], &10u32.to_be_bytes());
        assert!(body[4..].starts_with(b"SCRAM-SHA-256"));
        let nonce = "clientnonce123";
        let first_bare = format!("n={user},r={nonce}");
        let first = format!("n,,{first_bare}");
        let mut b = b"SCRAM-SHA-256\0".to_vec();
        b.extend_from_slice(&(first.len() as u32).to_be_bytes());
        b.extend_from_slice(first.as_bytes());
        self.msg(b'p', &b);
        let (ty, body) = self.read();
        if ty == b'E' {
            return Err(String::from_utf8_lossy(&body).into_owned());
        }
        assert_eq!(&body[..4], &11u32.to_be_bytes());
        let server_first = String::from_utf8_lossy(&body[4..]).into_owned();
        let attrs: Vec<&str> = server_first.split(',').collect();
        let combined = attrs[0].strip_prefix("r=").unwrap();
        assert!(combined.starts_with(nonce));
        let salt = crypto::base64_decode(attrs[1].strip_prefix("s=").unwrap()).unwrap();
        let iters: u32 = attrs[2].strip_prefix("i=").unwrap().parse().unwrap();
        let salted = crypto::pbkdf2_sha256(password.as_bytes(), &salt, iters);
        let client_key = crypto::hmac_sha256(&salted, &[b"Client Key"]);
        let stored = crypto::sha256(&client_key);
        let without_proof = format!("c=biws,r={combined}");
        let auth = format!("{first_bare},{server_first},{without_proof}");
        let sig = crypto::hmac_sha256(&stored, &[auth.as_bytes()]);
        let proof: Vec<u8> = client_key
            .iter()
            .zip(sig.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let final_msg = format!("{without_proof},p={}", crypto::base64_encode(&proof));
        self.msg(b'p', final_msg.as_bytes());
        let (ty, body) = self.read();
        if ty == b'E' {
            return Err(String::from_utf8_lossy(&body).into_owned());
        }
        assert_eq!(&body[..4], &12u32.to_be_bytes());
        let server_key = crypto::hmac_sha256(&salted, &[b"Server Key"]);
        let expected = crypto::hmac_sha256(&server_key, &[auth.as_bytes()]);
        assert_eq!(
            String::from_utf8_lossy(&body[4..]),
            format!("v={}", crypto::base64_encode(&expected))
        );
        Ok(())
    }

    /// Consome AuthenticationOk, ParameterStatus, BackendKeyData, ReadyForQuery.
    fn finish_startup(&mut self) -> Vec<(String, String)> {
        let (ty, body) = self.read();
        assert_eq!((ty, &body[..]), (b'R', &0u32.to_be_bytes()[..]));
        let mut params = Vec::new();
        for (ty, body) in self.until_ready() {
            if ty == b'S' {
                let parts: Vec<&[u8]> = body.split(|&b| b == 0).collect();
                params.push((
                    String::from_utf8_lossy(parts[0]).into_owned(),
                    String::from_utf8_lossy(parts[1]).into_owned(),
                ));
            }
        }
        params
    }

    fn query(&mut self, sql: &str) -> Vec<(u8, Vec<u8>)> {
        let mut b = sql.as_bytes().to_vec();
        b.push(0);
        self.msg(b'Q', &b);
        self.until_ready()
    }
}

fn rows(msgs: &[(u8, Vec<u8>)]) -> Vec<Vec<Option<String>>> {
    msgs.iter()
        .filter(|(t, _)| *t == b'D')
        .map(|(_, body)| {
            let n = u16::from_be_bytes([body[0], body[1]]) as usize;
            let mut pos = 2;
            (0..n)
                .map(|_| {
                    let len = i32::from_be_bytes(body[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                    if len < 0 {
                        None
                    } else {
                        let v =
                            String::from_utf8_lossy(&body[pos..pos + len as usize]).into_owned();
                        pos += len as usize;
                        Some(v)
                    }
                })
                .collect()
        })
        .collect()
}

fn tags(msgs: &[(u8, Vec<u8>)]) -> Vec<String> {
    msgs.iter()
        .filter(|(t, _)| *t == b'C')
        .map(|(_, b)| String::from_utf8_lossy(&b[..b.len() - 1]).into_owned())
        .collect()
}

fn errors(msgs: &[(u8, Vec<u8>)]) -> Vec<String> {
    msgs.iter()
        .filter(|(t, _)| *t == b'E')
        .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
        .collect()
}

fn columns(msgs: &[(u8, Vec<u8>)]) -> Vec<(String, u32)> {
    let Some((_, body)) = msgs.iter().find(|(t, _)| *t == b'T') else {
        return Vec::new();
    };
    let n = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut pos = 2;
    (0..n)
        .map(|_| {
            let end = body[pos..].iter().position(|&b| b == 0).unwrap();
            let name = String::from_utf8_lossy(&body[pos..pos + end]).into_owned();
            pos += end + 1 + 4 + 2;
            let oid = u32::from_be_bytes(body[pos..pos + 4].try_into().unwrap());
            pos += 4 + 2 + 4 + 2;
            (name, oid)
        })
        .collect()
}

fn ready_status(msgs: &[(u8, Vec<u8>)]) -> u8 {
    msgs.last().unwrap().1[0]
}

#[test]
fn postgres_protocol_trust_simple_and_extended() {
    let mut db = Db::open(tmpdir("pg-trust")).unwrap();
    ok(
        &mut db,
        "CREATE TABLE itens (id INT PRIMARY KEY, nome TEXT, preco REAL, ativo BOOL)",
    );
    let shared = SharedDb::new(db);
    let addr = free_addr();
    {
        let (db, addr) = (shared.clone(), addr.clone());
        thread::spawn(move || mini_db::pg::serve(db, &addr, NetOptions::default()));
    }
    let mut c = Pg::startup(&addr, "qualquer");
    let params = c.finish_startup();
    assert!(params
        .iter()
        .any(|(k, v)| k == "server_version" && v.starts_with("16")));
    assert!(params
        .iter()
        .any(|(k, v)| k == "client_encoding" && v == "UTF8"));

    // Consulta simples: várias instruções, tags e tipos.
    let m = c.query("SET client_encoding TO 'UTF8'; INSERT INTO itens VALUES (1, 'Espada', 10.5, true), (2, 'Escudo', 7, false); SELECT id, nome, preco, ativo FROM itens ORDER BY id");
    assert_eq!(tags(&m), ["SET", "INSERT 0 2", "SELECT 2"]);
    assert_eq!(
        columns(&m),
        [
            ("id".to_string(), 20),
            ("nome".into(), 25),
            ("preco".into(), 701),
            ("ativo".into(), 16)
        ]
    );
    assert_eq!(
        rows(&m),
        [
            vec![
                Some("1".into()),
                Some("Espada".into()),
                Some("10.5".into()),
                Some("t".into())
            ],
            vec![
                Some("2".into()),
                Some("Escudo".into()),
                Some("7".into()),
                Some("f".into())
            ],
        ]
    );
    assert_eq!(ready_status(&m), b'I');
    let m = c.query("SHOW server_version");
    assert_eq!(rows(&m), [vec![Some("16.0".to_string())]]);
    let m = c.query("");
    assert!(m.iter().any(|(t, _)| *t == b'I'), "EmptyQueryResponse");
    // Erro e transação abortada.
    let m = c.query("BEGIN");
    assert_eq!(ready_status(&m), b'T');
    let m = c.query("SELECT * FROM nao_existe");
    assert!(errors(&m)[0].contains("42P01"), "{:?}", errors(&m));
    assert_eq!(ready_status(&m), b'E');
    let m = c.query("SELECT 1");
    assert!(errors(&m)[0].contains("abortada"));
    let m = c.query("COMMIT");
    assert_eq!(tags(&m), ["ROLLBACK"]);
    assert_eq!(ready_status(&m), b'I');

    // Protocolo estendido: Parse/Bind/Describe/Execute/Sync com parâmetros em texto e binário.
    let mut parse = b"s1\0".to_vec();
    parse.extend_from_slice(
        b"SELECT id, nome FROM itens WHERE preco > $1 AND ativo = $2 ORDER BY id\0",
    );
    parse.extend_from_slice(&2u16.to_be_bytes());
    parse.extend_from_slice(&701u32.to_be_bytes());
    parse.extend_from_slice(&16u32.to_be_bytes());
    c.msg(b'P', &parse);
    let mut bind = b"\0s1\0".to_vec();
    bind.extend_from_slice(&2u16.to_be_bytes()); // formatos: texto, binário
    bind.extend_from_slice(&0u16.to_be_bytes());
    bind.extend_from_slice(&1u16.to_be_bytes());
    bind.extend_from_slice(&2u16.to_be_bytes());
    bind.extend_from_slice(&3u32.to_be_bytes());
    bind.extend_from_slice(b"5.0");
    bind.extend_from_slice(&1u32.to_be_bytes());
    bind.push(1);
    bind.extend_from_slice(&0u16.to_be_bytes());
    c.msg(b'B', &bind);
    c.msg(b'D', b"P\0");
    c.msg(b'E', b"\0\0\0\0\0");
    c.msg(b'S', &[]);
    let m = c.until_ready();
    let kinds: Vec<u8> = m.iter().map(|(t, _)| *t).collect();
    assert_eq!(kinds, [b'1', b'2', b'T', b'D', b'C', b'Z'], "{kinds:?}");
    assert_eq!(
        rows(&m),
        [vec![Some("1".to_string()), Some("Espada".into())]]
    );
    assert_eq!(tags(&m), ["SELECT 1"]);
    // Describe do comando: descrição de parâmetros + colunas (leitura).
    c.msg(b'D', b"Ss1\0");
    c.msg(b'S', &[]);
    let m = c.until_ready();
    assert_eq!(m[0].0, b't');
    assert_eq!(&m[0].1[..2], &2u16.to_be_bytes());
    assert_eq!(m[1].0, b'T');
    // Erro no estendido: ignora até Sync.
    let mut parse = b"\0SELECT * FROM x_nao_existe\0".to_vec();
    parse.extend_from_slice(&0u16.to_be_bytes());
    c.msg(b'P', &parse);
    c.msg(b'B', b"\0\0\0\0\0\0\0\0");
    c.msg(b'E', b"\0\0\0\0\0");
    c.msg(b'S', &[]);
    let m = c.until_ready();
    assert_eq!(m.iter().filter(|(t, _)| *t == b'E').count(), 1);
    assert_eq!(m.last().unwrap().0, b'Z');
    // Chave-valor pelo dialeto SQL vira tabela.
    shared.put(b"cfg", b"1").unwrap();
    let m = c.query("SELECT key, value FROM kv WHERE key = 'cfg'");
    assert_eq!(rows(&m), [vec![Some("cfg".to_string()), Some("1".into())]]);
    c.msg(b'X', &[]);
}

#[test]
fn postgres_protocol_scram_authentication_and_privileges() {
    let mut db = Db::open(tmpdir("pg-scram")).unwrap();
    ok(&mut db, "CREATE TABLE tb (id INT PRIMARY KEY)");
    ok(&mut db, "CREATE USER admin PASSWORD 'adm' SUPERUSER");
    ok(&mut db, "CREATE USER leitor PASSWORD 'ler'");
    ok(&mut db, "GRANT SELECT ON tb TO leitor");
    let shared = SharedDb::new(db);
    let addr = free_addr();
    {
        let (db, addr) = (shared.clone(), addr.clone());
        thread::spawn(move || mini_db::pg::serve(db, &addr, NetOptions::default()));
    }
    let mut c = Pg::startup(&addr, "leitor");
    assert!(c.scram("leitor", "errada").unwrap_err().contains("28P01"));
    let mut c = Pg::startup(&addr, "fantasma");
    assert!(c.scram("fantasma", "x").unwrap_err().contains("28P01"));
    let mut c = Pg::startup(&addr, "leitor");
    c.scram("leitor", "ler").unwrap();
    let params = c.finish_startup();
    assert!(params
        .iter()
        .any(|(k, v)| k == "is_superuser" && v == "off"));
    let m = c.query("SELECT count(*) FROM tb");
    assert_eq!(rows(&m), [vec![Some("0".to_string())]]);
    let m = c.query("INSERT INTO tb VALUES (1)");
    assert!(errors(&m)[0].contains("42501"), "{:?}", errors(&m));
    let mut a = Pg::startup(&addr, "admin");
    a.scram("admin", "adm").unwrap();
    a.finish_startup();
    assert_eq!(tags(&a.query("INSERT INTO tb VALUES (1)")), ["INSERT 0 1"]);
}

#[test]
fn encryption_at_rest_hides_data_and_checks_passphrase() {
    let dir = tmpdir("crypt");
    let secret = "texto-secreto-do-jogo-XYZ";
    {
        let mut db = Db::open_encrypted(&dir, 64, true, Some("senha forte")).unwrap();
        assert!(db.is_encrypted());
        ok(&mut db, "CREATE TABLE s (id INT PRIMARY KEY, v TEXT)");
        for i in 0..200 {
            ok(
                &mut db,
                &format!("INSERT INTO s VALUES ({i}, '{secret}-{i}')"),
            );
        }
        db.put(b"kv-key", secret.as_bytes()).unwrap();
        db.checkpoint().unwrap();
        ok(
            &mut db,
            &format!("INSERT INTO s VALUES (999, '{secret}-wal')"),
        );
        db.close().unwrap();
    }
    let contains = |path: &std::path::Path| {
        let bytes = std::fs::read(path).unwrap();
        bytes.windows(secret.len()).any(|w| w == secret.as_bytes())
    };
    assert!(!contains(&Db::data_path(&dir)), "data.mdb em claro");
    assert!(!contains(&Db::wal_path(&dir)), "WAL em claro");
    assert!(dir.join("data.mdb.key").exists());
    // Sem senha ou com senha errada não abre.
    assert!(Db::open(&dir).is_err());
    assert!(Db::open_encrypted(&dir, 64, true, Some("errada")).is_err());
    let mut db = Db::open_encrypted(&dir, 64, true, Some("senha forte")).unwrap();
    assert_eq!(q(&mut db, "SELECT count(*) FROM s"), ["201"]);
    assert_eq!(
        q(&mut db, "SELECT v FROM s WHERE id = 999"),
        [format!("{secret}-wal")]
    );
    assert_eq!(db.get(b"kv-key").unwrap().unwrap(), secret.as_bytes());
    // VACUUM mantém a cifra; banco em claro existente não aceita senha.
    db.vacuum().unwrap();
    assert_eq!(q(&mut db, "SELECT count(*) FROM s"), ["201"]);
    db.close().unwrap();
    let mut db = Db::open_encrypted(&dir, 64, true, Some("senha forte")).unwrap();
    assert_eq!(q(&mut db, "SELECT count(*) FROM s"), ["201"]);
    db.close().unwrap();
    let plain = tmpdir("plain");
    Db::open(&plain).unwrap().put(b"a", b"b").unwrap();
    assert!(Db::open_encrypted(&plain, 64, true, Some("x")).is_err());
}

#[test]
fn backup_full_incremental_and_point_in_time_restore() {
    let dir = tmpdir("bk-src");
    let dest = tmpdir("bk-dest");
    let mut db = Db::open(&dir).unwrap();
    ok(&mut db, "CREATE TABLE ev (id INT PRIMARY KEY, nota TEXT)");
    ok(&mut db, "INSERT INTO ev VALUES (1, 'base')");
    let r = backup::backup(&mut db, &dest).unwrap();
    assert!(r.starts_with("backup completo"), "{r}");
    assert!(dest.join("base/data.mdb").exists());
    // Mudanças depois do completo: parte arquivada (checkpoint), parte no WAL atual.
    ok(&mut db, "INSERT INTO ev VALUES (2, 'depois-1')");
    db.checkpoint().unwrap();
    ok(&mut db, "INSERT INTO ev VALUES (3, 'depois-2')");
    let lsn_marker = db.last_lsn();
    thread::sleep(Duration::from_millis(1100));
    let t_marker = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    thread::sleep(Duration::from_millis(1100));
    ok(
        &mut db,
        "BEGIN; INSERT INTO ev VALUES (4, 'tarde'); UPDATE ev SET nota = 'x' WHERE id = 1; COMMIT",
    );
    ok(&mut db, "DELETE FROM ev WHERE id = 2");
    let r = backup::backup(&mut db, &dest).unwrap();
    assert!(r.starts_with("backup incremental"), "{r}");
    let all = q(&mut db, "SELECT id, nota FROM ev ORDER BY id");
    db.close().unwrap();

    // Restauração completa.
    let full = tmpdir("bk-full");
    backup::restore(&dest, &full, RestoreTarget::Latest, None).unwrap();
    let mut f = Db::open(&full).unwrap();
    assert_eq!(q(&mut f, "SELECT id, nota FROM ev ORDER BY id"), all);
    assert_eq!(all, ["1|x", "3|depois-2", "4|tarde"]);
    f.close().unwrap();
    // Até um LSN: só o que existia naquele momento.
    let lsn_dir = tmpdir("bk-lsn");
    backup::restore(&dest, &lsn_dir, RestoreTarget::Lsn(lsn_marker), None).unwrap();
    let mut l = Db::open(&lsn_dir).unwrap();
    assert_eq!(
        q(&mut l, "SELECT id, nota FROM ev ORDER BY id"),
        ["1|base", "2|depois-1", "3|depois-2"]
    );
    l.close().unwrap();
    // Até um instante: a transação posterior fica fora inteira.
    let t_dir = tmpdir("bk-time");
    backup::restore(&dest, &t_dir, RestoreTarget::Time(t_marker), None).unwrap();
    let mut t = Db::open(&t_dir).unwrap();
    assert_eq!(
        q(&mut t, "SELECT id, nota FROM ev ORDER BY id"),
        ["1|base", "2|depois-1", "3|depois-2"]
    );
    t.close().unwrap();
    // Destino ocupado é recusado; instante em texto.
    assert!(backup::restore(&dest, &t_dir, RestoreTarget::Latest, None).is_err());
    assert_eq!(backup::parse_time("1700000000").unwrap(), 1_700_000_000_000);
    assert!(backup::parse_time("2024-01-02 03:04:05").unwrap() > 1_700_000_000_000);
    assert!(backup::parse_time("ontem").is_err());
}

#[test]
fn encrypted_backup_restores_with_passphrase() {
    let dir = tmpdir("bk-crypt");
    let dest = tmpdir("bk-crypt-dest");
    let mut db = Db::open_encrypted(&dir, 64, true, Some("s3nha")).unwrap();
    ok(&mut db, "CREATE TABLE tb (id INT PRIMARY KEY, v TEXT)");
    ok(&mut db, "INSERT INTO tb VALUES (1, 'um')");
    backup::backup(&mut db, &dest).unwrap();
    ok(&mut db, "INSERT INTO tb VALUES (2, 'dois')");
    backup::backup(&mut db, &dest).unwrap();
    db.close().unwrap();
    let out = tmpdir("bk-crypt-out");
    assert!(backup::restore(&dest, &out, RestoreTarget::Latest, None).is_err());
    let _ = std::fs::remove_dir_all(&out);
    backup::restore(&dest, &out, RestoreTarget::Latest, Some("s3nha")).unwrap();
    let mut r = Db::open_encrypted(&out, 64, true, Some("s3nha")).unwrap();
    assert_eq!(
        q(&mut r, "SELECT id, v FROM tb ORDER BY id"),
        ["1|um", "2|dois"]
    );
}

#[test]
fn convert_encryption_in_place() {
    let dir = tmpdir("convert");
    let mut db = Db::open(&dir).unwrap();
    ok(&mut db, "CREATE TABLE tb (id INT PRIMARY KEY, v TEXT)");
    for i in 0..500 {
        ok(
            &mut db,
            &format!("INSERT INTO tb VALUES ({i}, 'valor-secreto-{i}')"),
        );
    }
    db.close().unwrap();
    let r = mini_db::encryption::convert(&dir, None, Some("nova")).unwrap();
    assert!(r.contains("cifrado"), "{r}");
    assert!(Db::open(&dir).is_err());
    let bytes = std::fs::read(Db::data_path(&dir)).unwrap();
    assert!(!bytes.windows(13).any(|w| w == b"valor-secreto"));
    let mut db = Db::open_encrypted(&dir, 64, true, Some("nova")).unwrap();
    assert_eq!(q(&mut db, "SELECT count(*) FROM tb"), ["500"]);
    ok(&mut db, "INSERT INTO tb VALUES (500, 'x')");
    db.close().unwrap();
    mini_db::encryption::convert(&dir, Some("nova"), Some("outra")).unwrap();
    assert!(Db::open_encrypted(&dir, 64, true, Some("nova")).is_err());
    mini_db::encryption::convert(&dir, Some("outra"), None).unwrap();
    let mut db = Db::open(&dir).unwrap();
    assert_eq!(q(&mut db, "SELECT count(*) FROM tb"), ["501"]);
}

#[test]
fn pg_catalog_information_schema_and_regex() {
    let mut db = Db::open(tmpdir("pgcat")).unwrap();
    ok(&mut db, "CREATE TABLE jogos (id INT PRIMARY KEY, nome TEXT NOT NULL, preco REAL DEFAULT 0, UNIQUE (nome))");
    ok(&mut db, "CREATE INDEX jogos_preco ON jogos (preco)");
    ok(
        &mut db,
        "CREATE VIEW caros AS SELECT nome FROM jogos WHERE preco > 100",
    );
    // O que o psql manda em \dt e \d.
    assert_eq!(
        q(&mut db, "SELECT n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r','p','') AND n.nspname !~ '^pg_toast' AND pg_catalog.pg_table_is_visible(c.oid) ORDER BY 1,2"),
        ["public|jogos|r"]
    );
    let oid = q(&mut db, "SELECT c.oid FROM pg_catalog.pg_class c WHERE c.relname OPERATOR(pg_catalog.~) '^(jogos)$' COLLATE pg_catalog.default")[0].clone();
    let cols = q(&mut db, &format!("SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), (SELECT pg_catalog.pg_get_expr(d.adbin, d.adrelid, true) FROM pg_catalog.pg_attrdef d WHERE d.adrelid = a.attrelid AND d.adnum = a.attnum AND a.atthasdef), a.attnotnull FROM pg_catalog.pg_attribute a WHERE a.attrelid = '{oid}' AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum"));
    assert_eq!(
        cols,
        [
            "id|bigint|NULL|true",
            "nome|text|NULL|true",
            "preco|double precision|0.0|false"
        ]
    );
    let idx = q(&mut db, &format!("SELECT c2.relname, i.indisprimary, i.indisunique, pg_catalog.pg_get_indexdef(i.indexrelid, 0, true), pg_catalog.pg_get_constraintdef(con.oid, true) FROM pg_catalog.pg_class c, pg_catalog.pg_class c2, pg_catalog.pg_index i LEFT JOIN pg_catalog.pg_constraint con ON (conrelid = i.indrelid AND conindid = i.indexrelid AND contype IN ('p','u','x')) WHERE c.oid = '{oid}' AND c.oid = i.indrelid AND i.indexrelid = c2.oid ORDER BY i.indisprimary DESC, c2.relname"));
    assert_eq!(idx.len(), 3, "{idx:?}");
    assert!(idx[0].starts_with("jogos_pkey|true|true|CREATE UNIQUE INDEX jogos_pkey ON jogos USING btree (id)|PRIMARY KEY (id)"), "{idx:?}");
    assert!(idx.iter().any(|r| r.contains("UNIQUE (nome)")), "{idx:?}");
    // information_schema e funções de sessão.
    assert_eq!(q(&mut db, "SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_name = 'jogos' ORDER BY ordinal_position"), ["id|bigint|NO", "nome|text|NO", "preco|double precision|YES"]);
    assert_eq!(
        q(
            &mut db,
            "SELECT table_name, table_type FROM information_schema.tables ORDER BY 1"
        ),
        ["caros|VIEW", "jogos|BASE TABLE"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT current_database(), current_schema(), current_user, pg_typeof(1)"
        ),
        ["minidb|public|minidb|bigint"]
    );
    assert_eq!(
        q(&mut db, "SELECT viewname, definition FROM pg_views"),
        ["caros|SELECT nome FROM jogos WHERE preco > 100"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT to_regclass('jogos') IS NOT NULL, to_regclass('nada') IS NULL"
        ),
        ["true|true"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT x FROM generate_series(1, 3) x ORDER BY x DESC"
        ),
        ["3", "2", "1"]
    );
    assert_eq!(q(&mut db, "SELECT unnest FROM unnest('{a,b}')"), ["a", "b"]);
    assert_eq!(
        q(&mut db, "SELECT 'x' = ANY('{x,y}'), ('{a,b,c}')[2]"),
        ["true|b"]
    );
    // Regex: operadores e funções.
    assert_eq!(q(&mut db, "SELECT 'Jogo 42' ~ '\\d+', 'Jogo' ~* '^jogo$', 'abc' !~ 'x', regexp_replace('a1b22', '\\d+', '#', 'g'), regexp_substr('id=77', '\\d+'), regexp_count('a,b,c', ',')"), ["true|true|true|a#b#|77|2"]);
    assert_eq!(
        q(&mut db, "SELECT nome FROM jogos WHERE nome ~ '^N'").len(),
        0
    );
    ok(
        &mut db,
        "INSERT INTO jogos VALUES (1, 'Nebula', 10), (2, 'orbit', 200)",
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT nome FROM jogos WHERE nome ~* '^n' OR nome ~ 'it$' ORDER BY id"
        ),
        ["Nebula", "orbit"]
    );
    assert_eq!(
        q(
            &mut db,
            "SELECT E'a\\tb' = 'a' || char(9) || 'b', \"Nome\" FROM (SELECT 1 AS \"Nome\") s"
        ),
        ["true|1"]
    );
    assert!(
        matches!(db.execute_sql("SELECT regexp_like('a', '(')"), Err(Error::Sql(m)) if m.contains("regular"))
    );
}

// --- TLS 1.3 nativo: cliente mínimo de teste (X25519 + ChaCha20-Poly1305) --

mod tls_client {
    use mini_db::crypto::*;
    use mini_db::curve25519::*;
    use mini_db::pubkey::PrivateKey;
    use std::io::{Read, Write};

    fn label(secret: &[u8; 32], l: &str, ctx: &[u8], n: usize) -> Vec<u8> {
        let mut info = (n as u16).to_be_bytes().to_vec();
        let full = format!("tls13 {l}");
        info.push(full.len() as u8);
        info.extend_from_slice(full.as_bytes());
        info.push(ctx.len() as u8);
        info.extend_from_slice(ctx);
        hkdf_expand(secret, &info, n)
    }

    fn rec(s: &mut impl Write, ty: u8, b: &[u8]) {
        let mut r = vec![ty, 3, 3];
        r.extend_from_slice(&(b.len() as u16).to_be_bytes());
        r.extend_from_slice(b);
        s.write_all(&r).unwrap();
    }

    fn read_rec(s: &mut impl Read) -> (u8, Vec<u8>) {
        let mut h = [0u8; 5];
        s.read_exact(&mut h).unwrap();
        let mut b = vec![0u8; u16::from_be_bytes([h[3], h[4]]) as usize];
        s.read_exact(&mut b).unwrap();
        (h[0], b)
    }

    struct Keys {
        key: [u8; 32],
        iv: [u8; 12],
        seq: u64,
    }
    impl Keys {
        fn new(secret: &[u8; 32]) -> Self {
            Self {
                key: label(secret, "key", &[], 32).try_into().unwrap(),
                iv: label(secret, "iv", &[], 12).try_into().unwrap(),
                seq: 0,
            }
        }
        fn nonce(&mut self) -> [u8; 12] {
            let mut n = self.iv;
            for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
                n[4 + i] ^= b;
            }
            self.seq += 1;
            n
        }
        fn seal(&mut self, ty: u8, plain: &[u8]) -> Vec<u8> {
            let mut inner = plain.to_vec();
            inner.push(ty);
            let len = inner.len() + 16;
            let aad = [23, 3, 3, (len >> 8) as u8, len as u8];
            let nonce = self.nonce();
            aead_seal(&self.key, &nonce, &aad, &inner)
        }
        fn open(&mut self, body: &[u8]) -> (u8, Vec<u8>) {
            let aad = [23, 3, 3, (body.len() >> 8) as u8, body.len() as u8];
            let nonce = self.nonce();
            let mut p = aead_open(&self.key, &nonce, &aad, body).expect("registro autentica");
            while p.last() == Some(&0) {
                p.pop();
            }
            let ty = p.pop().unwrap();
            (ty, p)
        }
    }

    pub struct Client<S: Read + Write> {
        s: S,
        r: Keys,
        w: Keys,
        pub server_cert: Vec<u8>,
        pub server_scheme: u16,
    }

    impl<S: Read + Write> Client<S> {
        /// Handshake TLS 1.3 como cliente; verifica CertificateVerify e Finished.
        pub fn connect(s: S) -> Self {
            Self::connect_with(s, None)
        }

        /// Handshake com certificado de cliente opcional (chave + cadeia DER).
        pub fn connect_with(mut s: S, identity: Option<(PrivateKey, Vec<Vec<u8>>)>) -> Self {
            let mut cert_requested = false;
            let eph = random_bytes::<32>();
            let share = x25519_base(&eph);
            let mut ch = vec![3, 3];
            ch.extend_from_slice(&random_bytes::<32>());
            ch.push(0); // session id
            ch.extend_from_slice(&[0, 2, 0x13, 0x03, 1, 0]);
            let mut ext = Vec::new();
            ext.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]);
            ext.extend_from_slice(&[0, 13, 0, 14, 0, 12, 8, 7, 4, 3, 5, 3, 8, 4, 8, 5, 8, 6]);
            ext.extend_from_slice(&[0, 10, 0, 4, 0, 2, 0, 0x1d]);
            ext.extend_from_slice(&[0, 51, 0, 38, 0, 36, 0, 0x1d, 0, 32]);
            ext.extend_from_slice(&share);
            ch.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            ch.extend_from_slice(&ext);
            let mut hello = vec![
                1,
                (ch.len() >> 16) as u8,
                (ch.len() >> 8) as u8,
                ch.len() as u8,
            ];
            hello.extend_from_slice(&ch);
            rec(&mut s, 22, &hello);
            let mut transcript = hello.clone();
            let (ty, sh) = read_rec(&mut s);
            assert_eq!(ty, 22);
            transcript.extend_from_slice(&sh);
            // key_share do servidor: últimos 32 bytes do ServerHello.
            let server_share: [u8; 32] = sh[sh.len() - 32..].try_into().unwrap();
            let shared = x25519(&eph, &server_share);
            let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
            let derived: [u8; 32] = label(&early, "derived", &sha256(&[]), 32)
                .try_into()
                .unwrap();
            let hs = hkdf_extract(&derived, &shared);
            let th = sha256(&transcript);
            let c_hs: [u8; 32] = label(&hs, "c hs traffic", &th, 32).try_into().unwrap();
            let s_hs: [u8; 32] = label(&hs, "s hs traffic", &th, 32).try_into().unwrap();
            let mut r = Keys::new(&s_hs);
            // Mensagens cifradas do servidor até o Finished.
            let mut msgs = Vec::new();
            let mut server_cert = Vec::new();
            let mut server_scheme = 0u16;
            let mut finished_ok = false;
            let mut transcript_before_finished = Vec::new();
            while !finished_ok {
                let (ty, body) = read_rec(&mut s);
                if ty == 20 {
                    continue;
                }
                assert_eq!(ty, 23);
                let (ity, plain) = r.open(&body);
                assert_eq!(ity, 22);
                msgs.extend_from_slice(&plain);
                while msgs.len() >= 4 {
                    let len =
                        ((msgs[1] as usize) << 16) | ((msgs[2] as usize) << 8) | msgs[3] as usize;
                    if msgs.len() < 4 + len {
                        break;
                    }
                    let m: Vec<u8> = msgs.drain(..4 + len).collect();
                    match m[0] {
                        11 => {
                            let clen =
                                ((m[8] as usize) << 16) | ((m[9] as usize) << 8) | m[10] as usize;
                            server_cert = m[11..11 + clen].to_vec();
                            transcript.extend_from_slice(&m);
                        }
                        15 => {
                            // CertificateVerify: Ed25519, ECDSA ou RSA-PSS sobre a transcrição.
                            let mut to_sign = vec![0x20u8; 64];
                            to_sign.extend_from_slice(b"TLS 1.3, server CertificateVerify");
                            to_sign.push(0);
                            to_sign.extend_from_slice(&sha256(&transcript));
                            let code = u16::from_be_bytes([m[4], m[5]]);
                            let n = u16::from_be_bytes([m[6], m[7]]) as usize;
                            assert_eq!(m.len(), 8 + n);
                            let pubkey = mini_db::x509::Cert::parse(&server_cert).unwrap().public;
                            assert!(
                                pubkey.verify_tls(code, &to_sign, &m[8..]),
                                "assinatura do servidor (esquema {code:#06x})"
                            );
                            server_scheme = code;
                            transcript.extend_from_slice(&m);
                        }
                        20 => {
                            transcript_before_finished = transcript.clone();
                            let fk: [u8; 32] =
                                label(&s_hs, "finished", &[], 32).try_into().unwrap();
                            let expected = hmac_sha256(&fk, &[&sha256(&transcript)]);
                            assert_eq!(&m[4..], &expected[..], "Finished do servidor");
                            transcript.extend_from_slice(&m);
                            finished_ok = true;
                        }
                        13 => {
                            cert_requested = true;
                            transcript.extend_from_slice(&m);
                        }
                        _ => transcript.extend_from_slice(&m),
                    }
                }
            }
            let _ = transcript_before_finished;
            let derived2: [u8; 32] = label(&hs, "derived", &sha256(&[]), 32).try_into().unwrap();
            let master = hkdf_extract(&derived2, &[0u8; 32]);
            let th2 = sha256(&transcript);
            let c_app: [u8; 32] = label(&master, "c ap traffic", &th2, 32).try_into().unwrap();
            let s_app: [u8; 32] = label(&master, "s ap traffic", &th2, 32).try_into().unwrap();
            // Finished do cliente.
            let mut w = Keys::new(&c_hs);
            let hs_msg = |ty: u8, body: &[u8]| {
                let mut m = vec![
                    ty,
                    (body.len() >> 16) as u8,
                    (body.len() >> 8) as u8,
                    body.len() as u8,
                ];
                m.extend_from_slice(body);
                m
            };
            if cert_requested {
                let mut list = Vec::new();
                if let Some((_, chain)) = &identity {
                    for der in chain {
                        list.extend_from_slice(&[
                            (der.len() >> 16) as u8,
                            (der.len() >> 8) as u8,
                            der.len() as u8,
                        ]);
                        list.extend_from_slice(der);
                        list.extend_from_slice(&[0, 0]);
                    }
                }
                let mut body = vec![
                    0,
                    (list.len() >> 16) as u8,
                    (list.len() >> 8) as u8,
                    list.len() as u8,
                ];
                body.extend_from_slice(&list);
                let cert_msg = hs_msg(11, &body);
                transcript.extend_from_slice(&cert_msg);
                rec(&mut s, 23, &w.seal(22, &cert_msg));
                if let Some((key, _)) = &identity {
                    let mut to_sign = vec![0x20u8; 64];
                    to_sign.extend_from_slice(b"TLS 1.3, client CertificateVerify");
                    to_sign.push(0);
                    to_sign.extend_from_slice(&sha256(&transcript));
                    let code = key.tls_schemes()[0];
                    let sig = key.sign_tls(code, &to_sign).unwrap();
                    let mut cv = code.to_be_bytes().to_vec();
                    cv.extend_from_slice(&(sig.len() as u16).to_be_bytes());
                    cv.extend_from_slice(&sig);
                    let cv_msg = hs_msg(15, &cv);
                    transcript.extend_from_slice(&cv_msg);
                    rec(&mut s, 23, &w.seal(22, &cv_msg));
                }
            }
            let cfk: [u8; 32] = label(&c_hs, "finished", &[], 32).try_into().unwrap();
            let verify = hmac_sha256(&cfk, &[&sha256(&transcript)]);
            let mut fin = vec![20, 0, 0, 32];
            fin.extend_from_slice(&verify);
            let sealed = w.seal(22, &fin);
            rec(&mut s, 23, &sealed);
            s.flush().unwrap();
            Client {
                s,
                r: Keys::new(&s_app),
                w: Keys::new(&c_app),
                server_cert,
                server_scheme,
            }
        }

        pub fn send(&mut self, data: &[u8]) {
            let sealed = self.w.seal(23, data);
            rec(&mut self.s, 23, &sealed);
            self.s.flush().unwrap();
        }

        /// Próximo registro já decifrado: (tipo interno, conteúdo).
        pub fn recv_record(&mut self) -> (u8, Vec<u8>) {
            let (ty, body) = read_rec(&mut self.s);
            assert_eq!(
                ty, 23,
                "depois do handshake tudo vem cifrado (inclusive alertas)"
            );
            self.r.open(&body)
        }

        pub fn recv(&mut self) -> Vec<u8> {
            loop {
                let (ty, body) = read_rec(&mut self.s);
                assert_eq!(ty, 23);
                let (ity, plain) = self.r.open(&body);
                if ity == 23 {
                    return plain;
                }
            }
        }
    }
}

#[test]
fn tls13_postgres_and_https_with_generated_certificate() {
    let dir = tmpdir("tls");
    let mut db = Db::open(&dir).unwrap();
    ok(&mut db, "CREATE TABLE tb (id INT PRIMARY KEY)");
    ok(&mut db, "INSERT INTO tb VALUES (7)");
    let identity = mini_db::tls::Identity::load_or_create(&dir, "127.0.0.1").unwrap();
    assert!(dir.join("tls.key").exists() && dir.join("tls.crt").exists());
    // Recarregar do disco dá a mesma chave.
    let again = mini_db::tls::Identity::load_or_create(&dir, "127.0.0.1").unwrap();
    assert_eq!(again.public_key(), identity.public_key());
    let shared = SharedDb::new(db);
    let opts = NetOptions {
        tls: Some(identity.clone()),
        ..NetOptions::default()
    };
    let addr = free_addr();
    {
        let (db, addr, opts) = (shared.clone(), addr.clone(), opts.clone());
        thread::spawn(move || mini_db::pg::serve(db, &addr, opts));
    }
    // SSLRequest → 'S' → handshake → protocolo PostgreSQL por dentro do TLS.
    let mut s = connect(&addr);
    s.write_all(&8u32.to_be_bytes()).unwrap();
    s.write_all(&80877103u32.to_be_bytes()).unwrap();
    let mut b = [0u8; 1];
    s.read_exact(&mut b).unwrap();
    assert_eq!(b[0], b'S');
    let mut c = tls_client::Client::connect(s);
    assert_eq!(c.server_cert, identity.cert_der);
    let mut startup = 196608u32.to_be_bytes().to_vec();
    startup.extend_from_slice(b"user\0dev\0\0");
    let mut msg = ((startup.len() + 4) as u32).to_be_bytes().to_vec();
    msg.extend_from_slice(&startup);
    c.send(&msg);
    let mut got = Vec::new();
    while !got.ends_with(&[b'Z', 0, 0, 0, 5, b'I']) {
        got.extend(c.recv());
    }
    assert_eq!(got[0], b'R');
    let mut q = b"Q".to_vec();
    q.extend_from_slice(&15u32.to_be_bytes());
    q.extend_from_slice(b"SELECT id FROM tb\0");
    q[1..5].copy_from_slice(&((b"SELECT id FROM tb\0".len() + 4) as u32).to_be_bytes());
    c.send(&q);
    let mut got = Vec::new();
    while !got.ends_with(&[b'Z', 0, 0, 0, 5, b'I']) {
        got.extend(c.recv());
    }
    assert!(
        got.windows(1).any(|w| w == b"7"),
        "linha 7 na resposta cifrada"
    );
    // HTTPS com o mesmo certificado.
    let haddr = free_addr();
    {
        let (db, haddr, opts) = (shared.clone(), haddr.clone(), opts.clone());
        let metrics = std::sync::Arc::new(mini_db::metrics::Metrics::new());
        thread::spawn(move || mini_db::http::serve_http_with(db, metrics, &haddr, opts));
    }
    let s = connect(&haddr);
    let mut c = tls_client::Client::connect(s);
    c.send(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n");
    let mut resp = String::from_utf8_lossy(&c.recv()).into_owned();
    while !resp.contains("\"ok\":true") {
        resp.push_str(&String::from_utf8_lossy(&c.recv()));
    }
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    // Sem TLS negociado o servidor recusa texto claro.
    let mut plain = connect(&haddr);
    plain.write_all(b"GET /v1/health HTTP/1.1\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    let _ = plain.read_to_end(&mut buf);
    assert!(!String::from_utf8_lossy(&buf).contains("\"ok\":true"));
}

// --- PKI própria + certificado de cliente (mTLS) ---------------------------

fn pg_startup(user: &str) -> Vec<u8> {
    let mut startup = 196608u32.to_be_bytes().to_vec();
    startup.extend_from_slice(format!("user\0{user}\0\0").as_bytes());
    let mut msg = ((startup.len() + 4) as u32).to_be_bytes().to_vec();
    msg.extend_from_slice(&startup);
    msg
}

fn pg_ssl_connect(addr: &str) -> TcpStream {
    let mut s = connect(addr);
    s.write_all(&8u32.to_be_bytes()).unwrap();
    s.write_all(&80877103u32.to_be_bytes()).unwrap();
    let mut b = [0u8; 1];
    s.read_exact(&mut b).unwrap();
    assert_eq!(b[0], b'S');
    s
}

/// Lê mensagens cifradas até `ReadyForQuery` (ou até o `ErrorResponse`).
fn pg_read_until_ready<S: Read + Write>(c: &mut tls_client::Client<S>) -> Vec<u8> {
    let mut got = Vec::new();
    while !got.ends_with(&[b'Z', 0, 0, 0, 5, b'I']) && got.first() != Some(&b'E') {
        got.extend(c.recv());
    }
    got
}

fn pg_query<S: Read + Write>(c: &mut tls_client::Client<S>, sql: &str) -> String {
    let mut q = b"Q".to_vec();
    q.extend_from_slice(&((sql.len() + 5) as u32).to_be_bytes());
    q.extend_from_slice(sql.as_bytes());
    q.push(0);
    c.send(&q);
    String::from_utf8_lossy(&pg_read_until_ready(c)).into_owned()
}

fn client_identity(dir: &std::path::Path, user: &str) -> (PrivateKey, Vec<Vec<u8>>) {
    client_identity_files(
        &dir.join(format!("client-{user}.key")),
        &dir.join(format!("client-{user}.crt")),
        &[],
    )
}

fn client_identity_files(
    key: &std::path::Path,
    crt: &std::path::Path,
    extra: &[&std::path::Path],
) -> (PrivateKey, Vec<Vec<u8>>) {
    let key = PrivateKey::from_pem(&std::fs::read_to_string(key).unwrap()).unwrap();
    let mut chain = Vec::new();
    for f in std::iter::once(&crt).chain(extra.iter()) {
        chain.extend(
            mini_db::x509::pem_all(&std::fs::read_to_string(f).unwrap(), "CERTIFICATE").unwrap(),
        );
    }
    (key, chain)
}

#[test]
fn mtls_client_certificates_authenticate_database_users() {
    use mini_db::tls::{ClientAuth, Identity};
    use mini_db::x509::{self, Kind};
    let pki = tmpdir("pki");
    x509::create_ca(&pki, "CA de teste").unwrap();
    x509::issue(&pki, Kind::Server, "127.0.0.1", 30).unwrap();
    x509::issue(&pki, Kind::Client, "ana", 30).unwrap();
    x509::issue(&pki, Kind::Client, "bia", 30).unwrap();
    // Outra CA: certificados dela não são aceitos.
    let rogue = tmpdir("rogue");
    x509::create_ca(&rogue, "CA intrusa").unwrap();
    x509::issue(&rogue, Kind::Client, "ana", 30).unwrap();

    let dir = tmpdir("mtls");
    let mut db = Db::open(&dir).unwrap();
    ok(&mut db, "CREATE USER ana PASSWORD 'ana123' SUPERUSER");
    ok(&mut db, "CREATE USER bia PASSWORD 'bia123' SUPERUSER");
    let shared = SharedDb::new(db);
    let roots = x509::load_roots(&std::fs::read_to_string(pki.join("ca.crt")).unwrap()).unwrap();
    let identity = Identity::load(&pki.join("server.key"), &pki.join("server.crt"))
        .unwrap()
        .with_client_auth(ClientAuth::Required(roots.clone()));
    let opts = NetOptions {
        tls: Some(std::sync::Arc::new(identity)),
        ..NetOptions::default()
    };
    let addr = free_addr();
    {
        let (db, addr, opts) = (shared.clone(), addr.clone(), opts.clone());
        thread::spawn(move || mini_db::pg::serve(db, &addr, opts));
    }

    // Certificado de "ana" + usuário ana: entra sem senha (sem SCRAM).
    let mut c =
        tls_client::Client::connect_with(pg_ssl_connect(&addr), Some(client_identity(&pki, "ana")));
    c.send(&pg_startup("ana"));
    let got = pg_read_until_ready(&mut c);
    assert_eq!(
        &got[..9],
        &[b'R', 0, 0, 0, 8, 0, 0, 0, 0],
        "AuthenticationOk direto"
    );
    let who = pg_query(
        &mut c,
        "SELECT current_user, ssl_is_used(), ssl_client_dn()",
    );
    assert!(
        who.contains("ana") && who.contains("CN=ana") && who.contains('t'),
        "{who:?}"
    );
    let ssl = pg_query(
        &mut c,
        "SELECT ssl, version, client_dn, issuer_dn FROM pg_stat_ssl",
    );
    assert!(
        ssl.contains("TLSv1.3") && ssl.contains("CN=ana") && ssl.contains("CA de teste"),
        "{ssl:?}"
    );

    // Certificado de "bia" não vale para o usuário ana.
    let mut c =
        tls_client::Client::connect_with(pg_ssl_connect(&addr), Some(client_identity(&pki, "bia")));
    c.send(&pg_startup("ana"));
    let got = String::from_utf8_lossy(&c.recv()).into_owned();
    assert!(got.starts_with('E') && got.contains("28000"), "{got:?}");

    // Sem certificado ou com certificado de outra CA: o handshake falha com
    // alerta cifrado (certificate_required = 116, unknown_ca = 48).
    for (identity, code) in [(None, 116u8), (Some(client_identity(&rogue, "ana")), 48)] {
        let mut c = tls_client::Client::connect_with(pg_ssl_connect(&addr), identity);
        assert_eq!(c.recv_record(), (21, vec![2, code]));
    }

    // HTTPS: o CN do certificado vira o usuário da requisição.
    let haddr = free_addr();
    {
        let (db, haddr, opts) = (shared.clone(), haddr.clone(), opts.clone());
        let metrics = std::sync::Arc::new(mini_db::metrics::Metrics::new());
        thread::spawn(move || mini_db::http::serve_http_with(db, metrics, &haddr, opts));
    }
    let mut c =
        tls_client::Client::connect_with(connect(&haddr), Some(client_identity(&pki, "bia")));
    let body = r#"{"sql":"SELECT current_user"}"#;
    c.send(
        format!(
            "POST /v1/sql HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    let mut resp = String::from_utf8_lossy(&c.recv()).into_owned();
    while !resp.contains("bia") && resp.len() < 4000 {
        resp.push_str(&String::from_utf8_lossy(&c.recv()));
    }
    assert!(
        resp.starts_with("HTTP/1.1 200") && resp.contains("bia"),
        "{resp}"
    );
    let _ = (pki, rogue);
}

#[test]
fn mtls_optional_mode_and_chain_files() {
    use mini_db::tls::{ClientAuth, Identity};
    use mini_db::x509::{self, Kind};
    let pki = tmpdir("pki2");
    x509::create_ca(&pki, "CA opcional").unwrap();
    x509::issue(&pki, Kind::Server, "127.0.0.1", 30).unwrap();
    x509::issue(&pki, Kind::Client, "ana", 30).unwrap();
    let roots = x509::load_roots(&std::fs::read_to_string(pki.join("ca.crt")).unwrap()).unwrap();
    // Cadeia no arquivo: folha + CA (a CA segue como "intermediária").
    let both = format!(
        "{}{}",
        std::fs::read_to_string(pki.join("server.crt")).unwrap(),
        std::fs::read_to_string(pki.join("ca.crt")).unwrap()
    );
    std::fs::write(pki.join("chain.crt"), both).unwrap();
    let identity = Identity::load(&pki.join("server.key"), &pki.join("chain.crt"))
        .unwrap()
        .with_client_auth(ClientAuth::Optional(roots));
    assert_eq!(identity.chain.len(), 1);
    let dir = tmpdir("mtls2");
    let shared = SharedDb::new(Db::open(&dir).unwrap());
    let opts = NetOptions {
        tls: Some(std::sync::Arc::new(identity)),
        ..NetOptions::default()
    };
    let addr = free_addr();
    {
        let (db, addr, opts) = (shared.clone(), addr.clone(), opts.clone());
        thread::spawn(move || mini_db::pg::serve(db, &addr, opts));
    }
    // Sem certificado: permitido no modo opcional (banco sem usuários).
    let mut c = tls_client::Client::connect(pg_ssl_connect(&addr));
    c.send(&pg_startup("dev"));
    assert_eq!(&pg_read_until_ready(&mut c)[..5], &[b'R', 0, 0, 0, 8]);
    let ssl = pg_query(&mut c, "SELECT ssl, client_dn FROM pg_stat_ssl");
    assert!(ssl.contains('t') && !ssl.contains("CN="), "{ssl:?}");
    // Com certificado válido: o DN aparece.
    let mut c =
        tls_client::Client::connect_with(pg_ssl_connect(&addr), Some(client_identity(&pki, "ana")));
    c.send(&pg_startup("dev"));
    assert_eq!(&pg_read_until_ready(&mut c)[..5], &[b'R', 0, 0, 0, 8]);
    let ssl = pg_query(&mut c, "SELECT client_dn FROM pg_stat_ssl");
    assert!(ssl.contains("CN=ana"), "{ssl:?}");
}

#[test]
fn pg_catalog_extended_relations_have_real_data() {
    let dir = tmpdir("pgmore");
    let mut db = Db::open(&dir).unwrap();
    ok(
        &mut db,
        "CREATE TABLE pai (id INT PRIMARY KEY, nome TEXT NOT NULL)",
    );
    ok(&mut db, "CREATE TABLE filho (id INT PRIMARY KEY, pai_id INT REFERENCES pai(id) ON DELETE CASCADE, n INT CHECK (n > 0))");
    ok(&mut db, "CREATE TABLE log (msg TEXT)");
    ok(
        &mut db,
        "CREATE TRIGGER audita AFTER INSERT ON pai BEGIN INSERT INTO log VALUES (NEW.nome); END",
    );
    ok(&mut db, "CREATE INDEX ix_nome ON pai (nome)");
    ok(&mut db, "CREATE USER root PASSWORD 'r' SUPERUSER");
    ok(
        &mut db,
        "INSERT INTO pai VALUES (1, 'a'), (2, 'b'), (3, 'c')",
    );
    ok(&mut db, "ANALYZE");
    let q = |db: &mut Db, sql: &str| q(db, sql).join("\n");
    // pg_proc / pg_aggregate / pg_operator / pg_cast / pg_language
    let n = q(
        &mut db,
        "SELECT count(*) FROM pg_proc WHERE proname IN ('lower','count','row_number','vec_cosine')",
    );
    assert!(n.contains('4'), "{n}");
    assert!(q(
        &mut db,
        "SELECT prokind FROM pg_proc WHERE proname = 'count'"
    )
    .contains('a'));
    assert!(q(&mut db, "SELECT aggfnoid FROM pg_aggregate a JOIN pg_proc p ON p.oid = a.aggfnoid WHERE p.proname = 'sum'").parse::<i64>().unwrap() > 30_000);
    assert!(q(
        &mut db,
        "SELECT oprname FROM pg_operator WHERE oprname = '<=>'"
    )
    .contains("<=>"));
    assert!(q(&mut db, "SELECT count(*) FROM pg_cast") != "0");
    assert!(q(&mut db, "SELECT lanname FROM pg_language").contains("sql"));
    assert!(q(&mut db, "SELECT extname FROM pg_extension").contains("minidb_vector"));
    assert!(q(&mut db, "SELECT cfgname FROM pg_ts_config").contains("portuguese"));
    assert!(q(&mut db, "SELECT collname FROM pg_collation").contains("POSIX"));
    // gatilhos
    let tg = q(&mut db, "SELECT tgname, tgtype FROM pg_trigger");
    assert!(tg.contains("audita") && tg.contains("5"), "{tg}"); // linha + INSERT = 1 + 4
    let tr = q(&mut db, "SELECT trigger_name, event_manipulation, event_object_table, action_timing FROM information_schema.triggers");
    assert!(
        tr.contains("audita")
            && tr.contains("INSERT")
            && tr.contains("pai")
            && tr.contains("AFTER"),
        "{tr}"
    );
    // restrições
    let rc = q(
        &mut db,
        "SELECT delete_rule FROM information_schema.referential_constraints",
    );
    assert!(rc.contains("CASCADE"), "{rc}");
    let cc = q(
        &mut db,
        "SELECT check_clause FROM information_schema.check_constraints",
    );
    assert!(cc.contains("n > 0") && cc.contains("IS NOT NULL"), "{cc}");
    // rotinas
    assert!(q(
        &mut db,
        "SELECT routine_name FROM information_schema.routines WHERE routine_name = 'lower'"
    )
    .contains("lower"));
    // estatísticas do ANALYZE
    let st = q(
        &mut db,
        "SELECT relname, n_live_tup FROM pg_stat_user_tables WHERE relname = 'pai'",
    );
    assert!(st.contains("pai") && st.contains('3'), "{st}");
    let ps = q(
        &mut db,
        "SELECT attname, n_distinct FROM pg_stats WHERE tablename = 'pai' ORDER BY attname",
    );
    assert!(ps.contains("id") && ps.contains("nome"), "{ps}");
    assert!(
        q(&mut db, "SELECT indexrelname FROM pg_stat_user_indexes")
            .lines()
            .count()
            >= 1
    );
    // dependências e sessão
    let dep = q(
        &mut db,
        "SELECT count(*) FROM pg_depend WHERE deptype = 'a'",
    );
    assert!(dep != "0", "{dep}");
    assert!(q(&mut db, "SELECT usename, state FROM pg_stat_activity").contains("active"));
    assert!(q(&mut db, "SELECT ssl FROM pg_stat_ssl").contains('f'));
    assert!(q(&mut db, "SELECT name FROM pg_timezone_names").contains("UTC"));
}

/// Sobe um servidor PG com mTLS obrigatório e confere que o usuário `ana` entra
/// só com o certificado; devolve o esquema de assinatura que o servidor usou.
fn mtls_login(
    server: mini_db::tls::Identity,
    roots: Vec<mini_db::x509::Cert>,
    client: (PrivateKey, Vec<Vec<u8>>),
) -> (u16, u16) {
    use mini_db::tls::ClientAuth;
    let dir = tmpdir("mtls-algo");
    let mut db = Db::open(&dir).unwrap();
    ok(&mut db, "CREATE USER ana PASSWORD 'ana123' SUPERUSER");
    let opts = NetOptions {
        tls: Some(std::sync::Arc::new(
            server.with_client_auth(ClientAuth::Required(roots)),
        )),
        ..NetOptions::default()
    };
    let addr = free_addr();
    {
        let (db, addr) = (SharedDb::new(db), addr.clone());
        thread::spawn(move || mini_db::pg::serve(db, &addr, opts));
    }
    let client_scheme = client.0.tls_schemes()[0];
    let mut c = tls_client::Client::connect_with(pg_ssl_connect(&addr), Some(client));
    c.send(&pg_startup("ana"));
    let got = pg_read_until_ready(&mut c);
    assert_eq!(&got[..9], &[b'R', 0, 0, 0, 8, 0, 0, 0, 0], "{got:?}");
    let who = pg_query(&mut c, "SELECT current_user, ssl_client_dn()");
    assert!(who.contains("ana") && who.contains("CN=ana"), "{who:?}");
    (c.server_scheme, client_scheme)
}

#[test]
fn tls_and_mtls_with_ed25519_p256_p384_keys_and_mixed_cas() {
    use mini_db::tls::Identity;
    use mini_db::x509::{self, Kind};
    let cases = [
        (KeyAlgo::Ed25519, KeyAlgo::Ed25519, 0x0807),
        (KeyAlgo::P256, KeyAlgo::P256, 0x0403),
        (KeyAlgo::P384, KeyAlgo::P384, 0x0503),
        (KeyAlgo::Ed25519, KeyAlgo::P256, 0x0403), // CA Ed25519 assinando folha P-256
        (KeyAlgo::P384, KeyAlgo::Ed25519, 0x0807), // CA P-384 assinando folha Ed25519
        (KeyAlgo::Rsa2048, KeyAlgo::P256, 0x0403), // CA RSA gerada por nós
        (KeyAlgo::P256, KeyAlgo::Rsa2048, 0x0804), // folha RSA gerada por nós
    ];
    for (ca_algo, leaf_algo, scheme) in cases {
        let pki = tmpdir("pki-algo");
        x509::create_ca_with(&pki, "CA mista", ca_algo).unwrap();
        x509::issue_with(&pki, Kind::Server, "127.0.0.1", 30, leaf_algo).unwrap();
        x509::issue_with(&pki, Kind::Client, "ana", 30, leaf_algo).unwrap();
        let roots =
            x509::load_roots(&std::fs::read_to_string(pki.join("ca.crt")).unwrap()).unwrap();
        let server = Identity::load(&pki.join("server.key"), &pki.join("server.crt")).unwrap();
        let (srv, cli) = mtls_login(server, roots, client_identity(&pki, "ana"));
        assert_eq!((srv, cli), (scheme, scheme), "{ca_algo:?}/{leaf_algo:?}");
    }
}

#[test]
fn tls_and_mtls_with_rsa_and_ecdsa_certificates_from_openssl() {
    use mini_db::tls::Identity;
    use mini_db::x509;
    let fx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pki");
    let tmp = tmpdir("fx-chain");
    std::fs::create_dir_all(&tmp).unwrap();
    for (kind, server_key, scheme_srv, scheme_cli) in [
        ("rsa", "rsa-server.key", 0x0804, 0x0804),
        ("rsa", "rsa-server.p8.key", 0x0804, 0x0804),
        ("rsa", "rsa-server.pkcs1.key", 0x0804, 0x0804),
        ("ec", "ec-server.key", 0x0403, 0x0503),
        ("ec", "ec-server.p8.key", 0x0403, 0x0503),
    ] {
        // a cadeia do servidor é folha + intermediária, como a Let's Encrypt entrega
        let chain = format!(
            "{}{}",
            std::fs::read_to_string(fx.join(format!("{kind}-server.crt"))).unwrap(),
            std::fs::read_to_string(fx.join(format!("{kind}-inter.crt"))).unwrap()
        );
        let chain_path = tmp.join(format!("{kind}-chain.crt"));
        std::fs::write(&chain_path, chain).unwrap();
        let server = Identity::load(&fx.join(server_key), &chain_path).unwrap();
        let roots = x509::load_roots(
            &std::fs::read_to_string(fx.join(format!("{kind}-root.crt"))).unwrap(),
        )
        .unwrap();
        let client = client_identity_files(
            &fx.join(format!("{kind}-client.key")),
            &fx.join(format!("{kind}-client.crt")),
            &[&fx.join(format!("{kind}-inter.crt"))],
        );
        let got = mtls_login(server, roots, client);
        assert_eq!(got, (scheme_srv, scheme_cli), "{server_key}");
    }
}
