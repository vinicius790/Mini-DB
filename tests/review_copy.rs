//! `COPY ... FROM STDIN` e `COPY ... TO STDOUT` (formatos texto e CSV) no protocolo PostgreSQL.
use mini_db::config::NetOptions;
use mini_db::mvcc::SharedDb;
use mini_db::Db;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    // Uma pasta por chamada: os testes rodam em paralelo no mesmo processo.
    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let name = format!("minidb-copy-{tag}-{}-{n}", std::process::id());
    let p = std::env::temp_dir().join(name);
    let _ = std::fs::remove_dir_all(&p);
    p
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

type Msgs = Vec<(u8, Vec<u8>)>;

struct Pg {
    s: TcpStream,
}

impl Pg {
    fn msg(&mut self, ty: u8, body: &[u8]) {
        self.s.write_all(&[ty]).unwrap();
        let len = (body.len() + 4) as u32;
        self.s.write_all(&len.to_be_bytes()).unwrap();
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

    fn until_ready(&mut self) -> Msgs {
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

    fn startup(addr: &str) -> Self {
        let mut s = connect(addr);
        let mut body = 196608u32.to_be_bytes().to_vec();
        body.extend_from_slice(b"user\0teste\0database\0minidb\0\0");
        s.write_all(&((body.len() + 4) as u32).to_be_bytes())
            .unwrap();
        s.write_all(&body).unwrap();
        let mut c = Self { s };
        let (ty, body) = c.read();
        assert_eq!((ty, &body[..]), (b'R', &0u32.to_be_bytes()[..]));
        c.until_ready();
        c
    }

    fn query(&mut self, sql: &str) -> Msgs {
        let mut b = sql.as_bytes().to_vec();
        b.push(0);
        self.msg(b'Q', &b);
        self.until_ready()
    }
}

fn kinds(msgs: &Msgs) -> String {
    msgs.iter().map(|(t, _)| *t as char).collect()
}

fn rows(msgs: &Msgs) -> Vec<Vec<Option<String>>> {
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
                        return None;
                    }
                    let end = pos + len as usize;
                    let v = String::from_utf8_lossy(&body[pos..end]).into_owned();
                    pos = end;
                    Some(v)
                })
                .collect()
        })
        .collect()
}

fn tags(msgs: &Msgs) -> Vec<String> {
    msgs.iter()
        .filter(|(t, _)| *t == b'C')
        .map(|(_, b)| String::from_utf8_lossy(&b[..b.len() - 1]).into_owned())
        .collect()
}

fn errors(msgs: &Msgs) -> Vec<String> {
    msgs.iter()
        .filter(|(t, _)| *t == b'E')
        .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
        .collect()
}

/// Linhas de dados (`CopyData`) como texto.
fn copy_lines(msgs: &Msgs) -> Vec<String> {
    msgs.iter()
        .filter(|(t, _)| *t == b'd')
        .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
        .collect()
}

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

fn server(tag: &str) -> Pg {
    let mut db = Db::open(tmpdir(tag)).unwrap();
    db.execute_sql("CREATE TABLE copiar (id INT PRIMARY KEY, nome TEXT, nota REAL)")
        .unwrap();
    let shared = SharedDb::new(db);
    let addr = free_addr();
    let a = addr.clone();
    thread::spawn(move || mini_db::pg::serve(shared, &a, NetOptions::default()));
    Pg::startup(&addr)
}

fn count(c: &mut Pg) -> String {
    let m = c.query("SELECT count(*) FROM copiar");
    rows(&m)[0][0].clone().unwrap()
}

/// `COPY ... FROM STDIN` completo: cada pedaço vai num `CopyData`.
fn copy_in(c: &mut Pg, sql: &str, parts: &[&str]) -> Msgs {
    let mut q = sql.as_bytes().to_vec();
    q.push(0);
    c.msg(b'Q', &q);
    assert_eq!(c.read().0, b'G', "{sql}");
    for p in parts {
        c.msg(b'd', p.as_bytes());
    }
    c.msg(b'c', &[]);
    c.until_ready()
}

#[test]
fn copy_from_stdin_and_to_stdout_text_format() {
    let mut c = server("texto");
    // FROM STDIN: três linhas, uma com \N e uma com tab escapado; dados em pedaços
    // que não coincidem com as linhas.
    c.msg(b'Q', b"COPY copiar FROM STDIN\0");
    let (ty, body) = c.read();
    assert_eq!(ty, b'G');
    assert_eq!(body, [0, 0, 3, 0, 0, 0, 0, 0, 0]);
    c.msg(b'd', b"1\tAna\t9.5\n2\t\\N\t7\n3\tCom\\t");
    c.msg(b'd', b"tab\t\\N\n\\.\n");
    c.msg(b'c', &[]);
    let m = c.until_ready();
    assert_eq!(kinds(&m), "CZ", "{:?}", errors(&m));
    assert_eq!(tags(&m), ["COPY 3"]);
    let m = c.query("SELECT id, nome, nota FROM copiar ORDER BY id");
    assert_eq!(
        rows(&m),
        [
            vec![s("1"), s("Ana"), s("9.5")],
            vec![s("2"), None, s("7")],
            vec![s("3"), s("Com\ttab"), None],
        ]
    );

    // TO STDOUT.
    let m = c.query("COPY copiar TO STDOUT");
    assert_eq!(kinds(&m), "HdddcCZ");
    assert_eq!(m[0].1, [0, 0, 3, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        copy_lines(&m),
        ["1\tAna\t9.5\n", "2\t\\N\t7\n", "3\tCom\\ttab\t\\N\n"]
    );
    assert_eq!(tags(&m), ["COPY 3"]);

    // Colunas escolhidas, consulta e opções.
    let m = c.query("COPY copiar (nome, id) TO STDOUT WITH (FORMAT text, DELIMITER '|')");
    assert_eq!(copy_lines(&m), ["Ana|1\n", "\\N|2\n", "Com\\ttab|3\n"]);
    let m = c.query("COPY (SELECT id FROM copiar WHERE id > 1 ORDER BY id) TO STDOUT;");
    assert_eq!(copy_lines(&m), ["2\n", "3\n"]);
    assert_eq!(tags(&m), ["COPY 2"]);

    // FROM com lista de colunas, NULL personalizado e transação do cliente.
    assert_eq!(c.query("BEGIN").last().unwrap().1, b"T");
    let copy = b"COPY copiar (id, nome) FROM STDIN WITH NULL AS 'nada'\0";
    c.msg(b'Q', copy);
    assert_eq!(c.read().0, b'G');
    c.msg(b'd', b"10\tnada\n11\tx\n");
    c.msg(b'c', &[]);
    assert_eq!(tags(&c.until_ready()), ["COPY 2"]);
    c.query("ROLLBACK");
    assert_eq!(count(&mut c), "3");
}

#[test]
fn copy_from_failure_writes_nothing() {
    let mut c = server("falha");
    // CopyFail.
    c.msg(b'Q', b"COPY copiar FROM STDIN\0");
    assert_eq!(c.read().0, b'G');
    c.msg(b'd', b"20\tx\t1\n");
    c.msg(b'f', b"desisti\0");
    let m = c.until_ready();
    assert!(errors(&m)[0].contains("desisti"), "{:?}", errors(&m));
    assert_eq!(count(&mut c), "0");

    // Linha malformada (coluna a menos) e valor de tipo errado.
    for dados in ["1\ta\t1\n2\tb\n", "1\ta\t1\nx\tb\t2\n"] {
        c.msg(b'Q', b"COPY copiar FROM STDIN\0");
        assert_eq!(c.read().0, b'G');
        c.msg(b'd', dados.as_bytes());
        c.msg(b'c', &[]);
        let m = c.until_ready();
        assert_eq!(errors(&m).len(), 1, "{m:?}");
        assert_eq!(count(&mut c), "0");
    }

    // Mais de um lote de INSERT: o último lote falha (id 1 repetido) e o primeiro,
    // já executado, precisa ser desfeito.
    let mut dados = String::new();
    for i in 100..700 {
        dados.push_str(&format!("{i}\tn{i}\t1\n"));
    }
    dados.push_str("1\tdup\t1\n1\tdup\t1\n");
    c.msg(b'Q', b"COPY copiar FROM STDIN\0");
    assert_eq!(c.read().0, b'G');
    c.msg(b'd', dados.as_bytes());
    c.msg(b'c', &[]);
    let m = c.until_ready();
    assert_eq!(errors(&m).len(), 1, "{m:?}");
    assert_eq!(*m.last().unwrap(), (b'Z', vec![b'I']));
    assert_eq!(count(&mut c), "0");
}

#[test]
fn copy_errors_keep_the_connection_usable() {
    let mut c = server("erros");
    let m = c.query("COPY nao_existe FROM STDIN");
    assert_eq!(kinds(&m), "EZ");
    assert!(errors(&m)[0].contains("42P01"), "{:?}", errors(&m));
    let m = c.query("COPY nao_existe TO STDOUT");
    assert!(errors(&m)[0].contains("42P01"), "{:?}", errors(&m));
    for sql in [
        "COPY copiar (zzz) FROM STDIN",
        "COPY copiar FROM '/tmp/x'",
        "COPY copiar FROM STDIN WITH (FORMAT binary)",
        "COPY (SELECT 1) FROM STDIN",
        "COPY copiar",
    ] {
        let m = c.query(sql);
        assert_eq!(kinds(&m), "EZ", "{sql}: {m:?}");
    }
    // CopyData solto, fora de um COPY, é ignorado.
    c.msg(b'd', b"lixo");
    let m = c.query("SELECT 1");
    assert_eq!(rows(&m), [vec![s("1")]]);
}

#[test]
fn copy_csv_round_trip_with_header() {
    let mut c = server("csv");
    // HEADER descarta a 1ª linha; as aspas protegem vírgula, aspa dobrada e quebra de linha
    // (aqui partida entre dois CopyData); vazio sem aspas é NULL e "" é texto vazio.
    let sql = "COPY copiar FROM STDIN WITH (FORMAT csv, HEADER true)";
    let dados = [
        "id,nome,nota\n1,\"Silva, Ana\",9.5\n2,,7\n3,\"diz \"\"oi\"\"\n",
        "tchau\",\n4,\"\",1\n\\.\n",
    ];
    let m = copy_in(&mut c, sql, &dados);
    assert_eq!(kinds(&m), "CZ", "{:?}", errors(&m));
    assert_eq!(tags(&m), ["COPY 4"]);
    let m = c.query("SELECT id, nome, nota FROM copiar ORDER BY id");
    assert_eq!(
        rows(&m),
        [
            vec![s("1"), s("Silva, Ana"), s("9.5")],
            vec![s("2"), None, s("7")],
            vec![s("3"), s("diz \"oi\"\ntchau"), None],
            vec![s("4"), s(""), s("1")],
        ]
    );

    // TO STDOUT com HEADER: formato geral texto (0) e aspas só onde precisa.
    let m = c.query("COPY copiar TO STDOUT WITH (FORMAT csv, HEADER)");
    assert_eq!(kinds(&m), "HdddddcCZ");
    assert_eq!(m[0].1, [0, 0, 3, 0, 0, 0, 0, 0, 0]);
    let saida = copy_lines(&m);
    assert_eq!(
        saida,
        [
            "id,nome,nota\n",
            "1,\"Silva, Ana\",9.5\n",
            "2,,7\n",
            "3,\"diz \"\"oi\"\"\ntchau\",\n",
            "4,\"\",1\n",
        ]
    );
    assert_eq!(tags(&m), ["COPY 4"]);

    // Ida e volta pela forma antiga (`CSV HEADER`): a saída volta igual.
    c.query("DELETE FROM copiar");
    let tudo = saida.concat();
    let sql = "COPY copiar FROM STDIN CSV HEADER";
    let m = copy_in(&mut c, sql, &[tudo.as_str()]);
    assert_eq!(tags(&m), ["COPY 4"], "{:?}", errors(&m));
    let m = c.query("COPY copiar TO STDOUT WITH CSV HEADER");
    assert_eq!(copy_lines(&m), saida);
}

#[test]
fn copy_csv_delimiter_and_null() {
    let mut c = server("csv-opcoes");
    // DELIMITER ';' e NULL próprio: a vírgula é texto comum e "nulo" entre aspas é texto.
    let sql = "COPY copiar (id, nome) FROM STDIN (FORMAT csv, DELIMITER ';', NULL 'nulo')";
    let dados = ["1;a,b\n2;\"x;y\"\n3;nulo\n4;\"nulo\"\n"];
    let m = copy_in(&mut c, sql, &dados);
    assert_eq!(tags(&m), ["COPY 4"], "{:?}", errors(&m));
    let m = c.query("SELECT id FROM copiar WHERE nome IS NULL");
    assert_eq!(rows(&m), [vec![s("3")]]);
    let sql = "COPY copiar (id, nome) TO STDOUT (FORMAT csv, DELIMITER ';', NULL 'nulo')";
    let m = c.query(sql);
    assert_eq!(
        copy_lines(&m),
        ["1;a,b\n", "2;\"x;y\"\n", "3;nulo\n", "4;\"nulo\"\n"]
    );
}

#[test]
fn copy_csv_errors_write_nothing() {
    let mut c = server("csv-erros");
    // Opções inválidas: recusadas antes do CopyInResponse.
    for sql in [
        "COPY copiar FROM STDIN WITH (FORMAT csv, DELIMITER ';;')",
        "COPY copiar FROM STDIN WITH (FORMAT csv, QUOTE ',')",
        "COPY copiar FROM STDIN WITH (FORMAT csv, NULL ',')",
        "COPY copiar TO STDOUT WITH (FORMAT csv, FOO 'x')",
        "COPY copiar TO STDOUT WITH (FORMAT text, HEADER)",
    ] {
        let m = c.query(sql);
        assert_eq!(kinds(&m), "EZ", "{sql}: {m:?}");
    }

    // Coluna a mais na linha 3 (o cabeçalho é a 1): erro com o número da linha.
    let sql = "COPY copiar FROM STDIN CSV HEADER";
    let m = copy_in(&mut c, sql, &["id,nome,nota\n1,a,1\n2,b,2,9\n"]);
    let e = errors(&m);
    assert!(e.len() == 1 && e[0].contains("linha 3"), "{e:?}");
    // Aspas sem fechamento.
    let sql = "COPY copiar FROM STDIN CSV";
    let m = copy_in(&mut c, sql, &["1,\"aberta,1\n"]);
    let e = errors(&m);
    assert!(e.len() == 1 && e[0].contains("aspas"), "{e:?}");
    assert_eq!(count(&mut c), "0");
}
