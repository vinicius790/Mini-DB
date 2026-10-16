//! Protocolo de rede do PostgreSQL (versão 3): `psql` e os drivers PG (libpq,
//! node-postgres, psycopg, JDBC, pgx...) conectam direto no Mini-DB.
//!
//! Suporta o fluxo de startup (SSL/GSS recusados com `N`), autenticação
//! SCRAM-SHA-256 (quando há usuários), senha em claro contra o token (quando
//! só há token) ou `trust` (banco sem usuários), consulta simples (`Q`) e o
//! protocolo estendido (Parse/Bind/Describe/Execute/Sync/Close). Resultados vão
//! em formato texto; parâmetros chegam em texto ou binário (inteiros, reais,
//! booleanos e texto). Comandos de sessão dos clientes (`SET`, `SHOW x`,
//! `RESET`, `DISCARD`, `DEALLOCATE`) são aceitos como no-op. `COPY ... FROM STDIN` e
//! `COPY ... TO STDOUT` (formatos texto e CSV) valem na consulta simples.

use crate::auth::{self, Privilege, ScramServer};
use crate::config::NetOptions;
use crate::db::ExecResult;
use crate::error::{Error, Result};
use crate::mvcc::{Session, SharedDb};
use crate::rel::Value;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const PROTOCOL_3: u32 = 196_608;
const SSL_REQUEST: u32 = 80_877_103;
const GSSENC_REQUEST: u32 = 80_877_104;
const CANCEL_REQUEST: u32 = 80_877_102;
const MAX_MESSAGE: usize = 256 << 20;
/// Antes da autenticação (SASL/senha) o cliente ainda é anônimo: como o PostgreSQL.
const MAX_AUTH_MESSAGE: usize = 65_535;
const IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

// OIDs de tipos do PostgreSQL.
const OID_BOOL: u32 = 16;
const OID_INT8: u32 = 20;
const OID_INT2: u32 = 21;
const OID_INT4: u32 = 23;
const OID_TEXT: u32 = 25;
const OID_FLOAT4: u32 = 700;
const OID_FLOAT8: u32 = 701;
const OID_VARCHAR: u32 = 1043;

/// Socket em claro ou cifrado (TLS 1.3), com buffers de leitura e escrita.
enum Io {
    Plain(TcpStream),
    Tls(Box<crate::tls::TlsStream<TcpStream>>),
    Closed,
}

struct Chan {
    io: Io,
    rbuf: Vec<u8>,
    rpos: usize,
    wbuf: Vec<u8>,
}

impl Chan {
    fn new(stream: TcpStream) -> Self {
        Self {
            io: Io::Plain(stream),
            rbuf: Vec::new(),
            rpos: 0,
            wbuf: Vec::new(),
        }
    }

    /// Faz o handshake TLS sobre o socket em claro.
    fn upgrade(&mut self, identity: &crate::tls::Identity) -> io::Result<()> {
        // Bytes em claro já lidos junto do SSLRequest seriam tratados como se
        // viessem do canal cifrado (injeção antes do handshake): recusa.
        if self.rpos < self.rbuf.len() {
            return Err(io::Error::other("dados em claro antes do handshake TLS"));
        }
        self.rbuf.clear();
        self.rpos = 0;
        let Io::Plain(stream) = std::mem::replace(&mut self.io, Io::Closed) else {
            return Err(io::Error::other("TLS já negociado"));
        };
        self.io = Io::Tls(Box::new(crate::tls::accept(stream, identity)?));
        Ok(())
    }

    /// Certificado de cliente verificado na sessão TLS, se houver.
    fn peer(&self) -> Option<crate::tls::Peer> {
        match &self.io {
            Io::Tls(t) => t.peer().cloned(),
            _ => None,
        }
    }

    fn peer_addr(&self) -> Option<String> {
        match &self.io {
            Io::Plain(s) => s.peer_addr().ok().map(|a| a.ip().to_string()),
            Io::Tls(t) => t.get_ref().peer_addr().ok().map(|a| a.ip().to_string()),
            Io::Closed => None,
        }
    }

    fn is_tls(&self) -> bool {
        matches!(self.io, Io::Tls(_))
    }

    fn raw(&mut self) -> io::Result<&mut dyn ReadWrite> {
        match &mut self.io {
            Io::Plain(s) => Ok(s),
            Io::Tls(t) => Ok(&mut **t),
            Io::Closed => Err(io::Error::other("conexão fechada")),
        }
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

impl Read for Chan {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rpos >= self.rbuf.len() {
            let mut tmp = vec![0u8; 16384];
            let n = self.raw()?.read(&mut tmp)?;
            tmp.truncate(n);
            self.rbuf = tmp;
            self.rpos = 0;
            if n == 0 {
                return Ok(0);
            }
        }
        let n = (self.rbuf.len() - self.rpos).min(buf.len());
        buf[..n].copy_from_slice(&self.rbuf[self.rpos..self.rpos + n]);
        self.rpos += n;
        Ok(n)
    }
}

impl Write for Chan {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.wbuf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let data = std::mem::take(&mut self.wbuf);
        if !data.is_empty() {
            let raw = self.raw()?;
            raw.write_all(&data)?;
            raw.flush()?;
        }
        Ok(())
    }
}

pub fn serve(db: SharedDb, addr: &str, opts: NetOptions) -> Result<()> {
    let listener = TcpListener::bind(addr).map_err(|e| Error::Server(e.to_string()))?;
    eprintln!("minidb pg listen {addr}");
    let active = Arc::new(AtomicUsize::new(0));
    let opts = Arc::new(opts);
    for incoming in listener.incoming() {
        let stream = incoming.map_err(|e| Error::Server(e.to_string()))?;
        let _ = stream.set_read_timeout(Some(IDLE_TIMEOUT));
        let _ = stream.set_nodelay(true);
        if active.load(Ordering::Acquire) >= opts.max_connections {
            let mut w = Chan::new(stream);
            let _ = error_response(&mut w, "53300", "muitas conexões");
            let _ = w.flush();
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let (db, active, opts) = (db.clone(), Arc::clone(&active), Arc::clone(&opts));
        // `Slot` devolve a vaga mesmo se a thread terminar em panic.
        struct Slot(Arc<AtomicUsize>);
        impl Drop for Slot {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let slot = Slot(active);
        crate::server::spawn_connection(move || {
            let _slot = slot;
            if let Err(e) = handle(&db, stream, &opts) {
                if !matches!(&e, Error::Io(io) if io.kind() == std::io::ErrorKind::UnexpectedEof) {
                    eprintln!("pg client: {e}");
                }
            }
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mensagens
// ---------------------------------------------------------------------------

fn read_u32(r: &mut impl Read) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn read_body(r: &mut impl Read, len: usize) -> Result<Vec<u8>> {
    if len > MAX_MESSAGE {
        return Err(Error::Server("mensagem grande demais".into()));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Próxima mensagem do cliente: `(tipo, corpo)`, com corpo de até `max` bytes
/// (conferido antes de alocar).
fn read_message(r: &mut impl Read, max: usize) -> Result<(u8, Vec<u8>)> {
    let mut ty = [0u8; 1];
    r.read_exact(&mut ty)?;
    let len = read_u32(r)? as usize;
    if len < 4 || len - 4 > max {
        return Err(Error::Server("tamanho de mensagem inválido".into()));
    }
    Ok((ty[0], read_body(r, len - 4)?))
}

fn send(w: &mut impl Write, ty: u8, body: &[u8]) -> Result<()> {
    w.write_all(&[ty])?;
    w.write_all(&((body.len() + 4) as u32).to_be_bytes())?;
    w.write_all(body)?;
    Ok(())
}

fn cstr(s: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

/// Lê uma string terminada em NUL a partir de `pos`, avançando-o.
fn take_cstr(body: &[u8], pos: &mut usize) -> Result<String> {
    let rest = &body[(*pos).min(body.len())..];
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error::Server("string sem terminador".into()))?;
    let s = String::from_utf8_lossy(&rest[..end]).into_owned();
    *pos += end + 1;
    Ok(s)
}

fn take_u16(body: &[u8], pos: &mut usize) -> Result<u16> {
    let b = body
        .get(*pos..*pos + 2)
        .ok_or_else(|| Error::Server("mensagem truncada".into()))?;
    *pos += 2;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn take_i32(body: &[u8], pos: &mut usize) -> Result<i32> {
    let b = body
        .get(*pos..*pos + 4)
        .ok_or_else(|| Error::Server("mensagem truncada".into()))?;
    *pos += 4;
    Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn error_response(w: &mut impl Write, code: &str, message: &str) -> Result<()> {
    let mut body = Vec::new();
    body.push(b'S');
    cstr("ERROR", &mut body);
    body.push(b'V');
    cstr("ERROR", &mut body);
    body.push(b'C');
    cstr(code, &mut body);
    body.push(b'M');
    cstr(message, &mut body);
    body.push(0);
    send(w, b'E', &body)
}

fn sqlstate(e: &Error) -> &'static str {
    match e {
        Error::Sql(_) | Error::Cli(_) | Error::InvalidInput(_) => "42601",
        Error::UnknownTable(_) => "42P01",
        Error::UnknownIndex(_) => "42704",
        Error::Constraint(_) => "23000",
        Error::Conflict(_) => "40001",
        Error::Unauthorized => "28P01",
        Error::Forbidden(_) => "42501",
        Error::ReadOnly => "25006",
        Error::TxnOpen => "25001",
        Error::TxnNotOpen => "25P01",
        Error::Unavailable(_) => "57P03",
        Error::KeyTooLarge(..) | Error::ValueTooLarge(..) => "54000",
        _ => "XX000",
    }
}

fn ready(w: &mut impl Write, status: u8) -> Result<()> {
    send(w, b'Z', &[status])?;
    w.flush()?;
    Ok(())
}

fn command_complete(w: &mut impl Write, tag: &str) -> Result<()> {
    let mut body = Vec::new();
    cstr(tag, &mut body);
    send(w, b'C', &body)
}

fn parameter_status(w: &mut impl Write, k: &str, v: &str) -> Result<()> {
    let mut body = Vec::new();
    cstr(k, &mut body);
    cstr(v, &mut body);
    send(w, b'S', &body)
}

fn oid_of(rows: &[Vec<Value>], col: usize) -> u32 {
    rows.iter()
        .find_map(|r| match r.get(col) {
            Some(Value::Int(_)) => Some(OID_INT8),
            Some(Value::Real(_)) => Some(OID_FLOAT8),
            Some(Value::Bool(_)) => Some(OID_BOOL),
            Some(Value::Text(_)) => Some(OID_TEXT),
            _ => None,
        })
        .unwrap_or(OID_TEXT)
}

fn row_description(w: &mut impl Write, columns: &[String], rows: &[Vec<Value>]) -> Result<()> {
    let mut body = Vec::new();
    body.extend_from_slice(&(columns.len() as u16).to_be_bytes());
    for (i, name) in columns.iter().enumerate() {
        let oid = oid_of(rows, i);
        let (len, modifier): (i16, i32) = match oid {
            OID_INT8 | OID_FLOAT8 => (8, -1),
            OID_BOOL => (1, -1),
            _ => (-1, -1),
        };
        cstr(name, &mut body);
        body.extend_from_slice(&0u32.to_be_bytes()); // tabela
        body.extend_from_slice(&0u16.to_be_bytes()); // coluna
        body.extend_from_slice(&oid.to_be_bytes());
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(&modifier.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes()); // formato texto
    }
    send(w, b'T', &body)
}

/// Texto de um valor no formato do PostgreSQL.
fn text_of(v: &Value) -> Option<String> {
    Some(match v {
        Value::Null => return None,
        Value::Bool(true) => "t".into(),
        Value::Bool(false) => "f".into(),
        Value::Real(x) if x.is_nan() => "NaN".into(),
        Value::Real(x) if x.is_infinite() => if *x > 0.0 { "Infinity" } else { "-Infinity" }.into(),
        Value::Real(x) => {
            let s = format!("{x:?}");
            s.strip_suffix(".0").map(str::to_string).unwrap_or(s)
        }
        other => other.to_string(),
    })
}

fn data_row(w: &mut impl Write, row: &[Value]) -> Result<()> {
    let mut body = Vec::new();
    body.extend_from_slice(&(row.len() as u16).to_be_bytes());
    for v in row {
        match text_of(v) {
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(s) => {
                body.extend_from_slice(&(s.len() as u32).to_be_bytes());
                body.extend_from_slice(s.as_bytes());
            }
        }
    }
    send(w, b'D', &body)
}

/// Resultados do dialeto chave-valor viram tabelas (`key`, `value`).
fn tabular(result: ExecResult) -> ExecResult {
    let text = |b: &[u8]| Value::Text(String::from_utf8_lossy(b).into_owned());
    match result {
        ExecResult::Rows(rows) => ExecResult::Table {
            columns: vec!["key".into(), "value".into()],
            rows: rows.iter().map(|(k, v)| vec![text(k), text(v)]).collect(),
        },
        ExecResult::Value(v) => ExecResult::Table {
            columns: vec!["value".into()],
            rows: vec![vec![v.as_deref().map_or(Value::Null, text)]],
        },
        ExecResult::Count(n) => ExecResult::Table {
            columns: vec!["count".into()],
            rows: vec![vec![Value::Int(n as i64)]],
        },
        other => other,
    }
}

/// Tag de `CommandComplete` a partir do resultado do motor.
fn tag_of(result: &ExecResult, rows: usize) -> String {
    match result {
        ExecResult::Table { .. } => format!("SELECT {rows}"),
        ExecResult::Ok(msg) => {
            let mut words = msg.split_whitespace();
            let first = words.next().unwrap_or("OK").to_ascii_uppercase();
            let second = words.next().unwrap_or("");
            match first.as_str() {
                "INSERT" => format!("INSERT 0 {}", second.parse::<u64>().unwrap_or(0)),
                "UPDATE" | "DELETE" => {
                    format!("{first} {}", second.parse::<u64>().unwrap_or(0))
                }
                "BEGIN" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" | "SET" | "RESET"
                | "DISCARD" | "DEALLOCATE" | "LISTEN" | "UNLISTEN" | "NOTIFY" | "GRANT"
                | "REVOKE" | "ANALYZE" | "REINDEX" | "TRUNCATE" | "REFRESH" => first,
                _ if second.chars().all(|c| c.is_ascii_uppercase()) && !second.is_empty() => {
                    format!("{first} {second}")
                }
                _ => first,
            }
        }
        ExecResult::Batch(_)
        | ExecResult::Rows(_)
        | ExecResult::Value(_)
        | ExecResult::Count(_) => {
            format!("SELECT {rows}")
        }
    }
}

// ---------------------------------------------------------------------------
// Parâmetros
// ---------------------------------------------------------------------------

/// Texto de parâmetro → valor: o servidor não conhece o tipo esperado, então
/// infere números e booleanos; o motor converte na atribuição.
pub fn value_from_text(s: &str) -> Value {
    let t = s.trim();
    if let Ok(n) = t.parse::<i64>() {
        let leading_zero = t.len() > 1 && t.starts_with('0');
        if !t.starts_with('+') && !leading_zero {
            return Value::Int(n);
        }
    }
    if (t.contains('.') || t.contains('e') || t.contains('E'))
        && t.bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+' | b'e' | b'E'))
    {
        if let Ok(x) = t.parse::<f64>() {
            return Value::Real(x);
        }
    }
    match t {
        "true" | "TRUE" | "t" => Value::Bool(true),
        "false" | "FALSE" | "f" => Value::Bool(false),
        _ => Value::Text(s.to_string()),
    }
}

fn value_from_binary(oid: u32, b: &[u8]) -> Result<Value> {
    let bad = || Error::InvalidInput(format!("parâmetro binário inválido para o tipo {oid}"));
    Ok(match (oid, b.len()) {
        (OID_BOOL, 1) => Value::Bool(b[0] != 0),
        (OID_INT2, 2) => Value::Int(i16::from_be_bytes([b[0], b[1]]) as i64),
        (OID_INT4, 4) => Value::Int(i32::from_be_bytes(b.try_into().map_err(|_| bad())?) as i64),
        (OID_INT8, 8) => Value::Int(i64::from_be_bytes(b.try_into().map_err(|_| bad())?)),
        (OID_FLOAT4, 4) => Value::Real(f32::from_be_bytes(b.try_into().map_err(|_| bad())?) as f64),
        (OID_FLOAT8, 8) => Value::Real(f64::from_be_bytes(b.try_into().map_err(|_| bad())?)),
        (OID_TEXT | OID_VARCHAR | 0, _) => Value::Text(String::from_utf8_lossy(b).into_owned()),
        _ => return Err(bad()),
    })
}

// ---------------------------------------------------------------------------
// Conexão
// ---------------------------------------------------------------------------

struct Prepared {
    sql: String,
    param_oids: Vec<u32>,
}

struct Portal {
    sql: String,
    params: Vec<Value>,
    /// Resultado já calculado por `Describe` (enviado no `Execute`).
    result: Option<ExecResult>,
}

struct Conn<'a> {
    session: Session,
    db: &'a SharedDb,
    prepared: HashMap<String, Prepared>,
    portals: HashMap<String, Portal>,
    /// Um comando falhou dentro da transação: só ROLLBACK/COMMIT saem dela.
    failed: bool,
}

impl Conn<'_> {
    fn status(&self) -> u8 {
        if !self.session.in_transaction() {
            b'I'
        } else if self.failed {
            b'E'
        } else {
            b'T'
        }
    }

    /// Executa um comando (com os no-ops de sessão do PostgreSQL).
    fn run(&mut self, sql: &str, params: &[Value]) -> Result<ExecResult> {
        if std::env::var_os("MINIDB_PG_TRACE").is_some() {
            eprintln!("pg> {sql}");
        }
        let trimmed = sql.trim().trim_end_matches(';').trim();
        if trimmed.is_empty() {
            return Ok(ExecResult::Ok(String::new()));
        }
        let lower = trimmed.to_ascii_lowercase();
        let first = lower
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next()
            .unwrap_or("");
        if self.failed && self.session.in_transaction() {
            match first {
                "rollback" | "abort" => {}
                "commit" | "end" => {
                    self.session.rollback()?;
                    self.failed = false;
                    return Ok(ExecResult::Ok("ROLLBACK".into()));
                }
                _ => {
                    return Err(Error::Sql(
                        "transação abortada: comandos ignorados até o fim do bloco (ROLLBACK)"
                            .into(),
                    ))
                }
            }
        }
        match first {
            "set" | "reset" | "discard" | "deallocate" => {
                return Ok(ExecResult::Ok(first.to_ascii_uppercase()));
            }
            "show" => {
                let arg = lower[4..].trim();
                let ours = [
                    "tables", "indexes", "index", "keys", "triggers", "create", "columns", "users",
                    "roles", "grants",
                ];
                if !ours.iter().any(|k| arg.starts_with(k)) {
                    let value = match arg {
                        "server_version" => "16.0",
                        "server_encoding" | "client_encoding" => "UTF8",
                        "transaction isolation level" | "default_transaction_isolation" => {
                            "repeatable read"
                        }
                        "datestyle" => "ISO, MDY",
                        "timezone" => "UTC",
                        "standard_conforming_strings" | "integer_datetimes" => "on",
                        "search_path" => "public",
                        "max_identifier_length" => "63",
                        _ => "",
                    };
                    return Ok(ExecResult::Table {
                        columns: vec![arg.replace(' ', "_")],
                        rows: vec![vec![Value::Text(value.into())]],
                    });
                }
            }
            "end" => return self.session.execute("COMMIT"),
            "abort" => return self.session.execute("ROLLBACK"),
            _ => {}
        }
        let result = self.session.execute_params(trimmed, params);
        if result.is_err() && self.session.in_transaction() {
            self.failed = true;
        }
        if matches!(first, "commit" | "rollback") {
            self.failed = false;
        }
        result
    }

    #[allow(clippy::only_used_in_recursion)]
    fn send_result(&self, w: &mut impl Write, result: ExecResult, describe: bool) -> Result<()> {
        let result = tabular(result);
        match &result {
            ExecResult::Table { columns, rows } => {
                if describe {
                    row_description(w, columns, rows)?;
                }
                for row in rows {
                    data_row(w, row)?;
                }
                command_complete(w, &tag_of(&result, rows.len()))
            }
            ExecResult::Ok(msg) if msg.is_empty() => send(w, b'I', &[]),
            ExecResult::Ok(_) => command_complete(w, &tag_of(&result, 0)),
            ExecResult::Batch(items) => {
                for item in items.clone() {
                    self.send_result(w, item, describe)?;
                }
                Ok(())
            }
            ExecResult::Rows(_) | ExecResult::Value(_) | ExecResult::Count(_) => {
                unreachable!("normalizado por tabular()")
            }
        }
    }

    /// `NotificationResponse` para cada `NOTIFY` já entregue aos canais em `LISTEN`
    /// desta conexão (enviado antes do `ReadyForQuery`, como o cliente espera).
    fn send_notifications(&self, w: &mut impl Write) -> Result<()> {
        for n in self.session.notifications(Duration::ZERO) {
            // PID do backend que notificou: não rastreado, vai 0.
            let mut body = 0u32.to_be_bytes().to_vec();
            cstr(&n.channel, &mut body);
            cstr(&n.payload, &mut body);
            send(w, b'A', &body)?;
        }
        Ok(())
    }

    fn simple_query(&mut self, w: &mut impl Write, sql: &str) -> Result<()> {
        let statements = crate::rel::split_statements(sql).unwrap_or_else(|_| vec![sql]);
        let statements: Vec<&str> = statements
            .into_iter()
            .filter(|s| !s.trim().trim_end_matches(';').trim().is_empty())
            .collect();
        if statements.is_empty() {
            send(w, b'I', &[])?;
            self.send_notifications(w)?;
            return ready(w, self.status());
        }
        for stmt in statements {
            match self.run(stmt, &[]) {
                Ok(result) => self.send_result(w, result, true)?,
                Err(e) => {
                    error_response(w, sqlstate(&e), &e.to_string())?;
                    break;
                }
            }
        }
        self.send_notifications(w)?;
        ready(w, self.status())
    }

    fn bind(&mut self, body: &[u8]) -> Result<()> {
        let mut pos = 0;
        let portal = take_cstr(body, &mut pos)?;
        let name = take_cstr(body, &mut pos)?;
        let prepared = self
            .prepared
            .get(&name)
            .ok_or_else(|| Error::Sql(format!("comando preparado {name:?} não existe")))?;
        let n_formats = take_u16(body, &mut pos)? as usize;
        let mut formats = Vec::with_capacity(n_formats);
        for _ in 0..n_formats {
            formats.push(take_u16(body, &mut pos)?);
        }
        let n_params = take_u16(body, &mut pos)? as usize;
        let mut params = Vec::with_capacity(n_params);
        for i in 0..n_params {
            let len = take_i32(body, &mut pos)?;
            if len < 0 {
                params.push(Value::Null);
                continue;
            }
            let raw = body
                .get(pos..pos + len as usize)
                .ok_or_else(|| Error::Server("parâmetro truncado".into()))?;
            pos += len as usize;
            let format = match formats.len() {
                0 => 0,
                1 => formats[0],
                _ => formats.get(i).copied().unwrap_or(0),
            };
            let oid = prepared.param_oids.get(i).copied().unwrap_or(0);
            params.push(if format == 1 {
                value_from_binary(oid, raw)?
            } else {
                let text = String::from_utf8_lossy(raw);
                match oid {
                    OID_TEXT | OID_VARCHAR => Value::Text(text.into_owned()),
                    _ => value_from_text(&text),
                }
            });
        }
        self.portals.insert(
            portal,
            Portal {
                sql: prepared.sql.clone(),
                params,
                result: None,
            },
        );
        Ok(())
    }

    fn execute_portal(&mut self, name: &str) -> Result<ExecResult> {
        let (sql, params) = {
            let portal = self
                .portals
                .get_mut(name)
                .ok_or_else(|| Error::Sql(format!("portal {name:?} não existe")))?;
            if let Some(result) = portal.result.take() {
                return Ok(result);
            }
            (portal.sql.clone(), portal.params.clone())
        };
        self.run(&sql, &params)
    }

    fn describe(&mut self, w: &mut impl Write, body: &[u8]) -> Result<()> {
        let kind = body.first().copied().unwrap_or(b'S');
        let mut pos = 1;
        let name = take_cstr(body, &mut pos)?;
        if kind == b'S' {
            let prepared = self
                .prepared
                .get(&name)
                .ok_or_else(|| Error::Sql(format!("comando preparado {name:?} não existe")))?;
            let n = crate::rel::prepare(&prepared.sql)
                .map(|p| p.param_count())
                .unwrap_or(prepared.param_oids.len());
            let mut desc = Vec::new();
            desc.extend_from_slice(&(n as u16).to_be_bytes());
            for i in 0..n {
                let oid = prepared.param_oids.get(i).copied().unwrap_or(0);
                desc.extend_from_slice(&if oid == 0 { OID_TEXT } else { oid }.to_be_bytes());
            }
            send(w, b't', &desc)?;
            // Colunas: só para leituras, executando com parâmetros NULL num snapshot.
            let sql = prepared.sql.clone();
            let is_read = crate::rel::prepare(&sql).is_ok_and(|p| p.is_read_only());
            if is_read {
                let nulls = vec![Value::Null; n];
                if let Ok(ExecResult::Table { columns, rows }) = self
                    .db
                    .snapshot()
                    .and_then(|s| s.query_params(&sql, &nulls))
                {
                    return row_description(w, &columns, &rows);
                }
            }
            return send(w, b'n', &[]);
        }
        let result = tabular(self.execute_portal(&name)?);
        match &result {
            ExecResult::Table { columns, rows } => row_description(w, columns, rows)?,
            _ => send(w, b'n', &[])?,
        }
        if let Some(p) = self.portals.get_mut(&name) {
            p.result = Some(result);
        }
        Ok(())
    }

    /// Protocolo estendido: uma mensagem. Erros são devolvidos para o chamador
    /// enviar `ErrorResponse` e ignorar até o `Sync`.
    fn extended(&mut self, w: &mut impl Write, ty: u8, body: &[u8]) -> Result<()> {
        match ty {
            b'P' => {
                let mut pos = 0;
                let name = take_cstr(body, &mut pos)?;
                let sql = take_cstr(body, &mut pos)?;
                let n = take_u16(body, &mut pos)? as usize;
                let mut param_oids = Vec::with_capacity(n);
                for _ in 0..n {
                    param_oids.push(take_i32(body, &mut pos)? as u32);
                }
                let trimmed = sql.trim().trim_end_matches(';').trim();
                let first = trimmed
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let passthrough = matches!(
                    first.as_str(),
                    "set" | "reset" | "discard" | "deallocate" | "show" | "end" | "abort" | ""
                ) || crate::db::is_transaction_control(trimmed)
                    || crate::sql::parse_sql(trimmed).is_ok();
                if !passthrough {
                    crate::rel::prepare(trimmed)?;
                }
                self.prepared.insert(name, Prepared { sql, param_oids });
                send(w, b'1', &[])
            }
            b'B' => {
                self.bind(body)?;
                send(w, b'2', &[])
            }
            b'D' => self.describe(w, body),
            b'E' => {
                let mut pos = 0;
                let name = take_cstr(body, &mut pos)?;
                let result = self.execute_portal(&name)?;
                self.send_result(w, result, false)
            }
            b'C' => {
                let kind = body.first().copied().unwrap_or(b'S');
                let mut pos = 1;
                let name = take_cstr(body, &mut pos)?;
                if kind == b'S' {
                    self.prepared.remove(&name);
                } else {
                    self.portals.remove(&name);
                }
                send(w, b'3', &[])
            }
            b'H' => {
                w.flush()?;
                Ok(())
            }
            // Como o PostgreSQL: CopyData/CopyDone/CopyFail fora de um COPY são ignorados.
            b'd' | b'c' | b'f' => Ok(()),
            other => Err(Error::Server(format!(
                "mensagem {:?} inesperada",
                other as char
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// COPY (formatos texto e CSV)
// ---------------------------------------------------------------------------

/// Teto dos bytes de dados de um `COPY ... FROM STDIN` (ficam em memória até o `CopyDone`).
const MAX_COPY_BYTES: usize = 256 << 20;
/// Teto de linhas de um `COPY ... FROM STDIN`.
const MAX_COPY_ROWS: usize = 1_000_000;
/// Linhas por `INSERT` gerado pelo `COPY ... FROM STDIN`.
const COPY_CHUNK: usize = 500;

enum CopyTarget {
    Table(String, Vec<String>),
    Query(String),
}

struct CopyOpts {
    delim: u8,
    null: String,
    /// Formato CSV (senão, texto); `header`, `quote` e `escape` só valem nele.
    csv: bool,
    header: bool,
    quote: u8,
    escape: u8,
}

struct CopySpec {
    target: CopyTarget,
    copy_in: bool,
    opts: CopyOpts,
}

impl CopySpec {
    fn table(&self) -> &str {
        match &self.target {
            CopyTarget::Table(name, _) => name,
            CopyTarget::Query(_) => "",
        }
    }
}

enum CopyTok {
    Word(String),
    Ident(String),
    Str(String),
    Sym(char),
}

type Fields = Vec<Option<String>>;

fn bad(msg: &str) -> Error {
    Error::Sql(format!("COPY: {msg}"))
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// A consulta simples é um `COPY` (sozinho: não vale junto de outros comandos).
fn is_copy(sql: &str) -> bool {
    let s = sql.trim_start();
    let head = s.get(..4).unwrap_or("");
    head.eq_ignore_ascii_case("copy") && !s[4..].starts_with(is_word)
}

fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn quote_list(cols: &[String]) -> String {
    let names: Vec<String> = cols.iter().map(|c| quote_ident(c)).collect();
    names.join(", ")
}

fn copy_tokens(s: &str) -> Result<Vec<CopyTok>> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c.is_whitespace() {
            continue;
        }
        if c == '\'' || c == '"' {
            let mut text = String::new();
            loop {
                match chars.get(i) {
                    None => return Err(bad("texto sem aspas de fechamento")),
                    Some(&q) if q == c && chars.get(i + 1) == Some(&c) => {
                        text.push(c);
                        i += 2;
                    }
                    Some(&q) if q == c => {
                        i += 1;
                        break;
                    }
                    Some(&x) => {
                        text.push(x);
                        i += 1;
                    }
                }
            }
            out.push(if c == '\'' {
                CopyTok::Str(text)
            } else {
                CopyTok::Ident(text)
            });
        } else if is_word(c) {
            let start = i - 1;
            while i < chars.len() && is_word(chars[i]) {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            out.push(CopyTok::Word(word.to_ascii_lowercase()));
        } else {
            out.push(CopyTok::Sym(c));
        }
    }
    Ok(out)
}

/// Posição do `)` que fecha um `(` já consumido, ignorando o que está entre aspas.
fn close_paren(s: &str) -> Option<usize> {
    let mut depth = 1;
    let mut quote: Option<char> = None;
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '(') => depth += 1,
            (None, ')') => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            (None, _) => {}
        }
    }
    None
}

fn copy_name(tok: Option<CopyTok>) -> Result<String> {
    match tok {
        Some(CopyTok::Word(s) | CopyTok::Ident(s)) => Ok(s),
        _ => Err(bad("esperava um identificador")),
    }
}

/// Valor booleano opcional de `HEADER` (`true`/`on`/`1` ou `false`/`off`/`0`).
fn copy_bool(tok: &CopyTok) -> Option<bool> {
    match tok {
        CopyTok::Word(w) if matches!(w.as_str(), "true" | "on" | "1") => Some(true),
        CopyTok::Word(w) if matches!(w.as_str(), "false" | "off" | "0") => Some(false),
        _ => None,
    }
}

/// Opção de um só caractere ASCII (`None`: o padrão).
fn one_char(v: Option<String>, default: u8, what: &str) -> Result<u8> {
    match v {
        None => Ok(default),
        Some(s) if s.len() == 1 && s.is_ascii() => Ok(s.as_bytes()[0]),
        Some(_) => Err(bad(&format!("{what}: um caractere ASCII"))),
    }
}

/// `[WITH] [(] FORMAT text|csv, HEADER [bool], DELIMITER 'x', NULL 'x', QUOTE 'x',
/// ESCAPE 'x' [)]` e a forma antiga `[WITH] DELIMITER [AS] 'x' NULL [AS] 'x' CSV [HEADER]
/// [QUOTE [AS] 'x'] [ESCAPE [AS] 'x']` (BINARY: não suportado).
fn parse_copy_opts(toks: Vec<CopyTok>) -> Result<CopyOpts> {
    let mut it = toks.into_iter().peekable();
    let _ = it.next_if(|t| matches!(t, CopyTok::Word(w) if w == "with"));
    let paren = it.next_if(|t| matches!(t, CopyTok::Sym('('))).is_some();
    let mut closed = !paren;
    let (mut csv, mut header) = (false, None);
    let (mut delim, mut null, mut quote, mut escape) = (None, None, None, None);
    while let Some(tok) = it.next() {
        let name = match tok {
            CopyTok::Word(w) => w,
            CopyTok::Sym(',') if paren => continue,
            CopyTok::Sym(')') if paren => {
                closed = true;
                break;
            }
            _ => return Err(bad("opção inválida")),
        };
        match name.as_str() {
            "format" => match it.next() {
                Some(CopyTok::Word(f)) if f == "text" => csv = false,
                Some(CopyTok::Word(f)) if f == "csv" => csv = true,
                _ => return Err(bad("FORMAT: só text ou csv (sem BINARY)")),
            },
            // Forma antiga, sem parênteses: `CSV [HEADER]`.
            "csv" if !paren => csv = true,
            "header" => {
                let v = it.next_if(|t| copy_bool(t).is_some());
                header = Some(v.as_ref().and_then(copy_bool).unwrap_or(true));
            }
            "delimiter" | "null" | "quote" | "escape" => {
                let _ = it.next_if(|t| matches!(t, CopyTok::Word(w) if w == "as"));
                let Some(CopyTok::Str(v)) = it.next() else {
                    return Err(bad(&format!("{} quer um texto", name.to_uppercase())));
                };
                match name.as_str() {
                    "delimiter" => delim = Some(v),
                    "null" => null = Some(v),
                    "quote" => quote = Some(v),
                    _ => escape = Some(v),
                }
            }
            _ => return Err(Error::Sql(format!("COPY: opção {name} não suportada"))),
        }
    }
    if !closed || it.next().is_some() {
        return Err(bad("opções mal formadas"));
    }
    if !csv && (header.is_some() || quote.is_some() || escape.is_some()) {
        return Err(bad("HEADER, QUOTE e ESCAPE só valem com FORMAT csv"));
    }
    let default_delim = if csv { b',' } else { b'\t' };
    let delim = one_char(delim, default_delim, "DELIMITER")?;
    if matches!(delim, b'\n' | b'\r') || (!csv && delim == b'\\') {
        return Err(bad("DELIMITER inválido"));
    }
    let quote = one_char(quote, b'"', "QUOTE")?;
    let escape = one_char(escape, quote, "ESCAPE")?;
    let default_null = if csv { "" } else { "\\N" };
    let null = null.unwrap_or_else(|| default_null.to_string());
    if csv {
        if quote == delim {
            return Err(bad("DELIMITER e QUOTE precisam ser diferentes"));
        }
        if matches!(quote, b'\n' | b'\r') || matches!(escape, b'\n' | b'\r') {
            return Err(bad("QUOTE/ESCAPE inválido"));
        }
        if null.bytes().any(|b| b == delim || b == quote) {
            return Err(bad("NULL não pode conter o delimitador nem a aspa"));
        }
    }
    Ok(CopyOpts {
        delim,
        null,
        csv,
        header: header.unwrap_or(false),
        quote,
        escape,
    })
}

/// `COPY tabela [(colunas)] FROM STDIN|TO STDOUT [opções]` e `COPY (consulta) TO STDOUT`.
fn parse_copy(sql: &str) -> Result<CopySpec> {
    let sql = sql.trim().trim_end_matches(';').trim_end();
    let rest = sql.get(4..).unwrap_or("").trim_start();
    let (query, toks) = match rest.strip_prefix('(') {
        Some(inner) => {
            let Some(end) = close_paren(inner) else {
                return Err(bad("parênteses sem fechamento"));
            };
            let query = inner[..end].trim().to_string();
            (Some(query), copy_tokens(&inner[end + 1..])?)
        }
        None => (None, copy_tokens(rest)?),
    };
    let mut it = toks.into_iter().peekable();
    let target = match query {
        Some(q) => CopyTarget::Query(q),
        None => {
            let name = copy_name(it.next())?;
            let mut columns = Vec::new();
            if it.next_if(|t| matches!(t, CopyTok::Sym('('))).is_some() {
                loop {
                    columns.push(copy_name(it.next())?);
                    match it.next() {
                        Some(CopyTok::Sym(',')) => {}
                        Some(CopyTok::Sym(')')) => break,
                        _ => return Err(bad("lista de colunas inválida")),
                    }
                }
            }
            CopyTarget::Table(name, columns)
        }
    };
    let copy_in = match it.next() {
        Some(CopyTok::Word(w)) if w == "from" => true,
        Some(CopyTok::Word(w)) if w == "to" => false,
        _ => return Err(bad("esperava FROM ou TO")),
    };
    let channel = if copy_in { "stdin" } else { "stdout" };
    if !matches!(it.next(), Some(CopyTok::Word(w)) if w == channel) {
        return Err(bad("só STDIN/STDOUT (sem arquivo/PROGRAM)"));
    }
    if copy_in && matches!(target, CopyTarget::Query(_)) {
        return Err(bad("(consulta) só vale com TO STDOUT"));
    }
    let opts = parse_copy_opts(it.collect())?;
    Ok(CopySpec {
        target,
        copy_in,
        opts,
    })
}

/// Campo do formato texto → bytes escapados (`\\ \n \r \t \b \f \v` e o delimitador).
fn text_field(s: &str, delim: u8, out: &mut Vec<u8>) {
    for &b in s.as_bytes() {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            8 => out.extend_from_slice(b"\\b"),
            11 => out.extend_from_slice(b"\\v"),
            12 => out.extend_from_slice(b"\\f"),
            _ if b == delim => out.extend_from_slice(&[b'\\', b]),
            _ => out.push(b),
        }
    }
}

/// Uma linha do `COPY ... TO STDOUT` (terminada em `\n`).
fn copy_line(fields: &[Option<String>], opts: &CopyOpts) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(opts.delim);
        }
        match field {
            None => out.extend_from_slice(opts.null.as_bytes()),
            Some(s) if opts.csv => csv_field(s, opts, &mut out),
            Some(s) => text_field(s, opts.delim, &mut out),
        }
    }
    out.push(b'\n');
    out
}

/// Campo CSV: vai entre aspas se tiver delimitador, aspa, `\r` ou `\n`, se for vazio, igual
/// ao NULL ou `\.` (que encerraria os dados); dentro das aspas, aspa e ESCAPE ganham ESCAPE.
fn csv_field(s: &str, opts: &CopyOpts, out: &mut Vec<u8>) {
    let special = |b: u8| b == opts.delim || b == opts.quote || b == b'\n' || b == b'\r';
    let quoted = s.is_empty() || s == opts.null || s == "\\." || s.bytes().any(special);
    if !quoted {
        out.extend_from_slice(s.as_bytes());
        return;
    }
    out.push(opts.quote);
    for b in s.bytes() {
        if b == opts.quote || b == opts.escape {
            out.push(opts.escape);
        }
        out.push(b);
    }
    out.push(opts.quote);
}

/// Inverso de `text_field`: escapes, octal (`\101`) e hexadecimal (`\x41`).
fn text_unescape(f: &[u8]) -> Result<String> {
    let mut out = Vec::with_capacity(f.len());
    let mut i = 0;
    while i < f.len() {
        let b = f[i];
        i += 1;
        if b != b'\\' || i >= f.len() {
            out.push(b);
            continue;
        }
        let c = f[i];
        i += 1;
        match c {
            b'b' => out.push(8),
            b'f' => out.push(12),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(11),
            b'0'..=b'7' => {
                let mut v = u32::from(c - b'0');
                let mut n = 1;
                while n < 3 && i < f.len() && matches!(f[i], b'0'..=b'7') {
                    v = v * 8 + u32::from(f[i] - b'0');
                    i += 1;
                    n += 1;
                }
                out.push(v as u8);
            }
            b'x' if i < f.len() && f[i].is_ascii_hexdigit() => {
                let mut v = 0u32;
                let mut n = 0;
                while n < 2 && i < f.len() && f[i].is_ascii_hexdigit() {
                    v = v * 16 + char::from(f[i]).to_digit(16).unwrap_or(0);
                    i += 1;
                    n += 1;
                }
                out.push(v as u8);
            }
            other => out.push(other),
        }
    }
    String::from_utf8(out).map_err(|_| bad("dados não são UTF-8 válido"))
}

struct CopyRows<'a> {
    data: &'a [u8],
    pos: usize,
    line: usize,
    opts: &'a CopyOpts,
}

impl CopyRows<'_> {
    /// Próxima linha como campos (`None` = NULL), conferindo `width` colunas;
    /// `Ok(None)` no fim dos dados (fim do texto ou linha `\.`).
    fn next_row(&mut self, width: usize) -> Result<Option<Fields>> {
        let data = self.data;
        let rest = &data[self.pos..];
        if rest.is_empty() {
            return Ok(None);
        }
        if rest.starts_with(b"\\.") && matches!(rest.get(2), None | Some(b'\n' | b'\r')) {
            self.pos = data.len();
            return Ok(None);
        }
        self.line += 1;
        if self.opts.csv {
            let fields = self.csv_fields()?;
            // HEADER: a 1ª linha (nomes das colunas) é descartada sem conferir.
            if self.opts.header && self.line == 1 {
                return self.next_row(width);
            }
            if fields.len() != width {
                return Err(width_error(self.line, width, fields.len()));
            }
            return Ok(Some(fields));
        }
        let nl = rest.iter().position(|&b| b == b'\n');
        let end = nl.unwrap_or(rest.len());
        self.pos += (end + 1).min(rest.len());
        let line = &rest[..end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        // Separa nos delimitadores sem escape (a barra invertida protege o próximo byte).
        let mut raw = Vec::new();
        let (mut start, mut i) = (0, 0);
        while i < line.len() {
            if line[i] == b'\\' {
                i += 2;
                continue;
            }
            if line[i] == self.opts.delim {
                raw.push(&line[start..i]);
                start = i + 1;
            }
            i += 1;
        }
        raw.push(&line[start..]);
        if raw.len() != width {
            return Err(width_error(self.line, width, raw.len()));
        }
        let null = self.opts.null.as_bytes();
        let mut fields = Vec::with_capacity(width);
        for f in raw {
            if f == null {
                fields.push(None);
            } else {
                fields.push(Some(text_unescape(f)?));
            }
        }
        Ok(Some(fields))
    }

    /// Um registro CSV a partir de `self.pos`: as aspas protegem delimitador, quebras de
    /// linha e a própria aspa (dobrada ou após o ESCAPE). Só o NULL sem aspas é NULL.
    fn csv_fields(&mut self) -> Result<Fields> {
        let (data, o) = (self.data, self.opts);
        let mut fields = Vec::new();
        let mut i = self.pos;
        loop {
            let mut buf = Vec::new();
            let (mut quoted, mut inside) = (false, false);
            // Lê um campo; `true` quando a linha (o registro) acabou.
            let last = loop {
                let Some(&c) = data.get(i) else {
                    if inside {
                        let msg = format!("linha {}: aspas sem fechamento", self.line);
                        return Err(bad(&msg));
                    }
                    break true;
                };
                i += 1;
                if inside {
                    let next = data.get(i).copied();
                    if c == o.escape && (next == Some(o.quote) || next == Some(o.escape)) {
                        buf.push(data[i]);
                        i += 1;
                    } else if c == o.quote {
                        inside = false;
                    } else {
                        buf.push(c);
                    }
                } else if c == o.delim {
                    break false;
                } else if c == b'\n' {
                    break true;
                } else if c == b'\r' && matches!(data.get(i), None | Some(b'\n')) {
                    i = (i + 1).min(data.len());
                    break true;
                } else if c == o.quote {
                    quoted = true;
                    inside = true;
                } else {
                    buf.push(c);
                }
            };
            let field = if !quoted && buf == o.null.as_bytes() {
                None
            } else {
                let s = String::from_utf8(buf).map_err(|_| bad("dados não são UTF-8 válido"))?;
                Some(s)
            };
            fields.push(field);
            if last {
                self.pos = i;
                return Ok(fields);
            }
        }
    }
}

/// Linha com número de colunas diferente do esperado.
fn width_error(line: usize, width: usize, got: usize) -> Error {
    let msg = format!("linha {line}: esperava {width} coluna(s), veio {got}");
    bad(&msg)
}

/// `CopyInResponse` ('G') ou `CopyOutResponse` ('H'): formato texto em todas as colunas
/// (o CSV também é 0, como no PostgreSQL).
fn copy_response(w: &mut impl Write, ty: u8, width: usize) -> Result<()> {
    let mut body = vec![0u8];
    body.extend_from_slice(&(width as u16).to_be_bytes());
    for _ in 0..width {
        body.extend_from_slice(&0u16.to_be_bytes());
    }
    send(w, ty, &body)
}

/// `($1, $2, ...)` da linha `row` de um `INSERT` com `width` colunas.
fn placeholders(row: usize, width: usize) -> String {
    let first = row * width + 1;
    let items: Vec<String> = (first..first + width).map(|i| format!("${i}")).collect();
    format!("({})", items.join(", "))
}

/// Recebe os `CopyData` de um `COPY ... FROM STDIN` até `CopyDone`/`CopyFail`.
/// Erro externo: conexão perdida; `Ok(Err(_))`: COPY recusado (o fluxo foi lido até o fim,
/// como no PostgreSQL, para a conexão seguir válida).
fn copy_receive(ch: &mut Chan) -> Result<Result<Vec<u8>>> {
    let mut data = Vec::new();
    let mut failure: Option<Error> = None;
    loop {
        let (ty, body) = read_message(ch, MAX_MESSAGE)?;
        match ty {
            b'd' if failure.is_none() => {
                if data.len() + body.len() > MAX_COPY_BYTES {
                    data = Vec::new();
                    failure = Some(bad("dados passaram de 256 MiB"));
                } else {
                    data.extend_from_slice(&body);
                }
            }
            b'd' | b'S' => {}
            b'c' => break,
            b'f' => {
                let mut pos = 0;
                let why = take_cstr(&body, &mut pos).unwrap_or_default();
                if failure.is_none() {
                    failure = Some(bad(&format!("cancelado pelo cliente: {why}")));
                }
                break;
            }
            b'H' => ch.flush()?,
            b'X' => return Err(Error::Io(io::ErrorKind::UnexpectedEof.into())),
            other => {
                if failure.is_none() {
                    let msg = format!("mensagem {:?} inesperada", other as char);
                    failure = Some(bad(&msg));
                }
            }
        }
    }
    Ok(match failure {
        Some(e) => Err(e),
        None => Ok(data),
    })
}

impl Conn<'_> {
    /// `COPY` na consulta simples. Erros do comando viram `ErrorResponse` e a conexão segue.
    fn copy(&mut self, ch: &mut Chan, sql: &str) -> Result<()> {
        let outcome = match parse_copy(sql) {
            Ok(spec) if spec.copy_in => self.copy_in(ch, &spec)?,
            Ok(spec) => self.copy_out(ch, &spec),
            Err(e) => Err(e),
        };
        match outcome {
            Ok(n) => command_complete(ch, &format!("COPY {n}"))?,
            Err(e) => error_response(ch, sqlstate(&e), &e.to_string())?,
        }
        self.send_notifications(ch)?;
        ready(ch, self.status())
    }

    /// Erro externo: conexão perdida; `Ok(Err(_))`: COPY recusado.
    fn copy_in(&mut self, ch: &mut Chan, spec: &CopySpec) -> Result<Result<u64>> {
        let cols = match self.copy_columns(spec) {
            Ok(cols) => cols,
            Err(e) => return Ok(Err(e)),
        };
        copy_response(ch, b'G', cols.len())?;
        ch.flush()?;
        let data = copy_receive(ch)?;
        Ok(data.and_then(|d| self.copy_insert(spec, &cols, &d)))
    }

    /// Confere o privilégio e a tabela antes de pedir os dados; devolve as colunas a preencher.
    fn copy_columns(&mut self, spec: &CopySpec) -> Result<Vec<String>> {
        let CopyTarget::Table(name, columns) = &spec.target else {
            return Err(bad("FROM exige uma tabela"));
        };
        self.session.authorize_object(name, Privilege::Insert)?;
        let sql = format!("DESCRIBE {}", quote_ident(name));
        let ExecResult::Table { rows, .. } = self.run(&sql, &[])? else {
            return Err(bad("tabela sem descrição"));
        };
        let mut all = Vec::new();
        for row in &rows {
            if matches!(row.get(1), Some(Value::Text(t)) if t == "VIEW") {
                return Err(bad("não copia para uma view"));
            }
            all.extend(row.first().map(ToString::to_string));
        }
        if columns.is_empty() {
            return Ok(all);
        }
        for c in columns {
            if !all.contains(c) {
                let msg = format!("a coluna {c:?} não existe em {name:?}");
                return Err(bad(&msg));
            }
        }
        Ok(columns.clone())
    }

    /// Insere os dados numa transação só (a do cliente, se aberta; senão uma própria):
    /// qualquer erro desfaz tudo.
    fn copy_insert(&mut self, spec: &CopySpec, cols: &[String], data: &[u8]) -> Result<u64> {
        let own = !self.session.in_transaction();
        if own {
            self.run("BEGIN", &[])?;
        }
        let outcome = self.copy_rows(spec, cols, data);
        if !own {
            return outcome;
        }
        match outcome {
            Ok(n) => self.run("COMMIT", &[]).map(|_| n),
            Err(e) => {
                let _ = self.run("ROLLBACK", &[]);
                Err(e)
            }
        }
    }

    /// `INSERT` parametrizado de até `COPY_CHUNK` linhas por comando; todo valor vai
    /// como texto e o motor converte para o tipo da coluna na atribuição.
    fn copy_rows(&mut self, spec: &CopySpec, cols: &[String], data: &[u8]) -> Result<u64> {
        let width = cols.len();
        let mut rows = CopyRows {
            data,
            pos: 0,
            line: 0,
            opts: &spec.opts,
        };
        let table = quote_ident(spec.table());
        let list = quote_list(cols);
        let head = format!("INSERT INTO {table} ({list}) VALUES ");
        let mut total = 0usize;
        loop {
            let mut params = Vec::new();
            let mut n = 0;
            while n < COPY_CHUNK {
                let Some(row) = rows.next_row(width)? else {
                    break;
                };
                for f in row {
                    params.push(f.map_or(Value::Null, Value::Text));
                }
                n += 1;
            }
            if n == 0 {
                break;
            }
            total += n;
            if total > MAX_COPY_ROWS {
                return Err(bad("passou do limite de 1.000.000 de linhas"));
            }
            let tuples: Vec<String> = (0..n).map(|r| placeholders(r, width)).collect();
            let sql = format!("{head}{}", tuples.join(", "));
            self.run(&sql, &params)?;
        }
        Ok(total as u64)
    }

    /// `COPY tabela|(consulta) TO STDOUT`: a consulta roda inteira antes de enviar
    /// qualquer coisa, então um erro ainda vira `ErrorResponse` normal.
    fn copy_out(&mut self, ch: &mut Chan, spec: &CopySpec) -> Result<u64> {
        let sql = match &spec.target {
            CopyTarget::Table(name, columns) => {
                let list = if columns.is_empty() {
                    "*".to_string()
                } else {
                    quote_list(columns)
                };
                format!("SELECT {list} FROM {}", quote_ident(name))
            }
            CopyTarget::Query(q) => {
                let word: String = q.chars().take_while(char::is_ascii_alphabetic).collect();
                if !matches!(
                    word.to_ascii_lowercase().as_str(),
                    "select" | "with" | "values"
                ) {
                    return Err(bad("(consulta) deve ser SELECT, WITH ou VALUES"));
                }
                q.clone()
            }
        };
        let result = tabular(self.run(&sql, &[])?);
        let ExecResult::Table { columns, rows } = result else {
            return Err(bad("a consulta não devolve linhas"));
        };
        copy_response(ch, b'H', columns.len())?;
        if spec.opts.header {
            let names: Fields = columns.iter().cloned().map(Some).collect();
            send(ch, b'd', &copy_line(&names, &spec.opts))?;
        }
        for row in &rows {
            let fields: Fields = row.iter().map(text_of).collect();
            send(ch, b'd', &copy_line(&fields, &spec.opts))?;
        }
        send(ch, b'c', &[])?;
        Ok(rows.len() as u64)
    }
}

/// Identificador de backend por conexão (`pg_backend_pid`, chave de cancelamento).
static BACKEND_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000);

fn handle(db: &SharedDb, stream: TcpStream, opts: &NetOptions) -> Result<()> {
    let mut ch = Chan::new(stream);
    // Startup (SSL/GSS recusados; cancelamento ignorado).
    let params = loop {
        let len = read_u32(&mut ch)? as usize;
        // Como o PostgreSQL, limita o pacote de startup (ainda sem autenticação).
        if !(8..=10_000).contains(&len) {
            return Err(Error::Server("startup inválido".into()));
        }
        let body = read_body(&mut ch, len - 4)?;
        let code = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
        match code {
            SSL_REQUEST if opts.tls.is_some() => {
                ch.write_all(b"S")?;
                ch.flush()?;
                ch.upgrade(opts.tls.as_deref().expect("tls"))?;
            }
            SSL_REQUEST | GSSENC_REQUEST => {
                ch.write_all(b"N")?;
                ch.flush()?;
            }
            CANCEL_REQUEST => return Ok(()),
            PROTOCOL_3 => {
                // Certificado de cliente exigido: conexão em claro não vale.
                if !ch.is_tls()
                    && matches!(
                        opts.tls.as_deref().map(|i| &i.client_auth),
                        Some(crate::tls::ClientAuth::Required(_))
                    )
                {
                    error_response(&mut ch, "28000", "exige TLS com certificado de cliente")?;
                    ch.flush()?;
                    return Ok(());
                }
                let mut pos = 4;
                let mut params = HashMap::new();
                while pos < body.len() && body[pos] != 0 {
                    let k = take_cstr(&body, &mut pos)?;
                    let v = take_cstr(&body, &mut pos)?;
                    params.insert(k, v);
                }
                break params;
            }
            _ => {
                error_response(&mut ch, "08P01", "versão de protocolo não suportada")?;
                ch.flush()?;
                return Ok(());
            }
        }
    };
    let user = params.get("user").cloned().unwrap_or_default();
    let mut session = db.session();
    let peer = ch.peer();
    let has_users = auth::has_users(&*db.read()?)?;
    // Certificado de cliente verificado (mTLS): o CN precisa ser o usuário pedido.
    let cert_user = match (&peer, has_users) {
        (Some(p), true) => {
            if p.cn.as_deref() == Some(user.as_str()) {
                auth::load(&*db.read()?, &user)?.filter(|u| u.login)
            } else if matches!(
                opts.tls.as_deref().map(|i| &i.client_auth),
                Some(crate::tls::ClientAuth::Required(_))
            ) {
                error_response(
                    &mut ch,
                    "28000",
                    &format!(
                        "certificado de cliente ({}) não corresponde ao usuário {user:?}",
                        p.subject
                    ),
                )?;
                ch.flush()?;
                return Ok(());
            } else {
                None
            }
        }
        _ => None,
    };
    // Autenticação.
    let principal = if cert_user.is_some() {
        cert_user
    } else if peer.is_some() && !has_users {
        None // certificado válido basta quando não há usuários cadastrados
    } else if has_users {
        let mut body = Vec::new();
        cstr("SCRAM-SHA-256", &mut body);
        body.push(0);
        let mut auth_body = 10u32.to_be_bytes().to_vec();
        auth_body.extend_from_slice(&body);
        send(&mut ch, b'R', &auth_body)?;
        ch.flush()?;
        let (ty, body) = read_message(&mut ch, MAX_AUTH_MESSAGE)?;
        if ty != b'p' {
            return Err(Error::Server("esperava SASLInitialResponse".into()));
        }
        let mut pos = 0;
        let mechanism = take_cstr(&body, &mut pos)?;
        let len = take_i32(&body, &mut pos)?;
        let client_first = if len < 0 {
            String::new()
        } else {
            String::from_utf8_lossy(body.get(pos..pos + len as usize).unwrap_or_default())
                .into_owned()
        };
        let (principal, secret) = {
            let guard = db.read()?;
            (auth::load(&*guard, &user)?, auth::mock_secret_for(&*guard)?)
        };
        let outcome = if mechanism != "SCRAM-SHA-256" {
            Err(Error::Unauthorized)
        } else {
            ScramServer::start(principal.as_ref(), &user, &client_first, &secret)
        };
        let (server, server_first) = match outcome {
            Ok(v) => v,
            Err(_) => {
                error_response(
                    &mut ch,
                    "28P01",
                    &format!("autenticação falhou para {user:?}"),
                )?;
                ch.flush()?;
                return Ok(());
            }
        };
        let mut cont = 11u32.to_be_bytes().to_vec();
        cont.extend_from_slice(server_first.as_bytes());
        send(&mut ch, b'R', &cont)?;
        ch.flush()?;
        let (ty, body) = read_message(&mut ch, MAX_AUTH_MESSAGE)?;
        if ty != b'p' {
            return Err(Error::Server("esperava SASLResponse".into()));
        }
        match server.finish(&String::from_utf8_lossy(&body)) {
            Ok(server_final) => {
                let mut fin = 12u32.to_be_bytes().to_vec();
                fin.extend_from_slice(server_final.as_bytes());
                send(&mut ch, b'R', &fin)?;
            }
            Err(_) => {
                error_response(
                    &mut ch,
                    "28P01",
                    &format!("autenticação falhou para {user:?}"),
                )?;
                ch.flush()?;
                return Ok(());
            }
        }
        principal
    } else if let Some(token) = &opts.token {
        send(&mut ch, b'R', &3u32.to_be_bytes())?;
        ch.flush()?;
        let (ty, body) = read_message(&mut ch, MAX_AUTH_MESSAGE)?;
        let mut pos = 0;
        let given = take_cstr(&body, &mut pos).unwrap_or_default();
        if ty != b'p' || !crate::crypto::constant_time_eq(given.as_bytes(), token.as_bytes()) {
            error_response(&mut ch, "28P01", "senha inválida")?;
            ch.flush()?;
            return Ok(());
        }
        None
    } else {
        None
    };
    let superuser = principal.as_ref().is_none_or(|p| p.superuser);
    session.set_principal(principal);
    send(&mut ch, b'R', &0u32.to_be_bytes())?;
    for (k, v) in [
        ("server_version", "16.0 (minidb 1.3)"),
        ("server_encoding", "UTF8"),
        ("client_encoding", "UTF8"),
        ("DateStyle", "ISO, MDY"),
        ("IntervalStyle", "postgres"),
        ("TimeZone", "UTC"),
        ("integer_datetimes", "on"),
        ("standard_conforming_strings", "on"),
        ("is_superuser", if superuser { "on" } else { "off" }),
        ("session_authorization", user.as_str()),
        (
            "application_name",
            params
                .get("application_name")
                .map(String::as_str)
                .unwrap_or(""),
        ),
    ] {
        parameter_status(&mut ch, k, v)?;
    }
    let pid = BACKEND_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut key = pid.to_be_bytes().to_vec();
    key.extend_from_slice(&crate::crypto::random_bytes::<4>());
    send(&mut ch, b'K', &key)?;
    ready(&mut ch, b'I')?;

    crate::rel::set_conn_info(crate::rel::ConnInfo {
        pid: pid as i64,
        ssl: ch.is_tls(),
        client_addr: ch.peer_addr(),
        client_dn: peer.as_ref().map(|p| p.subject.clone()),
        client_issuer: peer.as_ref().map(|p| p.issuer.clone()),
    });
    let mut conn = Conn {
        session,
        db,
        prepared: HashMap::new(),
        portals: HashMap::new(),
        failed: false,
    };
    // Entrou em modo aberto (sem usuários nem token): se alguém criar o primeiro
    // usuário, a conexão é encerrada e o cliente reconecta autenticando (como no TCP).
    let open_mode = !has_users && opts.token.is_none();
    let mut skipping = false; // erro no protocolo estendido: ignora até Sync
    loop {
        let (ty, body) = match read_message(&mut ch, MAX_MESSAGE) {
            Ok(m) => m,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        // `Sync` não executa nada: fecha o lote em que o próprio `CREATE USER` veio.
        if open_mode && !matches!(ty, b'X' | b'S') && conn.session.auth_required()? {
            error_response(&mut ch, "28000", "autenticação exigida: reconecte")?;
            ch.flush()?;
            return Ok(());
        }
        match ty {
            b'X' => return Ok(()),
            b'S' => {
                skipping = false;
                conn.send_notifications(&mut ch)?;
                ready(&mut ch, conn.status())?;
            }
            b'Q' => {
                skipping = false;
                let mut pos = 0;
                let sql = take_cstr(&body, &mut pos)?;
                if is_copy(&sql) {
                    conn.copy(&mut ch, &sql)?;
                } else {
                    conn.simple_query(&mut ch, &sql)?;
                }
            }
            _ if skipping => {}
            _ => {
                if let Err(e) = conn.extended(&mut ch, ty, &body) {
                    error_response(&mut ch, sqlstate(&e), &e.to_string())?;
                    ch.flush()?;
                    skipping = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_text_inference_and_tags() {
        assert_eq!(value_from_text("42"), Value::Int(42));
        assert_eq!(value_from_text("-7"), Value::Int(-7));
        assert_eq!(value_from_text("007"), Value::Text("007".into()));
        assert_eq!(value_from_text("2.5"), Value::Real(2.5));
        assert_eq!(value_from_text("1e3"), Value::Real(1000.0));
        assert_eq!(value_from_text("t"), Value::Bool(true));
        assert_eq!(value_from_text("olá"), Value::Text("olá".into()));
        assert_eq!(tag_of(&ExecResult::Ok("INSERT 3".into()), 0), "INSERT 0 3");
        assert_eq!(tag_of(&ExecResult::Ok("UPDATE 2".into()), 0), "UPDATE 2");
        assert_eq!(
            tag_of(&ExecResult::Ok("CREATE TABLE t".into()), 0),
            "CREATE TABLE"
        );
        assert_eq!(tag_of(&ExecResult::Ok("BEGIN".into()), 0), "BEGIN");
        assert_eq!(text_of(&Value::Real(1.0)).unwrap(), "1");
        assert_eq!(text_of(&Value::Real(2.5)).unwrap(), "2.5");
        assert_eq!(text_of(&Value::Bool(false)).unwrap(), "f");
        assert!(text_of(&Value::Null).is_none());
        assert_eq!(
            value_from_binary(OID_INT4, &7i32.to_be_bytes()).unwrap(),
            Value::Int(7)
        );
        assert_eq!(
            value_from_binary(OID_FLOAT8, &1.5f64.to_be_bytes()).unwrap(),
            Value::Real(1.5)
        );
    }

    #[test]
    fn copy_csv_options_and_fields() {
        let opts = |sql: &str| parse_copy_opts(copy_tokens(sql).unwrap());
        let s = |v: &str| Some(v.to_string());
        let o = opts("WITH (FORMAT csv, HEADER true, DELIMITER ';')").unwrap();
        assert!(o.csv && o.header && o.null.is_empty());
        assert_eq!((o.delim, o.quote, o.escape), (b';', b'"', b'"'));
        let o = opts("WITH CSV HEADER").unwrap();
        assert!(o.csv && o.header && o.delim == b',');
        assert!(!opts("(FORMAT csv, HEADER off)").unwrap().header);
        for wrong in [
            "(FORMAT binary)",
            "(FORMAT csv, DELIMITER ';;')",
            "(FORMAT csv, DELIMITER '\"')",
            "(FORMAT csv, NULL ',')",
            "(FORMAT csv, QUOTE 'xy')",
            "(FORMAT text, HEADER)",
            "(FORMAT csv, FORCE_QUOTE x)",
        ] {
            assert!(opts(wrong).is_err(), "{wrong}");
        }

        // Ida e volta: vírgula, aspa, quebra de linha, vazio e NULL.
        let o = opts("(FORMAT csv)").unwrap();
        let fields = vec![s("a,b"), s("x\"y"), s("1\n2"), s(""), None];
        let line = copy_line(&fields, &o);
        assert_eq!(line, b"\"a,b\",\"x\"\"y\",\"1\n2\",\"\",\n");
        assert_eq!(copy_line(&[s("\\.")], &o), b"\"\\.\"\n");
        let mut rows = CopyRows {
            data: &line,
            pos: 0,
            line: 0,
            opts: &o,
        };
        assert_eq!(rows.next_row(5).unwrap(), Some(fields));
        assert_eq!(rows.next_row(5).unwrap(), None);

        // ESCAPE próprio, NULL entre aspas é texto e aspas sem fechamento.
        let o = opts("(FORMAT csv, ESCAPE '\\', NULL 'N')").unwrap();
        let mut rows = CopyRows {
            data: b"\"a\\\"b\",N,\"N\",\n\"aberta,x\n",
            pos: 0,
            line: 0,
            opts: &o,
        };
        assert_eq!(
            rows.next_row(4).unwrap(),
            Some(vec![s("a\"b"), None, s("N"), s("")])
        );
        let err = rows.next_row(4).unwrap_err().to_string();
        assert!(err.contains("linha 2"), "{err}");
    }
}
