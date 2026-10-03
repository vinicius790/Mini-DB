//! API HTTP/1.1 JSON (REST) sobre o mesmo `Db`, com CORS, métricas e OpenAPI.
//!
//! | Método | Caminho | Corpo / query |
//! |---|---|---|
//! | GET | `/health` | — |
//! | GET | `/metrics` | Prometheus |
//! | GET | `/v1/stats` | JSON |
//! | GET | `/v1/kv?key=` | JSON |
//! | PUT | `/v1/kv` | `{"key","value"}` |
//! | DELETE | `/v1/kv?key=` | — |
//! | GET | `/v1/scan?start=&end=` | JSON array |
//! | POST | `/v1/sql` | `{"sql":"..."}` |

use crate::config::NetOptions;
use crate::db::ExecResult;
use crate::error::{Error, Result};
use crate::json::Json;
use crate::metrics::Metrics;
use crate::mvcc::SharedDb;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_HEADER_BYTES: usize = 32 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Libera a vaga de conexão ao sair de escopo (compartilhado com o TCP).
pub(crate) struct ConnectionGuard(pub(crate) Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) fn reserve_connection(active: &AtomicUsize, limit: usize) -> bool {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |count| {
            (count < limit).then_some(count + 1)
        })
        .is_ok()
}

/// Status HTTP de um erro do motor.
fn status_of(e: &Error) -> u16 {
    match e {
        Error::Unauthorized => 401,
        Error::Forbidden(_) => 403,
        Error::ReadOnly => 403,
        Error::Conflict(_) => 409,
        Error::Unavailable(_) => 503,
        e if e.is_client_error() => 400,
        _ => 500,
    }
}

/// Servidor HTTP com as opções padrão (sem token).
pub fn serve_http(db: SharedDb, metrics: Arc<Metrics>, addr: &str) -> Result<()> {
    serve_http_with(db, metrics, addr, NetOptions::default())
}

/// Servidor HTTP: uma thread por conexão; leituras rodam em paralelo.
pub fn serve_http_with(
    db: SharedDb,
    metrics: Arc<Metrics>,
    addr: &str,
    opts: NetOptions,
) -> Result<()> {
    let listener = TcpListener::bind(addr).map_err(|e| Error::Server(e.to_string()))?;
    let active = Arc::new(AtomicUsize::new(0));
    let opts = Arc::new(opts);
    eprintln!(
        "minidb-http listen {addr}{}",
        if opts.token.is_some() {
            " (token exigido)"
        } else {
            ""
        }
    );
    for incoming in listener.incoming() {
        let mut stream = incoming.map_err(|e| Error::Server(e.to_string()))?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        if !reserve_connection(&active, opts.max_connections) {
            metrics.inc_http();
            metrics.inc_err();
            let _ = write_http(
                &mut stream,
                503,
                "application/json",
                "{\"ok\":false,\"error\":\"server busy\"}",
            );
            continue;
        }
        let db = db.clone();
        let metrics = Arc::clone(&metrics);
        // Criado aqui: se a thread não nascer, o guarda cai junto com o fechamento.
        let connection = ConnectionGuard(Arc::clone(&active));
        let opts = Arc::clone(&opts);
        crate::server::spawn_connection(move || {
            let _connection = connection;
            metrics.inc_http();
            let mut tls_stream;
            let io: &mut dyn HttpIo = match &opts.tls {
                Some(identity) => match crate::tls::accept(stream, identity) {
                    Ok(t) => {
                        tls_stream = t;
                        &mut tls_stream
                    }
                    Err(e) => {
                        metrics.inc_err();
                        eprintln!("https: {e}");
                        return;
                    }
                },
                None => &mut stream,
            };
            if let Err(e) = handle(&db, &metrics, io, &opts) {
                metrics.inc_err();
                let _ = write_http(io, status_of(&e), "application/json", &error_json(&e));
            }
        });
    }
    Ok(())
}

fn sse_headers(stream: &mut dyn HttpIo) -> Result<()> {
    let cors = cors_headers();
    stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n{cors}\r\n"
        )
        .as_bytes(),
    )?;
    Ok(())
}

fn change_json(c: &crate::events::Change) -> Json {
    let row = |r: &Option<Vec<crate::rel::Value>>| match r {
        None => Json::Null,
        Some(values) => {
            let mut obj = Json::obj();
            for (name, v) in c.columns.iter().zip(values) {
                obj = obj.put(name, v.to_json());
            }
            obj
        }
    };
    Json::obj()
        .put("lsn", Json::Number(c.lsn as i64))
        .put("table", Json::String(c.table.clone()))
        .put("kind", Json::String(c.kind.name().into()))
        .put("old", row(&c.old))
        .put("new", row(&c.new))
}

/// `GET /v1/changes`: mudanças confirmadas desde um LSN, como Server-Sent
/// Events (`event: change`) ou, com `once`, um JSON com o lote atual.
fn stream_changes(
    db: &SharedDb,
    stream: &mut dyn HttpIo,
    mut since: u64,
    table: Option<&str>,
    limit: usize,
    timeout: Duration,
    once: bool,
) -> Result<()> {
    use crate::events::ChangeError;
    let bus = db.events();
    if once {
        return match bus.changes_since(since, limit, Duration::from_millis(50)) {
            Ok(changes) => {
                let filtered: Vec<Json> = changes
                    .iter()
                    .filter(|c| table.is_none_or(|t| c.table == t))
                    .map(change_json)
                    .collect();
                let last = changes.last().map_or(since, |c| c.lsn);
                write_http(
                    stream,
                    200,
                    "application/json",
                    &Json::obj()
                        .put("ok", Json::Bool(true))
                        .put("since", Json::Number(since as i64))
                        .put("last_lsn", Json::Number(last as i64))
                        .put("changes", Json::Array(filtered))
                        .stringify(),
                )
            }
            Err(ChangeError::TooOld { first_available }) => write_http(
                stream,
                410,
                "application/json",
                &Json::obj()
                    .put("ok", Json::Bool(false))
                    .put(
                        "error",
                        Json::String("LSN antigo demais: releia as tabelas".into()),
                    )
                    .put("first_available", Json::Number(first_available as i64))
                    .stringify(),
            ),
        };
    }
    sse_headers(stream)?;
    stream.set_read_timeout(None)?;
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(());
        }
        match bus.changes_since(since, limit, remaining.min(Duration::from_secs(15))) {
            Ok(changes) if changes.is_empty() => stream.write_all(b": keepalive\n\n")?,
            Ok(changes) => {
                for c in &changes {
                    since = since.max(c.lsn);
                    if table.is_none_or(|t| c.table == t) {
                        stream.write_all(
                            format!(
                                "id: {}\nevent: change\ndata: {}\n\n",
                                c.lsn,
                                change_json(c).stringify()
                            )
                            .as_bytes(),
                        )?;
                    }
                }
            }
            Err(ChangeError::TooOld { first_available }) => {
                stream.write_all(
                    format!(
                        "event: error\ndata: {}\n\n",
                        Json::obj()
                            .put(
                                "error",
                                Json::String("LSN antigo demais: releia as tabelas".into())
                            )
                            .put("first_available", Json::Number(first_available as i64))
                            .stringify()
                    )
                    .as_bytes(),
                )?;
                return Ok(());
            }
        }
        stream.flush()?;
    }
}

/// `GET /v1/listen?channel=a&channel=b`: notificações `NOTIFY` como SSE.
fn stream_notifications(
    db: &SharedDb,
    stream: &mut dyn HttpIo,
    channels: &[String],
    timeout: Duration,
) -> Result<()> {
    let bus = db.events();
    let id = bus.subscribe();
    for c in channels {
        bus.listen(id, c);
    }
    let result = (|| {
        sse_headers(stream)?;
        stream.set_read_timeout(None)?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            let batch = bus.poll(id, remaining.min(Duration::from_secs(15)));
            if batch.is_empty() {
                stream.write_all(b": keepalive\n\n")?;
            }
            for n in batch {
                let data = Json::obj()
                    .put("lsn", Json::Number(n.lsn as i64))
                    .put("channel", Json::String(n.channel))
                    .put("payload", Json::String(n.payload))
                    .stringify();
                stream.write_all(format!("event: notify\ndata: {data}\n\n").as_bytes())?;
            }
            stream.flush()?;
        }
    })();
    bus.unsubscribe(id);
    result
}

fn error_json(e: &Error) -> String {
    Json::obj()
        .put("ok", Json::Bool(false))
        .put("error", Json::String(e.to_string()))
        .stringify()
}

fn handle(
    db: &SharedDb,
    metrics: &Metrics,
    stream: &mut dyn HttpIo,
    opts: &NetOptions,
) -> Result<()> {
    let Request {
        method,
        target,
        body,
        auth,
        origin,
        host,
    } = match read_request(stream, opts.max_body_bytes) {
        Ok(request) => request,
        Err(error) => {
            write_http(stream, 400, "application/json", &error_json(&error))?;
            return Ok(());
        }
    };
    if method.is_empty() {
        return Ok(());
    }
    // Uma página web manda `Origin` em todo POST/PUT/DELETE, inclusive nos pedidos
    // "simples" (formulário ou `fetch` sem preflight): só a origem liberada escreve.
    if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        if let Some(origin) = origin.as_deref() {
            let allowed = cors_origin();
            if allowed != "*" && allowed != origin {
                return Err(Error::Forbidden(format!("origem {origin} não liberada")));
            }
        }
    }
    let (path, query) = split_target(&target);
    let health = matches!(path.as_str(), "/health" | "/v1/health");
    // Contra DNS rebinding: uma página pode apontar um nome dela para 127.0.0.1 e ler a
    // API como "mesma origem". O `Host` revela o nome usado; nomes de fora são recusados.
    if !health && !host_allowed(host.as_deref(), allowed_hosts()) {
        let name = host.as_deref().unwrap_or_default();
        return Err(Error::Forbidden(format!(
            "nome de host {name} não liberado; defina MINIDB_ALLOWED_HOSTS para liberá-lo"
        )));
    }
    let public = method == "OPTIONS" || health;
    // `Authorization: Basic base64(usuário:senha)` → principal com privilégios.
    let basic = auth
        .as_deref()
        .and_then(|h| {
            h.strip_prefix("Basic ")
                .or_else(|| h.strip_prefix("basic "))
        })
        .and_then(|b| crate::crypto::base64_decode(b.trim()))
        .and_then(|raw| String::from_utf8(raw).ok());
    let mut principal = None;
    if let Some(pair) = basic {
        let (user, password) = pair.split_once(':').unwrap_or((pair.as_str(), ""));
        principal = Some(crate::auth::authenticate(&*db.read()?, user, password)?);
    }
    // Certificado de cliente verificado: o CN é o usuário do banco.
    let peer = stream.peer();
    crate::rel::set_conn_info(crate::rel::ConnInfo {
        pid: 0,
        ssl: stream.is_tls(),
        client_addr: None,
        client_dn: peer.as_ref().map(|p| p.subject.clone()),
        client_issuer: peer.as_ref().map(|p| p.issuer.clone()),
    });
    if principal.is_none() {
        if let Some(cn) = peer.as_ref().and_then(|p| p.cn.as_deref()) {
            principal = crate::auth::load(&*db.read()?, cn)?.filter(|p| p.login);
        }
    }
    let cert_trusted =
        principal.is_none() && peer.is_some() && !crate::auth::has_users(&*db.read()?)?;
    if !public && principal.is_none() && !cert_trusted {
        match &opts.token {
            Some(expected) => {
                let given = auth
                    .as_deref()
                    .and_then(|h| {
                        h.strip_prefix("Bearer ")
                            .or_else(|| h.strip_prefix("bearer "))
                    })
                    .unwrap_or_default();
                if !crate::crypto::constant_time_eq(given.trim().as_bytes(), expected.as_bytes()) {
                    return Err(Error::Unauthorized);
                }
            }
            None => {
                if crate::auth::has_users(&*db.read()?)? {
                    return Err(Error::Unauthorized);
                }
            }
        }
    }
    if let Some(p) = &principal {
        // Os streams mostram linhas de todas as tabelas: exigem SELECT em `*`.
        if matches!(path.as_str(), "/v1/changes" | "/v1/listen") {
            crate::auth::authorize_object(&*db.read()?, p, "*", crate::auth::Privilege::Select)?;
        }
        // Chave-valor e administração: privilégio em `kv`; SQL é conferido por comando.
        let needed = match (method.as_str(), path.as_str()) {
            (_, "/v1/sql") | (_, "/metrics") | (_, "/v1/metrics") | (_, "/v1/stats") => None,
            ("GET", _) => Some(crate::auth::Privilege::Select),
            ("PUT" | "POST", "/v1/kv" | "/v1/expire" | "/v1/batch") => {
                Some(crate::auth::Privilege::Insert)
            }
            ("DELETE", _) | ("POST", "/v1/purge") => Some(crate::auth::Privilege::Delete),
            _ => Some(crate::auth::Privilege::All),
        };
        if let Some(needed) = needed {
            crate::auth::authorize_object(&*db.read()?, p, "kv", needed)?;
        }
    }
    if let Err(error) = validate_query(&query) {
        return bad_request(stream, &error.to_string());
    }
    if let Some(result) = handle_extended(db, metrics, stream, &method, &path, &query, &body) {
        return result;
    }
    if method == "OPTIONS" {
        return match allowed_methods(&path) {
            Some(methods) => write_preflight(stream, methods),
            None => write_http(
                stream,
                404,
                "application/json",
                "{\"ok\":false,\"error\":\"not found\"}",
            ),
        };
    }

    match (method.as_str(), path.as_str()) {
        ("GET", "/health") | ("GET", "/v1/health") => write_http(
            stream,
            200,
            "application/json",
            "{\"ok\":true,\"service\":\"minidb\"}",
        ),
        ("GET", "/metrics") | ("GET", "/v1/metrics") => write_http(
            stream,
            200,
            "text/plain; version=0.0.4",
            &metrics.render_prometheus(),
        ),
        ("GET", "/v1/stats") => {
            let s = db.read()?.stats();
            let js = Json::obj()
                .put("root_page", Json::Number(s.root_page as i64))
                .put("index_root", Json::Number(s.index_root as i64))
                .put("next_page_id", Json::Number(s.next_page_id as i64))
                .put("checkpoint_lsn", Json::Number(s.checkpoint_lsn as i64))
                .put("next_lsn", Json::Number(s.next_lsn as i64))
                .put("pool_capacity", Json::Number(s.pool_capacity as i64))
                .put("next_txn_id", Json::Number(s.next_txn_id as i64))
                .put("ttl_root", Json::Number(s.ttl_root as i64))
                .put("value_index", Json::Bool(s.value_index))
                .put("txn_open", Json::Bool(s.txn_open))
                .put("applied_lsn", Json::Number(s.applied_lsn as i64))
                .put("wal_bytes", Json::Number(s.wal_bytes as i64))
                .put("cached_pages", Json::Number(s.cached_pages as i64))
                .put("read_only", Json::Bool(s.read_only))
                .put("snapshots", Json::Number(s.snapshots as i64))
                .put("versions", Json::Number(s.versions as i64))
                .put("compressed", Json::Bool(s.compressed))
                .stringify();
            write_http(stream, 200, "application/json", &js)
        }
        ("GET", "/v1/kv") => {
            let key_bytes = match query_bytes(&query, "key", "key_hex") {
                Ok(value) => value.unwrap_or_default(),
                Err(error) => return bad_request(stream, &error.to_string()),
            };
            if let Err(error) = crate::btree::validate_user_key(&key_bytes) {
                return bad_request(stream, &error.to_string());
            }
            let hit = db.get(&key_bytes)?;
            metrics.inc_get(hit.is_some());
            let js = match hit {
                Some(v) => Json::obj()
                    .put("ok", Json::Bool(true))
                    .put(
                        "key",
                        Json::String(String::from_utf8_lossy(&key_bytes).into_owned()),
                    )
                    .put("key_hex", Json::String(hex_encode(&key_bytes)))
                    .put(
                        "value",
                        Json::String(String::from_utf8_lossy(&v).into_owned()),
                    )
                    .put("value_hex", Json::String(hex_encode(&v)))
                    .stringify(),
                None => Json::obj()
                    .put("ok", Json::Bool(true))
                    .put(
                        "key",
                        Json::String(String::from_utf8_lossy(&key_bytes).into_owned()),
                    )
                    .put("key_hex", Json::String(hex_encode(&key_bytes)))
                    .put("value", Json::Null)
                    .put("value_hex", Json::Null)
                    .stringify(),
            };
            write_http(stream, 200, "application/json", &js)
        }
        ("PUT", "/v1/kv") | ("POST", "/v1/kv") => {
            let j = match Json::parse(&body) {
                Ok(value) => value,
                Err(e) => return bad_request(stream, &e.to_string()),
            };
            let key = match json_bytes(&j, "key", "key_hex") {
                Ok(bytes) => bytes,
                Err(error) => return bad_request(stream, &error.to_string()),
            };
            let val = match json_bytes(&j, "value", "value_hex") {
                Ok(bytes) => bytes,
                Err(error) => return bad_request(stream, &error.to_string()),
            };
            if let Err(error) = crate::btree::validate_user_key(&key) {
                return bad_request(stream, &error.to_string());
            }
            if let Err(error) = crate::btree::validate_value(&val) {
                return bad_request(stream, &error.to_string());
            }
            match json_ttl(&j) {
                Ok(Some(ttl)) => db.put_with_ttl(&key, &val, ttl)?,
                Ok(None) => db.put(&key, &val)?,
                Err(error) => return bad_request(stream, &error.to_string()),
            }
            metrics.inc_put();
            write_http(stream, 200, "application/json", "{\"ok\":true}")
        }
        ("DELETE", "/v1/kv") => {
            let key_bytes = match query_bytes(&query, "key", "key_hex") {
                Ok(value) => value.unwrap_or_default(),
                Err(error) => return bad_request(stream, &error.to_string()),
            };
            if let Err(error) = crate::btree::validate_user_key(&key_bytes) {
                return bad_request(stream, &error.to_string());
            }
            let ok = db.delete(&key_bytes)?;
            metrics.inc_delete();
            write_http(
                stream,
                200,
                "application/json",
                &format!("{{\"ok\":true,\"deleted\":{ok}}}"),
            )
        }
        ("GET", "/v1/scan") => {
            let start = match query_bytes(&query, "start", "start_hex") {
                Ok(Some(bytes)) => bytes,
                Ok(None) => vec![0],
                Err(error) => return bad_request(stream, &error.to_string()),
            };
            let start = if start.is_empty() { vec![0] } else { start };
            let end = match query_bytes(&query, "end", "end_hex") {
                Ok(value) => value,
                Err(error) => return bad_request(stream, &error.to_string()),
            };
            let (start, end) = match query_bytes(&query, "prefix", "prefix_hex") {
                Ok(None) => (start, end),
                Ok(Some(_))
                    if qget(&query, "start").is_some()
                        || qget(&query, "start_hex").is_some()
                        || end.is_some() =>
                {
                    return bad_request(stream, "prefix não combina com start/end");
                }
                Ok(Some(prefix)) => {
                    let end = crate::db::prefix_successor(&prefix);
                    (prefix, end)
                }
                Err(error) => return bad_request(stream, &error.to_string()),
            };
            let after = match query_bytes(&query, "after", "after_hex") {
                Ok(value) => value.filter(|cursor| !cursor.is_empty()),
                Err(error) => return bad_request(stream, &error.to_string()),
            };
            let limit = match qget(&query, "limit") {
                Some(raw) => match raw.parse::<usize>() {
                    Ok(value) if (1..=10_000).contains(&value) => Some(value),
                    _ => return bad_request(stream, "limit deve estar entre 1 e 10000"),
                },
                None => None,
            };
            if after.is_some() && limit.is_none() {
                return bad_request(stream, "after/after_hex requer limit");
            }
            if let Err(error) = crate::btree::validate_user_key(&start) {
                return bad_request(stream, &error.to_string());
            }
            if let Some(end) = end.as_deref() {
                if let Err(error) = crate::btree::validate_user_key(end) {
                    return bad_request(stream, &error.to_string());
                }
            }
            if let Some(after) = after.as_deref() {
                if let Err(error) = crate::btree::validate_user_key(after) {
                    return bad_request(stream, &error.to_string());
                }
            }
            let guard = db.read()?;
            let rows = match limit {
                Some(limit) => guard.scan_page(&start, end.as_deref(), after.as_deref(), limit)?,
                None => guard.scan(&start, end.as_deref())?,
            };
            let arr: Vec<Json> = rows
                .into_iter()
                .map(|(k, v)| {
                    Json::obj()
                        .put(
                            "key",
                            Json::String(String::from_utf8_lossy(&k).into_owned()),
                        )
                        .put("key_hex", Json::String(hex_encode(&k)))
                        .put(
                            "value",
                            Json::String(String::from_utf8_lossy(&v).into_owned()),
                        )
                        .put("value_hex", Json::String(hex_encode(&v)))
                })
                .collect();
            let js = Json::obj()
                .put("ok", Json::Bool(true))
                .put("rows", Json::Array(arr))
                .stringify();
            write_http(stream, 200, "application/json", &js)
        }
        ("GET", "/v1/changes") => {
            let since = match qget(&query, "since") {
                Some(v) => match v.parse::<u64>() {
                    Ok(n) => n,
                    Err(_) => return bad_request(stream, "since deve ser um LSN inteiro"),
                },
                None => db.events().head_lsn(),
            };
            let table = qget(&query, "table");
            let limit = qget(&query, "limit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(500usize)
                .clamp(1, 10_000);
            let timeout = Duration::from_secs(
                qget(&query, "timeout")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(300u64)
                    .min(3600),
            );
            let once = qget(&query, "once").is_some();
            metrics.inc_sql();
            stream_changes(db, stream, since, table.as_deref(), limit, timeout, once)
        }
        ("GET", "/v1/listen") => {
            let channels: Vec<String> = query
                .split('&')
                .filter_map(|kv| kv.strip_prefix("channel="))
                .filter_map(|v| percent_decode(v).ok())
                .filter(|v| !v.is_empty())
                .collect();
            if channels.is_empty() {
                return bad_request(stream, "informe ao menos um channel=");
            }
            let timeout = Duration::from_secs(
                qget(&query, "timeout")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(300u64)
                    .min(3600),
            );
            metrics.inc_sql();
            stream_notifications(db, stream, &channels, timeout)
        }
        ("POST", "/v1/sql") => {
            let j = match Json::parse(&body) {
                Ok(value) => value,
                Err(e) => return bad_request(stream, &e.to_string()),
            };
            let sql = match j.get("sql").and_then(Json::as_str) {
                Some(value) => value,
                None => return bad_request(stream, "campo sql ausente ou inválido"),
            };
            let params = match j.get("params") {
                None | Some(Json::Null) => Vec::new(),
                Some(Json::Array(items)) => match items.iter().map(json_param).collect() {
                    Ok(params) => params,
                    Err(error) => return bad_request(stream, &error.to_string()),
                },
                Some(_) => return bad_request(stream, "params deve ser array"),
            };
            if let Ok(statement) = crate::sql::parse_sql(sql) {
                if let Err(error) = validate_sql_input(&statement) {
                    return bad_request(stream, &error.to_string());
                }
            }
            metrics.inc_sql();
            let outcome = match &principal {
                None => db.sql_params(sql, &params),
                Some(p) => {
                    let mut session = db.session();
                    session.set_principal(Some(p.clone()));
                    let result = session.execute_params(sql, &params);
                    if session.in_transaction() {
                        let _ = session.rollback();
                        return bad_request(
                            stream,
                            "script terminou com transação aberta: falta COMMIT",
                        );
                    }
                    result
                }
            };
            match outcome {
                Ok(result) => write_http(stream, 200, "application/json", &exec_json(result)),
                Err(error @ (Error::TxnOpen | Error::TxnNotOpen)) => {
                    bad_request(stream, &format!("estado transacional inválido: {error}"))
                }
                Err(error) => Err(error),
            }
        }
        ("GET", "/openapi.json") | ("GET", "/v1/openapi.json") => {
            write_http(stream, 200, "application/json", OPENAPI_MIN)
        }
        _ if allowed_methods(&path).is_some() => {
            write_method_not_allowed(stream, allowed_methods(&path).unwrap())
        }
        _ => write_http(
            stream,
            404,
            "application/json",
            "{\"ok\":false,\"error\":\"not found\"}",
        ),
    }
}

fn allowed_methods(path: &str) -> Option<&'static str> {
    match path {
        "/health" | "/v1/health" | "/metrics" | "/v1/metrics" | "/openapi.json"
        | "/v1/openapi.json" | "/v1/stats" | "/v1/scan" | "/v1/count" | "/v1/pages" | "/v1/ttl" => {
            Some("GET, OPTIONS")
        }
        "/v1/batch" | "/v1/expire" | "/v1/purge" | "/v1/replication/promote" | "/v1/maintain" => {
            Some("POST, OPTIONS")
        }
        "/v1/replication" | "/v1/changes" | "/v1/listen" => Some("GET, OPTIONS"),
        "/v1/kv" => Some("GET, PUT, POST, DELETE, OPTIONS"),
        "/v1/sql" => Some("POST, OPTIONS"),
        _ => None,
    }
}

const OPENAPI_MIN: &str = r##"{
    "openapi": "3.0.0",
    "info": {"title": "Mini-DB", "version": "1.3.0"},
    "paths": {
        "/health": {"get": {"responses": {"200": {"description": "Service is alive"}, "405": {"description": "Method not allowed"}, "503": {"description": "Connection limit reached"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/metrics": {"get": {"responses": {"200": {"description": "Prometheus text exposition"}, "405": {"description": "Method not allowed"}, "503": {"description": "Connection limit reached"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/openapi.json": {"get": {"responses": {"200": {"description": "This API description"}, "405": {"description": "Method not allowed"}, "503": {"description": "Connection limit reached"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/v1/stats": {"get": {"responses": {"200": {"description": "Database and buffer-pool counters"}, "405": {"description": "Method not allowed"}, "503": {"description": "Connection limit reached"}, "500": {"description": "Database error"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/v1/kv": {
            "get": {"parameters": [{"name": "key", "in": "query", "schema": {"type": "string"}}, {"name": "key_hex", "in": "query", "schema": {"type": "string", "pattern": "^([0-9a-fA-F]{2})*$"}}], "responses": {"200": {"description": "Found value or null; byte fields are also returned as hex"}, "400": {"description": "Malformed query or invalid key"}, "405": {"description": "Method not allowed"}, "503": {"description": "Connection limit reached"}, "500": {"description": "Database error"}}},
            "put": {"requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/KvRequest"}}}}, "responses": {"200": {"description": "Stored"}, "400": {"description": "Malformed JSON, key, or value"}, "405": {"description": "Method not allowed"}, "503": {"description": "Connection limit reached"}, "500": {"description": "Database error"}}},
            "post": {"requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/KvRequest"}}}}, "responses": {"200": {"description": "Stored"}, "400": {"description": "Malformed JSON, key, or value"}, "405": {"description": "Method not allowed"}, "503": {"description": "Connection limit reached"}, "500": {"description": "Database error"}}},
            "delete": {"parameters": [{"name": "key", "in": "query", "schema": {"type": "string"}}, {"name": "key_hex", "in": "query", "schema": {"type": "string", "pattern": "^([0-9a-fA-F]{2})*$"}}], "responses": {"200": {"description": "Deleted flag"}, "400": {"description": "Malformed query or invalid key"}, "405": {"description": "Method not allowed"}, "503": {"description": "Connection limit reached"}, "500": {"description": "Database error"}}},
            "options": {"responses": {"204": {"description": "CORS preflight response"}}}
        },
        "/v1/scan": {"get": {"parameters": [{"name": "start", "in": "query", "schema": {"type": "string"}}, {"name": "end", "in": "query", "schema": {"type": "string"}}, {"name": "after", "in": "query", "schema": {"type": "string"}}, {"name": "prefix", "in": "query", "schema": {"type": "string"}}, {"name": "prefix_hex", "in": "query", "schema": {"type": "string"}}, {"name": "start_hex", "in": "query", "schema": {"type": "string", "pattern": "^([0-9a-fA-F]{2})*$"}}, {"name": "end_hex", "in": "query", "schema": {"type": "string", "pattern": "^([0-9a-fA-F]{2})*$"}}, {"name": "after_hex", "in": "query", "schema": {"type": "string", "pattern": "^([0-9a-fA-F]{2})*$"}}, {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 10000}}], "responses": {"200": {"description": "Rows in key order; end is exclusive and after requires limit"}, "400": {"description": "Malformed query, key, cursor, or limit"}, "405": {"description": "Method not allowed"}, "503": {"description": "Connection limit reached"}, "500": {"description": "Database error"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/v1/count": {"get": {"parameters": [{"name": "start", "in": "query", "schema": {"type": "string"}}, {"name": "end", "in": "query", "schema": {"type": "string"}}, {"name": "prefix", "in": "query", "schema": {"type": "string"}}, {"name": "start_hex", "in": "query", "schema": {"type": "string"}}, {"name": "end_hex", "in": "query", "schema": {"type": "string"}}, {"name": "prefix_hex", "in": "query", "schema": {"type": "string"}}], "responses": {"200": {"description": "Number of visible keys in the range or prefix"}, "400": {"description": "Invalid input"}, "405": {"description": "Method not allowed"}, "500": {"description": "Database error"}, "503": {"description": "Connection limit reached"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/v1/ttl": {"get": {"parameters": [{"name": "key", "in": "query", "schema": {"type": "string"}}, {"name": "key_hex", "in": "query", "schema": {"type": "string"}}], "responses": {"200": {"description": "TTL state: missing, persistent or expires with ttl_ms"}, "400": {"description": "Invalid input"}, "405": {"description": "Method not allowed"}, "500": {"description": "Database error"}, "503": {"description": "Connection limit reached"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/v1/pages": {"get": {"parameters": [], "responses": {"200": {"description": "Page occupancy statistics"}, "400": {"description": "Invalid input"}, "405": {"description": "Method not allowed"}, "500": {"description": "Database error"}, "503": {"description": "Connection limit reached"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/v1/batch": {"post": {"requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/BatchRequest"}}}}, "responses": {"200": {"description": "Atomic batch applied"}, "400": {"description": "Invalid input"}, "405": {"description": "Method not allowed"}, "500": {"description": "Database error"}, "503": {"description": "Connection limit reached"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/v1/expire": {"post": {"requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ExpireRequest"}}}}, "responses": {"200": {"description": "TTL updated; ttl_ms null removes it"}, "400": {"description": "Invalid input"}, "405": {"description": "Method not allowed"}, "500": {"description": "Database error"}, "503": {"description": "Connection limit reached"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/v1/purge": {"post": {"responses": {"200": {"description": "Expired keys physically removed"}, "400": {"description": "Invalid input"}, "405": {"description": "Method not allowed"}, "500": {"description": "Database error"}, "503": {"description": "Connection limit reached"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/v1/sql": {"post": {"requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SqlRequest"}}}}, "responses": {"200": {"description": "SQL result; scripts return one result per statement"}, "400": {"description": "Invalid SQL or request state"}, "401": {"description": "Missing or invalid credentials"}, "403": {"description": "Missing privilege or read-only replica"}, "405": {"description": "Method not allowed"}, "409": {"description": "Transaction conflict"}, "503": {"description": "Connection limit reached"}, "500": {"description": "Database error"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}},
        "/v1/changes": {"get": {"parameters": [{"name": "since", "in": "query", "schema": {"type": "integer", "minimum": 0}}, {"name": "table", "in": "query", "schema": {"type": "string"}}, {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1}}, {"name": "timeout", "in": "query", "schema": {"type": "integer", "minimum": 1}}, {"name": "once", "in": "query", "schema": {"type": "integer", "enum": [1]}}], "responses": {"200": {"description": "Committed row changes as Server-Sent Events, or one JSON batch with once=1"}, "401": {"description": "Missing or invalid credentials"}, "403": {"description": "Requires SELECT on *"}, "410": {"description": "LSN no longer in the change ring; first_available is returned"}, "503": {"description": "Connection limit reached"}}}},
        "/v1/listen": {"get": {"parameters": [{"name": "channel", "in": "query", "required": true, "schema": {"type": "string"}}, {"name": "timeout", "in": "query", "schema": {"type": "integer", "minimum": 1}}], "responses": {"200": {"description": "NOTIFY messages as Server-Sent Events"}, "401": {"description": "Missing or invalid credentials"}, "403": {"description": "Requires SELECT on *"}, "503": {"description": "Connection limit reached"}}}},
        "/v1/replication": {"get": {"responses": {"200": {"description": "Role, epoch, LSNs, connected replicas and sync mode"}, "401": {"description": "Missing or invalid credentials"}, "503": {"description": "Connection limit reached"}}}},
        "/v1/replication/promote": {"post": {"responses": {"200": {"description": "Replica promoted to primary with a new epoch"}, "400": {"description": "Not a replica"}, "401": {"description": "Missing or invalid credentials"}, "503": {"description": "Connection limit reached"}}}},
        "/v1/maintain": {"post": {"responses": {"200": {"description": "Checkpoint, purge and vacuum decided by the maintenance policy"}, "401": {"description": "Missing or invalid credentials"}, "500": {"description": "Database error"}, "503": {"description": "Connection limit reached"}}}}
    },
    "components": {"schemas": {
        "KvRequest": {"type": "object", "properties": {"key": {"type": "string"}, "value": {"type": "string"}, "key_hex": {"type": "string"}, "value_hex": {"type": "string"}, "ttl_ms": {"type": "integer", "minimum": 1}}, "anyOf": [{"required": ["key", "value"]}, {"required": ["key_hex", "value_hex"]}]},
        "BatchRequest": {"type": "object", "required": ["ops"], "properties": {"ops": {"type": "array", "minItems": 1, "maxItems": 10000, "items": {"type": "object", "required": ["op"], "properties": {"op": {"enum": ["put", "delete"]}, "key": {"type": "string"}, "key_hex": {"type": "string"}, "value": {"type": "string"}, "value_hex": {"type": "string"}, "ttl_ms": {"type": "integer", "minimum": 1}}}}}},
        "ExpireRequest": {"type": "object", "properties": {"key": {"type": "string"}, "key_hex": {"type": "string"}, "ttl_ms": {"type": ["integer", "null"], "minimum": 1}}},
        "SqlRequest": {"type": "object", "required": ["sql"], "properties": {"sql": {"type": "string"}, "params": {"type": "array", "description": "Values for ?, ?N and $N (single statement only)", "items": {"type": ["string", "number", "boolean", "null"]}}}},
        "Error": {"type": "object", "required": ["ok", "error"], "properties": {"ok": {"type": "boolean"}, "error": {"type": "string"}}}
    }}
}"##;

fn split_target(t: &str) -> (String, String) {
    match t.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (t.to_string(), String::new()),
    }
}

fn qget(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let (encoded_key, encoded_value) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(encoded_key).ok().as_deref() == Some(key) {
            if let Ok(value) = percent_decode(encoded_value) {
                return Some(value);
            }
        }
    }
    None
}

fn json_bytes(json: &Json, text_field: &str, hex_field: &str) -> Result<Vec<u8>> {
    if let Some(value) = json.get(hex_field) {
        let value = value
            .as_str()
            .ok_or_else(|| Error::InvalidInput(format!("campo {hex_field} deve ser string")))?;
        return hex_decode(value);
    }
    json.get(text_field)
        .and_then(Json::as_str)
        .map(|value| value.as_bytes().to_vec())
        .ok_or_else(|| Error::InvalidInput(format!("campo {text_field} ou {hex_field} ausente")))
}

fn validate_query(query: &str) -> Result<()> {
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        percent_decode(key)?;
        percent_decode(value)?;
    }
    Ok(())
}

fn query_bytes(query: &str, text_key: &str, hex_key: &str) -> Result<Option<Vec<u8>>> {
    if let Some(value) = qget(query, hex_key) {
        return hex_decode(&value).map(Some);
    }
    Ok(qget(query, text_key).map(String::into_bytes))
}

fn validate_sql_input(statement: &crate::sql::Statement) -> Result<()> {
    use crate::sql::{Pred, Statement};

    match statement {
        Statement::Explain(inner) => validate_sql_input(inner),
        Statement::Insert { key, value, .. } | Statement::Update { key, value } => {
            crate::btree::validate_user_key(key)?;
            crate::btree::validate_value(value)
        }
        Statement::Delete { key } => crate::btree::validate_user_key(key),
        Statement::Select {
            pred: Some(Pred::KeyCmp { value, .. }),
            ..
        } => crate::btree::validate_user_key(value),
        _ => Ok(()),
    }
}

fn percent_decode(input: &str) -> Result<String> {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => decoded.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char)
                    .to_digit(16)
                    .ok_or_else(|| Error::InvalidInput("query inválida".into()))?;
                let lo = (bytes[i + 2] as char)
                    .to_digit(16)
                    .ok_or_else(|| Error::InvalidInput("query inválida".into()))?;
                decoded.push((hi * 16 + lo) as u8);
                i += 2;
            }
            b'%' => return Err(Error::InvalidInput("query inválida".into())),
            byte => decoded.push(byte),
        }
        i += 1;
    }
    String::from_utf8(decoded).map_err(|_| Error::InvalidInput("query não é UTF-8".into()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_decode(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::InvalidInput(
            "hexadecimal deve ter comprimento par".into(),
        ));
    }
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| Error::InvalidInput("hexadecimal inválido".into()))?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| Error::InvalidInput("hexadecimal inválido".into()))?;
        output.push(((high << 4) | low) as u8);
    }
    Ok(output)
}

fn bad_request(stream: &mut dyn HttpIo, message: &str) -> Result<()> {
    let body = error_json(&Error::Other(message.to_string()));
    write_http(stream, 400, "application/json", &body)
}

struct Request {
    method: String,
    target: String,
    body: String,
    /// Cabeçalho `Authorization`, se houver.
    auth: Option<String>,
    /// Cabeçalho `Origin`, se houver (requisição feita por uma página web).
    origin: Option<String>,
    /// Cabeçalho `Host` (com a porta, se houver).
    host: Option<String>,
}

/// Socket HTTP em claro (`TcpStream`) ou TLS.
pub trait HttpIo: Read + Write {
    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()>;
    /// Certificado de cliente verificado (mTLS), se houver.
    fn peer(&self) -> Option<crate::tls::Peer> {
        None
    }
    fn is_tls(&self) -> bool {
        false
    }
}

impl HttpIo for TcpStream {
    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
}

impl HttpIo for crate::tls::TlsStream<TcpStream> {
    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        self.get_ref().set_read_timeout(timeout)
    }
    fn peer(&self) -> Option<crate::tls::Peer> {
        crate::tls::TlsStream::peer(self).cloned()
    }
    fn is_tls(&self) -> bool {
        true
    }
}

fn read_request(stream: &mut dyn HttpIo, max_body: usize) -> Result<Request> {
    let mut request = Vec::with_capacity(4096);
    let header_end = loop {
        let mut byte = [0u8; 1024];
        let n = stream.read(&mut byte)?;
        if n == 0 {
            if request.is_empty() {
                return Ok(Request {
                    method: String::new(),
                    target: String::new(),
                    body: String::new(),
                    auth: None,
                    origin: None,
                    host: None,
                });
            }
            return Err(Error::Other("requisição HTTP incompleta".into()));
        }
        request.extend_from_slice(&byte[..n]);
        if let Some(pos) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = pos + 4;
            if end > MAX_HEADER_BYTES {
                return Err(Error::Other("cabeçalho HTTP muito grande".into()));
            }
            break end;
        }
        if request.len() > MAX_HEADER_BYTES {
            return Err(Error::Other("cabeçalho HTTP muito grande".into()));
        }
    };

    let header_text = std::str::from_utf8(&request[..header_end])
        .map_err(|_| Error::Other("cabeçalho HTTP não é UTF-8".into()))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| Error::Other("linha HTTP ausente".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| Error::Other("método HTTP ausente".into()))?
        .to_ascii_uppercase();
    let target = parts
        .next()
        .ok_or_else(|| Error::Other("alvo HTTP ausente".into()))?
        .to_string();
    let version = parts.next().unwrap_or("");
    if version != "HTTP/1.1" {
        return Err(Error::Other("somente HTTP/1.1 é suportado".into()));
    }

    let mut content_len = 0usize;
    let mut auth = None;
    let mut origin = None;
    let mut host = None;
    let mut has_content_len = false;
    let mut has_transfer_encoding = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Error::Other("cabeçalho HTTP inválido".into()))?;
        if name.eq_ignore_ascii_case("content-length") {
            if has_content_len || has_transfer_encoding {
                return Err(Error::Other("framing HTTP ambíguo".into()));
            }
            has_content_len = true;
            content_len = value
                .trim()
                .parse()
                .map_err(|_| Error::Other("Content-Length inválido".into()))?;
            if content_len > max_body {
                return Err(Error::Other(format!(
                    "corpo HTTP muito grande ({content_len} bytes; máx {max_body})"
                )));
            }
        } else if name.eq_ignore_ascii_case("authorization") {
            auth = Some(value.trim().to_string());
        } else if name.eq_ignore_ascii_case("origin") {
            origin = Some(value.trim().to_string());
        } else if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err(Error::Other("cabeçalho Host duplicado".into()));
            }
            host = Some(value.trim().to_string());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if has_transfer_encoding || has_content_len {
                return Err(Error::Other("framing HTTP ambíguo".into()));
            }
            has_transfer_encoding = true;
            if !value.trim().eq_ignore_ascii_case("identity") {
                return Err(Error::Other("Transfer-Encoding não suportado".into()));
            }
        }
    }

    let mut body = request[header_end..].to_vec();
    while body.len() < content_len {
        let remaining = content_len - body.len();
        let mut chunk = vec![0u8; remaining.min(8192)];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(Error::Other("corpo HTTP incompleto".into()));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_len);
    let body =
        String::from_utf8(body).map_err(|_| Error::Other("corpo HTTP não é UTF-8".into()))?;
    Ok(Request {
        method,
        target,
        body,
        auth,
        origin,
        host,
    })
}

fn write_http(stream: &mut dyn HttpIo, code: u16, ctype: &str, body: &str) -> Result<()> {
    let reason = match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        409 => "Conflict",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        404 => "Not Found",
        _ => "Error",
    };
    let cors = cors_headers();
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n{cors}\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

fn write_method_not_allowed(stream: &mut dyn HttpIo, allowed: &str) -> Result<()> {
    let body = "{\"ok\":false,\"error\":\"method not allowed\"}";
    let cors = cors_headers();
    let header = format!(
        "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAllow: {allowed}\r\n{cors}\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

/// Origem liberada por `MINIDB_CORS_ORIGIN`, lida uma vez (vazia: nenhuma; `*`: todas).
fn cors_origin() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE.get_or_init(|| match std::env::var("MINIDB_CORS_ORIGIN") {
        Ok(origin) if !origin.contains(['\r', '\n']) => origin,
        _ => String::new(),
    })
}

/// Nomes de host liberados por `MINIDB_ALLOWED_HOSTS` (separados por vírgula), lidos uma
/// vez. `*` desliga a checagem de `Host`.
fn allowed_hosts() -> &'static str {
    static VALUE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VALUE.get_or_init(|| std::env::var("MINIDB_ALLOWED_HOSTS").unwrap_or_default())
}

/// Nome do `Host` sem a porta, sem os colchetes de um IPv6 (`[::1]:80` vira `::1`) e sem
/// o ponto final (`exemplo.com.` vira `exemplo.com`).
fn host_name(host: &str) -> &str {
    let host = host.trim();
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(rest),
        None => host.split_once(':').map_or(host, |(name, _)| name),
    };
    name.trim_end_matches('.')
}

/// Decide se o cabeçalho `Host` é aceito (defesa contra DNS rebinding). Passam: ausente
/// (HTTP/1.0), IP literal, nome sem ponto (`localhost`, serviço do docker-compose: um
/// domínio que um atacante registra sempre tem ponto), `*.localhost` e os nomes de
/// `allowed` (lista separada por vírgula, sem diferenciar caixa; `*` libera tudo).
fn host_allowed(host: Option<&str>, allowed: &str) -> bool {
    let host = match host {
        Some(host) => host,
        None => return true,
    };
    if allowed.split(',').any(|item| item.trim() == "*") {
        return true;
    }
    let name = host_name(host).to_ascii_lowercase();
    if name.is_empty() {
        return false;
    }
    if name.parse::<std::net::IpAddr>().is_ok() || !name.contains('.') {
        return true;
    }
    if name.ends_with(".localhost") {
        return true;
    }
    allowed
        .split(',')
        .any(|item| host_name(item).eq_ignore_ascii_case(&name))
}

/// Cabeçalhos CORS (já com `\r\n` no fim). Por padrão não há nenhum: o navegador
/// não deixa um site qualquer ler as respostas nem mandar pedidos com preflight
/// (`PUT`, `DELETE`, JSON). O `POST` "simples", que dispensa preflight, é recusado
/// em `handle` pelo cabeçalho `Origin`. Para liberar uma origem (um painel web, por
/// exemplo), defina `MINIDB_CORS_ORIGIN`.
fn cors_headers() -> String {
    match cors_origin() {
        "" => String::new(),
        origin => format!("Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n"),
    }
}

fn write_preflight(stream: &mut dyn HttpIo, methods: &str) -> Result<()> {
    let cors = cors_headers();
    let header = format!(
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n{cors}Access-Control-Allow-Methods: {methods}\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nAccess-Control-Max-Age: 600\r\n\r\n"
    );
    stream.write_all(header.as_bytes())?;
    Ok(())
}

/// Parâmetro SQL a partir de JSON.
fn json_param(j: &Json) -> Result<crate::rel::Value> {
    use crate::rel::Value;
    Ok(match j {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => Value::Int(*n),
        Json::Float(x) => Value::Real(*x),
        Json::String(s) => Value::Text(s.clone()),
        _ => {
            return Err(Error::InvalidInput(
                "parâmetros devem ser null, bool, número ou texto".into(),
            ))
        }
    })
}

/// Lê `ttl_ms` opcional (inteiro > 0) de um corpo JSON.
fn json_ttl(json: &Json) -> Result<Option<Duration>> {
    match json.get("ttl_ms") {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Number(ms)) if *ms > 0 => Ok(Some(Duration::from_millis(*ms as u64))),
        Some(_) => Err(Error::InvalidInput("ttl_ms deve ser inteiro > 0".into())),
    }
}

fn ok_json(fields: &[(&str, Json)]) -> String {
    fields
        .iter()
        .fold(Json::obj().put("ok", Json::Bool(true)), |acc, (k, v)| {
            acc.put(k, v.clone())
        })
        .stringify()
}

const MAX_BATCH_OPS: usize = 10_000;

/// Rotas adicionadas na 0.4: contagem, lote atômico, TTL, purge e páginas.
/// Devolve `None` quando a rota não é uma delas.
fn handle_extended(
    db: &SharedDb,
    metrics: &Metrics,
    stream: &mut dyn HttpIo,
    method: &str,
    path: &str,
    query: &str,
    body: &str,
) -> Option<Result<()>> {
    let reply = |stream: &mut dyn HttpIo, fields: &[(&str, Json)]| {
        write_http(stream, 200, "application/json", &ok_json(fields))
    };
    let result = match (method, path) {
        ("GET", "/v1/count") => (|| {
            let (start, end) = match query_bytes(query, "prefix", "prefix_hex")? {
                Some(prefix) => {
                    let end = crate::db::prefix_successor(&prefix);
                    (prefix, end)
                }
                None => (
                    query_bytes(query, "start", "start_hex")?
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| vec![0]),
                    query_bytes(query, "end", "end_hex")?,
                ),
            };
            let n = db.read()?.count(&start, end.as_deref())?;
            reply(stream, &[("count", Json::Number(n as i64))])
        })(),
        ("GET", "/v1/ttl") => (|| {
            let key = query_bytes(query, "key", "key_hex")?.unwrap_or_default();
            let (state, ms) = match db.read()?.ttl(&key)? {
                crate::KeyTtl::Missing => ("missing", Json::Null),
                crate::KeyTtl::Persistent => ("persistent", Json::Null),
                crate::KeyTtl::ExpiresIn(d) => ("expires", Json::Number(d.as_millis() as i64)),
            };
            reply(
                stream,
                &[("state", Json::String(state.into())), ("ttl_ms", ms)],
            )
        })(),
        ("GET", "/v1/pages") => (|| {
            let s = db.read()?.page_stats()?;
            let n = |v: u64| Json::Number(v as i64);
            reply(
                stream,
                &[
                    ("total_pages", n(s.total_pages.into())),
                    ("leaves", n(s.leaves.into())),
                    ("empty_leaves", n(s.empty_leaves.into())),
                    ("internals", n(s.internals.into())),
                    ("free_pages", n(s.free_pages.into())),
                    ("overflow_pages", n(s.overflow_pages.into())),
                    ("live_bytes", n(s.live_bytes)),
                    ("fill_percent", n(s.fill_percent.into())),
                    ("height", n(s.height.into())),
                ],
            )
        })(),
        ("POST", "/v1/expire") => (|| {
            let j = Json::parse(body).map_err(|e| Error::InvalidInput(e.to_string()))?;
            let key = json_bytes(&j, "key", "key_hex")?;
            let mut guard = db.write()?;
            let updated = match json_ttl(&j)? {
                Some(ttl) => guard.expire(&key, ttl)?,
                None => guard.persist(&key)?,
            };
            reply(stream, &[("updated", Json::Bool(updated))])
        })(),
        ("POST", "/v1/purge") => (|| {
            let n = db.write()?.purge_expired()?;
            reply(stream, &[("purged", Json::Number(n as i64))])
        })(),
        ("POST", "/v1/batch") => (|| {
            let j = Json::parse(body).map_err(|e| Error::InvalidInput(e.to_string()))?;
            let Some(Json::Array(items)) = j.get("ops") else {
                return Err(Error::InvalidInput("campo ops deve ser array".into()));
            };
            if items.is_empty() || items.len() > MAX_BATCH_OPS {
                return Err(Error::InvalidInput(format!(
                    "ops deve ter entre 1 e {MAX_BATCH_OPS} itens"
                )));
            }
            let mut batch = Vec::with_capacity(items.len());
            for item in items {
                let key = json_bytes(item, "key", "key_hex")?;
                crate::btree::validate_user_key(&key)?;
                batch.push(match item.get("op").and_then(Json::as_str) {
                    Some("put") => {
                        let value = json_bytes(item, "value", "value_hex")?;
                        crate::btree::validate_value(&value)?;
                        match json_ttl(item)? {
                            Some(ttl) => crate::BatchOp::PutWithTtl { key, value, ttl },
                            None => crate::BatchOp::Put { key, value },
                        }
                    }
                    Some("delete") => crate::BatchOp::Delete { key },
                    _ => return Err(Error::InvalidInput("op deve ser put ou delete".into())),
                });
            }
            db.write_batch(&batch)?;
            metrics.inc_batch(batch.len() as u64);
            reply(stream, &[("applied", Json::Number(batch.len() as i64))])
        })(),
        ("GET", "/v1/replication") => (|| {
            let s = crate::replication::status(db)?;
            let (role, upstream) = match s.role {
                crate::replication::Role::Primary => ("primary", Json::Null),
                crate::replication::Role::Replica { upstream } => {
                    ("replica", Json::String(upstream))
                }
                crate::replication::Role::Fenced => ("fenced", Json::Null),
            };
            reply(
                stream,
                &[
                    ("role", Json::String(role.into())),
                    ("upstream", upstream),
                    ("epoch", Json::Number(s.epoch as i64)),
                    ("applied_lsn", Json::Number(s.applied_lsn as i64)),
                    ("head_lsn", Json::Number(s.head_lsn as i64)),
                    ("feed_enabled", Json::Bool(s.feed_enabled)),
                    (
                        "replicas",
                        Json::Array(s.replicas.iter().map(|&l| Json::Number(l as i64)).collect()),
                    ),
                    ("sync_replicas", Json::Number(s.sync_replicas as i64)),
                    ("sync_timeouts", Json::Number(s.sync_timeouts as i64)),
                    ("resyncing", Json::Bool(s.resyncing)),
                ],
            )
        })(),
        ("POST", "/v1/replication/promote") => (|| {
            let epoch = crate::replication::promote(db)?;
            reply(stream, &[("epoch", Json::Number(epoch as i64))])
        })(),
        ("POST", "/v1/maintain") => (|| {
            let r = db.write()?.maintain(0.25)?;
            reply(
                stream,
                &[
                    ("purged", Json::Number(r.purged as i64)),
                    ("vacuumed", Json::Bool(r.vacuumed)),
                    ("checkpointed", Json::Bool(r.checkpointed)),
                ],
            )
        })(),
        _ => return None,
    };
    Some(match result {
        Err(error) if status_of(&error) != 500 => write_http(
            stream,
            status_of(&error),
            "application/json",
            &error_json(&error),
        ),
        other => other,
    })
}

/// Serializa o resultado de um comando SQL.
fn exec_json(result: ExecResult) -> String {
    exec_json_value(result).stringify()
}

fn exec_json_value(result: ExecResult) -> Json {
    let ok = Json::obj().put("ok", Json::Bool(true));
    match result {
        ExecResult::Ok(s) => ok.put("result", Json::String(s)),
        ExecResult::Value(None) => ok.put("value", Json::Null),
        ExecResult::Value(Some(v)) => ok.put(
            "value",
            Json::String(String::from_utf8_lossy(&v).into_owned()),
        ),
        ExecResult::Count(n) => ok.put("count", Json::Number(n as i64)),
        ExecResult::Rows(rows) => {
            let arr: Vec<Json> = rows
                .into_iter()
                .map(|(k, v)| {
                    Json::obj()
                        .put(
                            "key",
                            Json::String(String::from_utf8_lossy(&k).into_owned()),
                        )
                        .put(
                            "value",
                            Json::String(String::from_utf8_lossy(&v).into_owned()),
                        )
                })
                .collect();
            ok.put("rows", Json::Array(arr))
        }
        ExecResult::Table { columns, rows } => ok
            .put(
                "columns",
                Json::Array(columns.into_iter().map(Json::String).collect()),
            )
            .put(
                "rows",
                Json::Array(
                    rows.into_iter()
                        .map(|r| Json::Array(r.iter().map(crate::rel::Value::to_json).collect()))
                        .collect(),
                ),
            ),
        ExecResult::Batch(results) => ok.put(
            "results",
            Json::Array(results.into_iter().map(exec_json_value).collect()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        handle, hex_decode, hex_encode, host_allowed, percent_decode, qget, read_request,
        validate_query, write_http, Metrics, OPENAPI_MIN,
    };
    use crate::config::NetOptions;
    use crate::json::Json;
    use crate::mvcc::SharedDb;
    use crate::Db;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn response_for(db: &SharedDb, request: &[u8]) -> String {
        response_with(db, request, &NetOptions::default())
    }

    fn response_with(db: &SharedDb, request: &[u8], opts: &NetOptions) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let request = request.to_vec();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream.write_all(&request).unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        });
        let (mut stream, _) = listener.accept().unwrap();
        let metrics = Metrics::new();
        if let Err(error) = handle(db, &metrics, &mut stream, opts) {
            write_http(
                &mut stream,
                super::status_of(&error),
                "application/json",
                &error.to_string(),
            )
            .unwrap();
        }
        drop(stream);
        client.join().unwrap()
    }

    #[test]
    fn query_strings_are_percent_decoded() {
        assert_eq!(qget("key=hello%20world", "key"), Some("hello world".into()));
        assert_eq!(qget("key=a+b", "key"), Some("a b".into()));
        assert!(percent_decode("%zz").is_err());
        assert!(validate_query("key=%zz").is_err());
    }

    #[test]
    fn malformed_query_and_sql_return_bad_request() {
        let dir = std::env::temp_dir().join(format!(
            "minidb-http-bad-request-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = SharedDb::new(Db::open(&dir).unwrap());

        let malformed_query = response_for(
            &db,
            b"GET /v1/kv?key=%zz HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(malformed_query.starts_with("HTTP/1.1 400 "));

        let body = r#"{"sql":"not sql"}"#;
        let request = format!(
            "POST /v1/sql HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let invalid_sql = response_for(&db, request.as_bytes());
        assert!(invalid_sql.starts_with("HTTP/1.1 400 "));

        let body = r#"{"key":"fallback","key_hex":17,"value":"v"}"#;
        let request = format!(
            "PUT /v1/kv HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let invalid_hex_type = response_for(&db, request.as_bytes());
        assert!(invalid_hex_type.starts_with("HTTP/1.1 400 "));

        let duplicate_content_length = response_for(
            &db,
            b"POST /v1/kv HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        );
        assert!(duplicate_content_length.starts_with("HTTP/1.1 400 "));

        let unsupported_method =
            response_for(&db, b"PATCH /v1/kv HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(unsupported_method.starts_with("HTTP/1.1 405 "));
        assert!(unsupported_method.contains("Allow: GET, PUT, POST, DELETE, OPTIONS"));

        {
            let mut guard = db.write().unwrap();
            guard.put(&[0x00, 0xff], b"first").unwrap();
            guard.put(&[0x00, 0xff, 0x01], &[0x80]).unwrap();
        }
        let scan = response_for(
            &db,
            b"GET /v1/scan?start_hex=00ff&end_hex=00ff02&limit=10 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(scan.contains("\"key_hex\":\"00ff\""));
        assert!(scan.contains("\"key_hex\":\"00ff01\""));
        assert!(scan.contains("\"value_hex\":\"80\""));

        let next_scan = response_for(
            &db,
            b"GET /v1/scan?start_hex=00ff&after_hex=00ff&limit=10 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(next_scan.contains("\"key_hex\":\"00ff01\""));
        assert!(!next_scan.contains("\"key_hex\":\"00ff\""));

        let cursor_without_limit = response_for(
            &db,
            b"GET /v1/scan?after_hex=00ff HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(cursor_without_limit.starts_with("HTTP/1.1 400 "));

        let missing = response_for(
            &db,
            b"GET /v1/kv?key=missing HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(missing.contains("\"value_hex\":null"));

        let preflight = response_for(
            &db,
            b"OPTIONS /v1/kv HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.test\r\nAccess-Control-Request-Method: PUT\r\nAccess-Control-Request-Headers: content-type\r\n\r\n",
        );
        assert!(preflight.starts_with("HTTP/1.1 204 "));
        assert!(preflight.contains("Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS"));
        assert!(preflight.contains("Access-Control-Allow-Headers: Content-Type"));

        let unknown_preflight = response_for(
            &db,
            b"OPTIONS /not-a-route HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(unknown_preflight.starts_with("HTTP/1.1 404 "));

        db.write().unwrap().close().unwrap();
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn extended_routes_count_batch_ttl_and_pages() {
        let dir = std::env::temp_dir().join(format!(
            "minidb-http-ext-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = SharedDb::new(Db::open(&dir).unwrap());
        let post = |path: &str, body: &str| {
            format!(
                "POST {path} HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let batch = post(
            "/v1/batch",
            r#"{"ops":[{"op":"put","key":"p:1","value":"a"},{"op":"put","key_hex":"703a32","value":"b","ttl_ms":3600000},{"op":"delete","key":"none"}]}"#,
        );
        assert!(response_for(&db, batch.as_bytes()).contains("\"applied\":3"));
        let count = response_for(&db, b"GET /v1/count?prefix=p%3A HTTP/1.1\r\n\r\n");
        assert!(count.contains("\"count\":2"), "{count}");
        let ttl = response_for(&db, b"GET /v1/ttl?key=p%3A2 HTTP/1.1\r\n\r\n");
        assert!(ttl.contains("\"state\":\"expires\""), "{ttl}");
        let persist = response_for(
            &db,
            post("/v1/expire", r#"{"key":"p:2","ttl_ms":null}"#).as_bytes(),
        );
        assert!(persist.contains("\"updated\":true"), "{persist}");
        let scan = response_for(&db, b"GET /v1/scan?prefix=p%3A&limit=1 HTTP/1.1\r\n\r\n");
        assert!(scan.contains("p:1") && !scan.contains("p:2"), "{scan}");
        let conflict = response_for(&db, b"GET /v1/scan?prefix=p&start=a HTTP/1.1\r\n\r\n");
        assert!(conflict.starts_with("HTTP/1.1 400 "));
        let bad_op = response_for(
            &db,
            post("/v1/batch", r#"{"ops":[{"op":"x","key":"k"}]}"#).as_bytes(),
        );
        assert!(bad_op.starts_with("HTTP/1.1 400 "), "{bad_op}");
        let empty_key = response_for(
            &db,
            post("/v1/batch", r#"{"ops":[{"op":"delete","key":""}]}"#).as_bytes(),
        );
        assert!(empty_key.starts_with("HTTP/1.1 400 "), "{empty_key}");
        let pages = response_for(&db, b"GET /v1/pages HTTP/1.1\r\n\r\n");
        assert!(pages.contains("\"height\":1"), "{pages}");
        let purge = response_for(&db, post("/v1/purge", "").as_bytes());
        assert!(purge.contains("\"purged\":0"), "{purge}");
        let sql = response_for(
            &db,
            post("/v1/sql", r#"{"sql":"SELECT COUNT(*) FROM kv"}"#).as_bytes(),
        );
        assert!(sql.contains("\"count\":2"), "{sql}");
        db.write().unwrap().close().unwrap();
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn active_connection_slots_are_bounded_and_released() {
        const LIMIT: usize = 7;
        let active = Arc::new(AtomicUsize::new(LIMIT));
        assert!(!super::reserve_connection(&active, LIMIT));
        active.store(LIMIT - 1, Ordering::Relaxed);
        assert!(super::reserve_connection(&active, LIMIT));
        assert_eq!(active.load(Ordering::Relaxed), LIMIT);
        drop(super::ConnectionGuard(Arc::clone(&active)));
        assert_eq!(active.load(Ordering::Relaxed), LIMIT - 1);
    }

    #[test]
    fn cross_origin_writes_are_refused() {
        // Supõe `MINIDB_CORS_ORIGIN` ausente, como no CI.
        let dir = std::env::temp_dir().join(format!("minidb-http-cors-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = SharedDb::new(Db::open(&dir).unwrap());
        let body = r#"{"key":"k","value":"v"}"#;
        let post = format!(
            "POST /v1/kv HTTP/1.1\r\nOrigin: http://x.test\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let refused = response_for(&db, post.as_bytes());
        assert!(refused.starts_with("HTTP/1.1 403 "), "{refused}");
        let read = response_for(
            &db,
            b"GET /v1/kv?key=k HTTP/1.1\r\nOrigin: http://x.test\r\n\r\n",
        );
        assert!(read.starts_with("HTTP/1.1 200 "), "{read}");
        assert!(read.contains("\"value\":null"), "{read}");
        db.write().unwrap().close().unwrap();
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn host_header_blocks_dns_rebinding() {
        // Supõe `MINIDB_ALLOWED_HOSTS` ausente, como no CI.
        let dir = std::env::temp_dir().join(format!("minidb-http-host-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = SharedDb::new(Db::open(&dir).unwrap());
        let get = |host: &str| {
            let request = format!("GET /v1/kv?key=k HTTP/1.1\r\nHost: {host}\r\n\r\n");
            response_for(&db, request.as_bytes())
        };
        for host in ["127.0.0.1:8080", "[::1]:8080", "localhost:8080", "minidb"] {
            let ok = get(host);
            assert!(ok.starts_with("HTTP/1.1 200 "), "{host}: {ok}");
        }
        let refused = get("evil.example");
        assert!(refused.starts_with("HTTP/1.1 403 "), "{refused}");
        assert!(refused.contains("MINIDB_ALLOWED_HOSTS"), "{refused}");
        let health = response_for(
            &db,
            b"GET /v1/health HTTP/1.1\r\nHost: rebinding.example\r\n\r\n",
        );
        assert!(health.starts_with("HTTP/1.1 200 "), "{health}");
        db.write().unwrap().close().unwrap();
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn host_allowed_rules() {
        assert!(host_allowed(None, ""));
        assert!(host_allowed(Some("127.0.0.1"), ""));
        assert!(host_allowed(Some("[::1]:8080"), ""));
        assert!(host_allowed(Some("LocalHost:8080"), ""));
        assert!(host_allowed(Some("app.localhost"), ""));
        assert!(host_allowed(Some("minidb:8080"), ""));
        assert!(!host_allowed(Some("evil.example"), ""));
        assert!(!host_allowed(Some("evil.example:8080"), ""));
        assert!(!host_allowed(Some("evil.example."), ""));
        assert!(!host_allowed(Some("127.0.0.1.evil.example"), ""));
        assert!(!host_allowed(Some("localhost.evil.example"), ""));
        assert!(!host_allowed(Some(""), ""));
        assert!(!host_allowed(Some(":8080"), ""));
        let list = "db.exemplo.com, Painel.Exemplo.com:443";
        assert!(host_allowed(Some("db.exemplo.com:8080"), list));
        assert!(host_allowed(Some("painel.exemplo.com"), list));
        assert!(!host_allowed(Some("evil.example"), list));
        assert!(host_allowed(Some("evil.example"), "a.com,*"));
        assert!(host_allowed(Some(""), "*"));
    }

    #[test]
    fn token_auth_params_and_status_codes() {
        let dir = std::env::temp_dir().join(format!("minidb-http-auth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = SharedDb::new(Db::open(&dir).unwrap());
        let opts = NetOptions {
            token: Some("s3cr3t".into()),
            ..NetOptions::default()
        };
        let sql = |auth: &str, body: &str| {
            format!(
                "POST /v1/sql HTTP/1.1\r\nHost: x\r\n{auth}Content-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let health = response_with(&db, b"GET /health HTTP/1.1\r\n\r\n", &opts);
        assert!(health.starts_with("HTTP/1.1 200"), "health é público");
        let denied = response_with(&db, sql("", r#"{"sql":"SHOW TABLES"}"#).as_bytes(), &opts);
        assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");
        let wrong = response_with(
            &db,
            sql("Authorization: Bearer nope\r\n", r#"{"sql":"SHOW TABLES"}"#).as_bytes(),
            &opts,
        );
        assert!(wrong.starts_with("HTTP/1.1 401"), "{wrong}");
        let auth = "Authorization: Bearer s3cr3t\r\n";
        for body in [
            r#"{"sql":"CREATE TABLE p (id INT PRIMARY KEY, name TEXT)"}"#,
            r#"{"sql":"INSERT INTO p VALUES (?, ?)","params":[1,"ana"]}"#,
        ] {
            let ok = response_with(&db, sql(auth, body).as_bytes(), &opts);
            assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        }
        let rows = response_with(
            &db,
            sql(
                auth,
                r#"{"sql":"SELECT name FROM p WHERE id = $1","params":[1]}"#,
            )
            .as_bytes(),
            &opts,
        );
        assert!(rows.contains("\"ana\""), "{rows}");
        let dup = response_with(
            &db,
            sql(auth, r#"{"sql":"INSERT INTO p VALUES (1, 'x')"}"#).as_bytes(),
            &opts,
        );
        assert!(dup.starts_with("HTTP/1.1 400"), "{dup}");
        db.write().unwrap().set_read_only(true);
        let ro = response_with(
            &db,
            sql(auth, r#"{"sql":"INSERT INTO p VALUES (2, 'y')"}"#).as_bytes(),
            &opts,
        );
        assert!(ro.starts_with("HTTP/1.1 403"), "{ro}");
        db.write().unwrap().close().unwrap();
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn hexadecimal_payloads_roundtrip() {
        let bytes = [0, 1, 127, 128, 255];
        assert_eq!(hex_encode(&bytes), "00017f80ff");
        assert_eq!(hex_decode("00017f80ff").unwrap(), bytes);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn openapi_document_is_valid_json() {
        Json::parse(OPENAPI_MIN).unwrap();
    }

    #[test]
    fn request_body_can_arrive_in_fragments() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let sender = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .write_all(b"PUT /v1/kv HTTP/1.1\r\nContent-Length: 7\r\n\r\n{")
                .unwrap();
            stream.write_all(b"\"a\":1}").unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream, 1024).unwrap();
        assert_eq!(request.method, "PUT");
        assert_eq!(request.target, "/v1/kv");
        assert_eq!(request.body, "{\"a\":1}");
        sender.join().unwrap();
    }

    #[test]
    fn body_bytes_do_not_count_toward_header_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body = vec![b'x'; super::MAX_HEADER_BYTES];
        let sender = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            write!(
                stream,
                "POST /v1/sql HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream, 1 << 20).unwrap();
        assert_eq!(request.body.len(), super::MAX_HEADER_BYTES);
        sender.join().unwrap();
    }
}
