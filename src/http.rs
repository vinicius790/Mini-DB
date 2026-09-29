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

use crate::db::{Db, ExecResult};
use crate::error::{Error, Result};
use crate::json::Json;
use crate::metrics::Metrics;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_ACTIVE_CONNECTIONS: usize = 128;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Libera a vaga de conexão ao sair de escopo (compartilhado com o TCP).
pub(crate) struct ConnectionGuard(pub(crate) Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) fn reserve_connection(active: &AtomicUsize) -> bool {
    active
        .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |count| {
            (count < MAX_ACTIVE_CONNECTIONS).then_some(count + 1)
        })
        .is_ok()
}

pub fn serve_http(db: Arc<Mutex<Db>>, metrics: Arc<Metrics>, addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).map_err(|e| Error::Server(e.to_string()))?;
    let active = Arc::new(AtomicUsize::new(0));
    eprintln!("minidb-http listen {addr}");
    for incoming in listener.incoming() {
        let mut stream = incoming.map_err(|e| Error::Server(e.to_string()))?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        if !reserve_connection(&active) {
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
        let db = Arc::clone(&db);
        let metrics = Arc::clone(&metrics);
        let active = Arc::clone(&active);
        std::thread::spawn(move || {
            let _connection = ConnectionGuard(active);
            metrics.inc_http();
            if let Err(e) = handle(&db, &metrics, &mut stream) {
                metrics.inc_err();
                let status = if e.is_client_error() { 400 } else { 500 };
                let _ = write_http(&mut stream, status, "application/json", &error_json(&e));
            }
        });
    }
    Ok(())
}

fn error_json(e: &Error) -> String {
    Json::obj()
        .put("ok", Json::Bool(false))
        .put("error", Json::String(e.to_string()))
        .stringify()
}

fn handle(db: &Arc<Mutex<Db>>, metrics: &Metrics, stream: &mut TcpStream) -> Result<()> {
    let (method, target, body) = match read_request(stream) {
        Ok(request) => request,
        Err(error) => {
            write_http(stream, 400, "application/json", &error_json(&error))?;
            return Ok(());
        }
    };
    if method.is_empty() {
        return Ok(());
    }
    let (path, query) = split_target(&target);
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
            let guard = db.lock().map_err(|e| Error::Server(e.to_string()))?;
            let s = guard.stats();
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
                .stringify();
            write_http(stream, 200, "application/json", &js)
        }
        ("GET", "/v1/kv") => {
            let key_bytes = match query_bytes(&query, "key", "key_hex") {
                Ok(value) => value.unwrap_or_default(),
                Err(error) => return bad_request(stream, &error.to_string()),
            };
            if let Err(error) = crate::btree::validate_key(&key_bytes) {
                return bad_request(stream, &error.to_string());
            }
            let mut guard = db.lock().map_err(|e| Error::Server(e.to_string()))?;
            let hit = guard.get(&key_bytes)?;
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
            if let Err(error) = crate::btree::validate_key(&key) {
                return bad_request(stream, &error.to_string());
            }
            if let Err(error) = crate::btree::validate_value(&val) {
                return bad_request(stream, &error.to_string());
            }
            let mut guard = db.lock().map_err(|e| Error::Server(e.to_string()))?;
            match json_ttl(&j) {
                Ok(Some(ttl)) => guard.put_with_ttl(&key, &val, ttl)?,
                Ok(None) => guard.put(&key, &val)?,
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
            if let Err(error) = crate::btree::validate_key(&key_bytes) {
                return bad_request(stream, &error.to_string());
            }
            let mut guard = db.lock().map_err(|e| Error::Server(e.to_string()))?;
            let ok = guard.delete(&key_bytes)?;
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
            if let Err(error) = crate::btree::validate_key(&start) {
                return bad_request(stream, &error.to_string());
            }
            if let Some(end) = end.as_deref() {
                if let Err(error) = crate::btree::validate_key(end) {
                    return bad_request(stream, &error.to_string());
                }
            }
            if let Some(after) = after.as_deref() {
                if let Err(error) = crate::btree::validate_key(after) {
                    return bad_request(stream, &error.to_string());
                }
            }
            let mut guard = db.lock().map_err(|e| Error::Server(e.to_string()))?;
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
        ("POST", "/v1/sql") => {
            let j = match Json::parse(&body) {
                Ok(value) => value,
                Err(e) => return bad_request(stream, &e.to_string()),
            };
            let sql = match j.get("sql").and_then(Json::as_str) {
                Some(value) => value,
                None => return bad_request(stream, "campo sql ausente ou inválido"),
            };
            let statement = match crate::sql::parse_sql(sql) {
                Ok(statement) => statement,
                // Não é o dialeto `kv`: tenta o SQL relacional.
                Err(legacy) => {
                    let mut guard = db.lock().map_err(|e| Error::Server(e.to_string()))?;
                    metrics.inc_sql();
                    return match guard.execute_sql(sql) {
                        Ok(result) => {
                            write_http(stream, 200, "application/json", &exec_json(result))
                        }
                        Err(Error::UnknownTable(_)) if sql.to_ascii_lowercase().contains(" kv") => {
                            bad_request(stream, &legacy.to_string())
                        }
                        Err(error) if error.is_client_error() => {
                            bad_request(stream, &error.to_string())
                        }
                        Err(error) => Err(error),
                    };
                }
            };
            if let Err(error) = validate_sql_input(&statement) {
                return bad_request(stream, &error.to_string());
            }
            let mut guard = db.lock().map_err(|e| Error::Server(e.to_string()))?;
            metrics.inc_sql();
            let result = match guard.execute_stmt(statement) {
                Ok(result) => result,
                Err(crate::error::Error::TxnOpen | crate::error::Error::TxnNotOpen) => {
                    return bad_request(stream, "estado transacional inválido")
                }
                Err(error) if error.is_client_error() => {
                    return bad_request(stream, &error.to_string())
                }
                Err(error) => return Err(error),
            };
            let js = exec_json(result);
            write_http(stream, 200, "application/json", &js)
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
        "/v1/batch" | "/v1/expire" | "/v1/purge" => Some("POST, OPTIONS"),
        "/v1/kv" => Some("GET, PUT, POST, DELETE, OPTIONS"),
        "/v1/sql" => Some("POST, OPTIONS"),
        _ => None,
    }
}

const OPENAPI_MIN: &str = r##"{
    "openapi": "3.0.0",
    "info": {"title": "Mini-DB", "version": "0.5.0"},
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
        "/v1/sql": {"post": {"requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SqlRequest"}}}}, "responses": {"200": {"description": "SQL result"}, "400": {"description": "Invalid SQL or request state"}, "405": {"description": "Method not allowed"}, "503": {"description": "Connection limit reached"}, "500": {"description": "Database error"}}}, "options": {"responses": {"204": {"description": "CORS preflight"}}}}
    },
    "components": {"schemas": {
        "KvRequest": {"type": "object", "properties": {"key": {"type": "string"}, "value": {"type": "string"}, "key_hex": {"type": "string"}, "value_hex": {"type": "string"}, "ttl_ms": {"type": "integer", "minimum": 1}}, "anyOf": [{"required": ["key", "value"]}, {"required": ["key_hex", "value_hex"]}]},
        "BatchRequest": {"type": "object", "required": ["ops"], "properties": {"ops": {"type": "array", "minItems": 1, "maxItems": 10000, "items": {"type": "object", "required": ["op"], "properties": {"op": {"enum": ["put", "delete"]}, "key": {"type": "string"}, "key_hex": {"type": "string"}, "value": {"type": "string"}, "value_hex": {"type": "string"}, "ttl_ms": {"type": "integer", "minimum": 1}}}}}},
        "ExpireRequest": {"type": "object", "properties": {"key": {"type": "string"}, "key_hex": {"type": "string"}, "ttl_ms": {"type": ["integer", "null"], "minimum": 1}}},
        "SqlRequest": {"type": "object", "required": ["sql"], "properties": {"sql": {"type": "string"}}},
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
            crate::btree::validate_key(key)?;
            crate::btree::validate_value(value)
        }
        Statement::Delete { key } => crate::btree::validate_key(key),
        Statement::Select {
            pred: Some(Pred::KeyCmp { value, .. }),
            ..
        } => crate::btree::validate_key(value),
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

fn bad_request(stream: &mut TcpStream, message: &str) -> Result<()> {
    let body = error_json(&Error::Other(message.to_string()));
    write_http(stream, 400, "application/json", &body)
}

fn read_request(stream: &mut TcpStream) -> Result<(String, String, String)> {
    let mut request = Vec::with_capacity(4096);
    let header_end = loop {
        let mut byte = [0u8; 1024];
        let n = stream.read(&mut byte)?;
        if n == 0 {
            if request.is_empty() {
                return Ok((String::new(), String::new(), String::new()));
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
            if content_len > MAX_BODY_BYTES {
                return Err(Error::Other("corpo HTTP muito grande".into()));
            }
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
    Ok((method, target, body))
}

fn write_http(stream: &mut TcpStream, code: u16, ctype: &str, body: &str) -> Result<()> {
    let reason = match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        404 => "Not Found",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

fn write_method_not_allowed(stream: &mut TcpStream, allowed: &str) -> Result<()> {
    let body = "{\"ok\":false,\"error\":\"method not allowed\"}";
    let header = format!(
        "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nAllow: {allowed}\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

fn write_preflight(stream: &mut TcpStream, methods: &str) -> Result<()> {
    let header = format!(
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: {methods}\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Max-Age: 600\r\n\r\n"
    );
    stream.write_all(header.as_bytes())?;
    Ok(())
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
    db: &Arc<Mutex<Db>>,
    metrics: &Metrics,
    stream: &mut TcpStream,
    method: &str,
    path: &str,
    query: &str,
    body: &str,
) -> Option<Result<()>> {
    let lock = || db.lock().map_err(|e| Error::Server(e.to_string()));
    let reply = |stream: &mut TcpStream, fields: &[(&str, Json)]| {
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
            let n = lock()?.count(&start, end.as_deref())?;
            reply(stream, &[("count", Json::Number(n as i64))])
        })(),
        ("GET", "/v1/ttl") => (|| {
            let key = query_bytes(query, "key", "key_hex")?.unwrap_or_default();
            let (state, ms) = match lock()?.ttl(&key)? {
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
            let s = lock()?.page_stats()?;
            let n = |v: u64| Json::Number(v as i64);
            reply(
                stream,
                &[
                    ("total_pages", n(s.total_pages.into())),
                    ("leaves", n(s.leaves.into())),
                    ("empty_leaves", n(s.empty_leaves.into())),
                    ("internals", n(s.internals.into())),
                    ("free_pages", n(s.free_pages.into())),
                    ("live_bytes", n(s.live_bytes)),
                    ("fill_percent", n(s.fill_percent.into())),
                    ("height", n(s.height.into())),
                ],
            )
        })(),
        ("POST", "/v1/expire") => (|| {
            let j = Json::parse(body).map_err(|e| Error::InvalidInput(e.to_string()))?;
            let key = json_bytes(&j, "key", "key_hex")?;
            let mut guard = lock()?;
            let updated = match json_ttl(&j)? {
                Some(ttl) => guard.expire(&key, ttl)?,
                None => guard.persist(&key)?,
            };
            reply(stream, &[("updated", Json::Bool(updated))])
        })(),
        ("POST", "/v1/purge") => (|| {
            let n = lock()?.purge_expired()?;
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
                crate::btree::validate_key(&key)?;
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
            lock()?.write_batch(&batch)?;
            metrics.inc_batch(batch.len() as u64);
            reply(stream, &[("applied", Json::Number(batch.len() as i64))])
        })(),
        _ => return None,
    };
    Some(match result {
        Err(error) if error.is_client_error() => bad_request(stream, &error.to_string()),
        other => other,
    })
}

/// Serializa o resultado de um comando SQL.
fn exec_json(result: ExecResult) -> String {
    match result {
        ExecResult::Ok(s) => Json::obj()
            .put("ok", Json::Bool(true))
            .put("result", Json::String(s))
            .stringify(),
        ExecResult::Value(None) => Json::obj()
            .put("ok", Json::Bool(true))
            .put("value", Json::Null)
            .stringify(),
        ExecResult::Value(Some(v)) => Json::obj()
            .put("ok", Json::Bool(true))
            .put(
                "value",
                Json::String(String::from_utf8_lossy(&v).into_owned()),
            )
            .stringify(),
        ExecResult::Count(n) => Json::obj()
            .put("ok", Json::Bool(true))
            .put("count", Json::Number(n as i64))
            .stringify(),
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
            Json::obj()
                .put("ok", Json::Bool(true))
                .put("rows", Json::Array(arr))
                .stringify()
        }
        ExecResult::Table { columns, rows } => Json::obj()
            .put("ok", Json::Bool(true))
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
            )
            .stringify(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        handle, hex_decode, hex_encode, percent_decode, qget, read_request, validate_query,
        write_http, Metrics, OPENAPI_MIN,
    };
    use crate::json::Json;
    use crate::Db;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn response_for(db: &Arc<Mutex<Db>>, request: &[u8]) -> String {
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
        if let Err(error) = handle(db, &metrics, &mut stream) {
            write_http(&mut stream, 500, "application/json", &error.to_string()).unwrap();
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
        let db = Arc::new(Mutex::new(Db::open(&dir).unwrap()));

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
            let mut guard = db.lock().unwrap();
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

        db.lock().unwrap().close().unwrap();
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
        let db = Arc::new(Mutex::new(Db::open(&dir).unwrap()));
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
        db.lock().unwrap().close().unwrap();
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn active_connection_slots_are_bounded_and_released() {
        let active = Arc::new(AtomicUsize::new(super::MAX_ACTIVE_CONNECTIONS));
        assert!(!super::reserve_connection(&active));
        active.store(super::MAX_ACTIVE_CONNECTIONS - 1, Ordering::Relaxed);
        assert!(super::reserve_connection(&active));
        assert_eq!(
            active.load(Ordering::Relaxed),
            super::MAX_ACTIVE_CONNECTIONS
        );
        drop(super::ConnectionGuard(Arc::clone(&active)));
        assert_eq!(
            active.load(Ordering::Relaxed),
            super::MAX_ACTIVE_CONNECTIONS - 1
        );
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
        let request = read_request(&mut stream).unwrap();
        assert_eq!(request.0, "PUT");
        assert_eq!(request.1, "/v1/kv");
        assert_eq!(request.2, "{\"a\":1}");
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
        let request = read_request(&mut stream).unwrap();
        assert_eq!(request.2.len(), super::MAX_HEADER_BYTES);
        sender.join().unwrap();
    }
}
