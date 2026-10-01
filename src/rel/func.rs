//! Funções escalares do SQL: texto, matemática, condicionais, data/hora
//! (UTC, formato ISO 8601 ou segundos Unix), JSON e hash.

use super::search::{self, Metric, TextQuery};
use super::value::{Type, Value};
use crate::error::{Error, Result};
use crate::json::Json;
use std::cmp::Ordering;

fn arg_err(name: &str, usage: &str) -> Error {
    Error::Sql(format!("{name}({usage})"))
}

fn text(v: &Value) -> String {
    v.to_string()
}

fn int(name: &str, v: &Value) -> Result<i64> {
    match v {
        Value::Int(n) => Ok(*n),
        Value::Real(x) if x.fract() == 0.0 && x.abs() < 9.2e18 => Ok(*x as i64),
        Value::Bool(b) => Ok(*b as i64),
        other => Err(Error::Sql(format!(
            "{name}() espera inteiro, recebeu {}",
            other.type_name()
        ))),
    }
}

fn num(name: &str, v: &Value) -> Result<f64> {
    v.as_f64()
        .or(match v {
            Value::Bool(b) => Some(*b as i64 as f64),
            _ => None,
        })
        .ok_or_else(|| Error::Sql(format!("{name}() espera número, recebeu {}", v.type_name())))
}

thread_local! {
    static CURRENT_USER: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    static CONN: std::cell::RefCell<ConnInfo> = std::cell::RefCell::new(ConnInfo::default());
    static REGEX_CACHE: std::cell::RefCell<Vec<(String, String, super::regex::Regex)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Usuário da sessão em execução nesta thread (`current_user`).
pub fn set_current_user(user: Option<String>) {
    CURRENT_USER.with(|u| *u.borrow_mut() = user);
}

/// Dados da conexão em execução nesta thread (`pg_stat_activity`, `pg_stat_ssl`,
/// `ssl_is_used()`...). Definidos pelo servidor PostgreSQL a cada consulta.
#[derive(Clone, Debug, Default)]
pub struct ConnInfo {
    pub pid: i64,
    pub ssl: bool,
    pub client_addr: Option<String>,
    /// Sujeito do certificado de cliente verificado (mTLS).
    pub client_dn: Option<String>,
    pub client_issuer: Option<String>,
}

pub fn set_conn_info(info: ConnInfo) {
    CONN.with(|c| *c.borrow_mut() = info);
}

pub(super) fn conn_info() -> ConnInfo {
    let mut info = CONN.with(|c| c.borrow().clone());
    if info.pid == 0 {
        info.pid = std::process::id() as i64;
    }
    info
}

pub(super) fn current_user_name() -> String {
    current_user()
}

fn current_user() -> String {
    CURRENT_USER.with(|u| u.borrow().clone().unwrap_or_else(|| "minidb".into()))
}

/// Regex compilada com cache pequeno por thread (padrões repetem-se por linha).
fn regex_for(pattern: &str, flags: &str) -> Result<super::regex::Regex> {
    REGEX_CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        if let Some((_, _, re)) = cache.iter().find(|(p, f, _)| p == pattern && f == flags) {
            return Ok(re.clone());
        }
        let re = super::regex::Regex::new(pattern, flags)?;
        if cache.len() >= 32 {
            cache.remove(0);
        }
        cache.push((pattern.to_string(), flags.to_string(), re.clone()));
        Ok(re)
    })
}

fn vector(v: &Value) -> Result<Vec<f32>> {
    search::parse_vector(&v.to_string())
}

fn real(x: f64) -> Result<Value> {
    if x.is_nan() {
        return Err(Error::Sql("resultado numérico indefinido (NaN)".into()));
    }
    Ok(Value::Real(x))
}

/// Chama a função escalar `name` (minúsculas) com os argumentos avaliados.
/// Funções com NULL em argumento obrigatório devolvem NULL, como no SQL.
pub fn call(name: &str, v: Vec<Value>) -> Result<Value> {
    let n = v.len();
    let arity = |min: usize, max: usize, usage: &str| {
        if n < min || n > max {
            Err(arg_err(name, usage))
        } else {
            Ok(())
        }
    };
    // Funções que tratam NULL de forma especial.
    match name {
        "coalesce" | "ifnull" | "nvl" => {
            return Ok(v.into_iter().find(|x| !x.is_null()).unwrap_or(Value::Null))
        }
        "nullif" => {
            arity(2, 2, "a, b")?;
            return Ok(if v[0].sql_cmp(&v[1]) == Some(Ordering::Equal) {
                Value::Null
            } else {
                v.into_iter().next().expect("aridade")
            });
        }
        "iif" | "if" => {
            arity(2, 3, "condição, se_verdadeiro[, se_falso]")?;
            let mut it = v.into_iter();
            let cond = it.next().expect("aridade");
            let yes = it.next().expect("aridade");
            let no = it.next().unwrap_or(Value::Null);
            return Ok(if cond.truth() == Some(true) { yes } else { no });
        }
        "is_true" => {
            arity(2, 2, "x, esperado")?;
            return Ok(Value::Bool(v[0].truth() == v[1].truth()));
        }
        "typeof" => {
            arity(1, 1, "x")?;
            return Ok(Value::Text(v[0].type_name().to_lowercase()));
        }
        "raise" => {
            // RAISE(ABORT|FAIL|ROLLBACK, msg) aborta o comando; RAISE(IGNORE) pula a linha.
            arity(2, 2, "tipo, mensagem")?;
            return Err(match text(&v[0]).as_str() {
                "ignore" => Error::Sql(super::write::RAISE_IGNORE.into()),
                _ => Error::Constraint(text(&v[1])),
            });
        }
        "format_type" => {
            arity(1, 2, "oid[, typmod]")?;
            return Ok(match &v[0] {
                Value::Null => Value::Null,
                x => Value::Text(
                    super::pgcatalog::type_name_by_oid(int(name, x).unwrap_or(25)).into(),
                ),
            });
        }
        "greatest" | "least" => {
            if n == 0 {
                return Err(arg_err(name, "a, b, ..."));
            }
            let mut best: Option<Value> = None;
            for x in v {
                if x.is_null() {
                    continue;
                }
                best = Some(match best {
                    None => x,
                    Some(b) => {
                        let take = match x.sql_cmp(&b) {
                            Some(Ordering::Greater) => name == "greatest",
                            Some(Ordering::Less) => name == "least",
                            _ => false,
                        };
                        if take {
                            x
                        } else {
                            b
                        }
                    }
                });
            }
            return Ok(best.unwrap_or(Value::Null));
        }
        "concat" => {
            return Ok(Value::Text(
                v.iter().filter(|x| !x.is_null()).map(text).collect(),
            ))
        }
        "concat_ws" => {
            arity(1, usize::MAX, "separador, a, b, ...")?;
            if v[0].is_null() {
                return Ok(Value::Null);
            }
            let sep = text(&v[0]);
            let parts: Vec<String> = v[1..].iter().filter(|x| !x.is_null()).map(text).collect();
            return Ok(Value::Text(parts.join(&sep)));
        }
        "random" | "rand" => {
            arity(0, 0, "")?;
            let b = crate::crypto::random_bytes::<8>();
            return Ok(Value::Int(i64::from_le_bytes(b)));
        }
        "uuid" | "gen_random_uuid" | "uuid4" => {
            arity(0, 0, "")?;
            let mut b = crate::crypto::random_bytes::<16>();
            b[6] = (b[6] & 0x0f) | 0x40;
            b[8] = (b[8] & 0x3f) | 0x80;
            let h = hex(&b);
            return Ok(Value::Text(format!(
                "{}-{}-{}-{}-{}",
                &h[..8],
                &h[8..12],
                &h[12..16],
                &h[16..20],
                &h[20..]
            )));
        }
        "pi" => {
            arity(0, 0, "")?;
            return Ok(Value::Real(std::f64::consts::PI));
        }
        "now" | "current_timestamp" | "localtimestamp" => {
            arity(0, 0, "")?;
            return Ok(Value::Text(fmt_datetime(now_secs(), true)));
        }
        "current_date" => {
            arity(0, 0, "")?;
            return Ok(Value::Text(fmt_datetime(now_secs(), false)));
        }
        "current_time" | "localtime" => {
            arity(0, 0, "")?;
            return Ok(Value::Text(fmt_time(now_secs())));
        }
        "json_object" => {
            if !n.is_multiple_of(2) {
                return Err(arg_err(name, "chave, valor, ..."));
            }
            let mut j = Json::obj();
            for pair in v.chunks(2) {
                j = j.put(&text(&pair[0]), to_json(&pair[1]));
            }
            return Ok(Value::Text(j.stringify()));
        }
        "json_array" => {
            return Ok(Value::Text(
                Json::Array(v.iter().map(to_json).collect()).stringify(),
            ))
        }
        "json_valid" => {
            arity(1, 1, "texto")?;
            return Ok(match &v[0] {
                Value::Null => Value::Null,
                x => Value::Bool(Json::parse(&text(x)).is_ok()),
            });
        }
        _ => {}
    }
    if v.iter().any(Value::is_null) {
        // Todas as funções abaixo são estritas em NULL.
        return Ok(Value::Null);
    }
    let a = |i: usize| &v[i];
    Ok(match name {
        // --- texto ---
        "lower" => {
            arity(1, 1, "texto")?;
            Value::Text(text(a(0)).to_lowercase())
        }
        "upper" => {
            arity(1, 1, "texto")?;
            Value::Text(text(a(0)).to_uppercase())
        }
        "initcap" => {
            arity(1, 1, "texto")?;
            let mut out = String::new();
            let mut start = true;
            for c in text(a(0)).chars() {
                if c.is_alphanumeric() {
                    out.extend(if start {
                        c.to_uppercase().collect::<Vec<_>>()
                    } else {
                        c.to_lowercase().collect()
                    });
                    start = false;
                } else {
                    out.push(c);
                    start = true;
                }
            }
            Value::Text(out)
        }
        "length" | "char_length" | "character_length" => {
            arity(1, 1, "texto")?;
            Value::Int(text(a(0)).chars().count() as i64)
        }
        "octet_length" | "byte_length" => {
            arity(1, 1, "texto")?;
            Value::Int(text(a(0)).len() as i64)
        }
        "trim" | "ltrim" | "rtrim" => {
            arity(1, 2, "texto[, caracteres]")?;
            let s = text(a(0));
            let chars: Vec<char> = match v.get(1) {
                Some(c) => text(c).chars().collect(),
                None => vec![' ', '\t', '\n', '\r'],
            };
            let f = |c: char| chars.contains(&c);
            Value::Text(match name {
                "trim" => s.trim_matches(f).to_string(),
                "ltrim" => s.trim_start_matches(f).to_string(),
                _ => s.trim_end_matches(f).to_string(),
            })
        }
        "replace" => {
            arity(3, 3, "texto, de, para")?;
            Value::Text(text(a(0)).replace(&text(a(1)), &text(a(2))))
        }
        "instr" | "position" | "strpos" => {
            arity(2, 2, "texto, busca")?;
            let (hay, needle) = if name == "position" {
                (text(a(1)), text(a(0)))
            } else {
                (text(a(0)), text(a(1)))
            };
            Value::Int(
                hay.find(&needle)
                    .map_or(0, |i| hay[..i].chars().count() as i64 + 1),
            )
        }
        "substr" | "substring" | "mid" => {
            arity(2, 3, "texto, início[, tamanho]")?;
            let s: Vec<char> = text(a(0)).chars().collect();
            let start = int(name, a(1))?;
            let len = match v.get(2) {
                Some(l) => int(name, l)?,
                None => i64::MAX,
            };
            // Semântica do SQLite: início 1-based; negativo conta do fim.
            let (from, len) = if start > 0 {
                (start - 1, len)
            } else if start == 0 {
                (0, len.saturating_sub(1).max(0))
            } else {
                let from = s.len() as i64 + start;
                if from < 0 {
                    (0, len.saturating_add(from).max(0))
                } else {
                    (from, len)
                }
            };
            Value::Text(
                s.iter()
                    .skip(from as usize)
                    .take(len.max(0) as usize)
                    .collect(),
            )
        }
        "left" => {
            arity(2, 2, "texto, n")?;
            let k = int(name, a(1))?.max(0) as usize;
            Value::Text(text(a(0)).chars().take(k).collect())
        }
        "right" => {
            arity(2, 2, "texto, n")?;
            let s: Vec<char> = text(a(0)).chars().collect();
            let k = (int(name, a(1))?.max(0) as usize).min(s.len());
            Value::Text(s[s.len() - k..].iter().collect())
        }
        "reverse" => {
            arity(1, 1, "texto")?;
            Value::Text(text(a(0)).chars().rev().collect())
        }
        "repeat" | "replicate" => {
            arity(2, 2, "texto, n")?;
            let k = int(name, a(1))?.max(0) as usize;
            let s = text(a(0));
            if s.len().saturating_mul(k) > 64 << 20 {
                return Err(Error::Sql("repeat() passaria de 64 MiB".into()));
            }
            Value::Text(s.repeat(k))
        }
        "lpad" | "rpad" => {
            arity(2, 3, "texto, tamanho[, preenchimento]")?;
            let s: Vec<char> = text(a(0)).chars().collect();
            let want = int(name, a(1))?.max(0) as usize;
            if want > 64 << 20 {
                return Err(Error::Sql(format!("{name}() passaria de 64 MiB")));
            }
            let pad: Vec<char> = match v.get(2) {
                Some(p) => text(p).chars().collect(),
                None => vec![' '],
            };
            if s.len() >= want {
                Value::Text(s[..want].iter().collect())
            } else if pad.is_empty() {
                Value::Text(s.iter().collect())
            } else {
                let fill: String = pad.iter().cycle().take(want - s.len()).collect();
                let body: String = s.iter().collect();
                Value::Text(if name == "lpad" {
                    fill + &body
                } else {
                    body + &fill
                })
            }
        }
        "starts_with" | "startswith" => {
            arity(2, 2, "texto, prefixo")?;
            Value::Bool(text(a(0)).starts_with(&text(a(1))))
        }
        "ends_with" | "endswith" => {
            arity(2, 2, "texto, sufixo")?;
            Value::Bool(text(a(0)).ends_with(&text(a(1))))
        }
        "contains" => {
            arity(2, 2, "texto, trecho")?;
            Value::Bool(text(a(0)).contains(&text(a(1))))
        }
        "split_part" => {
            arity(3, 3, "texto, separador, n")?;
            let k = int(name, a(2))?;
            let s = text(a(0));
            let sep = text(a(1));
            let parts: Vec<&str> = if sep.is_empty() {
                vec![s.as_str()]
            } else {
                s.split(sep.as_str()).collect()
            };
            let idx = if k > 0 {
                k as usize - 1
            } else if k < 0 {
                (parts.len() as i64 + k).max(0) as usize
            } else {
                return Err(Error::Sql("split_part(): n começa em 1".into()));
            };
            Value::Text(parts.get(idx).copied().unwrap_or("").to_string())
        }
        "char" | "chr" => {
            let s: String = v
                .iter()
                .map(|x| {
                    int(name, x).and_then(|c| {
                        char::from_u32(c as u32)
                            .ok_or_else(|| Error::Sql(format!("char({c}) inválido")))
                    })
                })
                .collect::<Result<_>>()?;
            Value::Text(s)
        }
        "unicode" | "ascii" => {
            arity(1, 1, "texto")?;
            match text(a(0)).chars().next() {
                Some(c) => Value::Int(c as i64),
                None => Value::Null,
            }
        }
        "hex" => {
            arity(1, 1, "x")?;
            Value::Text(hex(text(a(0)).as_bytes()).to_uppercase())
        }
        "quote" => {
            arity(1, 1, "x")?;
            match a(0) {
                Value::Text(s) => Value::Text(format!("'{}'", s.replace('\'', "''"))),
                other => Value::Text(other.to_string()),
            }
        }
        "format" | "printf" => {
            arity(1, usize::MAX, "formato, args...")?;
            Value::Text(printf(&text(a(0)), &v[1..])?)
        }
        "sha256" => {
            arity(1, 1, "x")?;
            Value::Text(hex(&crate::crypto::sha256(text(a(0)).as_bytes())))
        }
        // --- Vetores (texto `[0.1, 0.2]`) ---
        "vec_l2" | "vec_cosine" | "vec_dot" | "vec_distance" => {
            arity(
                2,
                if name == "vec_distance" { 3 } else { 2 },
                "a, b[, métrica]",
            )?;
            let metric = match name {
                "vec_l2" => Metric::L2,
                "vec_dot" => Metric::Dot,
                "vec_distance" if n == 3 => Metric::parse(&text(a(2)))
                    .ok_or_else(|| Error::Sql(format!("métrica {} desconhecida", a(2))))?,
                _ => Metric::Cosine,
            };
            let (x, y) = (vector(a(0))?, vector(a(1))?);
            if x.len() != y.len() {
                return Err(Error::Sql(format!(
                    "vetores de dimensões diferentes ({} e {})",
                    x.len(),
                    y.len()
                )));
            }
            real(metric.distance(&x, &y))?
        }
        "vec_dims" => {
            arity(1, 1, "v")?;
            Value::Int(vector(a(0))?.len() as i64)
        }
        "vec_norm" => {
            arity(1, 1, "v")?;
            real(
                vector(a(0))?
                    .iter()
                    .map(|x| (*x as f64).powi(2))
                    .sum::<f64>()
                    .sqrt(),
            )?
        }
        "vec_normalize" => {
            arity(1, 1, "v")?;
            let v = vector(a(0))?;
            let norm = v.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt();
            let out: Vec<f32> = if norm == 0.0 {
                v
            } else {
                v.iter().map(|x| (*x as f64 / norm) as f32).collect()
            };
            Value::Text(search::vector_text(&out))
        }
        "vec_add" | "vec_sub" => {
            arity(2, 2, "a, b")?;
            let (x, y) = (vector(a(0))?, vector(a(1))?);
            if x.len() != y.len() {
                return Err(Error::Sql("vetores de dimensões diferentes".into()));
            }
            let sign = if name == "vec_add" { 1.0 } else { -1.0 };
            let out: Vec<f32> = x.iter().zip(&y).map(|(p, q)| p + sign * q).collect();
            Value::Text(search::vector_text(&out))
        }
        // --- Espaço ---
        "st_distance" => {
            arity(4, 4, "x1, y1, x2, y2")?;
            let p: Vec<f64> = (0..4).map(|i| num(name, a(i))).collect::<Result<_>>()?;
            real(search::euclid(&p[..2], &p[2..]))?
        }
        "st_distance_sphere" => {
            arity(4, 4, "lat1, lon1, lat2, lon2")?;
            let p: Vec<f64> = (0..4).map(|i| num(name, a(i))).collect::<Result<_>>()?;
            real(search::haversine(p[0], p[1], p[2], p[3]))?
        }
        "st_dwithin" => {
            arity(5, 5, "x, y, cx, cy, raio")?;
            let p: Vec<f64> = (0..5).map(|i| num(name, a(i))).collect::<Result<_>>()?;
            Value::Bool(search::euclid(&p[..2], &p[2..4]) <= p[4])
        }
        // --- Texto completo ---
        "fts_tokens" => {
            arity(1, 1, "texto")?;
            Value::Text(
                Json::Array(
                    search::tokenize(&text(a(0)))
                        .into_iter()
                        .map(Json::String)
                        .collect(),
                )
                .stringify(),
            )
        }
        "fts_highlight" => {
            arity(2, 4, "texto, consulta[, abre, fecha]")?;
            let open = if n > 2 { text(a(2)) } else { "<b>".into() };
            let close = if n > 3 { text(a(3)) } else { "</b>".into() };
            Value::Text(search::highlight(
                &text(a(0)),
                &TextQuery::parse(&text(a(1))),
                &open,
                &close,
            ))
        }
        // --- Expressões regulares ---
        "regexp_like" | "regexp" | "regexp_match_op" => {
            arity(2, 3, "texto, padrão[, flags]")?;
            let flags = if n > 2 { text(a(2)) } else { String::new() };
            let re = regex_for(&text(a(1)), &flags)?;
            Value::Bool(re.is_match(&text(a(0))))
        }
        "regexp_replace" => {
            arity(3, 4, "texto, padrão, substituto[, flags]")?;
            let flags = if n > 3 { text(a(3)) } else { String::new() };
            let re = regex_for(&text(a(1)), &flags)?;
            Value::Text(re.replace(&text(a(0)), &text(a(2)), flags.contains('g')))
        }
        "regexp_substr" | "regexp_extract" => {
            arity(2, 4, "texto, padrão[, posição, grupo]")?;
            let re = regex_for(&text(a(1)), "")?;
            let s = text(a(0));
            let chars: Vec<char> = s.chars().collect();
            let group = if n > 3 { int(name, a(3))? as usize } else { 0 };
            match re.find_at(&chars, 0) {
                Some((_, _, caps)) => match caps.get(group).copied().flatten() {
                    Some((x, y)) => Value::Text(chars[x..y].iter().collect()),
                    None => Value::Null,
                },
                None => Value::Null,
            }
        }
        "regexp_count" => {
            arity(2, 3, "texto, padrão[, flags]")?;
            let flags = if n > 2 { text(a(2)) } else { String::new() };
            let re = regex_for(&text(a(1)), &flags)?;
            Value::Int(re.find_all(&text(a(0))).len() as i64)
        }
        "regexp_matches" | "regexp_split_to_array" => {
            arity(2, 3, "texto, padrão[, flags]")?;
            let flags = if n > 2 { text(a(2)) } else { String::new() };
            let re = regex_for(&text(a(1)), &flags)?;
            let s = text(a(0));
            let chars: Vec<char> = s.chars().collect();
            let items: Vec<Json> = if name == "regexp_matches" {
                re.find_all(&s)
                    .iter()
                    .map(|(x, y, _)| Json::String(chars[*x..*y].iter().collect()))
                    .collect()
            } else {
                let mut parts = Vec::new();
                let mut last = 0;
                for (x, y, _) in re.find_all(&s) {
                    parts.push(Json::String(chars[last..x].iter().collect()));
                    last = y;
                }
                parts.push(Json::String(chars[last..].iter().collect()));
                parts
            };
            Value::Text(Json::Array(items).stringify())
        }
        // --- Compatibilidade PostgreSQL (sessão e catálogo) ---
        "version" => Value::Text("PostgreSQL 16.0 (Mini-DB 1.3.0)".into()),
        "current_database" | "current_catalog" => Value::Text("minidb".into()),
        "current_schema" => Value::Text("public".into()),
        "current_schemas" => Value::Text("{public}".into()),
        "current_user" | "session_user" | "current_role" | "user" | "getpgusername" => {
            Value::Text(current_user())
        }
        "pg_backend_pid" => Value::Int(conn_info().pid),
        "ssl_is_used" => Value::Bool(conn_info().ssl),
        "ssl_version" => match conn_info().ssl {
            true => Value::Text("TLSv1.3".into()),
            false => Value::Null,
        },
        "ssl_cipher" => match conn_info().ssl {
            true => Value::Text("TLS_CHACHA20_POLY1305_SHA256".into()),
            false => Value::Null,
        },
        "ssl_client_dn" => conn_info().client_dn.map_or(Value::Null, Value::Text),
        "pg_is_in_recovery" => Value::Bool(false),
        "pg_table_is_visible"
        | "pg_type_is_visible"
        | "pg_function_is_visible"
        | "pg_has_role"
        | "has_table_privilege"
        | "has_schema_privilege"
        | "has_database_privilege"
        | "pg_operator_is_visible"
        | "pg_opclass_is_visible"
        | "pg_opfamily_is_visible"
        | "pg_collation_is_visible"
        | "pg_conversion_is_visible"
        | "pg_ts_config_is_visible"
        | "pg_ts_dict_is_visible"
        | "pg_ts_parser_is_visible"
        | "pg_ts_template_is_visible"
        | "pg_statistics_obj_is_visible"
        | "has_column_privilege"
        | "has_any_column_privilege"
        | "has_function_privilege"
        | "has_sequence_privilege"
        | "has_type_privilege"
        | "has_language_privilege"
        | "has_tablespace_privilege"
        | "has_server_privilege"
        | "has_foreign_data_wrapper_privilege" => Value::Bool(true),
        "pg_relation_is_publishable" | "pg_is_other_temp_schema" => Value::Bool(false),
        // sem partições: nenhum ancestral (a linha NULL não casa com nada em IN)
        "pg_partition_ancestors" | "pg_partition_root" => Value::Null,
        "pg_size_pretty" => {
            arity(1, 1, "bytes")?;
            let mut x = num(name, a(0))?;
            let mut unit = "bytes";
            for u in ["kB", "MB", "GB", "TB"] {
                if x.abs() < 10240.0 {
                    break;
                }
                x /= 1024.0;
                unit = u;
            }
            Value::Text(format!("{} {unit}", x.round() as i64))
        }
        "pg_get_userbyid" => Value::Text("minidb".into()),
        "pg_encoding_to_char" => Value::Text("UTF8".into()),
        "pg_postmaster_start_time" => Value::Text(fmt_datetime(now_secs(), true)),
        "txid_current" | "pg_current_xact_id" => Value::Int(now_secs()),
        "obj_description"
        | "col_description"
        | "shobj_description"
        | "pg_get_function_result"
        | "pg_get_function_arguments"
        | "pg_get_function_identity_arguments"
        | "pg_get_triggerdef"
        | "pg_get_ruledef"
        | "pg_get_partkeydef"
        | "pg_get_statisticsobjdef"
        | "pg_get_serial_sequence"
        | "pg_tablespace_location" => Value::Null,
        "in_array" => {
            arity(2, 2, "x, array")?;
            let needle = a(0);
            if needle.is_null() || a(1).is_null() {
                return Ok(Value::Null);
            }
            let hay = text(a(1));
            let items: Vec<String> = match Json::parse(&hay) {
                Ok(Json::Array(items)) => items
                    .iter()
                    .map(|x| match x {
                        Json::String(s) => s.clone(),
                        other => other.stringify(),
                    })
                    .collect(),
                _ => hay
                    .trim_matches(|c| c == '{' || c == '}')
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            };
            let n = text(needle);
            Value::Bool(items.contains(&n))
        }
        "array_get" => {
            arity(2, 2, "array, índice")?;
            let idx = int(name, a(1))?;
            match a(0) {
                Value::Null => Value::Null,
                v => {
                    let s = text(v);
                    let items: Vec<String> = match Json::parse(&s) {
                        Ok(Json::Array(items)) => items
                            .iter()
                            .map(|x| match x {
                                Json::String(s) => s.clone(),
                                other => other.stringify(),
                            })
                            .collect(),
                        _ => s
                            .trim_matches(|c| c == '{' || c == '}')
                            .split([',', ' '])
                            .filter(|x| !x.is_empty())
                            .map(|x| x.trim_matches('"').to_string())
                            .collect(),
                    };
                    // Arrays do PostgreSQL começam em 1.
                    match idx
                        .checked_sub(1)
                        .and_then(|i| usize::try_from(i).ok())
                        .and_then(|i| items.get(i))
                    {
                        Some(x) => Value::Text(x.clone()),
                        None => Value::Null,
                    }
                }
            }
        }
        "array_upper" | "array_length" | "cardinality" => {
            arity(1, 2, "array[, dim]")?;
            match a(0) {
                Value::Null => Value::Null,
                v => {
                    let s = text(v);
                    let n = match Json::parse(&s) {
                        Ok(Json::Array(items)) => items.len(),
                        _ => s
                            .trim_matches(|c| c == '{' || c == '}')
                            .split(',')
                            .filter(|x| !x.trim().is_empty())
                            .count(),
                    };
                    Value::Int(n as i64)
                }
            }
        }
        "pg_get_statisticsobjdef_columns" | "pg_get_statisticsobjdef_expressions" => Value::Null,
        "array_of" => {
            arity(1, 1, "subconsulta")?;
            match a(0) {
                Value::Null => Value::Text("{}".into()),
                v => Value::Text(format!("{{{v}}}")),
            }
        }
        "pg_get_expr" => {
            arity(1, 3, "expr, relid[, pretty]")?;
            a(0).clone()
        }
        "format_type" => {
            arity(1, 2, "oid[, typmod]")?;
            match a(0) {
                Value::Null => Value::Null,
                v => Value::Text(
                    super::pgcatalog::type_name_by_oid(int(name, v).unwrap_or(25)).into(),
                ),
            }
        }
        "array_to_string" => {
            arity(2, 3, "array, separador")?;
            match a(0) {
                Value::Null => Value::Null,
                Value::Text(s) if s.starts_with('[') => Value::Text(
                    Json::parse(s)
                        .ok()
                        .and_then(|j| match j {
                            Json::Array(items) => Some(
                                items
                                    .iter()
                                    .map(|x| match x {
                                        Json::String(s) => s.clone(),
                                        other => other.stringify(),
                                    })
                                    .collect::<Vec<_>>()
                                    .join(&text(a(1))),
                            ),
                            _ => None,
                        })
                        .unwrap_or_else(|| s.clone()),
                ),
                v => Value::Text(v.to_string()),
            }
        }
        "current_setting" => {
            arity(1, 2, "nome[, missing_ok]")?;
            Value::Text(
                match text(a(0)).to_ascii_lowercase().as_str() {
                    "server_version" => "16.0",
                    "server_version_num" => "160000",
                    "server_encoding" | "client_encoding" => "UTF8",
                    "search_path" => "public",
                    "timezone" => "UTC",
                    "datestyle" => "ISO, MDY",
                    "standard_conforming_strings" | "integer_datetimes" => "on",
                    "max_identifier_length" => "63",
                    "transaction_isolation" => "repeatable read",
                    _ => "",
                }
                .into(),
            )
        }
        "set_config" => {
            arity(2, 3, "nome, valor, local")?;
            a(1).clone()
        }
        "pg_typeof" => {
            arity(1, 1, "x")?;
            Value::Text(
                match a(0) {
                    Value::Null => "unknown",
                    Value::Int(_) => "bigint",
                    Value::Real(_) => "double precision",
                    Value::Text(_) => "text",
                    Value::Bool(_) => "boolean",
                }
                .into(),
            )
        }
        "quote_ident" => {
            arity(1, 1, "nome")?;
            let s = text(a(0));
            Value::Text(
                if s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                    && !s.is_empty()
                {
                    s
                } else {
                    format!("\"{}\"", s.replace('"', "\"\""))
                },
            )
        }
        "quote_literal" | "quote_nullable" => {
            arity(1, 1, "x")?;
            match a(0) {
                Value::Null => {
                    if name == "quote_nullable" {
                        Value::Text("NULL".into())
                    } else {
                        Value::Null
                    }
                }
                v => Value::Text(format!("'{}'", v.to_string().replace('\'', "''"))),
            }
        }
        "match" => {
            return Err(Error::Sql(
                "use MATCH (colunas) AGAINST ('consulta') para busca textual".into(),
            ))
        }
        // --- matemática ---
        "abs" => {
            arity(1, 1, "x")?;
            match a(0) {
                Value::Int(n) => Value::Int(
                    n.checked_abs()
                        .ok_or_else(|| Error::Sql("estouro".into()))?,
                ),
                x => Value::Real(num(name, x)?.abs()),
            }
        }
        "sign" => {
            arity(1, 1, "x")?;
            Value::Int(match num(name, a(0))? {
                x if x > 0.0 => 1,
                x if x < 0.0 => -1,
                _ => 0,
            })
        }
        "round" => {
            arity(1, 2, "x[, casas]")?;
            let digits = match v.get(1) {
                Some(d) => int(name, d)? as i32,
                None => 0,
            };
            let x = num(name, a(0))?;
            let m = 10f64.powi(digits);
            real((x * m).round() / m)?
        }
        "trunc" | "truncate" => {
            arity(1, 2, "x[, casas]")?;
            let digits = match v.get(1) {
                Some(d) => int(name, d)? as i32,
                None => 0,
            };
            let m = 10f64.powi(digits);
            real((num(name, a(0))? * m).trunc() / m)?
        }
        "floor" => {
            arity(1, 1, "x")?;
            match a(0) {
                Value::Int(n) => Value::Int(*n),
                x => Value::Int(num(name, x)?.floor() as i64),
            }
        }
        "ceil" | "ceiling" => {
            arity(1, 1, "x")?;
            match a(0) {
                Value::Int(n) => Value::Int(*n),
                x => Value::Int(num(name, x)?.ceil() as i64),
            }
        }
        "sqrt" => {
            arity(1, 1, "x")?;
            real(num(name, a(0))?.sqrt())?
        }
        "cbrt" => {
            arity(1, 1, "x")?;
            real(num(name, a(0))?.cbrt())?
        }
        "power" | "pow" => {
            arity(2, 2, "base, expoente")?;
            real(num(name, a(0))?.powf(num(name, a(1))?))?
        }
        "exp" => {
            arity(1, 1, "x")?;
            real(num(name, a(0))?.exp())?
        }
        "ln" => {
            arity(1, 1, "x")?;
            real(num(name, a(0))?.ln())?
        }
        "log" | "log10" => {
            arity(1, 2, "[base, ]x")?;
            let x = if n == 2 {
                num(name, a(1))?.ln() / num(name, a(0))?.ln()
            } else {
                num(name, a(0))?.log10()
            };
            real(x)?
        }
        "log2" => {
            arity(1, 1, "x")?;
            real(num(name, a(0))?.log2())?
        }
        "mod" => {
            arity(2, 2, "a, b")?;
            match (a(0), a(1)) {
                (Value::Int(_), Value::Int(0)) => Value::Null,
                (Value::Int(x), Value::Int(y)) => Value::Int(x.wrapping_rem(*y)),
                (x, y) => real(num(name, x)? % num(name, y)?)?,
            }
        }
        "sin" | "cos" | "tan" | "asin" | "acos" | "atan" | "degrees" | "radians" => {
            arity(1, 1, "x")?;
            let x = num(name, a(0))?;
            real(match name {
                "sin" => x.sin(),
                "cos" => x.cos(),
                "tan" => x.tan(),
                "asin" => x.asin(),
                "acos" => x.acos(),
                "atan" => x.atan(),
                "degrees" => x.to_degrees(),
                _ => x.to_radians(),
            })?
        }
        "atan2" => {
            arity(2, 2, "y, x")?;
            real(num(name, a(0))?.atan2(num(name, a(1))?))?
        }
        // --- conversão ---
        "to_number" | "tonumber" => {
            arity(1, 1, "texto")?;
            let s = text(a(0));
            match s.trim().parse::<i64>() {
                Ok(n) => Value::Int(n),
                Err(_) => match s.trim().parse::<f64>() {
                    Ok(x) if x.is_finite() => Value::Real(x),
                    _ => Value::Null,
                },
            }
        }
        "to_char" | "tostring" | "to_text" => {
            arity(1, 1, "x")?;
            Value::Text(text(a(0)))
        }
        // --- data e hora (UTC) ---
        "datetime" | "date" | "time" | "unixepoch" | "strftime" | "julianday" => {
            let (fmt, rest) = if name == "strftime" {
                arity(1, usize::MAX, "formato, momento[, modificadores...]")?;
                (Some(text(a(0))), &v[1..])
            } else {
                (None, &v[..])
            };
            let secs = match rest.first() {
                None => now_secs(),
                Some(x) => parse_datetime(x)
                    .ok_or_else(|| Error::Sql(format!("data/hora inválida: {x}")))?,
            };
            let mut secs = secs;
            for m in rest.iter().skip(1) {
                secs = apply_modifier(secs, &text(m))?;
            }
            match name {
                "datetime" => Value::Text(fmt_datetime(secs, true)),
                "date" => Value::Text(fmt_datetime(secs, false)),
                "time" => Value::Text(fmt_time(secs)),
                "unixepoch" => Value::Int(secs),
                "julianday" => Value::Real(secs as f64 / 86400.0 + 2440587.5),
                _ => Value::Text(strftime(&fmt.expect("strftime"), secs)?),
            }
        }
        "year" | "month" | "day" | "hour" | "minute" | "second" | "weekday" | "dayofweek"
        | "dayofyear" | "quarter" => {
            arity(1, 1, "momento")?;
            let secs = parse_datetime(a(0))
                .ok_or_else(|| Error::Sql(format!("data/hora inválida: {}", a(0))))?;
            let c = civil(secs);
            Value::Int(match name {
                "year" => c.year,
                "month" => c.month as i64,
                "day" => c.day as i64,
                "hour" => c.hour as i64,
                "minute" => c.minute as i64,
                "second" => c.second as i64,
                "weekday" | "dayofweek" => c.weekday as i64,
                "dayofyear" => c.yday as i64,
                _ => (c.month as i64 - 1) / 3 + 1,
            })
        }
        "date_add" | "dateadd" | "date_sub" | "datesub" => {
            arity(2, 2, "momento, modificador ('+1 day')")?;
            let secs = parse_datetime(a(0))
                .ok_or_else(|| Error::Sql(format!("data/hora inválida: {}", a(0))))?;
            let m = text(a(1));
            let m = if name.ends_with("sub") {
                flip_sign(&m)
            } else {
                m
            };
            Value::Text(fmt_datetime(apply_modifier(secs, &m)?, true))
        }
        "date_diff" | "datediff" => {
            arity(2, 3, "a, b[, unidade]")?;
            let x = parse_datetime(a(0))
                .ok_or_else(|| Error::Sql(format!("data/hora inválida: {}", a(0))))?;
            let y = parse_datetime(a(1))
                .ok_or_else(|| Error::Sql(format!("data/hora inválida: {}", a(1))))?;
            let unit = v.get(2).map(text).unwrap_or_else(|| "day".into());
            let div = match unit.trim_end_matches('s') {
                "second" | "sec" => 1,
                "minute" | "min" => 60,
                "hour" => 3600,
                "day" => 86400,
                "week" => 7 * 86400,
                other => return Err(Error::Sql(format!("unidade desconhecida {other}"))),
            };
            Value::Int((x - y) / div)
        }
        // --- JSON ---
        "json_extract" | "json_value" | "json_query" => {
            arity(2, 2, "json, caminho ('$.a.b[0]')")?;
            let doc =
                Json::parse(&text(a(0))).map_err(|e| Error::Sql(format!("JSON inválido: {e}")))?;
            match json_path(&doc, &text(a(1)))? {
                None => Value::Null,
                Some(j) => from_json(j),
            }
        }
        "json_type" => {
            arity(1, 2, "json[, caminho]")?;
            let doc =
                Json::parse(&text(a(0))).map_err(|e| Error::Sql(format!("JSON inválido: {e}")))?;
            let node = match v.get(1) {
                Some(p) => json_path(&doc, &text(p))?,
                None => Some(&doc),
            };
            match node {
                None => Value::Null,
                Some(j) => Value::Text(
                    match j {
                        Json::Null => "null",
                        Json::Bool(true) => "true",
                        Json::Bool(false) => "false",
                        Json::Number(_) => "integer",
                        Json::Float(_) => "real",
                        Json::String(_) => "text",
                        Json::Array(_) => "array",
                        Json::Object(_) => "object",
                    }
                    .into(),
                ),
            }
        }
        "json_array_length" => {
            arity(1, 2, "json[, caminho]")?;
            let doc =
                Json::parse(&text(a(0))).map_err(|e| Error::Sql(format!("JSON inválido: {e}")))?;
            let node = match v.get(1) {
                Some(p) => json_path(&doc, &text(p))?,
                None => Some(&doc),
            };
            match node {
                Some(Json::Array(items)) => Value::Int(items.len() as i64),
                Some(_) => Value::Int(0),
                None => Value::Null,
            }
        }
        "json_pretty" | "json" => {
            arity(1, 1, "json")?;
            Value::Text(
                Json::parse(&text(a(0)))
                    .map_err(|e| Error::Sql(format!("JSON inválido: {e}")))?
                    .stringify(),
            )
        }
        _ => return Err(Error::Sql(format!("função desconhecida {name}()"))),
    })
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn flip_sign(m: &str) -> String {
    let t = m.trim();
    if let Some(rest) = t.strip_prefix('-') {
        format!("+{rest}")
    } else if let Some(rest) = t.strip_prefix('+') {
        format!("-{rest}")
    } else {
        format!("-{t}")
    }
}

/// `printf` mínimo: `%s`, `%d`, `%i`, `%f`, `%.Nf`, `%x`, `%%`, `%Nd`, `%-Ns`.
fn printf(fmt: &str, args: &[Value]) -> Result<String> {
    let mut out = String::new();
    let mut chars = fmt.chars().peekable();
    let mut next = args.iter();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        let mut spec = String::new();
        let mut conv = None;
        for c in chars.by_ref() {
            if c.is_ascii_alphabetic() || c == '%' {
                conv = Some(c);
                break;
            }
            spec.push(c);
        }
        let Some(conv) = conv else {
            return Err(Error::Sql("formato incompleto em printf".into()));
        };
        if conv == '%' {
            out.push('%');
            continue;
        }
        let left = spec.starts_with('-');
        let spec = spec.trim_start_matches('-');
        let (width, prec): (usize, Option<usize>) = match spec.split_once('.') {
            Some((w, p)) => (w.parse().unwrap_or(0), p.parse().ok()),
            None => (spec.parse().unwrap_or(0), None),
        };
        if width > 1 << 20 || prec.is_some_and(|p| p > 1 << 20) {
            return Err(Error::Sql("printf: largura ou precisão grande demais".into()));
        }
        let arg = next.next().unwrap_or(&Value::Null);
        let body = match conv {
            's' => arg.to_string(),
            'd' | 'i' => int("printf", arg)
                .map(|n| n.to_string())
                .unwrap_or_default(),
            'x' => format!("{:x}", int("printf", arg).unwrap_or(0)),
            'X' => format!("{:X}", int("printf", arg).unwrap_or(0)),
            'f' | 'F' => format!("{:.*}", prec.unwrap_or(6), arg.as_f64().unwrap_or(0.0)),
            'e' | 'E' => format!("{:.*e}", prec.unwrap_or(6), arg.as_f64().unwrap_or(0.0)),
            other => return Err(Error::Sql(format!("conversão %{other} desconhecida"))),
        };
        let body = match (conv, prec) {
            ('s', Some(p)) => body.chars().take(p).collect(),
            _ => body,
        };
        if left {
            out.push_str(&format!("{body:<width$}"));
        } else if spec.starts_with('0') && conv != 's' {
            out.push_str(&format!("{body:0>width$}"));
        } else {
            out.push_str(&format!("{body:>width$}"));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Data e hora (calendário proléptico gregoriano, UTC)
// ---------------------------------------------------------------------------

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    /// 0 = domingo.
    weekday: u32,
    /// 1-based.
    yday: u32,
}

/// Dias desde 1970-01-01 (Howard Hinnant, `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn civil(secs: i64) -> Civil {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400) as u32;
    let (year, month, day) = civil_from_days(days);
    Civil {
        year,
        month,
        day,
        hour: rem / 3600,
        minute: rem % 3600 / 60,
        second: rem % 60,
        weekday: (days + 4).rem_euclid(7) as u32,
        yday: (days - days_from_civil(year, 1, 1)) as u32 + 1,
    }
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        _ => 28,
    }
}

pub fn fmt_datetime(secs: i64, with_time: bool) -> String {
    let c = civil(secs);
    if with_time {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        )
    } else {
        format!("{:04}-{:02}-{:02}", c.year, c.month, c.day)
    }
}

fn fmt_time(secs: i64) -> String {
    let c = civil(secs);
    format!("{:02}:{:02}:{:02}", c.hour, c.minute, c.second)
}

/// Aceita `YYYY-MM-DD`, `YYYY-MM-DD[T ]HH:MM[:SS[.fff]][Z|±HH:MM]`, `now`,
/// e números (segundos Unix).
pub fn parse_datetime(v: &Value) -> Option<i64> {
    match v {
        Value::Int(n) => Some(*n),
        Value::Real(x) => Some(x.floor() as i64),
        Value::Text(s) => parse_datetime_text(s),
        _ => None,
    }
}

fn parse_datetime_text(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("now") {
        return Some(now_secs());
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        s.get(from..from + len)?
            .parse::<i64>()
            .ok()
            .filter(|_| b[from..from + len].iter().all(u8::is_ascii_digit))
    };
    let (y, m, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    if b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return None;
    }
    if !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m as u32) as i64 {
        return None;
    }
    let mut secs = days_from_civil(y, m as u32, d as u32) * 86400;
    let mut i = 10;
    if matches!(b.get(i), Some(b'T' | b' ' | b't')) {
        i += 1;
        let (hh, mm) = (num(i, 2)?, num(i + 3, 2)?);
        if b.get(i + 2) != Some(&b':') || hh > 23 || mm > 59 {
            return None;
        }
        secs += hh * 3600 + mm * 60;
        i += 5;
        if b.get(i) == Some(&b':') {
            let ss = num(i + 1, 2)?;
            if ss > 60 {
                return None;
            }
            secs += ss;
            i += 3;
            if b.get(i) == Some(&b'.') {
                i += 1;
                while b.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
            }
        }
        match b.get(i) {
            None => {}
            Some(b'Z' | b'z') => i += 1,
            Some(sign @ (b'+' | b'-')) => {
                let (oh, om) = (num(i + 1, 2)?, num(i + 4, 2)?);
                if b.get(i + 3) != Some(&b':') {
                    return None;
                }
                let off = oh * 3600 + om * 60;
                secs += if *sign == b'+' { -off } else { off };
                i += 6;
            }
            _ => return None,
        }
    }
    (i == b.len()).then_some(secs)
}

/// Modificadores no estilo SQLite: `+N day(s)`, `-2 hours`, `3 months`,
/// `start of day|month|year`, `weekday N`.
fn apply_modifier(secs: i64, m: &str) -> Result<i64> {
    let m = m.trim().to_ascii_lowercase();
    let bad = || Error::Sql(format!("modificador de data desconhecido: {m}"));
    if let Some(rest) = m.strip_prefix("start of ") {
        let c = civil(secs);
        return Ok(match rest.trim() {
            "day" => secs.div_euclid(86400) * 86400,
            "month" => days_from_civil(c.year, c.month, 1) * 86400,
            "year" => days_from_civil(c.year, 1, 1) * 86400,
            _ => return Err(bad()),
        });
    }
    if let Some(rest) = m.strip_prefix("weekday ") {
        let want: i64 = rest.trim().parse().map_err(|_| bad())?;
        if !(0..=6).contains(&want) {
            return Err(bad());
        }
        let c = civil(secs);
        let ahead = (want - c.weekday as i64).rem_euclid(7);
        return Ok(secs + ahead * 86400);
    }
    if m == "unixepoch" || m == "utc" || m == "localtime" {
        return Ok(secs);
    }
    let (amount, unit) = m.split_once(' ').ok_or_else(bad)?;
    let amount: f64 = amount.trim().parse().map_err(|_| bad())?;
    let unit = unit.trim().trim_end_matches('s');
    Ok(match unit {
        "second" | "sec" => secs + amount.round() as i64,
        "minute" | "min" => secs + (amount * 60.0).round() as i64,
        "hour" => secs + (amount * 3600.0).round() as i64,
        "day" => secs + (amount * 86400.0).round() as i64,
        "week" => secs + (amount * 7.0 * 86400.0).round() as i64,
        "month" | "year" => {
            let c = civil(secs);
            let months = if unit == "year" {
                amount * 12.0
            } else {
                amount
            }
            .round() as i64;
            let total = c.year * 12 + c.month as i64 - 1 + months;
            let (y, mo) = (total.div_euclid(12), (total.rem_euclid(12) + 1) as u32);
            // Dia além do fim do mês transborda para o mês seguinte (SQLite).
            days_from_civil(y, mo, 1) * 86400
                + (c.day as i64 - 1) * 86400
                + (c.hour as i64 * 3600 + c.minute as i64 * 60 + c.second as i64)
        }
        _ => return Err(bad()),
    })
}

/// `strftime` com `%Y %m %d %H %M %S %s %j %w %f %e %Y-%m-%d %%`.
fn strftime(fmt: &str, secs: i64) -> Result<String> {
    let c = civil(secs);
    let mut out = String::new();
    let mut chars = fmt.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&format!("{:04}", c.year)),
            Some('m') => out.push_str(&format!("{:02}", c.month)),
            Some('d') => out.push_str(&format!("{:02}", c.day)),
            Some('e') => out.push_str(&format!("{}", c.day)),
            Some('H') => out.push_str(&format!("{:02}", c.hour)),
            Some('M') => out.push_str(&format!("{:02}", c.minute)),
            Some('S') => out.push_str(&format!("{:02}", c.second)),
            Some('f') => out.push_str(&format!("{:02}.000", c.second)),
            Some('s') => out.push_str(&secs.to_string()),
            Some('j') => out.push_str(&format!("{:03}", c.yday)),
            Some('w') => out.push_str(&c.weekday.to_string()),
            Some('u') => out.push_str(&(if c.weekday == 0 { 7 } else { c.weekday }).to_string()),
            Some('F') => out.push_str(&fmt_datetime(secs, false)),
            Some('T') => out.push_str(&fmt_time(secs)),
            Some('%') => out.push('%'),
            other => {
                return Err(Error::Sql(format!(
                    "strftime: diretiva %{} desconhecida",
                    other.unwrap_or(' ')
                )))
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn to_json(v: &Value) -> Json {
    match v {
        Value::Text(s) => match Json::parse(s) {
            Ok(j @ (Json::Array(_) | Json::Object(_))) => j,
            _ => Json::String(s.clone()),
        },
        other => other.to_json(),
    }
}

fn from_json(j: &Json) -> Value {
    match j {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => Value::Int(*n),
        Json::Float(x) => Value::Real(*x),
        Json::String(s) => Value::Text(s.clone()),
        other => Value::Text(other.stringify()),
    }
}

/// Caminho `$`, `$.a.b`, `$.itens[2].nome`, `$[0]`.
fn json_path<'j>(doc: &'j Json, path: &str) -> Result<Option<&'j Json>> {
    let bad = || Error::Sql(format!("caminho JSON inválido: {path}"));
    let mut rest = path.strip_prefix('$').ok_or_else(bad)?;
    let mut node = doc;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix('.') {
            let end = r.find(['.', '[']).unwrap_or(r.len());
            let key = &r[..end];
            if key.is_empty() {
                return Err(bad());
            }
            node = match node {
                Json::Object(map) => match map.get(key) {
                    Some(n) => n,
                    None => return Ok(None),
                },
                _ => return Ok(None),
            };
            rest = &r[end..];
        } else if let Some(r) = rest.strip_prefix('[') {
            let end = r.find(']').ok_or_else(bad)?;
            let idx: usize = r[..end].trim().parse().map_err(|_| bad())?;
            node = match node {
                Json::Array(items) => match items.get(idx) {
                    Some(n) => n,
                    None => return Ok(None),
                },
                _ => return Ok(None),
            };
            rest = &r[end + 1..];
        } else {
            return Err(bad());
        }
    }
    Ok(Some(node))
}

/// Conversão explícita de tipos (`CAST`).
pub fn cast(v: Value, ty: Type) -> Result<Value> {
    let bad = |v: &Value| Error::Sql(format!("CAST de {v} para {} inválido", ty.name()));
    Ok(match (v, ty) {
        (Value::Null, _) => Value::Null,
        (v, Type::Text) => Value::Text(v.to_string()),
        (Value::Text(s), Type::Int) => {
            let t = s.trim();
            match t.parse::<i64>() {
                Ok(n) => Value::Int(n),
                Err(_) => match t.parse::<f64>() {
                    Ok(x) if x.is_finite() && x.abs() < 9.2e18 => Value::Int(x.trunc() as i64),
                    _ => return Err(bad(&Value::Text(s))),
                },
            }
        }
        (Value::Text(s), Type::Real) => match s.trim().parse::<f64>() {
            Ok(x) if !x.is_nan() => Value::Real(x),
            _ => return Err(bad(&Value::Text(s))),
        },
        (Value::Text(s), Type::Bool) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "t" | "1" | "yes" | "on" => Value::Bool(true),
            "false" | "f" | "0" | "no" | "off" => Value::Bool(false),
            _ => return Err(bad(&Value::Text(s))),
        },
        (Value::Real(x), Type::Int) if x.is_finite() && x.abs() < 9.2e18 => {
            Value::Int(x.trunc() as i64)
        }
        (Value::Bool(b), Type::Int) => Value::Int(b as i64),
        (Value::Bool(b), Type::Real) => Value::Real(b as i64 as f64),
        (Value::Int(n), Type::Bool) => Value::Bool(n != 0),
        (Value::Real(x), Type::Bool) => Value::Bool(x != 0.0),
        (v, ty) => v.coerce(ty)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    #[test]
    fn datetime_roundtrip_and_modifiers() {
        assert_eq!(parse_datetime(&t("1970-01-01")), Some(0));
        assert_eq!(
            parse_datetime(&t("2024-02-29T12:30:00Z")),
            Some(1_709_209_800)
        );
        assert_eq!(parse_datetime(&t("2024-02-30")), None);
        assert_eq!(
            parse_datetime(&t("2024-01-01 00:00:00+02:00")),
            Some(1_704_060_000)
        );
        let secs = parse_datetime(&t("2024-01-31 10:00:00")).unwrap();
        assert_eq!(
            fmt_datetime(apply_modifier(secs, "+1 month").unwrap(), true),
            "2024-03-02 10:00:00"
        );
        assert_eq!(
            fmt_datetime(apply_modifier(secs, "-1 day").unwrap(), false),
            "2024-01-30"
        );
        assert_eq!(
            fmt_datetime(apply_modifier(secs, "start of year").unwrap(), true),
            "2024-01-01 00:00:00"
        );
        assert_eq!(strftime("%Y/%j %w", secs).unwrap(), "2024/031 3");
        for (y, m, d) in [(2000, 2, 29), (1600, 12, 31), (-44, 3, 15), (9999, 1, 1)] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
    }

    #[test]
    fn scalar_functions() {
        let c = |n: &str, v: Vec<Value>| call(n, v).unwrap();
        assert_eq!(
            c("substr", vec![t("olá mundo"), Value::Int(-5)]),
            t("mundo")
        );
        assert_eq!(c("lpad", vec![t("7"), Value::Int(3), t("0")]), t("007"));
        assert_eq!(
            c("split_part", vec![t("a,b,c"), t(","), Value::Int(-1)]),
            t("c")
        );
        assert_eq!(
            c(
                "printf",
                vec![
                    t("%05.1f|%-3s|%x"),
                    Value::Real(1.23456),
                    t("ab"),
                    Value::Int(255)
                ]
            ),
            t("001.2|ab |ff")
        );
        assert_eq!(
            c(
                "json_extract",
                vec![t(r#"{"a":{"b":[1,{"c":"x"}]}}"#), t("$.a.b[1].c")]
            ),
            t("x")
        );
        assert_eq!(
            c("json_extract", vec![t(r#"{"a":1}"#), t("$.z")]),
            Value::Null
        );
        assert_eq!(
            c(
                "greatest",
                vec![Value::Int(1), Value::Null, Value::Real(2.5)]
            ),
            Value::Real(2.5)
        );
        assert_eq!(
            c("coalesce", vec![Value::Null, Value::Int(3)]),
            Value::Int(3)
        );
        assert_eq!(c("initcap", vec![t("olá MUNDO-x")]), t("Olá Mundo-X"));
        assert_eq!(c("sha256", vec![t("abc")]).to_string().len(), 64);
        assert_eq!(c("uuid", vec![]).to_string().len(), 36);
        assert!(call("nada", vec![]).is_err());
        assert_eq!(c("upper", vec![Value::Null]), Value::Null);
    }
}
