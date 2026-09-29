//! Interpretador de comandos compartilhado entre CLI e servidor TCP.

use crate::db::{Db, ExecResult, KeyTtl};
use crate::error::{Error, Result};

pub fn apply(db: &mut Db, line: &str) -> Result<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.eq_ignore_ascii_case("QUIT")
        || trimmed.eq_ignore_ascii_case("EXIT")
        || trimmed.eq_ignore_ascii_case("Q")
    {
        return Ok("QUIT\n".into());
    }

    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("SQL ") {
        return format_exec(db.execute_sql(&trimmed[4..])?);
    }
    if looks_like_sql(&upper) {
        return format_exec(db.execute_sql(trimmed)?);
    }

    let parts = split_cmd(trimmed);
    if parts.is_empty() {
        return Ok(String::new());
    }
    let op = parts[0].to_ascii_uppercase();
    match op.as_str() {
        "PUT" | "INSERT" => {
            if parts.len() < 3 {
                return Err(Error::Cli("uso: PUT <chave> <valor>".into()));
            }
            let key = parts[1].as_bytes();
            let value = parts[2..].join(" ");
            db.put(key, value.as_bytes())?;
            Ok(format!(
                "OK lsn={}\n",
                db.stats().next_lsn.saturating_sub(1)
            ))
        }
        "GET" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: GET <chave>".into()));
            }
            match db.get(parts[1].as_bytes())? {
                Some(v) => Ok(format!("{}\n", String::from_utf8_lossy(&v))),
                None => Ok("(nil)\n".into()),
            }
        }
        "DELETE" | "DEL" | "RM" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: DELETE <chave>".into()));
            }
            let ok = db.delete(parts[1].as_bytes())?;
            Ok(format!(
                "{}\n",
                if ok { "OK deleted" } else { "OK missing" }
            ))
        }
        "SCAN" => {
            let pairs = if parts.len() < 2 {
                db.scan(&[0], None)?
            } else {
                let start = parts[1].as_bytes();
                let end = parts.get(2).map(|s| s.as_bytes());
                db.scan(start, end)?
            };
            Ok(format_rows(&pairs))
        }
        "GETVAL" | "BYVALUE" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: GETVAL <valor>".into()));
            }
            let keys = db.get_by_value(parts[1].as_bytes())?;
            let mut out = String::new();
            for k in keys {
                out.push_str(&String::from_utf8_lossy(&k));
                out.push('\n');
            }
            if out.is_empty() {
                out.push_str("(none)\n");
            }
            Ok(out)
        }
        "BEGIN" => {
            let id = db.begin()?;
            Ok(format!("OK BEGIN txn={id}\n"))
        }
        "COMMIT" => {
            let id = db.commit()?;
            Ok(format!("OK COMMIT txn={id}\n"))
        }
        "ROLLBACK" | "ABORT" => {
            db.rollback()?;
            Ok("OK ROLLBACK\n".into())
        }
        "CHECKPOINT" | "CKPT" => {
            db.checkpoint()?;
            Ok(format!("OK checkpoint lsn={}\n", db.meta().checkpoint_lsn))
        }
        "VACUUM" => {
            let n = db.vacuum()?;
            Ok(format!("OK VACUUM pages={n}\n"))
        }
        "INDEX" => {
            let n = db.create_value_index()?;
            Ok(format!("OK INDEX keys={n}\n"))
        }
        "VERIFY" => {
            let r = db.verify()?;
            Ok(format!(
                "OK VERIFY pages={} leaves={} internals={} keys={}\n",
                r.pages_ok, r.leaves, r.internals, r.keys
            ))
        }
        "INSPECT" => {
            if parts.len() < 2 {
                return Ok(db.inspect_meta_text());
            }
            let id: u32 = parts[1]
                .parse()
                .map_err(|_| Error::Cli("uso: INSPECT [page_id]".into()))?;
            db.inspect_page(id)
        }
        "HEX" => {
            if parts.len() < 2 {
                return Err(Error::Cli("uso: HEX <page_id> [bytes]".into()));
            }
            let id: u32 = parts[1].parse().map_err(|_| Error::Cli("page_id".into()))?;
            let n: usize = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(128);
            db.inspect_hex(id, n)
        }
        "CATALOG" => {
            crate::catalog::bootstrap(db)?;
            crate::catalog::format_dump(db)
        }
        "STATS" => {
            let s = db.stats();
            Ok(format!(
                "root={} index_root={} ttl_root={} next_page={} ckpt_lsn={} next_lsn={} pool={} txn_id={} value_index={} txn_open={}\n",
                s.root_page,
                s.index_root,
                s.ttl_root,
                s.next_page_id,
                s.checkpoint_lsn,
                s.next_lsn,
                s.pool_capacity,
                s.next_txn_id,
                s.value_index,
                s.txn_open
            ))
        }
        "SETEX" => {
            if parts.len() < 4 {
                return Err(Error::Cli("uso: SETEX <chave> <segundos> <valor>".into()));
            }
            let ttl = parse_secs(&parts[2])?;
            db.put_with_ttl(parts[1].as_bytes(), parts[3..].join(" ").as_bytes(), ttl)?;
            Ok(format!(
                "OK lsn={}\n",
                db.stats().next_lsn.saturating_sub(1)
            ))
        }
        "EXPIRE" => {
            if parts.len() != 3 {
                return Err(Error::Cli("uso: EXPIRE <chave> <segundos>".into()));
            }
            let ok = db.expire(parts[1].as_bytes(), parse_secs(&parts[2])?)?;
            Ok(if ok { "OK\n" } else { "OK missing\n" }.into())
        }
        "PERSIST" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: PERSIST <chave>".into()));
            }
            let ok = db.persist(parts[1].as_bytes())?;
            Ok(if ok { "OK\n" } else { "OK no-ttl\n" }.into())
        }
        "TTL" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: TTL <chave>".into()));
            }
            Ok(match db.ttl(parts[1].as_bytes())? {
                KeyTtl::Missing => "(missing)\n".into(),
                KeyTtl::Persistent => "(persistent)\n".into(),
                KeyTtl::ExpiresIn(d) => format!("ttl_ms={}\n", d.as_millis()),
            })
        }
        "PURGE" => Ok(format!("OK purged={}\n", db.purge_expired()?)),
        "EXISTS" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: EXISTS <chave>".into()));
            }
            Ok(format!("{}\n", u8::from(db.contains(parts[1].as_bytes())?)))
        }
        "COUNT" => {
            let start = parts.get(1).map_or(&b"\0"[..], |s| s.as_bytes());
            let end = parts.get(2).map(|s| s.as_bytes());
            Ok(format!("COUNT {}\n", db.count(start, end)?))
        }
        "PREFIX" => {
            if !(2..=3).contains(&parts.len()) {
                return Err(Error::Cli("uso: PREFIX <prefixo> [limite]".into()));
            }
            let limit = match parts.get(2) {
                Some(raw) => raw
                    .parse::<usize>()
                    .map_err(|_| Error::Cli("limite inválido".into()))?,
                None => usize::MAX,
            };
            let rows: Vec<_> = db
                .scan_prefix(parts[1].as_bytes())?
                .take(limit)
                .collect::<Result<_>>()?;
            Ok(format_rows(&rows))
        }
        "PAGES" => Ok(format!("{}\n", db.page_stats()?)),
        "HELP" | "?" => Ok(HELP.into()),
        other => Err(Error::Cli(format!("comando desconhecido: {other}"))),
    }
}

const HELP: &str = "\
Dados:      PUT|INSERT k v · GET k · DELETE|DEL|RM k · EXISTS k · GETVAL v
TTL:        SETEX k segundos v · EXPIRE k segundos · TTL k · PERSIST k · PURGE
Leitura:    SCAN [início] [fim] · PREFIX p [limite] · COUNT [início] [fim]
Transação:  BEGIN · COMMIT · ROLLBACK|ABORT
Manutenção: CHECKPOINT|CKPT · VACUUM · INDEX · VERIFY · PAGES · STATS · CATALOG
Forense:    INSPECT [página] · HEX página [bytes]
SQL:        SELECT/INSERT/UPDATE/DELETE/CREATE INDEX/EXPLAIN (ou prefixo SQL)
Sair:       QUIT|EXIT
";

fn parse_secs(raw: &str) -> Result<std::time::Duration> {
    raw.parse::<u64>()
        .ok()
        .filter(|s| *s > 0)
        .map(std::time::Duration::from_secs)
        .ok_or_else(|| Error::Cli("segundos devem ser inteiro > 0".into()))
}

fn looks_like_sql(upper: &str) -> bool {
    upper.starts_with("SELECT ")
        || upper.starts_with("INSERT INTO")
        || upper.starts_with("UPDATE ")
        || upper.starts_with("DELETE FROM")
        || upper.starts_with("CREATE ")
        || upper.starts_with("EXPLAIN ")
        || upper.starts_with("DROP ")
        || upper.starts_with("ALTER ")
        || upper.starts_with("DESCRIBE ")
        || upper == "SHOW TABLES"
}

fn format_exec(res: ExecResult) -> Result<String> {
    match res {
        ExecResult::Ok(s) => Ok(format!("OK {s}\n")),
        ExecResult::Value(None) => Ok("(nil)\n".into()),
        ExecResult::Value(Some(v)) => Ok(format!("{}\n", String::from_utf8_lossy(&v))),
        ExecResult::Rows(rows) => Ok(format_rows(&rows)),
        ExecResult::Count(n) => Ok(format!("COUNT {n}\n")),
        ExecResult::Table { columns, rows } => Ok(format_table(&columns, &rows)),
    }
}

/// Tabela alinhada em texto (estilo psql).
fn format_table(columns: &[String], rows: &[Vec<crate::rel::Value>]) -> String {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(ToString::to_string).collect())
        .collect();
    let widths: Vec<usize> = columns
        .iter()
        .enumerate()
        .map(|(i, c)| {
            cells
                .iter()
                .map(|r| r[i].chars().count())
                .chain([c.chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let line = |vals: &[String]| {
        let padded: Vec<String> = vals
            .iter()
            .zip(&widths)
            .map(|(v, w)| format!("{v:<w$}"))
            .collect();
        format!(" {} \n", padded.join(" | "))
    };
    let mut out = line(columns);
    out.push_str(&format!(
        "-{}-\n",
        widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("-+-")
    ));
    for r in &cells {
        out.push_str(&line(r));
    }
    out.push_str(&format!(
        "({} linha{})\n",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" }
    ));
    out
}

fn format_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> String {
    let mut out = String::new();
    for (k, v) in rows {
        out.push_str(&format!(
            "ROW key={} value={}\n",
            String::from_utf8_lossy(k),
            String::from_utf8_lossy(v)
        ));
    }
    out.push_str(&format!("END count={}\n", rows.len()));
    out
}

pub fn split_cmd(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote: Option<char> = None;
    for c in line.chars() {
        match in_quote {
            Some(q) => {
                if c == q {
                    in_quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    in_quote = Some(c);
                } else if c.is_whitespace() {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                } else {
                    cur.push(c);
                }
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}
