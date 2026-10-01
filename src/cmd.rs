//! Interpretador de comandos compartilhado entre CLI e servidor TCP.
//!
//! Opera sobre uma [`Session`] (uma por conexão): SQL, `BEGIN`/`COMMIT`/
//! `ROLLBACK`/`SAVEPOINT` e `PUT`/`GET`/`DEL` respeitam a transação aberta na
//! sessão; os demais comandos usam o [`SharedDb`] diretamente (leituras com o
//! lock compartilhado, escritas pelo caminho concorrente).

use crate::db::{ExecResult, KeyTtl};
use crate::error::{Error, Result};
use crate::mvcc::{Session, SharedDb};

pub fn apply(session: &mut Session, line: &str) -> Result<String> {
    let db: SharedDb = session.db().clone();
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
        let out = format_exec(session.execute(&trimmed[4..])?);
        return with_notifications(session, out);
    }
    if looks_like_sql(&upper) || crate::db::is_transaction_control(trimmed) {
        let out = format_exec(session.execute(trimmed)?);
        return with_notifications(session, out);
    }
    if upper == "WAIT" || upper.starts_with("WAIT ") {
        // Espera notificações dos canais escutados (LISTEN) por até N segundos.
        let secs: u64 = trimmed
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        let got = session.notifications(std::time::Duration::from_secs(secs.min(3600)));
        if got.is_empty() {
            return Ok("(timeout)\n".into());
        }
        return Ok(got
            .iter()
            .map(|n| format!("NOTIFY {} {}\n", n.channel, n.payload))
            .collect());
    }

    let parts = split_cmd(trimmed);
    if parts.is_empty() {
        return Ok(String::new());
    }
    let op = parts[0].to_ascii_uppercase();
    if session.principal().is_some() {
        use crate::auth::Privilege;
        let needed = match op.as_str() {
            "GET" | "SCAN" | "GETVAL" | "BYVALUE" | "TTL" | "EXISTS" | "COUNT" | "PREFIX"
            | "STATS" | "PAGES" | "HELP" | "?" | "ROLE" => Privilege::Select,
            "PUT" | "INSERT" | "SETEX" | "EXPIRE" | "PERSIST" => Privilege::Insert,
            "DELETE" | "DEL" | "RM" | "PURGE" => Privilege::Delete,
            "ABORT" => Privilege::Select,
            _ => Privilege::All,
        };
        session.authorize_object("kv", needed)?;
        // Páginas brutas e catálogo expõem todas as tabelas e as credenciais.
        if matches!(op.as_str(), "VERIFY" | "INSPECT" | "HEX" | "CATALOG") {
            session.authorize_object("*", Privilege::All)?;
        }
    }
    let lsn = || -> Result<String> { Ok(format!("OK lsn={}\n", db.read()?.last_lsn())) };
    match op.as_str() {
        "PUT" | "INSERT" => {
            if parts.len() < 3 {
                return Err(Error::Cli("uso: PUT <chave> <valor>".into()));
            }
            let value = parts[2..].join(" ");
            session.put(parts[1].as_bytes(), value.as_bytes())?;
            if session.in_transaction() {
                return Ok("OK (pendente na transação)\n".into());
            }
            lsn()
        }
        "GET" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: GET <chave>".into()));
            }
            match session.get(parts[1].as_bytes())? {
                Some(v) => Ok(format!("{}\n", String::from_utf8_lossy(&v))),
                None => Ok("(nil)\n".into()),
            }
        }
        "DELETE" | "DEL" | "RM" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: DELETE <chave>".into()));
            }
            let ok = session.delete(parts[1].as_bytes())?;
            Ok(format!(
                "{}\n",
                if ok { "OK deleted" } else { "OK missing" }
            ))
        }
        "SCAN" => {
            let guard = db.read()?;
            let pairs = if parts.len() < 2 {
                guard.scan(&[0], None)?
            } else {
                let start = parts[1].as_bytes();
                let end = parts.get(2).map(|s| s.as_bytes());
                guard.scan(start, end)?
            };
            Ok(format_rows(&pairs))
        }
        "GETVAL" | "BYVALUE" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: GETVAL <valor>".into()));
            }
            let keys = db.read()?.get_by_value(parts[1].as_bytes())?;
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
        "ABORT" => format_exec(session.execute("ROLLBACK")?),
        "CHECKPOINT" | "CKPT" => {
            let mut guard = db.write()?;
            guard.checkpoint()?;
            Ok(format!(
                "OK checkpoint lsn={}\n",
                guard.meta().checkpoint_lsn
            ))
        }
        "VACUUM" => {
            let n = db.write()?.vacuum()?;
            Ok(format!("OK VACUUM pages={n}\n"))
        }
        "MAINTAIN" => {
            let r = db.write()?.maintain(0.25)?;
            Ok(format!(
                "OK MAINTAIN purged={} vacuumed={} checkpointed={}\n",
                r.purged, r.vacuumed, r.checkpointed
            ))
        }
        "INDEX" => {
            let n = db.write()?.create_value_index()?;
            Ok(format!("OK INDEX keys={n}\n"))
        }
        "VERIFY" => {
            let r = db.read()?.verify()?;
            Ok(format!(
                "OK VERIFY pages={} leaves={} internals={} overflow={} free={} keys={}\n",
                r.pages_ok, r.leaves, r.internals, r.overflow_pages, r.free_pages, r.keys
            ))
        }
        "INSPECT" => {
            let guard = db.read()?;
            if parts.len() < 2 {
                return Ok(guard.inspect_meta_text());
            }
            let id: u32 = parts[1]
                .parse()
                .map_err(|_| Error::Cli("uso: INSPECT [page_id]".into()))?;
            guard.inspect_page(id)
        }
        "HEX" => {
            if parts.len() < 2 {
                return Err(Error::Cli("uso: HEX <page_id> [bytes]".into()));
            }
            let id: u32 = parts[1].parse().map_err(|_| Error::Cli("page_id".into()))?;
            let n: usize = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(128);
            db.read()?.inspect_hex(id, n)
        }
        "CATALOG" => {
            let mut guard = db.write()?;
            crate::catalog::bootstrap(&mut guard)?;
            crate::catalog::format_dump(&mut guard)
        }
        "STATS" => {
            let s = db.read()?.stats();
            Ok(format!(
                "root={} index_root={} ttl_root={} next_page={} ckpt_lsn={} next_lsn={} applied_lsn={} wal_bytes={} pool={} cached={} txn_id={} value_index={} txn_open={} read_only={} snapshots={} versions={} compressed={}\n",
                s.root_page,
                s.index_root,
                s.ttl_root,
                s.next_page_id,
                s.checkpoint_lsn,
                s.next_lsn,
                s.applied_lsn,
                s.wal_bytes,
                s.pool_capacity,
                s.cached_pages,
                s.next_txn_id,
                s.value_index,
                s.txn_open,
                s.read_only,
                s.snapshots,
                s.versions,
                s.compressed
            ))
        }
        "SETEX" => {
            if parts.len() < 4 {
                return Err(Error::Cli("uso: SETEX <chave> <segundos> <valor>".into()));
            }
            let ttl = parse_secs(&parts[2])?;
            db.put_with_ttl(parts[1].as_bytes(), parts[3..].join(" ").as_bytes(), ttl)?;
            lsn()
        }
        "EXPIRE" => {
            if parts.len() != 3 {
                return Err(Error::Cli("uso: EXPIRE <chave> <segundos>".into()));
            }
            let ok = db
                .write()?
                .expire(parts[1].as_bytes(), parse_secs(&parts[2])?)?;
            Ok(if ok { "OK\n" } else { "OK missing\n" }.into())
        }
        "PERSIST" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: PERSIST <chave>".into()));
            }
            let ok = db.write()?.persist(parts[1].as_bytes())?;
            Ok(if ok { "OK\n" } else { "OK no-ttl\n" }.into())
        }
        "TTL" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: TTL <chave>".into()));
            }
            Ok(match db.read()?.ttl(parts[1].as_bytes())? {
                KeyTtl::Missing => "(missing)\n".into(),
                KeyTtl::Persistent => "(persistent)\n".into(),
                KeyTtl::ExpiresIn(d) => format!("ttl_ms={}\n", d.as_millis()),
            })
        }
        "PURGE" => Ok(format!("OK purged={}\n", db.write()?.purge_expired()?)),
        "EXISTS" => {
            if parts.len() != 2 {
                return Err(Error::Cli("uso: EXISTS <chave>".into()));
            }
            Ok(format!(
                "{}\n",
                u8::from(db.read()?.contains(parts[1].as_bytes())?)
            ))
        }
        "COUNT" => {
            let start = parts.get(1).map_or(&b"\0"[..], |s| s.as_bytes());
            let end = parts.get(2).map(|s| s.as_bytes());
            Ok(format!("COUNT {}\n", db.read()?.count(start, end)?))
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
            let guard = db.read()?;
            let rows: Vec<_> = guard
                .scan_prefix(parts[1].as_bytes())?
                .take(limit)
                .collect::<Result<_>>()?;
            Ok(format_rows(&rows))
        }
        "PAGES" => Ok(format!("{}\n", db.read()?.page_stats()?)),
        "ROLE" => {
            let s = crate::replication::status(&db)?;
            let role = match &s.role {
                crate::replication::Role::Primary => "primary".to_string(),
                crate::replication::Role::Replica { upstream } => format!("replica of {upstream}"),
                crate::replication::Role::Fenced => "fenced".to_string(),
            };
            Ok(format!(
                "ROLE {role} epoch={} applied_lsn={} head_lsn={} replicas={:?} sync_replicas={} sync_timeouts={} resyncing={}\n",
                s.epoch,
                s.applied_lsn,
                s.head_lsn,
                s.replicas,
                s.sync_replicas,
                s.sync_timeouts,
                s.resyncing
            ))
        }
        "PROMOTE" => Ok(format!(
            "OK PROMOTE epoch={}\n",
            crate::replication::promote(&db)?
        )),
        "HELP" | "?" => Ok(HELP.into()),
        other => Err(Error::Cli(format!("comando desconhecido: {other}"))),
    }
}

const HELP: &str = "\
Dados:      PUT|INSERT k v · GET k · DELETE|DEL|RM k · EXISTS k · GETVAL v
TTL:        SETEX k segundos v · EXPIRE k segundos · TTL k · PERSIST k · PURGE
Leitura:    SCAN [início] [fim] · PREFIX p [limite] · COUNT [início] [fim]
Transação:  BEGIN · COMMIT · ROLLBACK|ABORT
Manutenção: CHECKPOINT|CKPT · VACUUM · MAINTAIN · INDEX · VERIFY · PAGES · STATS · CATALOG
Replicação: ROLE · PROMOTE
Forense:    INSPECT [página] · HEX página [bytes]
SQL:        SELECT/WITH/INSERT/UPDATE/DELETE/CREATE/DROP/ALTER/SHOW/DESCRIBE/EXPLAIN
            (ou prefixo SQL)
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
        || upper.starts_with("WITH ")
        || upper.starts_with("VALUES")
        || upper.starts_with("REPLACE INTO")
        || upper.starts_with("TRUNCATE ")
        || upper.starts_with("SHOW ")
        || upper.starts_with("DESC ")
        || upper.starts_with("ANALYZE")
        || upper.starts_with("REFRESH ")
        || upper.starts_with("NOTIFY ")
        || upper.starts_with("LISTEN ")
        || upper.starts_with("UNLISTEN")
        || upper.starts_with("GRANT ")
        || upper.starts_with("REVOKE ")
        || upper.starts_with("REINDEX ")
}

/// Anexa à resposta as notificações já entregues (canais em LISTEN).
fn with_notifications(session: &Session, mut out: Result<String>) -> Result<String> {
    let pending = session.notifications(std::time::Duration::ZERO);
    if pending.is_empty() {
        return out;
    }
    if let Ok(text) = &mut out {
        if !text.ends_with('\n') {
            text.push('\n');
        }
        for n in pending {
            text.push_str(&format!("NOTIFY {} {}\n", n.channel, n.payload));
        }
    }
    out
}

fn format_exec(res: ExecResult) -> Result<String> {
    match res {
        ExecResult::Ok(s) => Ok(format!("OK {s}\n")),
        ExecResult::Value(None) => Ok("(nil)\n".into()),
        ExecResult::Value(Some(v)) => Ok(format!("{}\n", String::from_utf8_lossy(&v))),
        ExecResult::Rows(rows) => Ok(format_rows(&rows)),
        ExecResult::Count(n) => Ok(format!("COUNT {n}\n")),
        ExecResult::Table { columns, rows } => Ok(format_table(&columns, &rows)),
        ExecResult::Batch(results) => {
            let mut out = String::new();
            for r in results {
                out.push_str(&format_exec(r)?);
            }
            Ok(out)
        }
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
