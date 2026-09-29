//! CLI `minidb` — shell, exec, TCP, HTTP, export/import.

use std::env;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Arc, Mutex};

use mini_db::backup;
use mini_db::cmd;
use mini_db::config::Config;
use mini_db::http;
use mini_db::metrics::Metrics;
use mini_db::Db;

fn usage() -> ! {
    eprintln!(
        "uso:\n  \
         minidb shell [dir]\n  \
         minidb exec [dir] <comando...>\n  \
         minidb serve [dir] [addr] [--primary ADDR | --replica-of ADDR]\n  \
         minidb http [dir] [addr] [--primary ADDR | --replica-of ADDR]\n  \
         minidb export [dir] [out.jsonl]\n  \
         minidb import [dir] [in.jsonl]"
    );
    process::exit(2);
}

/// Remove `--flag valor` dos argumentos e devolve o valor.
fn take_flag(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    if i + 1 >= args.len() {
        usage();
    }
    args.remove(i);
    Some(args.remove(i))
}

/// Primário: publica o log de commits. Réplica: segue o primário (somente leitura).
fn start_replication(db: &Arc<Mutex<Db>>, primary: Option<String>, replica_of: Option<String>) {
    if let Some(addr) = primary {
        let shared = mini_db::mvcc::SharedDb::from_arc(Arc::clone(db));
        std::thread::spawn(move || {
            if let Err(e) = mini_db::replication::serve_primary(shared, &addr, 100_000) {
                eprintln!("erro na replicação (primário): {e}");
            }
        });
    }
    if let Some(addr) = replica_of {
        if let Ok(mut guard) = db.lock() {
            guard.set_read_only(true); // antes de aceitar clientes
        }
        let db = Arc::clone(db);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        std::thread::spawn(move || {
            if let Err(e) = mini_db::replication::run_replica(db, &addr, stop) {
                eprintln!("erro na replicação (réplica): {e}");
            }
        });
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("erro: {e}");
        process::exit(1);
    }
}

fn run() -> mini_db::Result<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let cmdn = args.remove(0).to_ascii_lowercase();
    let primary = take_flag(&mut args, "--primary");
    let replica_of = take_flag(&mut args, "--replica-of");
    match cmdn.as_str() {
        "open" | "shell" => {
            let path = PathBuf::from(args.first().map(|s| s.as_str()).unwrap_or("./data"));
            let mut db = Db::open(&path)?;
            println!(
                "minidb aberto em {}  (root={}, lsn={})",
                path.display(),
                db.meta().root_page,
                db.stats().next_lsn
            );
            println!("HELP para comandos. SQL e HTTP/TCP estão no README.");
            let stdin = io::stdin();
            let mut stdout = io::stdout();
            for line in stdin.lock().lines() {
                let line = line.map_err(mini_db::Error::from)?;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match cmd::apply(&mut db, line) {
                    Ok(msg) if msg == "QUIT\n" => break,
                    Ok(msg) => {
                        print!("{msg}");
                        stdout.flush().ok();
                    }
                    Err(e) => eprintln!("erro: {e}"),
                }
            }
            db.close()?;
            println!("checkpoint + close ok");
            Ok(())
        }
        "exec" => {
            if args.is_empty() {
                usage();
            }
            let (path, rest) = if args.len() >= 2 && !looks_like_cmd(&args[0]) {
                (PathBuf::from(&args[0]), args[1..].join(" "))
            } else {
                (PathBuf::from("./data"), args.join(" "))
            };
            let mut db = Db::open(&path)?;
            match cmd::apply(&mut db, &rest) {
                Ok(msg) => print!("{msg}"),
                Err(e) => {
                    let _ = db.close();
                    return Err(e);
                }
            }
            db.close()?;
            Ok(())
        }
        "serve" => {
            let cfg = Config::load(args.first().map(PathBuf::from).as_deref())?;
            let path = args
                .first()
                .map(PathBuf::from)
                .unwrap_or_else(|| cfg.path.clone());
            let addr = args.get(1).cloned().unwrap_or_else(|| cfg.tcp_addr.clone());
            let db = open_configured_db(&path, &cfg)?;
            let db = Arc::new(Mutex::new(db));
            start_replication(&db, primary, replica_of);
            mini_db::server::serve(db, &addr)
        }
        "http" => {
            let cfg = Config::load(args.first().map(PathBuf::from).as_deref())?;
            let path = args
                .first()
                .map(PathBuf::from)
                .unwrap_or_else(|| cfg.path.clone());
            let addr = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| cfg.http_addr.clone());
            let db = open_configured_db(&path, &cfg)?;
            let db = Arc::new(Mutex::new(db));
            start_replication(&db, primary, replica_of);
            let metrics = Arc::new(Metrics::new());
            http::serve_http(db, metrics, &addr)
        }
        "export" => {
            let path = PathBuf::from(args.first().map(|s| s.as_str()).unwrap_or("./data"));
            let out = PathBuf::from(args.get(1).map(|s| s.as_str()).unwrap_or("backup.jsonl"));
            let mut db = Db::open(&path)?;
            let n = backup::export_jsonl(&mut db, &out)?;
            db.close()?;
            println!("export {n} rows -> {}", out.display());
            Ok(())
        }
        "import" => {
            let path = PathBuf::from(args.first().map(|s| s.as_str()).unwrap_or("./data"));
            let src = PathBuf::from(args.get(1).map(|s| s.as_str()).unwrap_or("backup.jsonl"));
            let mut db = Db::open(&path)?;
            let n = backup::import_jsonl(&mut db, &src)?;
            db.close()?;
            println!("import {n} rows <- {}", src.display());
            Ok(())
        }
        _ => usage(),
    }
}

fn looks_like_cmd(s: &str) -> bool {
    matches!(
        s.to_ascii_uppercase().as_str(),
        "PUT"
            | "INSERT"
            | "GET"
            | "DELETE"
            | "DEL"
            | "RM"
            | "SCAN"
            | "GETVAL"
            | "BYVALUE"
            | "SQL"
            | "SELECT"
            | "UPDATE"
            | "EXPLAIN"
            | "CREATE"
            | "BEGIN"
            | "COMMIT"
            | "ROLLBACK"
            | "ABORT"
            | "STATS"
            | "CHECKPOINT"
            | "CKPT"
            | "VACUUM"
            | "INDEX"
            | "VERIFY"
            | "INSPECT"
            | "HEX"
            | "CATALOG"
            | "HELP"
            | "SETEX"
            | "EXPIRE"
            | "PERSIST"
            | "TTL"
            | "PURGE"
            | "EXISTS"
            | "COUNT"
            | "PREFIX"
            | "PAGES"
            | "?"
    )
}

fn open_configured_db(path: impl AsRef<Path>, cfg: &Config) -> mini_db::Result<Db> {
    Db::open_with_options(path, cfg.pool_frames, cfg.fsync)
}

#[cfg(test)]
mod tests {
    use super::{looks_like_cmd, open_configured_db};
    use mini_db::config::Config;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn configured_pool_capacity_is_used_by_server_database() {
        let path = std::env::temp_dir().join(format!(
            "minidb-cli-config-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cfg = Config {
            pool_frames: 17,
            ..Config::default()
        };

        let mut db = open_configured_db(&path, &cfg).unwrap();
        assert_eq!(db.stats().pool_capacity, 17);
        db.close().unwrap();
        drop(db);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn exec_recognizes_sql_and_shell_commands_without_explicit_directory() {
        for command in ["PUT", "SELECT", "INSERT", "UPDATE", "EXPLAIN", "CREATE"] {
            assert!(looks_like_cmd(command), "not recognized: {command}");
        }
        assert!(!looks_like_cmd("./my-database"));
    }
}
