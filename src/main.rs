//! CLI `minidb` — shell, exec, TCP, HTTP, export/import, replicação.

use std::env;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use mini_db::backup;
use mini_db::cmd;
use mini_db::config::Config;
use mini_db::http;
use mini_db::metrics::Metrics;
use mini_db::mvcc::SharedDb;
use mini_db::replication::{self, ReplicationConfig};
use mini_db::Db;

fn usage() -> ! {
    eprintln!(
        "uso:\n  \
         minidb shell [dir]\n  \
         minidb exec [dir] <comando...>\n  \
         minidb serve [dir] [addr] [--primary ADDR] [--replica-of ADDR]\n  \
         minidb http [dir] [addr] [--primary ADDR] [--replica-of ADDR]\n  \
         minidb pg [dir] [addr]           (protocolo PostgreSQL; psql -h host -p porta)\n  \
         minidb encrypt|decrypt|rekey [dir]  (senhas em MINIDB_PASSPHRASE / MINIDB_NEW_PASSPHRASE)\n  \
         minidb cert ca <pki-dir> [nome] [--algo ed25519|p256|p384|rsa2048|rsa3072|rsa4096]   (cria a CA: ca.key/ca.crt)\n  \
         minidb cert server <pki-dir> <host> [--days N] [--algo ..]   (server.key/server.crt assinados pela CA)\n  \
         minidb cert client <pki-dir> <usuário> [--days N] [--algo ..] (client-<usuário>.key/.crt; CN = usuário)\n  \
         minidb backup [dir] <destino>    (completo; repete = incremental)\n  \
         minidb restore <backup> <dir> [--until-lsn N | --until-time 'AAAA-MM-DD HH:MM:SS']\n  \
         minidb export [dir] [out.jsonl]\n  \
         minidb import [dir] [in.jsonl]\n\n\
         --primary ADDR     publica os commits para réplicas em ADDR\n  \
         --replica-of ADDR  segue o primário em ADDR (somente leitura; PROMOTE promove)\n  \
         Ambos juntos: réplica em cascata, pronta para ser promovida."
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

fn repl_config(cfg: &Config) -> ReplicationConfig {
    ReplicationConfig {
        secret: cfg.repl_secret.clone().map(String::into_bytes),
        ..ReplicationConfig::default()
    }
}

/// Primário: publica os commits. Réplica: segue o upstream (somente leitura).
/// Manutenção: purge, vacuum e checkpoint periódicos.
fn start_background(
    db: &SharedDb,
    cfg: &Config,
    primary: Option<String>,
    replica_of: Option<String>,
) -> mini_db::Result<()> {
    {
        let mut guard = db.write()?;
        guard.set_auto_checkpoint(cfg.auto_checkpoint_mb << 20);
        // Arquiva o WAL (réplicas retomam e `minidb backup` faz incrementais).
        guard.set_wal_retention(cfg.wal_retention_mb << 20);
        if replica_of.is_some() {
            guard.set_read_only(true); // antes de aceitar clientes
        }
    }
    let rcfg = repl_config(cfg);
    if let Some(addr) = primary {
        let timeout = (cfg.sync_timeout_ms > 0).then(|| Duration::from_millis(cfg.sync_timeout_ms));
        replication::enable_feed(db, rcfg.max_feed_ops)?;
        replication::set_sync_replicas(db, cfg.sync_replicas, timeout)?;
        let (db, rcfg) = (db.clone(), rcfg.clone());
        std::thread::spawn(move || {
            if let Err(e) = replication::serve_primary_with(db, &addr, rcfg) {
                eprintln!("erro na replicação (primário): {e}");
            }
        });
    }
    if let Some(addr) = replica_of {
        let db = db.clone();
        std::thread::spawn(move || {
            let stop = Arc::new(AtomicBool::new(false));
            if let Err(e) = replication::run_replica_with(db, &addr, stop, &rcfg) {
                eprintln!("erro na replicação (réplica): {e}");
            }
        });
    }
    if cfg.maintenance_secs > 0 {
        let db = db.clone();
        let every = Duration::from_secs(cfg.maintenance_secs);
        std::thread::spawn(move || loop {
            std::thread::sleep(every);
            let result = db.write().and_then(|mut guard| {
                if guard.is_read_only() {
                    // Réplica: o primário decide purge/vacuum; só checkpoint local.
                    return guard.checkpoint().map(|_| ());
                }
                guard.maintain(0.25).map(|_| ())
            });
            if let Err(e) = result {
                eprintln!("manutenção: {e}");
            }
        });
    }
    Ok(())
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
            let db = SharedDb::new(open_cli_db(&path)?);
            {
                let guard = db.read()?;
                println!(
                    "minidb aberto em {}  (root={}, lsn={})",
                    path.display(),
                    guard.meta().root_page,
                    guard.stats().next_lsn
                );
            }
            println!("HELP para comandos. SQL e HTTP/TCP estão no README.");
            let mut session = db.session();
            let stdin = io::stdin();
            let mut stdout = io::stdout();
            for line in stdin.lock().lines() {
                let line = line.map_err(mini_db::Error::from)?;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match cmd::apply(&mut session, line) {
                    Ok(msg) if msg == "QUIT\n" => break,
                    Ok(msg) => {
                        print!("{msg}");
                        stdout.flush().ok();
                    }
                    Err(e) => eprintln!("erro: {e}"),
                }
            }
            drop(session);
            db.write()?.close()?;
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
            let db = SharedDb::new(open_cli_db(&path)?);
            let mut session = db.session();
            let result = cmd::apply(&mut session, &rest);
            drop(session);
            let closed = db.write().and_then(|mut guard| guard.close());
            print!("{}", result?);
            closed
        }
        "serve" => {
            let cfg = Config::load(args.first().map(PathBuf::from).as_deref())?;
            let path = args
                .first()
                .map(PathBuf::from)
                .unwrap_or_else(|| cfg.path.clone());
            let addr = args.get(1).cloned().unwrap_or_else(|| cfg.tcp_addr.clone());
            let db = SharedDb::new(open_configured_db(&path, &cfg)?);
            start_background(&db, &cfg, primary, replica_of)?;
            start_pg(&db, &cfg, &path);
            mini_db::server::serve_with(db, &addr, cfg.net())
        }
        "pg" | "postgres" => {
            let cfg = Config::load(args.first().map(PathBuf::from).as_deref())?;
            let path = args
                .first()
                .map(PathBuf::from)
                .unwrap_or_else(|| cfg.path.clone());
            let addr = args.get(1).cloned().unwrap_or_else(|| cfg.pg_addr.clone());
            let db = SharedDb::new(open_configured_db(&path, &cfg)?);
            start_background(&db, &cfg, primary, replica_of)?;
            let opts = cfg.net_with_tls(&path)?;
            mini_db::pg::serve(db, &addr, opts)
        }
        "cert" => {
            let mut args = args;
            let days = take_flag(&mut args, "--days")
                .map(|d| d.parse::<i64>())
                .transpose()
                .map_err(|_| mini_db::Error::Cli("--days espera número".into()))?
                .unwrap_or(365);
            let algo = match take_flag(&mut args, "--algo") {
                None => mini_db::pubkey::KeyAlgo::Ed25519,
                Some(a) => mini_db::pubkey::KeyAlgo::parse(&a).ok_or_else(|| {
                    mini_db::Error::Cli(
                        "--algo espera ed25519, p256, p384, rsa2048, rsa3072 ou rsa4096".into(),
                    )
                })?,
            };
            let (sub, dir, name) = match args.as_slice() {
                [s, d] => (s.as_str(), PathBuf::from(d), None),
                [s, d, n] => (s.as_str(), PathBuf::from(d), Some(n.as_str())),
                _ => usage(),
            };
            match (sub, name) {
                ("ca", n) => {
                    mini_db::x509::create_ca_with(&dir, n.unwrap_or("Mini-DB CA"), algo)?;
                    println!(
                        "CA criada: {0}/ca.crt (distribua aos clientes) e {0}/ca.key (guarde em segredo)",
                        dir.display()
                    );
                }
                ("server", Some(host)) => {
                    let (k, c) = mini_db::x509::issue_with(
                        &dir,
                        mini_db::x509::Kind::Server,
                        host,
                        days,
                        algo,
                    )?;
                    println!(
                        "servidor: tls_cert = \"{}\"  tls_key = \"{}\"  (clientes: sslrootcert={}/ca.crt sslmode=verify-full)",
                        c.display(), k.display(), dir.display()
                    );
                }
                ("client", Some(user)) => {
                    let (k, c) = mini_db::x509::issue_with(
                        &dir,
                        mini_db::x509::Kind::Client,
                        user,
                        days,
                        algo,
                    )?;
                    println!(
                        "cliente {user}: sslcert={} sslkey={}  (tls_ca = \"{}/ca.crt\" no servidor)",
                        c.display(), k.display(), dir.display()
                    );
                }
                _ => usage(),
            }
            Ok(())
        }
        "encrypt" | "decrypt" | "rekey" => {
            let path = PathBuf::from(args.first().map(|s| s.as_str()).unwrap_or("./data"));
            let cfg = Config::load(Some(&path))?;
            let current = cfg.passphrase.clone();
            let new = env::var("MINIDB_NEW_PASSPHRASE")
                .ok()
                .filter(|p| !p.is_empty());
            let (from, to) = match cmdn.as_str() {
                "encrypt" => (None, new.or(current)),
                "decrypt" => (current, None),
                _ => (current, new),
            };
            if to.is_none() && cmdn != "decrypt" {
                return Err(mini_db::Error::Cli(
                    "informe a senha em MINIDB_PASSPHRASE (ou MINIDB_NEW_PASSPHRASE para rekey)"
                        .into(),
                ));
            }
            println!(
                "{}",
                mini_db::encryption::convert(&path, from.as_deref(), to.as_deref())?
            );
            Ok(())
        }
        "backup" => {
            let (path, dest) = match args.as_slice() {
                [dest] => (PathBuf::from("./data"), PathBuf::from(dest)),
                [dir, dest, ..] => (PathBuf::from(dir), PathBuf::from(dest)),
                _ => usage(),
            };
            let cfg = Config::load(Some(&path))?;
            let mut db = open_configured_db(&path, &cfg)?;
            let report = backup::backup(&mut db, &dest)?;
            db.close()?;
            println!("{report}");
            Ok(())
        }
        "restore" => {
            let until_lsn = take_flag(&mut args, "--until-lsn").map(|v| v.parse::<u64>());
            let until_time = take_flag(&mut args, "--until-time");
            let [from, to] = args.as_slice() else { usage() };
            let mut target = backup::RestoreTarget::Latest;
            if let Some(lsn) = until_lsn {
                target = backup::RestoreTarget::Lsn(
                    lsn.map_err(|_| mini_db::Error::Cli("--until-lsn espera número".into()))?,
                );
            }
            if let Some(t) = until_time {
                target = backup::RestoreTarget::Time(backup::parse_time(&t)?);
            }
            let cfg = Config::load(Some(Path::new(to)))?;
            let report = backup::restore(
                Path::new(from),
                Path::new(to),
                target,
                cfg.passphrase.as_deref(),
            )?;
            println!("{report}");
            Ok(())
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
            let db = SharedDb::new(open_configured_db(&path, &cfg)?);
            start_background(&db, &cfg, primary, replica_of)?;
            start_pg(&db, &cfg, &path);
            let metrics = Arc::new(Metrics::new());
            // HTTPS só quando pedido (https = true): clientes HTTP simples esperam texto claro.
            let opts = if cfg.https {
                cfg.net_with_tls(&path)?
            } else {
                cfg.net()
            };
            http::serve_http_with(db, metrics, &addr, opts)
        }
        "export" => {
            let path = PathBuf::from(args.first().map(|s| s.as_str()).unwrap_or("./data"));
            let out = PathBuf::from(args.get(1).map(|s| s.as_str()).unwrap_or("backup.jsonl"));
            let mut db = open_cli_db(&path)?;
            let n = backup::export_jsonl(&mut db, &out)?;
            db.close()?;
            println!("export {n} rows -> {}", out.display());
            Ok(())
        }
        "import" => {
            let path = PathBuf::from(args.first().map(|s| s.as_str()).unwrap_or("./data"));
            let src = PathBuf::from(args.get(1).map(|s| s.as_str()).unwrap_or("backup.jsonl"));
            let mut db = open_cli_db(&path)?;
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
            | "WITH"
            | "DROP"
            | "ALTER"
            | "SHOW"
            | "DESCRIBE"
            | "MAINTAIN"
            | "ROLE"
            | "PROMOTE"
            | "?"
    )
}

fn open_configured_db(path: impl AsRef<Path>, cfg: &Config) -> mini_db::Result<Db> {
    Db::open_encrypted(path, cfg.pool_frames, cfg.fsync, cfg.passphrase.as_deref())
}

/// Abre o banco como os servidores (senha de `minidb.toml`/`MINIDB_PASSPHRASE`),
/// para os comandos locais também funcionarem com banco cifrado.
fn open_cli_db(path: &Path) -> mini_db::Result<Db> {
    let cfg = Config::load(Some(path))?;
    open_configured_db(path, &cfg)
}

/// Escuta o protocolo PostgreSQL em paralelo (`pg_addr` vazio desliga).
/// Os arquivos TLS ficam no diretório do banco aberto, não em `cfg.path`.
fn start_pg(db: &SharedDb, cfg: &Config, dir: &Path) {
    if cfg.pg_addr.is_empty() {
        return;
    }
    let opts = match cfg.net_with_tls(dir) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("TLS desligado: {e}");
            cfg.net()
        }
    };
    let (db, addr) = (db.clone(), cfg.pg_addr.clone());
    std::thread::spawn(move || {
        if let Err(e) = mini_db::pg::serve(db, &addr, opts) {
            eprintln!("erro no protocolo PostgreSQL: {e}");
        }
    });
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
