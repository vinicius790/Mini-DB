//! Configuração do processo: arquivo `minidb.toml` + variáveis de ambiente.
//!
//! Formato TOML reduzido (`chave = valor`). Env ganha do arquivo:
//! `MINIDB_PATH`, `MINIDB_HTTP`, `MINIDB_TCP`, `MINIDB_POOL`, `MINIDB_FSYNC`,
//! `MINIDB_TOKEN`, `MINIDB_MAX_CONNECTIONS`, `MINIDB_MAX_BODY`,
//! `MINIDB_REPL_SECRET`, `MINIDB_SYNC_REPLICAS`, `MINIDB_SYNC_TIMEOUT_MS`,
//! `MINIDB_WAL_RETENTION_MB`, `MINIDB_AUTO_CHECKPOINT_MB`,
//! `MINIDB_MAINTENANCE_SECS`.

use crate::error::{Error, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Config {
    pub path: PathBuf,
    pub pool_frames: usize,
    pub tcp_addr: String,
    pub http_addr: String,
    /// Protocolo PostgreSQL (`psql`, drivers); vazio desliga.
    pub pg_addr: String,
    /// Senha da criptografia em repouso (ou variável `MINIDB_PASSPHRASE`).
    pub passphrase: Option<String>,
    /// TLS no protocolo PostgreSQL (certificado autoassinado gerado em `tls.crt`).
    pub tls: bool,
    /// Servidor HTTP em HTTPS (mesmo certificado).
    pub https: bool,
    /// Cadeia/chave próprias (PEM Ed25519/ECDSA/RSA, relativas ao diretório de dados);
    /// padrão `tls.crt`/`tls.key` (gerados se não existirem).
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// CAs confiáveis para certificados de cliente (PEM).
    pub tls_ca: Option<PathBuf>,
    /// `off`, `optional` ou `required`; padrão `required` quando há `tls_ca`.
    pub tls_client_auth: Option<String>,
    pub fsync: bool,
    /// Token exigido por HTTP (`Authorization: Bearer`) e TCP (`AUTH`).
    pub token: Option<String>,
    pub max_connections: usize,
    pub max_body_bytes: usize,
    /// Segredo da replicação (autentica e cifra o canal).
    pub repl_secret: Option<String>,
    /// Réplicas que precisam confirmar cada commit (0 = assíncrona).
    pub sync_replicas: usize,
    /// Espera máxima por elas; 0 = espera sempre.
    pub sync_timeout_ms: u64,
    /// WAL arquivado para réplicas retomarem (MiB; 0 = não arquiva).
    pub wal_retention_mb: u64,
    /// Checkpoint automático quando o WAL passa disso (MiB; 0 = desliga).
    pub auto_checkpoint_mb: u64,
    /// Intervalo da manutenção automática (purge/vacuum/checkpoint; 0 = desliga).
    pub maintenance_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./data"),
            pool_frames: 1024,
            tcp_addr: "127.0.0.1:7432".into(),
            http_addr: "127.0.0.1:8080".into(),
            pg_addr: "127.0.0.1:5432".into(),
            passphrase: None,
            tls: true,
            https: false,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            tls_client_auth: None,
            fsync: true,
            token: None,
            max_connections: 1024,
            // Um valor máximo em hexadecimal cabe no corpo.
            max_body_bytes: 2 * crate::page::MAX_VALUE_LEN + (1 << 20),
            repl_secret: None,
            sync_replicas: 0,
            sync_timeout_ms: 0,
            wal_retention_mb: 256,
            auto_checkpoint_mb: 64,
            maintenance_secs: 60,
        }
    }
}

/// Limites e autenticação dos servidores HTTP e TCP.
#[derive(Clone, Debug)]
pub struct NetOptions {
    pub token: Option<String>,
    pub max_connections: usize,
    pub max_body_bytes: usize,
    /// Identidade TLS (certificado + chave): liga `sslmode=require` no
    /// protocolo PostgreSQL e HTTPS.
    pub tls: Option<std::sync::Arc<crate::tls::Identity>>,
}

impl Default for NetOptions {
    fn default() -> Self {
        Config::default().net()
    }
}

impl Config {
    pub fn net(&self) -> NetOptions {
        NetOptions {
            token: self.token.clone().filter(|t| !t.is_empty()),
            max_connections: self.max_connections.max(1),
            max_body_bytes: self.max_body_bytes.max(1024),
            tls: None,
        }
    }

    /// `NetOptions` com TLS carregado/gerado em `dir` (`tls = true` ou padrão).
    pub fn net_with_tls(&self, dir: &Path) -> Result<NetOptions> {
        let mut opts = self.net();
        if self.tls {
            let host = self
                .pg_addr
                .rsplit_once(':')
                .map(|(h, _)| h)
                .filter(|h| !h.is_empty() && *h != "0.0.0.0")
                .unwrap_or("localhost");
            let at = |p: &PathBuf| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    dir.join(p)
                }
            };
            let mut identity = match (&self.tls_cert, &self.tls_key) {
                (None, None) => crate::tls::Identity::create_or_load(dir, host)?,
                (cert, key) => crate::tls::Identity::load(
                    &at(key
                        .as_ref()
                        .ok_or_else(|| Error::Other("tls_cert exige tls_key".into()))?),
                    &at(cert
                        .as_ref()
                        .ok_or_else(|| Error::Other("tls_key exige tls_cert".into()))?),
                )?,
            };
            let ca_pem = match &self.tls_ca {
                Some(p) => Some(
                    std::fs::read_to_string(at(p))
                        .map_err(|e| Error::Other(format!("tls_ca {}: {e}", at(p).display())))?,
                ),
                None => None,
            };
            let mode = self
                .tls_client_auth
                .as_deref()
                .unwrap_or(if ca_pem.is_some() { "required" } else { "off" });
            identity = identity.with_client_auth(crate::tls::ClientAuth::from_config(
                mode,
                ca_pem.as_deref(),
            )?);
            opts.tls = Some(Arc::new(identity));
        }
        Ok(opts)
    }
}

impl Config {
    pub fn load(dir_hint: Option<&Path>) -> Result<Self> {
        let mut cfg = Config::default();
        if let Some(d) = dir_hint {
            cfg.path = d.to_path_buf();
        }
        let candidates = [cfg.path.join("minidb.toml"), PathBuf::from("minidb.toml")];
        for c in candidates {
            if c.exists() {
                parse_into(&fs::read_to_string(&c)?, &mut cfg);
                break;
            }
        }
        if let Ok(v) = env::var("MINIDB_PATH") {
            cfg.path = PathBuf::from(v);
        }
        if let Ok(v) = env::var("MINIDB_HTTP") {
            cfg.http_addr = v;
        }
        if let Ok(v) = env::var("MINIDB_TCP") {
            cfg.tcp_addr = v;
        }
        if let Ok(v) = env::var("MINIDB_PG") {
            cfg.pg_addr = v;
        }
        if let Ok(v) = env::var("MINIDB_HTTPS") {
            set_bool(&mut cfg.https, &v);
        }
        for (var, slot) in [
            ("MINIDB_TLS_CERT", &mut cfg.tls_cert),
            ("MINIDB_TLS_KEY", &mut cfg.tls_key),
            ("MINIDB_TLS_CA", &mut cfg.tls_ca),
        ] {
            if let Ok(v) = env::var(var) {
                *slot = Some(PathBuf::from(v)).filter(|p| !p.as_os_str().is_empty());
            }
        }
        if let Ok(v) = env::var("MINIDB_TLS_CLIENT_AUTH") {
            cfg.tls_client_auth = Some(v).filter(|v| !v.is_empty());
        }
        if let Ok(v) = env::var("MINIDB_TLS") {
            set_bool(&mut cfg.tls, &v);
        }
        if let Ok(v) = env::var("MINIDB_PASSPHRASE") {
            cfg.passphrase = Some(v).filter(|p| !p.is_empty());
        }
        if let Ok(v) = env::var("MINIDB_POOL") {
            if let Ok(n) = v.parse() {
                cfg.pool_frames = n;
            }
        }
        if let Ok(v) = env::var("MINIDB_FSYNC") {
            set_bool(&mut cfg.fsync, &v);
        }
        for (var, key) in [
            ("MINIDB_TOKEN", "token"),
            ("MINIDB_MAX_CONNECTIONS", "max_connections"),
            ("MINIDB_MAX_BODY", "max_body_bytes"),
            ("MINIDB_REPL_SECRET", "repl_secret"),
            ("MINIDB_SYNC_REPLICAS", "sync_replicas"),
            ("MINIDB_SYNC_TIMEOUT_MS", "sync_timeout_ms"),
            ("MINIDB_WAL_RETENTION_MB", "wal_retention_mb"),
            ("MINIDB_AUTO_CHECKPOINT_MB", "auto_checkpoint_mb"),
            ("MINIDB_MAINTENANCE_SECS", "maintenance_secs"),
        ] {
            if let Ok(v) = env::var(var) {
                set(&mut cfg, key, &v);
            }
        }
        Ok(cfg)
    }
}

fn parse_into(text: &str, cfg: &mut Config) {
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim();
        // `chave = "valor"  # comentário`: vale só o que está entre as aspas.
        let quoted = ['"', '\'']
            .into_iter()
            .find_map(|q| v.strip_prefix(q)?.split_once(q));
        let v = quoted.map_or(v.trim_matches('"').trim_matches('\''), |(inner, _)| inner);
        set(cfg, k.trim(), v);
    }
}

/// Booleanos de configuração (qualquer caixa): `1`/`true`/`yes`/`on` ligam e
/// `0`/`false`/`no`/`off` desligam; outro valor mantém o que já estava.
fn set_bool(slot: &mut bool, v: &str) {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => *slot = true,
        "0" | "false" | "no" | "off" => *slot = false,
        _ => {}
    }
}

fn set(cfg: &mut Config, key: &str, v: &str) {
    fn num<T: std::str::FromStr>(v: &str, slot: &mut T) {
        if let Ok(n) = v.parse() {
            *slot = n;
        }
    }
    match key {
        "path" | "data_dir" => cfg.path = PathBuf::from(v),
        "pool_frames" | "pool" => num(v, &mut cfg.pool_frames),
        "tcp_addr" | "tcp" => cfg.tcp_addr = v.to_string(),
        "http_addr" | "http" => cfg.http_addr = v.to_string(),
        "pg_addr" | "pg" | "postgres" => cfg.pg_addr = v.to_string(),
        "passphrase" => cfg.passphrase = Some(v.to_string()).filter(|p| !p.is_empty()),
        "tls" | "ssl" => set_bool(&mut cfg.tls, v),
        "https" => set_bool(&mut cfg.https, v),
        "tls_cert" => cfg.tls_cert = Some(PathBuf::from(v)).filter(|p| !p.as_os_str().is_empty()),
        "tls_key" => cfg.tls_key = Some(PathBuf::from(v)).filter(|p| !p.as_os_str().is_empty()),
        "tls_ca" => cfg.tls_ca = Some(PathBuf::from(v)).filter(|p| !p.as_os_str().is_empty()),
        "tls_client_auth" => cfg.tls_client_auth = Some(v.to_string()).filter(|v| !v.is_empty()),
        "fsync" => set_bool(&mut cfg.fsync, v),
        "token" => cfg.token = Some(v.to_string()).filter(|t| !t.is_empty()),
        "max_connections" => num(v, &mut cfg.max_connections),
        "max_body_bytes" => num(v, &mut cfg.max_body_bytes),
        "repl_secret" => cfg.repl_secret = Some(v.to_string()).filter(|t| !t.is_empty()),
        "sync_replicas" => num(v, &mut cfg.sync_replicas),
        "sync_timeout_ms" => num(v, &mut cfg.sync_timeout_ms),
        "wal_retention_mb" => num(v, &mut cfg.wal_retention_mb),
        "auto_checkpoint_mb" => num(v, &mut cfg.auto_checkpoint_mb),
        "maintenance_secs" => num(v, &mut cfg.maintenance_secs),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_value_drops_trailing_comment_and_unknown_bool_keeps_default() {
        let text = "tls_client_auth = \"required\"  # off\ntls = enabled\nfsync = off\n";
        let mut cfg = Config::default();
        parse_into(text, &mut cfg);
        assert_eq!(cfg.tls_client_auth.as_deref(), Some("required"));
        assert!(cfg.tls, "valor desconhecido mantém o padrão");
        assert!(!cfg.fsync);
    }
}
