//! Configuração do processo: arquivo `minidb.toml` + variáveis de ambiente.
//!
//! Formato TOML reduzido (`chave = valor`). Env ganha do arquivo:
//! `MINIDB_PATH`, `MINIDB_HTTP`, `MINIDB_TCP`, `MINIDB_POOL`, `MINIDB_FSYNC`.

use crate::error::Result;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
    pub path: PathBuf,
    pub pool_frames: usize,
    pub tcp_addr: String,
    pub http_addr: String,
    pub fsync: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            path: PathBuf::from("./data"),
            pool_frames: 64,
            tcp_addr: "127.0.0.1:7432".into(),
            http_addr: "127.0.0.1:8080".into(),
            fsync: true,
        }
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
        if let Ok(v) = env::var("MINIDB_POOL") {
            if let Ok(n) = v.parse() {
                cfg.pool_frames = n;
            }
        }
        if let Ok(v) = env::var("MINIDB_FSYNC") {
            cfg.fsync = v == "1" || v.eq_ignore_ascii_case("true");
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
        let k = k.trim();
        let v = v.trim().trim_matches('"').trim_matches('\'');
        match k {
            "path" | "data_dir" => cfg.path = PathBuf::from(v),
            "pool_frames" | "pool" => {
                if let Ok(n) = v.parse() {
                    cfg.pool_frames = n;
                }
            }
            "tcp_addr" | "tcp" => cfg.tcp_addr = v.to_string(),
            "http_addr" | "http" => cfg.http_addr = v.to_string(),
            "fsync" => cfg.fsync = v == "true" || v == "1",
            _ => {}
        }
    }
}
