//! Lossless JSONL backup for arbitrary byte keys and values; legacy text import.
use crate::db::Db;
use crate::error::{Error, Result};
use crate::json::Json;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return Err(Error::Other("invalid backup hex".into()));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| Error::Other("invalid backup hex".into()))
        })
        .collect()
}

pub fn export_jsonl(db: &mut Db, dest: &Path) -> Result<usize> {
    // Backup completo: inclui o espaço reservado (tabelas SQL e catálogo).
    let rows: Vec<_> = db.iter_raw(&[0], None)?.collect::<Result<_>>()?;
    let mut file = BufWriter::new(File::create(dest)?);
    for (key, value) in &rows {
        let line = Json::obj()
            .put("format", Json::String("minidb-jsonl/v1".into()))
            .put("key_hex", Json::String(hex(key)))
            .put("value_hex", Json::String(hex(value)))
            .stringify();
        writeln!(file, "{line}")?;
    }
    file.flush()?;
    file.get_ref().sync_all()?;
    Ok(rows.len())
}

pub fn import_jsonl(db: &mut Db, src: &Path) -> Result<usize> {
    let reader = BufReader::new(File::open(src)?);
    if db.is_read_only() {
        return Err(Error::ReadOnly);
    }
    db.begin()?;
    let load = (|| {
        let mut count = 0;
        for (number, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let row = Json::parse(&line)?;
            let (key, value) = if row.get("key_hex").is_some() || row.get("value_hex").is_some() {
                if row.get("format").and_then(Json::as_str) != Some("minidb-jsonl/v1") {
                    return Err(Error::Other(format!(
                        "unsupported backup format at line {}",
                        number + 1
                    )));
                }
                let key = row
                    .get("key_hex")
                    .and_then(Json::as_str)
                    .ok_or_else(|| Error::Other("missing key_hex".into()))?;
                let value = row
                    .get("value_hex")
                    .and_then(Json::as_str)
                    .ok_or_else(|| Error::Other("missing value_hex".into()))?;
                (unhex(key)?, unhex(value)?)
            } else {
                let key = row
                    .get("key")
                    .and_then(Json::as_str)
                    .ok_or_else(|| Error::Other("missing legacy key".into()))?;
                let value = row
                    .get("value")
                    .and_then(Json::as_str)
                    .ok_or_else(|| Error::Other("missing legacy value".into()))?;
                (key.as_bytes().to_vec(), value.as_bytes().to_vec())
            };
            db.write_internal(vec![crate::db::Op::Put { key, value }])?;
            count += 1;
        }
        Ok(count)
    })();
    match load {
        Ok(count) => {
            db.commit()?;
            Ok(count)
        }
        Err(error) => {
            db.rollback()?;
            Err(error)
        }
    }
}

// ---------------------------------------------------------------------------
// Backup físico (completo + incremental) e restauração até um ponto no tempo
// ---------------------------------------------------------------------------
//
// Layout de `destino/`:
//   MANIFEST            {"lsn": checkpoint do backup completo, "created": segundos Unix}
//   base/data.mdb       imagem consistente das páginas (após checkpoint)
//   base/data.mdb.key   arquivo de chave (banco criptografado; a senha continua necessária)
//   wal/*.wal           segmentos do WAL desde o backup completo (incrementais)
//
// `backup()` num destino vazio faz o completo; num destino já iniciado copia os
// segmentos arquivados novos e uma cópia do WAL atual. `restore()` monta o
// diretório do banco a partir da base + segmentos (até o LSN/instante pedido)
// e deixa a recuperação normal do `Db::open` aplicar só as transações
// confirmadas.

use crate::wal::{Wal, WalRecord};
use std::fs;
use std::path::PathBuf;

/// Até onde restaurar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreTarget {
    Latest,
    /// Inclui todo registro com LSN ≤ este.
    Lsn(u64),
    /// Inclui transações confirmadas até este instante (ms Unix).
    Time(u64),
}

fn manifest_path(dest: &Path) -> PathBuf {
    dest.join("MANIFEST")
}

fn read_manifest(dest: &Path) -> Result<Option<(u64, u64)>> {
    let Ok(text) = fs::read_to_string(manifest_path(dest)) else {
        return Ok(None);
    };
    let j = Json::parse(&text)?;
    let num = |k: &str| match j.get(k) {
        Some(Json::Number(n)) => Some(*n as u64),
        _ => None,
    };
    Ok(Some((
        num("lsn").ok_or_else(|| Error::Other("MANIFEST sem lsn".into()))?,
        num("created").unwrap_or(0),
    )))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Completo (destino vazio) ou incremental (destino com MANIFEST). Liga o
/// arquivamento do WAL no banco se estava desligado, para que os próximos
/// incrementais encontrem os segmentos.
pub fn backup(db: &mut Db, dest: &Path) -> Result<String> {
    if db.wal_retention() == 0 {
        db.set_wal_retention(256 << 20);
    }
    fs::create_dir_all(dest.join("wal"))?;
    let dir = db.dir().to_path_buf();
    let full = read_manifest(dest)?.is_none();
    if full {
        // Checkpoint: data.mdb passa a conter tudo até checkpoint_lsn.
        db.checkpoint()?;
        fs::create_dir_all(dest.join("base"))?;
        fs::copy(Db::data_path(&dir), dest.join("base/data.mdb"))?;
        let key = crate::encryption::keyfile_path(&dir);
        if key.exists() {
            fs::copy(&key, dest.join("base/data.mdb.key"))?;
        }
        let lsn = db.meta().checkpoint_lsn;
        let manifest = Json::obj()
            .put("lsn", Json::Number(lsn as i64))
            .put("created", Json::Number(now_secs() as i64))
            .put("encrypted", Json::Bool(key.exists()))
            .stringify();
        fs::write(manifest_path(dest), manifest)?;
        return Ok(format!("backup completo lsn={lsn} -> {}", dest.display()));
    }
    let (base_lsn, _) = read_manifest(dest)?.expect("manifest");
    // Segmentos arquivados ainda não copiados (nome = <primeiro>-<último>.wal).
    let mut copied = 0;
    if let Ok(entries) = fs::read_dir(Db::archive_dir(&dir)) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some((_, last)) = name.strip_suffix(".wal").and_then(|n| n.split_once('-')) else {
                continue;
            };
            if last.parse::<u64>().is_ok_and(|l| l > base_lsn)
                && !dest.join("wal").join(name).exists()
            {
                fs::copy(&path, dest.join("wal").join(name))?;
                copied += 1;
            }
        }
    }
    // WAL atual: cópia nomeada pela faixa que contém (substitui a anterior).
    db.sync_wal()?;
    let (_, records) = Wal::read_all_with(Db::wal_path(&dir), db.cipher().as_deref())?;
    if let (Some(first), Some(last)) = (records.first(), records.last()) {
        if last.lsn() > base_lsn {
            for old in fs::read_dir(dest.join("wal"))?.filter_map(|e| e.ok()) {
                if old.file_name().to_string_lossy().starts_with("current-") {
                    fs::remove_file(old.path())?;
                }
            }
            let name = format!("current-{:020}-{:020}.wal", first.lsn(), last.lsn());
            fs::copy(Db::wal_path(&dir), dest.join("wal").join(name))?;
            copied += 1;
        }
    }
    Ok(format!(
        "backup incremental base={base_lsn} segmentos={copied} -> {}",
        dest.display()
    ))
}

/// `AAAA-MM-DD HH:MM[:SS]` (UTC) ou segundos Unix → ms Unix.
pub fn parse_time(text: &str) -> Result<u64> {
    let bad = || Error::Cli(format!("instante inválido: {text}"));
    if let Ok(secs) = text.trim().parse::<u64>() {
        return secs.checked_mul(1000).ok_or_else(bad);
    }
    crate::rel::parse_datetime(&crate::rel::Value::Text(text.to_string()))
        .and_then(|secs| u64::try_from(secs).ok())
        .and_then(|secs| secs.checked_mul(1000))
        .ok_or_else(bad)
}

/// Monta `dir` (vazio ou inexistente) a partir do backup em `from`. Um
/// backup de banco criptografado exige a senha (`passphrase`).
pub fn restore(
    from: &Path,
    dir: &Path,
    target: RestoreTarget,
    passphrase: Option<&str>,
) -> Result<String> {
    let (base_lsn, _) =
        read_manifest(from)?.ok_or_else(|| Error::Other("MANIFEST não encontrado".into()))?;
    if fs::read_dir(dir)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
    {
        return Err(Error::Other(format!(
            "destino {} não está vazio",
            dir.display()
        )));
    }
    fs::create_dir_all(dir)?;
    fs::copy(from.join("base/data.mdb"), Db::data_path(dir))?;
    let key = from.join("base/data.mdb.key");
    let encrypted = key.exists();
    if encrypted {
        fs::copy(&key, crate::encryption::keyfile_path(dir))?;
    }
    let cipher = crate::encryption::open_key(dir, passphrase, true)?.map(std::sync::Arc::new);
    // Segmentos em ordem de LSN; registros com LSN ≤ base já estão na base.
    let mut segments: Vec<PathBuf> = fs::read_dir(from.join("wal"))
        .map(|d| d.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default();
    segments.sort_by_key(|p| {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let range = name.trim_start_matches("current-");
        range
            .split('-')
            .next()
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(u64::MAX)
    });
    let mut out = Wal::open_with(Db::wal_path(dir), base_lsn + 1, cipher.clone())?;
    let mut applied = 0u64;
    let mut last_lsn = base_lsn;
    let mut clock = 0u64;
    // Primeira lacuna de LSN entre os segmentos (segmento apagado pela retenção).
    let mut gap: Option<(u64, u64)> = None;
    'segments: for seg in segments {
        let (_, records) = Wal::read_all_with(&seg, cipher.as_deref())?;
        for rec in records {
            let lsn = rec.lsn();
            // Checkpoints descrevem o layout do arquivo original, não o restaurado.
            if lsn <= last_lsn || matches!(rec, WalRecord::Checkpoint { .. }) {
                continue;
            }
            if lsn != last_lsn + 1 && gap.is_none() {
                gap = Some((last_lsn + 1, lsn - 1));
            }
            if let WalRecord::Time { unix_ms, .. } = &rec {
                clock = *unix_ms;
            }
            let stop = match target {
                RestoreTarget::Latest => false,
                RestoreTarget::Lsn(max) => lsn > max,
                RestoreTarget::Time(until) => clock > until,
            };
            if stop {
                break 'segments;
            }
            out.append(rec)?;
            applied += 1;
            last_lsn = lsn;
        }
    }
    out.sync()?;
    drop(out);
    // Abre uma vez: a recuperação aplica as transações confirmadas (e fecha
    // uma transação interrompida pelo corte no instante pedido).
    drop(cipher);
    let mut db = Db::open_encrypted(dir, 64, true, passphrase)?;
    db.close()?;
    let warning = match gap {
        Some((from, to)) => {
            format!(" AVISO: faltam os LSNs {from}..{to} (segmento apagado?); backup incompleto")
        }
        None => String::new(),
    };
    Ok(format!(
        "restaurado em {} base={base_lsn} registros={applied} até lsn={last_lsn}{warning}",
        dir.display()
    ))
}
