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
