//! Catálogo de sistema persistido como chaves reservadas `__sys/*`.
//!
//! Mini-DB tem uma relação lógica `kv`. O catálogo registra versão de
//! formato, flags de índice e um relógio de schema — o suficiente para
//! um dump `SELECT * FROM __catalog` via API de comando.

use crate::db::Db;
use crate::error::Result;

pub const KEY_FORMAT: &[u8] = b"__sys/format";
pub const KEY_SCHEMA_EPOCH: &[u8] = b"__sys/schema_epoch";
pub const KEY_VALUE_INDEX: &[u8] = b"__sys/value_index";
pub const FORMAT_VERSION: &[u8] = b"minidb-1.1";

pub fn bootstrap(db: &mut Db) -> Result<()> {
    if db.get(KEY_FORMAT)?.is_none() {
        db.put(KEY_FORMAT, FORMAT_VERSION)?;
        db.put(KEY_SCHEMA_EPOCH, b"1")?;
        db.put(
            KEY_VALUE_INDEX,
            if db.stats().value_index { b"1" } else { b"0" },
        )?;
    }
    Ok(())
}

pub fn bump_schema(db: &mut Db) -> Result<u64> {
    let cur = db
        .get(KEY_SCHEMA_EPOCH)?
        .and_then(|v| String::from_utf8_lossy(&v).parse().ok())
        .unwrap_or(1u64);
    let next = cur + 1;
    db.put(KEY_SCHEMA_EPOCH, next.to_string().as_bytes())?;
    Ok(next)
}

pub fn format_dump(db: &mut Db) -> Result<String> {
    let fmt = db
        .get(KEY_FORMAT)?
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_else(|| "(ausente)".into());
    let epoch = db
        .get(KEY_SCHEMA_EPOCH)?
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_else(|| "0".into());
    Ok(format!(
        "format={fmt} schema_epoch={epoch} value_index={}\n",
        db.stats().value_index
    ))
}
