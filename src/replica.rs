//! Réplica física por shipping de WAL.
//!
//! Modelo: o primário já fez `append+sync` no `wal.log`. A réplica copia o
//! arquivo WAL + `data.mdb` *ou* só reabre o diretório após copiar o WAL
//! (recover refaz o redo). Não há consenso nem eleição — é ship síncrono
//! didático, o mesmo padrão de um warm standby.

use crate::db::Db;
use crate::error::Result;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn ship_snapshot(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<()> {
    let src = src.as_ref();
    let dst = dst.as_ref();
    let mut primary = Db::open(src)?;
    primary.checkpoint()?;
    primary.close()?;
    fs::create_dir_all(dst)?;
    let data = Db::data_path(src);
    let wal = Db::wal_path(src);
    if data.exists() {
        // Mapa de páginas (banco cifrado v3) pendente até o arquivo de dados chegar:
        // uma queda entre os dois é resolvida na abertura do destino.
        let map = crate::buffer::map_path(&data);
        let dst_data = Db::data_path(dst);
        if map.exists() {
            copy_and_publish(&map, &crate::buffer::pending_map_path(&dst_data))?;
        }
        copy_and_publish(&data, &dst_data)?;
        crate::buffer::install_page_map(&dst_data)?;
    }
    if wal.exists() {
        copy_and_publish(&wal, &Db::wal_path(dst))?;
    }
    Ok(())
}

fn copy_and_publish(src: &Path, dst: &Path) -> Result<()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let tmp = dst.with_extension(format!("snapshot.next-{}-{nonce}", std::process::id()));
    fs::copy(src, &tmp)?;
    #[cfg(windows)]
    if dst.exists() {
        fs::remove_file(dst)?;
    }
    fs::rename(tmp, dst)?;
    Ok(())
}

/// Abre o destino e deixa o recover aplicar o WAL copiado.
pub fn open_standby(dst: impl AsRef<Path>) -> Result<Db> {
    Db::open(dst)
}

/// Confere se as chaves do standby batem com uma amostra do primário.
pub fn compare_sample(primary: &mut Db, standby: &mut Db, keys: &[&[u8]]) -> Result<bool> {
    for k in keys {
        if primary.get(k)? != standby.get(k)? {
            return Ok(false);
        }
    }
    Ok(true)
}
