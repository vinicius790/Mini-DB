//! Índice secundário por valor sobre uma segunda B+ Tree.
//!
//! Chave do índice: `[sha256(valor)[..16]][chave primária]`, valor vazio.
//! O tamanho da entrada não depende do valor, então **qualquer** valor (até o
//! máximo de 64 MiB) é indexável. A busca faz um scan do prefixo de 16 bytes e
//! confere o valor real de cada candidata, então colisões nunca produzem
//! resultado errado.
//!
//! Permite `GET BY VALUE` e `WHERE value = ...` sem varrer a árvore primária.

use crate::btree::{BTree, TreeId};
use crate::buffer::BufferPool;
use crate::db::prefix_successor;
use crate::error::Result;
use crate::page::MetaInfo;

/// Bytes do hash do valor no começo de cada entrada.
pub const HASH_LEN: usize = 16;

pub fn value_hash(value: &[u8]) -> [u8; HASH_LEN] {
    let digest = crate::crypto::sha256(value);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest[..HASH_LEN]);
    out
}

pub fn encode_index_key(value: &[u8], pk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HASH_LEN + pk.len());
    out.extend_from_slice(&value_hash(value));
    out.extend_from_slice(pk);
    out
}

/// `(hash, chave primária)` de uma entrada.
pub fn decode_index_key(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    (raw.len() > HASH_LEN).then(|| raw.split_at(HASH_LEN))
}

pub fn upsert_value_index(
    pool: &mut BufferPool,
    meta: &mut MetaInfo,
    pk: &[u8],
    old_value: Option<&[u8]>,
    new_value: &[u8],
    lsn: u64,
) -> Result<()> {
    BTree::ensure_tree(pool, meta, TreeId::Secondary)?;
    if let Some(old) = old_value {
        if value_hash(old) == value_hash(new_value) {
            return Ok(());
        }
        BTree::delete_in(
            pool,
            meta,
            TreeId::Secondary,
            &encode_index_key(old, pk),
            lsn,
        )?;
    }
    BTree::insert_in(
        pool,
        meta,
        TreeId::Secondary,
        &encode_index_key(new_value, pk),
        &[],
        lsn,
    )
}

pub fn remove_value_index(
    pool: &mut BufferPool,
    meta: &mut MetaInfo,
    pk: &[u8],
    value: &[u8],
    lsn: u64,
) -> Result<bool> {
    if meta.index_root == 0 {
        return Ok(false);
    }
    BTree::delete_in(
        pool,
        meta,
        TreeId::Secondary,
        &encode_index_key(value, pk),
        lsn,
    )
}

/// Chaves primárias cujo valor gravado é exatamente `value`.
pub fn find_keys_by_value(
    pool: &BufferPool,
    meta: &MetaInfo,
    value: &[u8],
) -> Result<Vec<Vec<u8>>> {
    if meta.index_root == 0 {
        return Ok(Vec::new());
    }
    let start = value_hash(value);
    let end = prefix_successor(&start);
    let mut out = Vec::new();
    for (raw, _) in BTree::range_in(pool, meta, TreeId::Secondary, &start, end.as_deref())? {
        let Some((_, pk)) = decode_index_key(&raw) else {
            continue;
        };
        if BTree::get(pool, meta, pk)?.as_deref() == Some(value) {
            out.push(pk.to_vec());
        }
    }
    Ok(out)
}
