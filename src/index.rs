//! Índice secundário por valor sobre uma segunda B+ Tree.
//!
//! Chave do índice: `[val_len:u16][value][primary_key]`
//! Valor do índice: primary key (cópia).
//!
//! Permite `GET BY VALUE` e `WHERE value = ...` sem varrer a árvore primária.

use crate::btree::{BTree, TreeId};
use crate::buffer::BufferPool;
use crate::error::Result;
use crate::page::MetaInfo;

pub fn encode_index_key(value: &[u8], pk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len() + pk.len());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    out.extend_from_slice(pk);
    out
}

pub fn decode_index_key(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    if raw.len() < 2 {
        return None;
    }
    let vlen = u16::from_le_bytes(raw[0..2].try_into().ok()?) as usize;
    if raw.len() < 2 + vlen {
        return None;
    }
    Some((&raw[2..2 + vlen], &raw[2 + vlen..]))
}

pub fn prefix_for_value(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    out
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
        if old != new_value {
            let old_k = encode_index_key(old, pk);
            let _ = BTree::delete_in(pool, meta, TreeId::Secondary, &old_k, lsn)?;
        } else {
            return Ok(());
        }
    }
    let new_k = encode_index_key(new_value, pk);
    BTree::insert_in(pool, meta, TreeId::Secondary, &new_k, pk, lsn)
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
    let k = encode_index_key(value, pk);
    BTree::delete_in(pool, meta, TreeId::Secondary, &k, lsn)
}

pub fn find_keys_by_value(
    pool: &mut BufferPool,
    meta: &MetaInfo,
    value: &[u8],
) -> Result<Vec<Vec<u8>>> {
    if meta.index_root == 0 {
        return Ok(Vec::new());
    }
    let start = prefix_for_value(value);
    let rows = BTree::range_in(pool, meta, TreeId::Secondary, &start, None)?;
    let mut out = Vec::new();
    for (k, v) in rows {
        match decode_index_key(&k) {
            Some((val, pk)) if val == value => {
                if v.is_empty() {
                    out.push(pk.to_vec());
                } else {
                    out.push(v);
                }
            }
            Some((val, _)) if val != value => break,
            _ => continue,
        }
    }
    Ok(out)
}
