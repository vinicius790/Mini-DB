//! Verificador de invariantes do arquivo `data.mdb`.
//!
//! Checagens:
//! - magic + checksum de toda página alocada
//! - folhas em ordem de chave e encadeamento `right_sibling` crescente
//! - internos apontam para page_ids < next_page_id
//! - nenhuma página órfã: toda página é da árvore, de uma cadeia de overflow
//!   ou da freelist (sem ciclos nem páginas compartilhadas)
//! - índice por valor e árvore de TTL coerentes com a árvore primária

use crate::btree::{overflow_chain, BTree, TreeId};
use crate::buffer::BufferPool;
use crate::error::{Error, Result};
use crate::page::{MetaInfo, PageKind};
use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    pub pages_ok: u32,
    pub leaves: u32,
    pub internals: u32,
    pub overflow_pages: u32,
    pub free_pages: u32,
    pub keys: u64,
    pub errors: Vec<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn verify_pool(pool: &BufferPool, meta: &MetaInfo) -> Result<VerifyReport> {
    let mut r = VerifyReport::default();
    if meta.root_page == 0 || meta.root_page >= meta.next_page_id {
        r.errors
            .push(format!("root_page inválido: {}", meta.root_page));
        return Ok(r);
    }
    let mut reachable = HashSet::from([MetaInfo::META_PAGE_ID]);
    collect_reachable(pool, meta, meta.root_page, &mut reachable)
        .map_err(|e| Error::Other(format!("árvore primária: {e}")))?;
    for (name, root) in [
        ("índice secundário", meta.index_root),
        ("TTL", meta.ttl_root),
    ] {
        if root == 0 {
            continue;
        }
        if root >= meta.next_page_id {
            r.errors.push(format!("raiz de {name} inválida: {root}"));
        } else if let Err(e) = collect_reachable(pool, meta, root, &mut reachable) {
            r.errors.push(format!("{name}: {e}"));
        }
    }
    // Freelist: só páginas Free, sem ciclo e sem colidir com páginas em uso.
    let mut free = HashSet::new();
    let mut id = meta.freelist_head;
    while id != 0 {
        if id >= meta.next_page_id || !free.insert(id) {
            r.errors.push(format!("freelist inválida em {id}"));
            break;
        }
        let page = pool.get_page(id)?;
        if page.kind() != PageKind::Free || reachable.contains(&id) {
            r.errors
                .push(format!("página {id} na freelist está em uso"));
            break;
        }
        id = page.right_sibling();
    }
    for id in 0..meta.next_page_id {
        match pool.get_page(id) {
            Ok(page) => {
                if let Err(e) = page.validate_header() {
                    r.errors.push(format!("page {id}: {e}"));
                }
                match page.kind() {
                    PageKind::Leaf => r.leaves += 1,
                    PageKind::Internal => r.internals += 1,
                    PageKind::Overflow => r.overflow_pages += 1,
                    PageKind::Free => r.free_pages += 1,
                    PageKind::Meta => {}
                }
                if page.kind() != PageKind::Free && !reachable.contains(&id) {
                    r.errors.push(format!("página alocada órfã: {id}"));
                }
                r.pages_ok += 1;
            }
            Err(e) => r.errors.push(format!("page {id}: {e}")),
        }
    }

    // Percorre folhas da esquerda para a direita e confere ordem (e lê cada
    // valor, o que valida overflow e compressão).
    let mut prev: Option<Vec<u8>> = None;
    match BTree::range_scan(pool, meta, &[0u8], None) {
        Ok(rows) => {
            r.keys = rows.len() as u64;
            for (k, _) in rows {
                if let Some(p) = &prev {
                    if k.as_slice() < p.as_slice() {
                        r.errors.push("chaves fora de ordem no range scan".into());
                        break;
                    }
                    if k.as_slice() == p.as_slice() {
                        r.errors.push("chave duplicada no range scan".into());
                        break;
                    }
                }
                prev = Some(k);
            }
        }
        Err(e) => r.errors.push(format!("scan: {e}")),
    }
    if r.ok() {
        check_secondary_trees(pool, meta, &mut r)?;
    }
    if !r.ok() {
        return Err(Error::Other(format!(
            "verify falhou: {}",
            r.errors.join("; ")
        )));
    }
    Ok(r)
}

fn collect_reachable(
    pool: &BufferPool,
    meta: &MetaInfo,
    root: u32,
    reachable: &mut HashSet<u32>,
) -> Result<()> {
    let mut pending = vec![root];
    while let Some(page_id) = pending.pop() {
        if page_id == 0 || page_id >= meta.next_page_id {
            return Err(Error::Other(format!("filho fora do arquivo: {page_id}")));
        }
        if !reachable.insert(page_id) {
            continue;
        }
        let page = pool.get_page(page_id)?;
        match page.kind() {
            PageKind::Leaf => {
                if page.right_sibling() != 0 {
                    pending.push(page.right_sibling());
                }
                for i in 0..page.n_slots() as usize {
                    let (_, v, overflow) = page.leaf_entry(i);
                    if !overflow {
                        continue;
                    }
                    for id in overflow_chain(pool, meta, v)? {
                        if !reachable.insert(id) {
                            return Err(Error::Other(format!(
                                "página de overflow {id} compartilhada"
                            )));
                        }
                    }
                }
            }
            PageKind::Internal => {
                if page.leftmost_child() != 0 {
                    pending.push(page.leftmost_child());
                }
                for index in 0..page.n_slots() as usize {
                    pending.push(page.internal_cell(index).1);
                }
            }
            PageKind::Meta | PageKind::Free | PageKind::Overflow => {
                return Err(Error::Other(format!(
                    "página {page_id} ({:?}) no meio da árvore",
                    page.kind()
                )));
            }
        }
    }
    Ok(())
}

/// Coerência entre árvores: toda entrada do índice aponta para uma chave com
/// aquele valor (e toda chave do usuário tem entrada), e toda chave com TTL
/// existe na árvore primária.
fn check_secondary_trees(pool: &BufferPool, meta: &MetaInfo, r: &mut VerifyReport) -> Result<()> {
    if meta.index_root != 0 {
        let mut entries = 0u64;
        for (raw, _) in BTree::range_in(pool, meta, TreeId::Secondary, &[0], None)? {
            entries += 1;
            let Some((hash, pk)) = crate::index::decode_index_key(&raw) else {
                r.errors.push("entrada de índice malformada".into());
                continue;
            };
            match BTree::get(pool, meta, pk)? {
                Some(value) if crate::index::value_hash(&value) == hash => {}
                _ => {
                    r.errors
                        .push("índice por valor aponta para linha divergente".into());
                    break;
                }
            }
        }
        let user_rows =
            BTree::range_scan(pool, meta, &[0], Some(&[crate::db::RESERVED_PREFIX]))?.len() as u64;
        if entries != user_rows {
            r.errors.push(format!(
                "índice por valor com {entries} entradas para {user_rows} chaves"
            ));
        }
    }
    if meta.ttl_root != 0 {
        for (key, at) in BTree::range_in(pool, meta, TreeId::Ttl, &[0], None)? {
            if at.len() != 8 || BTree::get(pool, meta, &key)?.is_none() {
                r.errors
                    .push("entrada de TTL sem chave correspondente".into());
                break;
            }
        }
    }
    Ok(())
}
