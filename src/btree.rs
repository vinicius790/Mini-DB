//! B+ Tree persistente sobre o buffer pool.
//!
//! Inserção desce da raiz registrando o caminho de ancestrais; splits sobem por
//! esse caminho sem varrer a árvore. Exclusão é local à folha: folhas vazias
//! continuam no encadeamento (leituras e scans as atravessam) até o `VACUUM`,
//! que reconstrói a árvore compacta. Assim nenhum separador interno fica
//! inconsistente com o conteúdo das folhas.
use crate::buffer::BufferPool;
use crate::codec;
use crate::error::{Error, Result};
use crate::page::{
    MetaInfo, Page, PageKind, MAGIC, MAX_KEY_LEN, MAX_VALUE_LEN, META_FLAG_COMPRESSED_VALUES,
};
use std::collections::HashSet;

pub struct BTree;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeId {
    /// Chave do usuário → valor.
    Primary,
    /// Índice por valor: `[len][valor][chave]` → chave.
    Secondary,
    /// Expiração: chave → instante de expiração (ms desde a época, u64 BE).
    Ttl,
}

impl TreeId {
    fn root(self, meta: &MetaInfo) -> u32 {
        match self {
            Self::Primary => meta.root_page,
            Self::Secondary => meta.index_root,
            Self::Ttl => meta.ttl_root,
        }
    }

    fn set_root(self, meta: &mut MetaInfo, root: u32) {
        match self {
            Self::Primary => meta.root_page = root,
            Self::Secondary => meta.index_root = root,
            Self::Ttl => meta.ttl_root = root,
        }
    }
}

/// Resultado de um split que precisa ser publicado no pai.
/// Árvore primária de bancos 0.5+ guarda valores via [`codec`].
fn compressed(meta: &MetaInfo, tree: TreeId) -> bool {
    tree == TreeId::Primary && meta.flags & META_FLAG_COMPRESSED_VALUES != 0
}

fn load(meta: &MetaInfo, tree: TreeId, stored: Vec<u8>) -> Result<Vec<u8>> {
    if compressed(meta, tree) {
        codec::decode_value(&stored)
    } else {
        Ok(stored)
    }
}

fn load_rows(
    meta: &MetaInfo,
    tree: TreeId,
    rows: Vec<crate::db::Row>,
) -> Result<Vec<crate::db::Row>> {
    rows.into_iter()
        .map(|(k, v)| Ok((k, load(meta, tree, v)?)))
        .collect()
}

struct Split {
    left: u32,
    separator: Vec<u8>,
    right: u32,
}

impl BTree {
    /// Garante que a raiz primária seja uma página de árvore válida.
    pub fn ensure_root(pool: &mut BufferPool, meta: &mut MetaInfo) -> Result<()> {
        Self::ensure_tree(pool, meta, TreeId::Primary)
    }

    pub fn ensure_tree(pool: &mut BufferPool, meta: &mut MetaInfo, tree: TreeId) -> Result<()> {
        if tree != TreeId::Primary && tree.root(meta) == 0 {
            let id = pool.allocate_page(PageKind::Leaf, meta)?;
            pool.put_new_page(Page::zeroed(id, PageKind::Leaf))?;
            tree.set_root(meta, id);
            if tree == TreeId::Secondary {
                meta.flags |= crate::page::META_FLAG_VALUE_INDEX;
            }
            return Ok(());
        }
        let root_id = tree.root(meta);
        if root_id == 0 {
            return Err(Error::Other("raiz zero".into()));
        }
        let valid = {
            let page = pool.get_page(root_id)?;
            let ok =
                page.magic() == MAGIC && matches!(page.kind(), PageKind::Leaf | PageKind::Internal);
            pool.unpin(root_id);
            ok
        };
        if !valid {
            pool.put_new_page(Page::zeroed(root_id, PageKind::Leaf))?;
        }
        Ok(())
    }

    pub fn get(pool: &mut BufferPool, meta: &MetaInfo, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Self::get_in(pool, meta, TreeId::Primary, key)
    }

    pub fn get_in(
        pool: &mut BufferPool,
        meta: &MetaInfo,
        tree: TreeId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;
        if tree.root(meta) == 0 {
            return Ok(None);
        }
        let (leaf_id, _) = Self::descend(pool, tree.root(meta), key)?;
        let page = pool.get_page(leaf_id)?;
        let result = page
            .find_leaf_slot(key)
            .ok()
            .map(|i| page.leaf_cell(i).1.to_vec());
        pool.unpin(leaf_id);
        result.map(|v| load(meta, tree, v)).transpose()
    }

    pub fn range_scan(
        pool: &mut BufferPool,
        meta: &MetaInfo,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Self::range_in(pool, meta, TreeId::Primary, start, end)
    }

    /// Scan ordenado `[start, end)` pelo encadeamento de folhas.
    pub fn range_in(
        pool: &mut BufferPool,
        meta: &MetaInfo,
        tree: TreeId,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let rows = Self::range_stored(pool, meta, tree, start, end)?;
        load_rows(meta, tree, rows)
    }

    fn range_stored(
        pool: &mut BufferPool,
        meta: &MetaInfo,
        tree: TreeId,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        validate_key(start)?;
        if let Some(e) = end {
            validate_key(e)?;
        }
        if tree.root(meta) == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let (mut leaf_id, _) = Self::descend(pool, tree.root(meta), start)?;
        let mut first_leaf = true;
        let mut visited = HashSet::new();
        loop {
            if leaf_id == 0 || leaf_id >= meta.next_page_id || !visited.insert(leaf_id) {
                return Err(Error::Other("ciclo ou folha fora do arquivo".into()));
            }
            let page = pool.get_page(leaf_id)?;
            if page.kind() != PageKind::Leaf {
                pool.unpin(leaf_id);
                return Err(Error::Other(
                    "encadeamento aponta para página não folha".into(),
                ));
            }
            let from = if first_leaf {
                page.find_leaf_slot(start).unwrap_or_else(|i| i)
            } else {
                0
            };
            for i in from..page.n_slots() as usize {
                let (k, v) = page.leaf_cell(i);
                if end.is_some_and(|e| k >= e) {
                    pool.unpin(leaf_id);
                    return Ok(out);
                }
                out.push((k.to_vec(), v.to_vec()));
            }
            let sibling = page.right_sibling();
            pool.unpin(leaf_id);
            if sibling == 0 {
                return Ok(out);
            }
            first_leaf = false;
            leaf_id = sibling;
        }
    }

    /// Folha onde começa um scan a partir de `start` (0 se a árvore não existe).
    pub fn first_leaf(
        pool: &mut BufferPool,
        meta: &MetaInfo,
        tree: TreeId,
        start: &[u8],
    ) -> Result<u32> {
        if tree.root(meta) == 0 {
            return Ok(0);
        }
        Ok(Self::descend(pool, tree.root(meta), start)?.0)
    }

    /// Lê as linhas de uma folha com chave `>= from` e devolve o irmão direito.
    /// Base dos iteradores: memória proporcional a uma folha, não ao resultado.
    pub fn leaf_rows(
        pool: &mut BufferPool,
        meta: &MetaInfo,
        leaf_id: u32,
        from: &[u8],
    ) -> Result<(Vec<crate::db::Row>, u32)> {
        if leaf_id == 0 || leaf_id >= meta.next_page_id {
            return Err(Error::Other("folha fora do arquivo".into()));
        }
        let page = pool.get_page(leaf_id)?;
        if page.kind() != PageKind::Leaf {
            pool.unpin(leaf_id);
            return Err(Error::Other(
                "encadeamento aponta para página não folha".into(),
            ));
        }
        let first = page.find_leaf_slot(from).unwrap_or_else(|i| i);
        let rows = (first..page.n_slots() as usize)
            .map(|i| {
                let (k, v) = page.leaf_cell(i);
                (k.to_vec(), v.to_vec())
            })
            .collect();
        let sibling = page.right_sibling();
        pool.unpin(leaf_id);
        Ok((load_rows(meta, TreeId::Primary, rows)?, sibling))
    }

    pub fn insert(
        pool: &mut BufferPool,
        meta: &mut MetaInfo,
        key: &[u8],
        value: &[u8],
        lsn: u64,
    ) -> Result<()> {
        Self::insert_in(pool, meta, TreeId::Primary, key, value, lsn)
    }

    /// Upsert. Se a folha não comporta a célula, divide e propaga pelo caminho.
    pub fn insert_in(
        pool: &mut BufferPool,
        meta: &mut MetaInfo,
        tree: TreeId,
        key: &[u8],
        value: &[u8],
        lsn: u64,
    ) -> Result<()> {
        validate_key(key)?;
        validate_value(value)?;
        let encoded;
        let value = if compressed(meta, tree) {
            encoded = codec::encode_value(value);
            &encoded[..]
        } else {
            value
        };
        Self::ensure_tree(pool, meta, tree)?;
        let (leaf_id, path) = Self::descend(pool, tree.root(meta), key)?;
        let need_split = {
            let page = pool.get_page_mut(leaf_id)?;
            page.set_lsn(lsn);
            let index = match page.find_leaf_slot(key) {
                Ok(i) => {
                    page.remove_slot(i);
                    i
                }
                Err(i) => i,
            };
            let outcome = match page.insert_leaf_cell(index, key, value) {
                Ok(()) => Ok(false),
                Err(Error::PageFull) => Ok(true),
                Err(e) => Err(e),
            };
            pool.unpin(leaf_id);
            outcome?
        };
        if !need_split {
            return Ok(());
        }
        let split = Self::split_leaf(pool, meta, leaf_id, (key, value), lsn)?;
        Self::insert_into_parent(pool, meta, tree, path, split, lsn)
    }

    pub fn delete(
        pool: &mut BufferPool,
        meta: &mut MetaInfo,
        key: &[u8],
        lsn: u64,
    ) -> Result<bool> {
        Self::delete_in(pool, meta, TreeId::Primary, key, lsn)
    }

    /// Remove a chave da folha. Não altera nós internos: a folha pode ficar
    /// vazia e continua válida no encadeamento até o próximo `VACUUM`.
    pub fn delete_in(
        pool: &mut BufferPool,
        meta: &mut MetaInfo,
        tree: TreeId,
        key: &[u8],
        lsn: u64,
    ) -> Result<bool> {
        validate_key(key)?;
        if tree.root(meta) == 0 {
            return Ok(false);
        }
        let (leaf_id, _) = Self::descend(pool, tree.root(meta), key)?;
        let page = pool.get_page_mut(leaf_id)?;
        let removed = match page.find_leaf_slot(key) {
            Ok(i) => {
                page.remove_slot(i);
                let compacted = page.compact_leaf();
                page.set_lsn(lsn);
                page.write_checksum();
                compacted.map(|()| true)
            }
            Err(_) => Ok(false),
        };
        pool.unpin(leaf_id);
        removed
    }

    /// Divide a folha cheia incluindo o par pendente; devolve o separador.
    fn split_leaf(
        pool: &mut BufferPool,
        meta: &mut MetaInfo,
        leaf_id: u32,
        (key, value): (&[u8], &[u8]),
        lsn: u64,
    ) -> Result<Split> {
        let (mut pairs, old_right) = {
            let page = pool.get_page(leaf_id)?;
            let pairs: Vec<_> = (0..page.n_slots() as usize)
                .map(|i| {
                    let (k, v) = page.leaf_cell(i);
                    (k.to_vec(), v.to_vec())
                })
                .collect();
            let right = page.right_sibling();
            pool.unpin(leaf_id);
            (pairs, right)
        };
        match pairs.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
            Ok(i) => pairs[i].1 = value.to_vec(),
            Err(i) => pairs.insert(i, (key.to_vec(), value.to_vec())),
        }
        let right_pairs = pairs.split_off(pairs.len() / 2);
        let separator = right_pairs[0].0.clone();
        let right_id = pool.allocate_page(PageKind::Leaf, meta)?;
        pool.put_new_page(Page::rebuild_leaf(leaf_id, &pairs, right_id, lsn)?)?;
        pool.put_new_page(Page::rebuild_leaf(right_id, &right_pairs, old_right, lsn)?)?;
        Ok(Split {
            left: leaf_id,
            separator,
            right: right_id,
        })
    }

    /// Publica o split no pai (último item do caminho), dividindo internos
    /// cheios e criando nova raiz quando o caminho se esgota.
    fn insert_into_parent(
        pool: &mut BufferPool,
        meta: &mut MetaInfo,
        tree: TreeId,
        mut path: Vec<u32>,
        mut split: Split,
        lsn: u64,
    ) -> Result<()> {
        loop {
            let Some(parent_id) = path.pop() else {
                let root_id = pool.allocate_page(PageKind::Internal, meta)?;
                let entries = [(split.separator, split.right)];
                pool.put_new_page(Page::rebuild_internal(root_id, split.left, &entries, lsn)?)?;
                tree.set_root(meta, root_id);
                return Ok(());
            };
            let full = {
                let page = pool.get_page_mut(parent_id)?;
                page.set_lsn(lsn);
                let idx = Self::child_position(page, split.left);
                let res = match page.insert_internal_cell(idx, &split.separator, split.right) {
                    Ok(()) => Ok(false),
                    Err(Error::PageFull) => Ok(true),
                    Err(e) => Err(e),
                };
                pool.unpin(parent_id);
                res?
            };
            if !full {
                return Ok(());
            }
            let (leftmost, mut entries) = {
                let page = pool.get_page(parent_id)?;
                let idx = Self::child_position(page, split.left);
                let mut entries: Vec<_> = (0..page.n_slots() as usize)
                    .map(|i| {
                        let (k, c) = page.internal_cell(i);
                        (k.to_vec(), c)
                    })
                    .collect();
                let leftmost = page.leftmost_child();
                pool.unpin(parent_id);
                entries.insert(idx, (split.separator, split.right));
                (leftmost, entries)
            };
            // entries[mid] sobe para o avô; seu filho vira o leftmost da direita.
            let right_entries = entries.split_off(entries.len() / 2 + 1);
            let (promoted, right_leftmost) = entries.pop().expect("nó interno cheio");
            let right_id = pool.allocate_page(PageKind::Internal, meta)?;
            pool.put_new_page(Page::rebuild_internal(parent_id, leftmost, &entries, lsn)?)?;
            pool.put_new_page(Page::rebuild_internal(
                right_id,
                right_leftmost,
                &right_entries,
                lsn,
            )?)?;
            split = Split {
                left: parent_id,
                separator: promoted,
                right: right_id,
            };
        }
    }

    /// Slot onde entra o novo filho à direita de `left_id`.
    fn child_position(page: &Page, left_id: u32) -> usize {
        if page.leftmost_child() == left_id {
            return 0;
        }
        let n = page.n_slots() as usize;
        (0..n)
            .find(|&i| page.internal_cell(i).1 == left_id)
            .map_or(n, |i| i + 1)
    }

    /// Desce até a folha responsável por `key`; devolve também os ancestrais.
    fn descend(pool: &mut BufferPool, root: u32, key: &[u8]) -> Result<(u32, Vec<u32>)> {
        let mut path = Vec::new();
        let mut current = root;
        loop {
            let page = pool.get_page(current)?;
            let next = match page.kind() {
                PageKind::Leaf => None,
                PageKind::Internal => Some(page.child_for_key(key)),
                _ => {
                    pool.unpin(current);
                    return Err(Error::CorruptPage(current));
                }
            };
            pool.unpin(current);
            let Some(child) = next else {
                return Ok((current, path));
            };
            if child == 0 || path.len() >= 64 {
                return Err(Error::CorruptPage(current));
            }
            path.push(current);
            current = child;
        }
    }
}

pub(crate) fn validate_key(key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(Error::InvalidInput("chave vazia não permitida".into()));
    }
    if key.len() > MAX_KEY_LEN {
        return Err(Error::KeyTooLarge(key.len(), MAX_KEY_LEN));
    }
    Ok(())
}

pub(crate) fn validate_value(value: &[u8]) -> Result<()> {
    if value.len() > MAX_VALUE_LEN {
        return Err(Error::ValueTooLarge(value.len(), MAX_VALUE_LEN));
    }
    Ok(())
}
