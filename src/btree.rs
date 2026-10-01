//! B+ Tree persistente sobre o buffer pool.
//!
//! Inserção desce da raiz registrando o caminho de ancestrais; splits sobem por
//! esse caminho sem varrer a árvore e dividem por **bytes** (não por contagem):
//! como nenhuma célula passa de [`MAX_CELL`] (1/3 da página), as duas metades
//! sempre cabem. Valores que não cabem na célula vão para uma cadeia de
//! páginas de overflow; a célula guarda só `[total:u32][primeira:u32]`.
//!
//! Exclusão é local à folha: folhas vazias continuam no encadeamento até o
//! `VACUUM`. Páginas de overflow liberadas voltam à freelist na hora.
//!
//! Leituras recebem `&BufferPool` e podem rodar em várias threads ao mesmo
//! tempo; escritas recebem `&mut BufferPool`.
use crate::buffer::BufferPool;
use crate::codec;
use crate::db::Row;
use crate::error::{Error, Result};
use crate::page::{
    LeafEntry, MetaInfo, Page, PageKind, MAGIC, MAX_CELL, MAX_KEY_LEN, MAX_TREE_KEY, MAX_VALUE_LEN,
    META_FLAG_COMPRESSED_VALUES, OVERFLOW_CAPACITY, OVERFLOW_POINTER_LEN, PAGE_HEADER_SIZE,
    PAGE_SIZE,
};
use std::collections::HashSet;

pub struct BTree;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeId {
    /// Chave do usuário → valor.
    Primary,
    /// Índice por valor: `[hash do valor][chave]` → chave.
    Secondary,
    /// Expiração: chave → instante de expiração (ms desde a época, u64 BE).
    Ttl,
}

impl TreeId {
    pub(crate) fn root(self, meta: &MetaInfo) -> u32 {
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

/// Árvore primária de bancos 0.5+ guarda valores via [`codec`].
fn compressed(meta: &MetaInfo, tree: TreeId) -> bool {
    tree == TreeId::Primary && meta.flags & META_FLAG_COMPRESSED_VALUES != 0
}

/// Espaço útil de uma página (sem o cabeçalho).
const USABLE: usize = PAGE_SIZE - PAGE_HEADER_SIZE;

/// Resultado de um split que precisa ser publicado no pai.
struct Split {
    left: u32,
    separator: Vec<u8>,
    right: u32,
}

fn corrupt(id: u32) -> Error {
    Error::CorruptPage(id)
}

/// Páginas da cadeia de overflow apontada por `ptr`, validando tamanho e ciclos.
pub fn overflow_chain(pool: &BufferPool, meta: &MetaInfo, ptr: &[u8]) -> Result<Vec<u32>> {
    let (total, first) = parse_pointer(ptr)?;
    let expected = total.div_ceil(OVERFLOW_CAPACITY).max(1);
    let mut ids = Vec::with_capacity(expected);
    let mut id = first;
    let mut remaining = total;
    while remaining > 0 {
        if id == 0 || id >= meta.next_page_id || ids.len() >= expected {
            return Err(corrupt(id));
        }
        let page = pool.get_page(id)?;
        let data = page.overflow_data();
        if page.kind() != PageKind::Overflow || data.is_empty() || data.len() > remaining {
            return Err(corrupt(id));
        }
        remaining -= data.len();
        ids.push(id);
        id = page.right_sibling();
    }
    Ok(ids)
}

fn parse_pointer(ptr: &[u8]) -> Result<(usize, u32)> {
    if ptr.len() != OVERFLOW_POINTER_LEN {
        return Err(Error::Other("ponteiro de overflow inválido".into()));
    }
    let total = u32::from_le_bytes(ptr[0..4].try_into().expect("4")) as usize;
    let first = u32::from_le_bytes(ptr[4..8].try_into().expect("4"));
    // +16: cabeçalho do codec sobre um valor máximo.
    if total == 0 || total > MAX_VALUE_LEN + 16 {
        return Err(Error::Other("tamanho de overflow inválido".into()));
    }
    Ok((total, first))
}

fn read_overflow(pool: &BufferPool, meta: &MetaInfo, ptr: &[u8]) -> Result<Vec<u8>> {
    let (total, _) = parse_pointer(ptr)?;
    let mut out = Vec::with_capacity(total);
    for id in overflow_chain(pool, meta, ptr)? {
        out.extend_from_slice(pool.get_page(id)?.overflow_data());
    }
    Ok(out)
}

fn write_overflow(
    pool: &mut BufferPool,
    meta: &mut MetaInfo,
    stored: &[u8],
    lsn: u64,
) -> Result<Vec<u8>> {
    let chunks: Vec<&[u8]> = stored.chunks(OVERFLOW_CAPACITY).collect();
    let ids = chunks
        .iter()
        .map(|_| pool.allocate_page(PageKind::Overflow, meta))
        .collect::<Result<Vec<_>>>()?;
    for (i, chunk) in chunks.iter().enumerate() {
        let next = ids.get(i + 1).copied().unwrap_or(0);
        pool.put_new_page(Page::overflow(ids[i], next, chunk, lsn))?;
    }
    let mut ptr = (stored.len() as u32).to_le_bytes().to_vec();
    ptr.extend_from_slice(&ids[0].to_le_bytes());
    Ok(ptr)
}

fn free_overflow(pool: &mut BufferPool, meta: &mut MetaInfo, ptr: &[u8]) -> Result<()> {
    for id in overflow_chain(pool, meta, ptr)? {
        pool.free_page(id, meta)?;
    }
    Ok(())
}

/// Valor lógico de uma célula (resolve overflow e compressão).
fn load_cell(
    pool: &BufferPool,
    meta: &MetaInfo,
    tree: TreeId,
    val: &[u8],
    overflow: bool,
) -> Result<Vec<u8>> {
    let stored = if overflow {
        read_overflow(pool, meta, val)?
    } else {
        val.to_vec()
    };
    if compressed(meta, tree) {
        codec::decode_value(&stored)
    } else {
        Ok(stored)
    }
}

/// Índice que divide `sizes` em duas metades de bytes equilibradas, ambas
/// não vazias. Com células de no máximo 1/3 da página, as duas cabem.
fn split_point(sizes: &[usize]) -> usize {
    let total: usize = sizes.iter().sum();
    let mut acc = 0;
    for (i, s) in sizes.iter().enumerate() {
        acc += s;
        if acc * 2 >= total {
            return (i + 1).clamp(1, sizes.len() - 1);
        }
    }
    sizes.len() - 1
}

impl BTree {
    /// Garante que a raiz primária seja uma página de árvore válida.
    pub fn ensure_root(pool: &mut BufferPool, meta: &mut MetaInfo) -> Result<()> {
        Self::ensure_tree(pool, meta, TreeId::Primary)
    }

    pub fn ensure_tree(pool: &mut BufferPool, meta: &mut MetaInfo, tree: TreeId) -> Result<()> {
        if tree != TreeId::Primary && tree.root(meta) == 0 {
            let id = pool.allocate_page(PageKind::Leaf, meta)?;
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
        let page = pool.get_page(root_id)?;
        let valid =
            page.magic() == MAGIC && matches!(page.kind(), PageKind::Leaf | PageKind::Internal);
        if !valid {
            pool.put_new_page(Page::zeroed(root_id, PageKind::Leaf))?;
        }
        Ok(())
    }

    pub fn get(pool: &BufferPool, meta: &MetaInfo, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Self::get_in(pool, meta, TreeId::Primary, key)
    }

    pub fn get_in(
        pool: &BufferPool,
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
        match page.find_leaf_slot(key) {
            Ok(i) => {
                let (_, val, overflow) = page.leaf_entry(i);
                Ok(Some(load_cell(pool, meta, tree, val, overflow)?))
            }
            Err(_) => Ok(None),
        }
    }

    pub fn range_scan(
        pool: &BufferPool,
        meta: &MetaInfo,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<Row>> {
        Self::range_in(pool, meta, TreeId::Primary, start, end)
    }

    /// Scan ordenado `[start, end)` pelo encadeamento de folhas.
    pub fn range_in(
        pool: &BufferPool,
        meta: &MetaInfo,
        tree: TreeId,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<Row>> {
        validate_key(start)?;
        if let Some(e) = end {
            validate_key(e)?;
        }
        let mut out = Vec::new();
        let mut leaf_id = Self::first_leaf(pool, meta, tree, start)?;
        let mut visited = HashSet::new();
        while leaf_id != 0 {
            if !visited.insert(leaf_id) {
                return Err(Error::Other("ciclo no encadeamento de folhas".into()));
            }
            let (rows, sibling) = Self::leaf_rows(pool, meta, tree, leaf_id, start)?;
            for (k, v) in rows {
                if end.is_some_and(|e| k.as_slice() >= e) {
                    return Ok(out);
                }
                out.push((k, v));
            }
            leaf_id = sibling;
        }
        Ok(out)
    }

    /// Folha onde começa um scan a partir de `start` (0 se a árvore não existe).
    pub fn first_leaf(
        pool: &BufferPool,
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
        pool: &BufferPool,
        meta: &MetaInfo,
        tree: TreeId,
        leaf_id: u32,
        from: &[u8],
    ) -> Result<(Vec<Row>, u32)> {
        if leaf_id == 0 || leaf_id >= meta.next_page_id {
            return Err(Error::Other("folha fora do arquivo".into()));
        }
        let page = pool.get_page(leaf_id)?;
        if page.kind() != PageKind::Leaf {
            return Err(Error::Other(
                "encadeamento aponta para página não folha".into(),
            ));
        }
        let first = page.find_leaf_slot(from).unwrap_or_else(|i| i);
        let rows = (first..page.n_slots() as usize)
            .map(|i| {
                let (k, v, overflow) = page.leaf_entry(i);
                Ok((k.to_vec(), load_cell(pool, meta, tree, v, overflow)?))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((rows, page.right_sibling()))
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
        Self::ensure_tree(pool, meta, tree)?;
        let (leaf_id, path) = Self::descend(pool, tree.root(meta), key)?;
        // A cadeia antiga (se houver) volta para a freelist antes da nova ser
        // alocada: um upsert de valor grande reaproveita as mesmas páginas.
        let old_pointer = {
            let page = pool.get_page(leaf_id)?;
            page.find_leaf_slot(key).ok().and_then(|i| {
                let (_, v, overflow) = page.leaf_entry(i);
                overflow.then(|| v.to_vec())
            })
        };
        if let Some(ptr) = old_pointer {
            free_overflow(pool, meta, &ptr)?;
        }
        let stored = if compressed(meta, tree) {
            codec::encode_value(value)
        } else {
            value.to_vec()
        };
        let entry = if 4 + key.len() + stored.len() <= MAX_CELL {
            LeafEntry {
                key: key.to_vec(),
                val: stored,
                overflow: false,
            }
        } else {
            LeafEntry {
                key: key.to_vec(),
                val: write_overflow(pool, meta, &stored, lsn)?,
                overflow: true,
            }
        };
        let fits = {
            let page = pool.get_page_mut(leaf_id)?;
            page.set_lsn(lsn);
            let index = match page.find_leaf_slot(key) {
                Ok(i) => {
                    page.remove_slot(i);
                    i
                }
                Err(i) => i,
            };
            let need = 4 + entry.key.len() + entry.val.len() + 2;
            if page.free_space() < need {
                page.compact_leaf()?;
            }
            match page.insert_leaf_cell(index, &entry.key, &entry.val, entry.overflow) {
                Ok(()) => true,
                Err(Error::PageFull) => false,
                Err(e) => return Err(e),
            }
        };
        if fits {
            return Ok(());
        }
        let split = Self::split_leaf(pool, meta, leaf_id, entry, lsn)?;
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
        let found = {
            let page = pool.get_page(leaf_id)?;
            page.find_leaf_slot(key).ok().map(|i| {
                let (_, v, overflow) = page.leaf_entry(i);
                (i, overflow.then(|| v.to_vec()))
            })
        };
        let Some((slot, pointer)) = found else {
            return Ok(false);
        };
        if let Some(ptr) = pointer {
            free_overflow(pool, meta, &ptr)?;
        }
        let page = pool.get_page_mut(leaf_id)?;
        page.remove_slot(slot);
        page.compact_leaf()?;
        page.set_lsn(lsn);
        page.write_checksum();
        Ok(true)
    }

    /// Divide a folha cheia incluindo a célula pendente; devolve o separador.
    fn split_leaf(
        pool: &mut BufferPool,
        meta: &mut MetaInfo,
        leaf_id: u32,
        entry: LeafEntry,
        lsn: u64,
    ) -> Result<Split> {
        let (mut entries, old_right) = {
            let page = pool.get_page(leaf_id)?;
            (page.leaf_entries(), page.right_sibling())
        };
        match entries.binary_search_by(|e| e.key.as_slice().cmp(&entry.key)) {
            Ok(i) => entries[i] = entry,
            Err(i) => entries.insert(i, entry),
        }
        let sizes: Vec<usize> = entries
            .iter()
            .map(|e| 4 + e.key.len() + e.val.len() + 2)
            .collect();
        debug_assert!(sizes.iter().sum::<usize>() <= USABLE + MAX_CELL + 2);
        let right_entries = entries.split_off(split_point(&sizes));
        let separator = right_entries[0].key.clone();
        let right_id = pool.allocate_page(PageKind::Leaf, meta)?;
        pool.put_new_page(Page::rebuild_leaf(leaf_id, &entries, right_id, lsn)?)?;
        pool.put_new_page(Page::rebuild_leaf(
            right_id,
            &right_entries,
            old_right,
            lsn,
        )?)?;
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
            let inserted = {
                let page = pool.get_page_mut(parent_id)?;
                page.set_lsn(lsn);
                let idx = Self::child_position(page, split.left);
                if page.free_space() < 6 + split.separator.len() + 2 {
                    page.compact_internal()?;
                }
                match page.insert_internal_cell(idx, &split.separator, split.right) {
                    Ok(()) => true,
                    Err(Error::PageFull) => false,
                    Err(e) => return Err(e),
                }
            };
            if inserted {
                return Ok(());
            }
            let (leftmost, mut entries) = {
                let page = pool.get_page(parent_id)?;
                let idx = Self::child_position(&page, split.left);
                let mut entries: Vec<_> = (0..page.n_slots() as usize)
                    .map(|i| {
                        let (k, c) = page.internal_cell(i);
                        (k.to_vec(), c)
                    })
                    .collect();
                entries.insert(idx, (split.separator, split.right));
                (page.leftmost_child(), entries)
            };
            // entries[mid] sobe para o avô; seu filho vira o leftmost da direita.
            let sizes: Vec<usize> = entries.iter().map(|(k, _)| 6 + k.len() + 2).collect();
            let mid = split_point(&sizes).clamp(1, entries.len() - 2);
            let right_entries = entries.split_off(mid + 1);
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
    fn descend(pool: &BufferPool, root: u32, key: &[u8]) -> Result<(u32, Vec<u32>)> {
        let mut path = Vec::new();
        let mut current = root;
        loop {
            let page = pool.get_page(current)?;
            let child = match page.kind() {
                PageKind::Leaf => return Ok((current, path)),
                PageKind::Internal => page.child_for_key(key),
                _ => return Err(corrupt(current)),
            };
            if child == 0 || path.len() >= 64 {
                return Err(corrupt(current));
            }
            path.push(current);
            current = child;
        }
    }
}

/// Chave aceita pela árvore (inclui chaves internas de índice).
pub(crate) fn validate_key(key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(Error::InvalidInput("chave vazia não permitida".into()));
    }
    if key.len() > MAX_TREE_KEY {
        return Err(Error::KeyTooLarge(key.len(), MAX_TREE_KEY));
    }
    Ok(())
}

/// Chave aceita pela API pública (até [`MAX_KEY_LEN`]).
pub(crate) fn validate_user_key(key: &[u8]) -> Result<()> {
    validate_key(key)?;
    if key.len() > MAX_KEY_LEN {
        return Err(Error::KeyTooLarge(key.len(), MAX_KEY_LEN));
    }
    Ok(())
}

/// Libera todas as páginas de uma árvore (internos, folhas e overflow).
pub(crate) fn free_tree(pool: &mut BufferPool, meta: &mut MetaInfo, root: u32) -> Result<()> {
    let mut pending = vec![root];
    let mut seen = HashSet::new();
    let mut pages = Vec::new();
    while let Some(id) = pending.pop() {
        if id == 0 || id >= meta.next_page_id || !seen.insert(id) {
            continue;
        }
        let page = pool.get_page(id)?;
        match page.kind() {
            PageKind::Internal => {
                pending.push(page.leftmost_child());
                pending.extend((0..page.n_slots() as usize).map(|i| page.internal_cell(i).1));
            }
            PageKind::Leaf => {
                for i in 0..page.n_slots() as usize {
                    let (_, v, overflow) = page.leaf_entry(i);
                    if overflow {
                        pages.extend(overflow_chain(pool, meta, v)?);
                    }
                }
            }
            _ => continue,
        }
        pages.push(id);
    }
    for id in pages {
        pool.free_page(id, meta)?;
    }
    Ok(())
}

pub(crate) fn validate_value(value: &[u8]) -> Result<()> {
    if value.len() > MAX_VALUE_LEN {
        return Err(Error::ValueTooLarge(value.len(), MAX_VALUE_LEN));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_point_balances_bytes_and_never_empties_a_side() {
        assert_eq!(split_point(&[10, 10, 10, 10]), 2);
        assert_eq!(split_point(&[1000, 1, 1, 1]), 1);
        assert_eq!(split_point(&[1, 1, 1, 1000]), 3);
        // O caso que quebrava o split por contagem: várias células grandes no
        // começo. Por bytes, cada metade cabe na página.
        // Página com 2 células máximas + 193 mínimas; entra outra máxima no
        // início. Por contagem, a esquerda teria 3 grandes + 95 pequenas e não
        // caberia.
        let mut sizes = vec![MAX_CELL + 2; 3];
        sizes.extend(vec![7; 193]);
        assert!(sizes[1..].iter().sum::<usize>() <= USABLE);
        let at = split_point(&sizes);
        let left: usize = sizes[..at].iter().sum();
        let right: usize = sizes[at..].iter().sum();
        assert!(left <= USABLE && right <= USABLE, "{left} {right}");
    }
}
