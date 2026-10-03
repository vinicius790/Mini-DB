//! Layout de páginas de tamanho fixo (4 KiB) e freelist lógica.

use crate::error::{Error, Result};

pub const PAGE_SIZE: usize = 4096;
pub const PAGE_HEADER_SIZE: usize = 32;
pub const MAGIC: [u8; 4] = *b"MDB1";

/// Maior chave aceita pela API (1 KiB). Chaves ficam sempre dentro da página.
pub const MAX_KEY_LEN: usize = 1024;
/// Maior chave interna de árvore: a chave do usuário mais o prefixo das
/// entradas de índice (hash do valor, ids de tabela).
pub const MAX_TREE_KEY: usize = MAX_KEY_LEN + 64;
/// Maior valor aceito (64 MiB). Valores grandes vão para páginas de overflow.
pub const MAX_VALUE_LEN: usize = 64 << 20;
/// Maior célula (com o slot) que uma página aceita: 1/3 do espaço útil, o que
/// garante que qualquer split por bytes produza duas metades válidas.
pub const MAX_CELL: usize = (PAGE_SIZE - PAGE_HEADER_SIZE) / 3 - 2;
/// Bytes de valor por página de overflow.
pub const OVERFLOW_CAPACITY: usize = PAGE_SIZE - PAGE_HEADER_SIZE;
/// Bit de `val_len` que marca valor em overflow.
pub const VAL_OVERFLOW: u16 = 0x8000;
/// Tamanho do ponteiro de overflow guardado na célula.
pub const OVERFLOW_POINTER_LEN: usize = 8;

/// Célula de folha em memória (splits, compactação e VACUUM).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafEntry {
    pub key: Vec<u8>,
    pub val: Vec<u8>,
    pub overflow: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageKind {
    Free = 0,
    Meta = 1,
    Internal = 2,
    Leaf = 3,
    /// Pedaço de um valor grande (encadeado por `right_sibling`).
    Overflow = 4,
}

impl PageKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Free),
            1 => Some(Self::Meta),
            2 => Some(Self::Internal),
            3 => Some(Self::Leaf),
            4 => Some(Self::Overflow),
            _ => None,
        }
    }
}

/// Página bruta de 4096 bytes.
#[derive(Clone)]
pub struct Page {
    pub data: [u8; PAGE_SIZE],
}

impl Page {
    pub fn zeroed(page_id: u32, kind: PageKind) -> Self {
        let mut p = Self {
            data: [0u8; PAGE_SIZE],
        };
        p.set_magic();
        p.set_page_id(page_id);
        p.set_kind(kind);
        p.set_n_slots(0);
        p.set_cell_end(PAGE_SIZE as u16);
        p.set_right_sibling(0);
        p.set_extra(0);
        p.set_lsn(0);
        p.write_checksum();
        p
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PAGE_SIZE {
            return Err(Error::Other(format!(
                "tamanho de página inválido: {}",
                bytes.len()
            )));
        }
        let mut data = [0u8; PAGE_SIZE];
        data.copy_from_slice(bytes);
        let p = Self { data };
        if p.magic() != MAGIC {
            return Err(Error::CorruptPage(p.page_id()));
        }
        Ok(p)
    }

    fn set_magic(&mut self) {
        self.data[0..4].copy_from_slice(&MAGIC);
    }

    pub fn magic(&self) -> [u8; 4] {
        let mut m = [0u8; 4];
        m.copy_from_slice(&self.data[0..4]);
        m
    }

    pub fn page_id(&self) -> u32 {
        u32::from_le_bytes(self.data[4..8].try_into().unwrap())
    }

    pub fn set_page_id(&mut self, id: u32) {
        self.data[4..8].copy_from_slice(&id.to_le_bytes());
    }

    pub fn kind(&self) -> PageKind {
        PageKind::from_u8(self.data[8]).unwrap_or(PageKind::Free)
    }

    pub fn set_kind(&mut self, k: PageKind) {
        self.data[8] = k as u8;
    }

    pub fn flags(&self) -> u8 {
        self.data[9]
    }

    pub fn set_flags(&mut self, f: u8) {
        self.data[9] = f;
    }

    pub fn n_slots(&self) -> u16 {
        u16::from_le_bytes(self.data[10..12].try_into().unwrap())
    }

    pub fn set_n_slots(&mut self, n: u16) {
        self.data[10..12].copy_from_slice(&n.to_le_bytes());
    }

    /// Fim da região de células (células crescem de trás para frente).
    pub fn cell_end(&self) -> u16 {
        u16::from_le_bytes(self.data[12..14].try_into().unwrap())
    }

    pub fn set_cell_end(&mut self, e: u16) {
        self.data[12..14].copy_from_slice(&e.to_le_bytes());
    }

    /// Folha: irmão direito. Free: próximo na freelist.
    pub fn right_sibling(&self) -> u32 {
        u32::from_le_bytes(self.data[14..18].try_into().unwrap())
    }

    pub fn set_right_sibling(&mut self, id: u32) {
        self.data[14..18].copy_from_slice(&id.to_le_bytes());
    }

    /// Interno: filho mais à esquerda. Meta: ver MetaPage.
    pub fn extra(&self) -> u32 {
        u32::from_le_bytes(self.data[18..22].try_into().unwrap())
    }

    pub fn set_extra(&mut self, v: u32) {
        self.data[18..22].copy_from_slice(&v.to_le_bytes());
    }

    pub fn leftmost_child(&self) -> u32 {
        self.extra()
    }

    pub fn set_leftmost_child(&mut self, id: u32) {
        self.set_extra(id);
    }

    pub fn lsn(&self) -> u64 {
        u64::from_le_bytes(self.data[22..30].try_into().unwrap())
    }

    pub fn set_lsn(&mut self, lsn: u64) {
        self.data[22..30].copy_from_slice(&lsn.to_le_bytes());
    }

    pub fn stored_checksum(&self) -> u16 {
        u16::from_le_bytes(self.data[30..32].try_into().unwrap())
    }

    pub fn set_stored_checksum(&mut self, c: u16) {
        self.data[30..32].copy_from_slice(&c.to_le_bytes());
    }

    /// CRC16-CCITT sobre o corpo da página com os bytes de checksum zerados.
    pub fn compute_checksum(&self) -> u16 {
        // Equivale a calcular com os bytes 30-31 zerados, sem copiar a página.
        let crc = crc16_update(0xFFFF, &self.data[..30]);
        let crc = crc16_update(crc, &[0, 0]);
        crc16_update(crc, &self.data[32..])
    }

    pub fn write_checksum(&mut self) {
        self.set_stored_checksum(0);
        let c = self.compute_checksum();
        self.set_stored_checksum(c);
    }

    pub fn verify_checksum(&self) -> Result<()> {
        let stored = self.stored_checksum();
        if stored == 0 {
            return Ok(()); // páginas legado sem checksum
        }
        if stored != self.compute_checksum() {
            return Err(Error::BadChecksum(self.page_id()));
        }
        Ok(())
    }

    fn slot_offset(i: usize) -> usize {
        PAGE_HEADER_SIZE + i * 2
    }

    pub fn slot_ptr(&self, i: usize) -> u16 {
        let off = Self::slot_offset(i);
        u16::from_le_bytes(self.data[off..off + 2].try_into().unwrap())
    }

    pub fn set_slot_ptr(&mut self, i: usize, ptr: u16) {
        let off = Self::slot_offset(i);
        self.data[off..off + 2].copy_from_slice(&ptr.to_le_bytes());
    }

    /// Espaço livre entre slot directory e células.
    pub fn free_space(&self) -> usize {
        let slots_end = PAGE_HEADER_SIZE + self.n_slots() as usize * 2;
        let cell_end = self.cell_end() as usize;
        cell_end.saturating_sub(slots_end)
    }

    pub fn validate_header(&self) -> Result<()> {
        if self.magic() != MAGIC {
            return Err(Error::CorruptPage(self.page_id()));
        }
        if PageKind::from_u8(self.data[8]).is_none() {
            return Err(Error::CorruptPage(self.page_id()));
        }
        let slots_end = PAGE_HEADER_SIZE
            .checked_add(self.n_slots() as usize * 2)
            .ok_or(Error::CorruptPage(self.page_id()))?;
        let cell_end = self.cell_end() as usize;
        if slots_end > PAGE_SIZE || cell_end < slots_end || cell_end > PAGE_SIZE {
            return Err(Error::CorruptPage(self.page_id()));
        }
        for index in 0..self.n_slots() as usize {
            let ptr = self.slot_ptr(index) as usize;
            if ptr < cell_end || ptr >= PAGE_SIZE {
                return Err(Error::CorruptPage(self.page_id()));
            }
            match self.kind() {
                PageKind::Leaf => {
                    if ptr + 4 > PAGE_SIZE {
                        return Err(Error::CorruptPage(self.page_id()));
                    }
                    let key_len = u16::from_le_bytes(
                        self.data[ptr..ptr + 2]
                            .try_into()
                            .map_err(|_| Error::CorruptPage(self.page_id()))?,
                    ) as usize;
                    let raw = u16::from_le_bytes(
                        self.data[ptr + 2..ptr + 4]
                            .try_into()
                            .map_err(|_| Error::CorruptPage(self.page_id()))?,
                    );
                    let value_len = (raw & !VAL_OVERFLOW) as usize;
                    let bad_pointer = raw & VAL_OVERFLOW != 0 && value_len != OVERFLOW_POINTER_LEN;
                    if key_len > MAX_TREE_KEY
                        || bad_pointer
                        || ptr + 4 + key_len + value_len > PAGE_SIZE
                    {
                        return Err(Error::CorruptPage(self.page_id()));
                    }
                }
                PageKind::Internal => {
                    if ptr + 6 > PAGE_SIZE {
                        return Err(Error::CorruptPage(self.page_id()));
                    }
                    let key_len = u16::from_le_bytes(
                        self.data[ptr..ptr + 2]
                            .try_into()
                            .map_err(|_| Error::CorruptPage(self.page_id()))?,
                    ) as usize;
                    if key_len > MAX_TREE_KEY || ptr + 6 + key_len > PAGE_SIZE {
                        return Err(Error::CorruptPage(self.page_id()));
                    }
                }
                PageKind::Meta | PageKind::Free | PageKind::Overflow => {
                    return Err(Error::CorruptPage(self.page_id()));
                }
            }
        }
        if self.kind() == PageKind::Overflow && self.extra() as usize > OVERFLOW_CAPACITY {
            return Err(Error::CorruptPage(self.page_id()));
        }
        self.verify_checksum()?;
        Ok(())
    }

    // --- Leaf cells: [key_len:u16][val_len:u16][key][val] ---
    //
    // O bit 15 de `val_len` marca valor em páginas de overflow: a célula guarda
    // então 8 bytes `[total:u32][primeira_página:u32]` em vez do valor.

    /// Chave e campo de valor cru da célula `i` (ponteiro, se for overflow).
    pub fn leaf_cell(&self, i: usize) -> (&[u8], &[u8]) {
        let (k, v, _) = self.leaf_entry(i);
        (k, v)
    }

    /// Chave, campo de valor e se o valor está em páginas de overflow.
    pub fn leaf_entry(&self, i: usize) -> (&[u8], &[u8], bool) {
        let ptr = self.slot_ptr(i) as usize;
        let key_len = u16::from_le_bytes(self.data[ptr..ptr + 2].try_into().unwrap()) as usize;
        let raw = u16::from_le_bytes(self.data[ptr + 2..ptr + 4].try_into().unwrap());
        let val_len = (raw & !VAL_OVERFLOW) as usize;
        let key = &self.data[ptr + 4..ptr + 4 + key_len];
        let val = &self.data[ptr + 4 + key_len..ptr + 4 + key_len + val_len];
        (key, val, raw & VAL_OVERFLOW != 0)
    }

    pub fn insert_leaf_cell(
        &mut self,
        index: usize,
        key: &[u8],
        val: &[u8],
        overflow: bool,
    ) -> Result<()> {
        self.insert_leaf_cell_unchecked(index, key, val, overflow)?;
        self.write_checksum();
        Ok(())
    }

    /// Insere sem recalcular o checksum (usado em reconstruções em lote).
    fn insert_leaf_cell_unchecked(
        &mut self,
        index: usize,
        key: &[u8],
        val: &[u8],
        overflow: bool,
    ) -> Result<()> {
        let need = 4 + key.len() + val.len() + 2; // cell + slot
        if self.free_space() < need {
            return Err(Error::PageFull);
        }
        let cell_size = 4 + key.len() + val.len();
        let new_end = self.cell_end() as usize - cell_size;
        let ptr = new_end as u16;
        let raw_len = val.len() as u16 | if overflow { VAL_OVERFLOW } else { 0 };
        self.data[new_end..new_end + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
        self.data[new_end + 2..new_end + 4].copy_from_slice(&raw_len.to_le_bytes());
        self.data[new_end + 4..new_end + 4 + key.len()].copy_from_slice(key);
        self.data[new_end + 4 + key.len()..new_end + 4 + key.len() + val.len()]
            .copy_from_slice(val);
        self.set_cell_end(new_end as u16);

        let n = self.n_slots() as usize;
        // shift slots right from index..n
        for i in (index..n).rev() {
            let p = self.slot_ptr(i);
            self.set_slot_ptr(i + 1, p);
        }
        self.set_slot_ptr(index, ptr);
        self.set_n_slots((n + 1) as u16);
        Ok(())
    }

    pub fn remove_slot(&mut self, index: usize) {
        let n = self.n_slots() as usize;
        debug_assert!(index < n);
        for i in index..n - 1 {
            let p = self.slot_ptr(i + 1);
            self.set_slot_ptr(i, p);
        }
        self.set_n_slots((n - 1) as u16);
        self.write_checksum();
    }

    /// Busca binária: `Ok(slot)` se a chave existe, `Err(posição de inserção)`.
    pub fn find_leaf_slot(&self, key: &[u8]) -> std::result::Result<usize, usize> {
        let (mut lo, mut hi) = (0usize, self.n_slots() as usize);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.leaf_entry(mid).0.cmp(key) {
                std::cmp::Ordering::Equal => return Ok(mid),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        Err(lo)
    }

    // --- Internal cells: [key_len:u16][child:u32][key] ---

    pub fn internal_cell(&self, i: usize) -> (&[u8], u32) {
        let ptr = self.slot_ptr(i) as usize;
        let key_len = u16::from_le_bytes(self.data[ptr..ptr + 2].try_into().unwrap()) as usize;
        let child = u32::from_le_bytes(self.data[ptr + 2..ptr + 6].try_into().unwrap());
        let key = &self.data[ptr + 6..ptr + 6 + key_len];
        (key, child)
    }

    pub fn insert_internal_cell(&mut self, index: usize, key: &[u8], child: u32) -> Result<()> {
        self.insert_internal_cell_unchecked(index, key, child)?;
        self.write_checksum();
        Ok(())
    }

    /// Insere sem recalcular o checksum (usado em reconstruções em lote).
    fn insert_internal_cell_unchecked(
        &mut self,
        index: usize,
        key: &[u8],
        child: u32,
    ) -> Result<()> {
        let need = 6 + key.len() + 2;
        if self.free_space() < need {
            return Err(Error::PageFull);
        }
        let cell_size = 6 + key.len();
        let new_end = self.cell_end() as usize - cell_size;
        let ptr = new_end as u16;
        self.data[new_end..new_end + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
        self.data[new_end + 2..new_end + 6].copy_from_slice(&child.to_le_bytes());
        self.data[new_end + 6..new_end + 6 + key.len()].copy_from_slice(key);
        self.set_cell_end(new_end as u16);

        let n = self.n_slots() as usize;
        for i in (index..n).rev() {
            let p = self.slot_ptr(i);
            self.set_slot_ptr(i + 1, p);
        }
        self.set_slot_ptr(index, ptr);
        self.set_n_slots((n + 1) as u16);
        Ok(())
    }

    /// Filho à direita da chave `i` (slot i). Filho à esquerda de tudo = leftmost_child.
    /// Filho responsável por `key`: o da maior chave separadora `<= key`, ou
    /// `leftmost_child` se todas forem maiores (busca binária).
    pub fn child_for_key(&self, key: &[u8]) -> u32 {
        let (mut lo, mut hi) = (0usize, self.n_slots() as usize);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.internal_cell(mid).0 <= key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            self.leftmost_child()
        } else {
            self.internal_cell(lo - 1).1
        }
    }

    /// Reconstrói página limpa a partir de células folha (usado no split).
    pub fn rebuild_leaf(page_id: u32, entries: &[LeafEntry], right: u32, lsn: u64) -> Result<Self> {
        let mut p = Self::zeroed(page_id, PageKind::Leaf);
        p.set_right_sibling(right);
        p.set_lsn(lsn);
        for (i, e) in entries.iter().enumerate() {
            p.insert_leaf_cell_unchecked(i, &e.key, &e.val, e.overflow)?;
        }
        p.write_checksum();
        Ok(p)
    }

    pub fn rebuild_internal(
        page_id: u32,
        leftmost: u32,
        entries: &[(Vec<u8>, u32)],
        lsn: u64,
    ) -> Result<Self> {
        let mut p = Self::zeroed(page_id, PageKind::Internal);
        p.set_leftmost_child(leftmost);
        p.set_lsn(lsn);
        for (i, (k, child)) in entries.iter().enumerate() {
            p.insert_internal_cell_unchecked(i, k, *child)?;
        }
        p.write_checksum();
        Ok(p)
    }
    /// Reescreve as células folha de forma contígua, eliminando fragmentação.
    pub fn compact_leaf(&mut self) -> Result<()> {
        if self.kind() != PageKind::Leaf {
            return Err(Error::Other(
                "compact_leaf em página que não é folha".into(),
            ));
        }
        let entries = self.leaf_entries();
        let right = self.right_sibling();
        let lsn = self.lsn();
        let id = self.page_id();
        *self = Self::rebuild_leaf(id, &entries, right, lsn)?;
        self.write_checksum();
        Ok(())
    }

    pub fn compact_internal(&mut self) -> Result<()> {
        if self.kind() != PageKind::Internal {
            return Err(Error::Other(
                "compact_internal em página que não é interna".into(),
            ));
        }
        let leftmost = self.leftmost_child();
        let mut entries = Vec::new();
        for i in 0..self.n_slots() as usize {
            let (k, c) = self.internal_cell(i);
            entries.push((k.to_vec(), c));
        }
        let lsn = self.lsn();
        let id = self.page_id();
        *self = Self::rebuild_internal(id, leftmost, &entries, lsn)?;
        self.write_checksum();
        Ok(())
    }

    /// Todas as células de uma folha, na ordem.
    pub fn leaf_entries(&self) -> Vec<LeafEntry> {
        (0..self.n_slots() as usize)
            .map(|i| {
                let (k, v, overflow) = self.leaf_entry(i);
                LeafEntry {
                    key: k.to_vec(),
                    val: v.to_vec(),
                    overflow,
                }
            })
            .collect()
    }

    // --- Overflow: `right_sibling` = próxima página, `extra` = bytes usados ---

    /// Página de overflow com um pedaço do valor.
    pub fn overflow(page_id: u32, next: u32, chunk: &[u8], lsn: u64) -> Self {
        debug_assert!(chunk.len() <= OVERFLOW_CAPACITY);
        let mut p = Self::zeroed(page_id, PageKind::Overflow);
        p.set_right_sibling(next);
        p.set_extra(chunk.len() as u32);
        p.set_lsn(lsn);
        p.data[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + chunk.len()].copy_from_slice(chunk);
        p.write_checksum();
        p
    }

    /// Bytes do valor guardados nesta página de overflow.
    pub fn overflow_data(&self) -> &[u8] {
        let used = (self.extra() as usize).min(OVERFLOW_CAPACITY);
        &self.data[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + used]
    }
}

/// Tabela do CRC16-CCITT (polinômio 0x1021), gerada em tempo de compilação.
const CRC16_TABLE: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 0x8000 != 0 {
                (c << 1) ^ 0x1021
            } else {
                c << 1
            };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

fn crc16_update(mut crc: u16, data: &[u8]) -> u16 {
    for &b in data {
        crc = (crc << 8) ^ CRC16_TABLE[((crc >> 8) as u8 ^ b) as usize];
    }
    crc
}

/// CRC16-CCITT-FALSE (0x1021, init 0xFFFF), por tabela: um lookup por byte.
pub fn crc16(data: &[u8]) -> u16 {
    crc16_update(0xFFFF, data)
}

/// Metadados na página 0.
#[derive(Debug, Clone, Copy)]
pub struct MetaInfo {
    pub root_page: u32,
    pub freelist_head: u32,
    pub next_page_id: u32,
    pub checkpoint_lsn: u64,
    /// Próximo LSN a alocar (sobrevive ao truncate do WAL).
    pub next_lsn: u64,
    /// Raiz da B+ Tree do índice secundário por valor (0 = ainda não criado).
    pub index_root: u32,
    pub next_txn_id: u64,
    pub flags: u32,
    /// Raiz da B+ Tree de expiração (TTL) — 0 = nenhuma chave com TTL.
    pub ttl_root: u32,
}

pub const META_FLAG_VALUE_INDEX: u32 = 1;
/// Valores da árvore primária gravados com [`crate::codec`] (bancos 0.5+).
pub const META_FLAG_COMPRESSED_VALUES: u32 = 2;
/// Índice por valor no formato por hash (bancos 0.6+); sem a flag, o índice
/// antigo é reconstruído na abertura.
pub const META_FLAG_INDEX_V2: u32 = 4;

impl MetaInfo {
    pub const META_PAGE_ID: u32 = 0;

    pub fn from_page(page: &Page) -> Self {
        // Payload após header: root, freelist, next_page, checkpoint_lsn, next_lsn
        let base = PAGE_HEADER_SIZE;
        let root_page = u32::from_le_bytes(page.data[base..base + 4].try_into().unwrap());
        let freelist_head = u32::from_le_bytes(page.data[base + 4..base + 8].try_into().unwrap());
        let next_page_id = u32::from_le_bytes(page.data[base + 8..base + 12].try_into().unwrap());
        let checkpoint_lsn =
            u64::from_le_bytes(page.data[base + 12..base + 20].try_into().unwrap());
        let next_lsn = u64::from_le_bytes(page.data[base + 20..base + 28].try_into().unwrap());
        let next_lsn = if next_lsn == 0 {
            checkpoint_lsn.saturating_add(1).max(1)
        } else {
            next_lsn
        };
        let index_root = u32::from_le_bytes(page.data[base + 28..base + 32].try_into().unwrap());
        let next_txn_id = u64::from_le_bytes(page.data[base + 32..base + 40].try_into().unwrap());
        let flags = u32::from_le_bytes(page.data[base + 40..base + 44].try_into().unwrap());
        // Arquivos 0.3 têm zeros aqui: sem árvore de TTL.
        let ttl_root = u32::from_le_bytes(page.data[base + 44..base + 48].try_into().unwrap());
        let next_txn_id = if next_txn_id == 0 { 1 } else { next_txn_id };
        Self {
            root_page,
            freelist_head,
            next_page_id,
            checkpoint_lsn,
            next_lsn,
            index_root,
            next_txn_id,
            flags,
            ttl_root,
        }
    }

    pub fn write_to_page(&self, page: &mut Page) {
        page.set_kind(PageKind::Meta);
        page.set_page_id(Self::META_PAGE_ID);
        let base = PAGE_HEADER_SIZE;
        page.data[base..base + 4].copy_from_slice(&self.root_page.to_le_bytes());
        page.data[base + 4..base + 8].copy_from_slice(&self.freelist_head.to_le_bytes());
        page.data[base + 8..base + 12].copy_from_slice(&self.next_page_id.to_le_bytes());
        page.data[base + 12..base + 20].copy_from_slice(&self.checkpoint_lsn.to_le_bytes());
        page.data[base + 20..base + 28].copy_from_slice(&self.next_lsn.to_le_bytes());
        page.data[base + 28..base + 32].copy_from_slice(&self.index_root.to_le_bytes());
        page.data[base + 32..base + 40].copy_from_slice(&self.next_txn_id.to_le_bytes());
        page.data[base + 40..base + 44].copy_from_slice(&self.flags.to_le_bytes());
        page.data[base + 44..base + 48].copy_from_slice(&self.ttl_root.to_le_bytes());
        page.write_checksum();
    }

    pub fn fresh() -> Self {
        Self {
            root_page: 1,
            freelist_head: 0,
            next_page_id: 2, // 0=meta, 1=root leaf inicial
            checkpoint_lsn: 0,
            next_lsn: 1,
            index_root: 0,
            next_txn_id: 1,
            flags: 0,
            ttl_root: 0,
        }
    }

    /// Meta de um arquivo novo: já nasce com valores comprimidos.
    pub fn fresh_file() -> Self {
        Self {
            flags: META_FLAG_COMPRESSED_VALUES | META_FLAG_INDEX_V2,
            ..Self::fresh()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_matches_reference_vector() {
        assert_eq!(crc16(b"123456789"), 0x29B1);
        let mut p = Page::zeroed(3, PageKind::Leaf);
        p.insert_leaf_cell(0, b"k", b"v", false).unwrap();
        let mut copy = p.data;
        copy[30] = 0;
        copy[31] = 0;
        assert_eq!(p.compute_checksum(), crc16(&copy));
    }

    #[test]
    fn leaf_insert_and_find() {
        let mut p = Page::zeroed(1, PageKind::Leaf);
        p.insert_leaf_cell(0, b"a", b"1", false).unwrap();
        p.insert_leaf_cell(1, b"c", b"3", false).unwrap();
        p.insert_leaf_cell(1, b"b", b"2", false).unwrap();
        assert_eq!(p.n_slots(), 3);
        let (k, v) = p.leaf_cell(1);
        assert_eq!(k, b"b");
        assert_eq!(v, b"2");
        assert_eq!(p.find_leaf_slot(b"b"), Ok(1));
        assert_eq!(p.find_leaf_slot(b"d"), Err(3));
    }

    #[test]
    fn rejects_valid_checksum_with_invalid_cell_bounds() {
        let mut p = Page::zeroed(1, PageKind::Leaf);
        p.insert_leaf_cell(0, b"a", b"1", false).unwrap();
        p.set_slot_ptr(0, PAGE_SIZE as u16 - 1);
        p.write_checksum();
        assert!(p.validate_header().is_err());
    }
}
