//! Dump textual de páginas — ferramenta de forense do arquivo `data.mdb`.

use crate::buffer::BufferPool;
use crate::error::Result;
use crate::page::{MetaInfo, PageKind, PAGE_HEADER_SIZE, PAGE_SIZE};

pub fn dump_meta(meta: &MetaInfo) -> String {
    format!(
        "META root={} index_root={} next_page={} freelist={} ckpt_lsn={} next_lsn={} next_txn={} flags={:#x}\n",
        meta.root_page,
        meta.index_root,
        meta.next_page_id,
        meta.freelist_head,
        meta.checkpoint_lsn,
        meta.next_lsn,
        meta.next_txn_id,
        meta.flags
    )
}

pub fn dump_page(pool: &BufferPool, page_id: u32) -> Result<String> {
    let page = pool.get_page(page_id)?;
    let mut out = String::new();
    out.push_str(&format!(
        "page {page_id} kind={:?} slots={} lsn={} sibling={} checksum_ok={}\n",
        page.kind(),
        page.n_slots(),
        page.lsn(),
        page.right_sibling(),
        page.validate_header().is_ok()
    ));
    match page.kind() {
        PageKind::Leaf => {
            for i in 0..page.n_slots() as usize {
                let (k, v, overflow) = page.leaf_entry(i);
                let value = if overflow {
                    let total = u32::from_le_bytes(v[0..4].try_into().expect("ponteiro"));
                    let first = u32::from_le_bytes(v[4..8].try_into().expect("ponteiro"));
                    format!("overflow total={total} first_page={first}")
                } else {
                    format!("value_len={}", v.len())
                };
                out.push_str(&format!("  leaf[{i}] key={} {value}\n", escape(k)));
            }
        }
        PageKind::Overflow => out.push_str(&format!(
            "  overflow bytes={} next={}\n",
            page.overflow_data().len(),
            page.right_sibling()
        )),
        PageKind::Internal => {
            out.push_str(&format!("  leftmost={}\n", page.leftmost_child()));
            for i in 0..page.n_slots() as usize {
                let (k, child) = page.internal_cell(i);
                out.push_str(&format!("  sep[{i}] key={} child={child}\n", escape(k)));
            }
        }
        PageKind::Meta => out.push_str("  (meta payload)\n"),
        PageKind::Free => out.push_str(&format!("  free next={}\n", page.right_sibling())),
    }
    Ok(out)
}

pub fn hexdump_page(pool: &BufferPool, page_id: u32, bytes: usize) -> Result<String> {
    let page = pool.get_page(page_id)?;
    let n = bytes.min(PAGE_SIZE);
    let mut out = String::new();
    for (i, chunk) in page.data[..n].chunks(16).enumerate() {
        out.push_str(&format!("{:04x}  ", i * 16));
        for b in chunk {
            out.push_str(&format!("{b:02x} "));
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        out.push(' ');
        for b in chunk {
            let c = if (32..127).contains(b) {
                *b as char
            } else {
                '.'
            };
            out.push(c);
        }
        out.push('\n');
    }
    Ok(out)
}

fn escape(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) if s.chars().all(|c| !c.is_control()) => s.to_string(),
        _ => {
            let mut s = String::from("0x");
            for b in bytes {
                s.push_str(&format!("{b:02x}"));
            }
            s
        }
    }
}

/// Ocupação das páginas do arquivo (ver [`crate::Db::page_stats`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageStats {
    /// Páginas até o high-water mark (inclui a meta).
    pub total_pages: u32,
    pub leaves: u32,
    /// Folhas sem células — recuperadas pelo `VACUUM`.
    pub empty_leaves: u32,
    pub internals: u32,
    pub free_pages: u32,
    /// Páginas com pedaços de valores grandes.
    pub overflow_pages: u32,
    /// Bytes ocupados por células e slots nas páginas de árvore.
    pub live_bytes: u64,
    /// `live_bytes` sobre a área útil das páginas de árvore, em %.
    pub fill_percent: u32,
    /// Altura da árvore primária (1 = só uma folha).
    pub height: u32,
}

impl std::fmt::Display for PageStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pages={} leaves={} empty_leaves={} internals={} free={} overflow={} live_bytes={} fill={}% height={}",
            self.total_pages,
            self.leaves,
            self.empty_leaves,
            self.internals,
            self.free_pages,
            self.overflow_pages,
            self.live_bytes,
            self.fill_percent,
            self.height
        )
    }
}

pub fn page_stats(pool: &BufferPool, meta: &MetaInfo) -> Result<PageStats> {
    let mut s = PageStats {
        total_pages: meta.next_page_id,
        ..PageStats::default()
    };
    for id in 1..meta.next_page_id {
        let page = pool.get_page(id)?;
        let n = page.n_slots() as usize;
        match page.kind() {
            PageKind::Leaf => {
                s.leaves += 1;
                s.empty_leaves += u32::from(n == 0);
                s.live_bytes += (0..n)
                    .map(|i| {
                        let (k, v, _) = page.leaf_entry(i);
                        (6 + k.len() + v.len()) as u64
                    })
                    .sum::<u64>();
            }
            PageKind::Internal => {
                s.internals += 1;
                s.live_bytes += (0..n)
                    .map(|i| (8 + page.internal_cell(i).0.len()) as u64)
                    .sum::<u64>();
            }
            PageKind::Free => s.free_pages += 1,
            PageKind::Overflow => s.overflow_pages += 1,
            PageKind::Meta => {}
        }
    }
    let area = u64::from(s.leaves + s.internals) * (PAGE_SIZE - PAGE_HEADER_SIZE) as u64;
    s.fill_percent = (s.live_bytes * 100).checked_div(area).unwrap_or(0) as u32;
    let mut id = meta.root_page;
    loop {
        let page = pool.get_page(id)?;
        let (kind, child) = (page.kind(), page.leftmost_child());
        s.height += 1;
        if kind != PageKind::Internal || s.height > 64 {
            break;
        }
        id = child;
    }
    Ok(s)
}
