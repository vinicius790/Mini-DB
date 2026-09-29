//! Buffer pool com pin count e eviction LRU simples.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::page::{MetaInfo, Page, PageKind, PAGE_SIZE};

struct Frame {
    page: Page,
    dirty: bool,
    pin_count: u32,
    last_used: u64,
}

/// Pool de páginas em memória sobre um arquivo de dados.
pub struct BufferPool {
    path: PathBuf,
    file: File,
    spill: File,
    spilled: HashSet<u32>,
    frames: HashMap<u32, Frame>,
    capacity: usize,
    clock: u64,
}

impl BufferPool {
    pub fn open(path: impl AsRef<Path>, capacity: usize) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        if file.metadata()?.len() % PAGE_SIZE as u64 != 0 {
            return Err(Error::CorruptPage(0));
        }
        let spill = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.with_extension("mdb.spill"))?;
        Ok(Self {
            path,
            file,
            spill,
            spilled: HashSet::new(),
            frames: HashMap::new(),
            capacity: capacity.max(4),
            clock: 0,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn read_from_disk(&mut self, page_id: u32) -> Result<Page> {
        let offset = page_id as u64 * PAGE_SIZE as u64;
        if self.spilled.contains(&page_id) {
            self.spill.seek(SeekFrom::Start(offset))?;
            let mut bytes = [0u8; PAGE_SIZE];
            self.spill.read_exact(&mut bytes)?;
            let page = Page::from_bytes(&bytes)?;
            if page.page_id() != page_id {
                return Err(Error::CorruptPage(page_id));
            }
            page.validate_header()?;
            return Ok(page);
        }
        let file_len = self.file.metadata()?.len();
        if offset + PAGE_SIZE as u64 > file_len {
            // Página ainda não alocada no arquivo — devolve zeroed Free.
            return Ok(Page::zeroed(page_id, PageKind::Free));
        }
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = [0u8; PAGE_SIZE];
        self.file.read_exact(&mut buf)?;
        let page = Page::from_bytes(&buf)?;
        if page.page_id() != page_id {
            return Err(Error::CorruptPage(page_id));
        }
        page.validate_header()?;
        Ok(page)
    }

    fn write_to_disk(&mut self, page: &Page) -> Result<()> {
        // Eviction must never change the last committed checkpoint. A logical
        // WAL cannot repair an arbitrary partially-written B+ tree split.
        let page_id = page.page_id();
        let offset = page_id as u64 * PAGE_SIZE as u64;
        self.spill.seek(SeekFrom::Start(offset))?;
        self.spill.write_all(&page.data)?;
        self.spilled.insert(page_id);
        Ok(())
    }

    /// Garante espaço no pool; faz eviction de frames unpinados (LRU).
    fn ensure_capacity(&mut self) -> Result<()> {
        while self.frames.len() >= self.capacity {
            let victim = self
                .frames
                .iter()
                .filter(|(_, f)| f.pin_count == 0)
                .min_by_key(|(_, f)| f.last_used)
                .map(|(id, _)| *id);
            let Some(vid) = victim else {
                return Err(Error::Other(
                    "buffer pool esgotado: todas as páginas estão pinadas".into(),
                ));
            };
            self.evict(vid)?;
        }
        Ok(())
    }

    fn evict(&mut self, page_id: u32) -> Result<()> {
        if let Some(frame) = self.frames.get(&page_id) {
            if frame.dirty {
                let page = frame.page.clone();
                self.write_to_disk(&page)?;
            }
        }
        self.frames.remove(&page_id);
        Ok(())
    }

    pub fn get_page(&mut self, page_id: u32) -> Result<&Page> {
        if self.frames.contains_key(&page_id) {
            let t = self.tick();
            let f = self.frames.get_mut(&page_id).unwrap();
            f.pin_count += 1;
            f.last_used = t;
            return Ok(&self.frames.get(&page_id).unwrap().page);
        }
        self.ensure_capacity()?;
        let page = self.read_from_disk(page_id)?;
        let t = self.tick();
        self.frames.insert(
            page_id,
            Frame {
                page,
                dirty: false,
                pin_count: 1,
                last_used: t,
            },
        );
        Ok(&self.frames.get(&page_id).unwrap().page)
    }

    pub fn get_page_mut(&mut self, page_id: u32) -> Result<&mut Page> {
        if !self.frames.contains_key(&page_id) {
            self.ensure_capacity()?;
            let page = self.read_from_disk(page_id)?;
            let t = self.tick();
            self.frames.insert(
                page_id,
                Frame {
                    page,
                    dirty: false,
                    pin_count: 0,
                    last_used: t,
                },
            );
        }
        let t = self.tick();
        let f = self.frames.get_mut(&page_id).unwrap();
        f.pin_count += 1;
        f.last_used = t;
        f.dirty = true;
        Ok(&mut f.page)
    }

    pub fn unpin(&mut self, page_id: u32) {
        if let Some(f) = self.frames.get_mut(&page_id) {
            f.pin_count = f.pin_count.saturating_sub(1);
        }
    }

    pub fn mark_dirty(&mut self, page_id: u32) {
        if let Some(f) = self.frames.get_mut(&page_id) {
            f.dirty = true;
        }
    }

    /// Aloca nova página (freelist ou high-water).
    pub fn allocate_page(&mut self, kind: PageKind, meta: &mut MetaInfo) -> Result<u32> {
        let page_id = if meta.freelist_head != 0 {
            let id = meta.freelist_head;
            let page = self.get_page(id)?;
            let next = page.right_sibling();
            self.unpin(id);
            meta.freelist_head = next;
            // Reinit
            let p = self.get_page_mut(id)?;
            *p = Page::zeroed(id, kind);
            self.unpin(id);
            id
        } else {
            let id = meta.next_page_id;
            meta.next_page_id += 1;
            self.ensure_capacity()?;
            let t = self.tick();
            self.frames.insert(
                id,
                Frame {
                    page: Page::zeroed(id, kind),
                    dirty: true,
                    pin_count: 0,
                    last_used: t,
                },
            );
            id
        };
        Ok(page_id)
    }

    pub fn free_page(&mut self, page_id: u32, meta: &mut MetaInfo) -> Result<()> {
        let next = meta.freelist_head;
        {
            let p = self.get_page_mut(page_id)?;
            *p = Page::zeroed(page_id, PageKind::Free);
            p.set_right_sibling(next);
        }
        self.unpin(page_id);
        meta.freelist_head = page_id;
        Ok(())
    }

    pub fn flush_page(&mut self, page_id: u32) -> Result<()> {
        if let Some(f) = self.frames.get(&page_id) {
            if f.dirty {
                let page = f.page.clone();
                self.write_to_disk(&page)?;
                if let Some(f) = self.frames.get_mut(&page_id) {
                    f.dirty = false;
                }
            }
        }
        Ok(())
    }

    pub fn flush_all(&mut self) -> Result<()> {
        let dirty_ids: Vec<u32> = self
            .frames
            .iter()
            .filter(|(_, f)| f.dirty)
            .map(|(id, _)| *id)
            .collect();
        for id in dirty_ids {
            self.flush_page(id)?;
        }
        if self.spilled.is_empty() {
            return Ok(());
        }
        let next_path = self.path.with_extension("mdb.next");
        fs::copy(&self.path, &next_path)?;
        let mut next = OpenOptions::new().read(true).write(true).open(&next_path)?;
        let mut ids: Vec<u32> = self.spilled.iter().copied().collect();
        ids.sort_unstable();
        let mut bytes = [0u8; PAGE_SIZE];
        for id in ids {
            let offset = id as u64 * PAGE_SIZE as u64;
            self.spill.seek(SeekFrom::Start(offset))?;
            self.spill.read_exact(&mut bytes)?;
            next.seek(SeekFrom::Start(offset))?;
            next.write_all(&bytes)?;
        }
        next.sync_all()?;
        // Fecha o handle antigo antes do rename: no Windows, substituir um
        // destino que ainda está aberto falha. Renomear a origem aberta é
        // permitido (a std abre arquivos com FILE_SHARE_DELETE) e o handle
        // continua válido. O rename no mesmo diretório publica tudo de uma vez.
        self.file = next;
        fs::rename(&next_path, &self.path)?;
        #[cfg(unix)]
        File::open(self.path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
        self.spilled.clear();
        self.spill.set_len(0)?;
        Ok(())
    }

    /// Descarta frames e spill de páginas `>= first` (usado pelo VACUUM antes
    /// de reconstruir a árvore sobre os mesmos ids).
    pub fn discard_from(&mut self, first: u32) {
        self.frames.retain(|id, _| *id < first);
        self.spilled.retain(|id| *id < first);
    }
    /// Encolhe o arquivo publicado para `pages` páginas. Só remove páginas
    /// inalcançáveis; um crash no meio deixa apenas lixo além do high-water.
    pub fn truncate_pages(&mut self, pages: u32) -> Result<()> {
        self.discard_from(pages);
        let len = pages as u64 * PAGE_SIZE as u64;
        if self.file.metadata()?.len() > len {
            self.file.set_len(len)?;
            self.file.sync_all()?;
        }
        Ok(())
    }
    pub fn sync_file(&mut self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }

    pub fn put_new_page(&mut self, page: Page) -> Result<()> {
        let id = page.page_id();
        if !self.frames.contains_key(&id) {
            self.ensure_capacity()?;
        }
        let t = self.tick();
        self.frames.insert(
            id,
            Frame {
                page,
                dirty: true,
                pin_count: 0,
                last_used: t,
            },
        );
        Ok(())
    }
}
