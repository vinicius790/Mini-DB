//! Buffer pool LRU com leitura concorrente e checkpoint por journal.
//!
//! Leituras (`&self`) devolvem `Arc<Page>`: várias threads leem ao mesmo tempo
//! e só disputam um mutex curto para achar a página no cache. Escritas exigem
//! `&mut self` (acesso exclusivo, garantido pelo `RwLock` do [`crate::mvcc::SharedDb`])
//! e fazem copy-on-write se algum leitor ainda segura a versão anterior.
//!
//! Páginas sujas expulsas vão para `data.mdb.spill`, nunca para `data.mdb`: o
//! arquivo de dados só muda no checkpoint, em três passos à prova de crash:
//!
//! 1. grava as imagens das páginas em `data.mdb.journal` (com CRC) e faz fsync;
//! 2. escreve as páginas no lugar em `data.mdb` e faz fsync;
//! 3. apaga o journal.
//!
//! Na abertura, um journal completo é reaplicado (idempotente) e um incompleto
//! é descartado. O custo do checkpoint é proporcional às páginas alteradas,
//! não ao tamanho do arquivo.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::encryption::Cipher;
use crate::error::{Error, Result};
use crate::page::{MetaInfo, Page, PageKind, PAGE_SIZE};
use crate::wal::crc32_update;

const JOURNAL_MAGIC: &[u8; 4] = b"MJNL";
const JOURNAL_END: &[u8; 4] = b"END!";

struct Frame {
    page: Arc<Page>,
    dirty: bool,
    last_used: u64,
}

struct Inner {
    file: File,
    spill: File,
    spilled: HashSet<u32>,
    frames: HashMap<u32, Frame>,
    capacity: usize,
    clock: u64,
    cipher: Option<Arc<Cipher>>,
}

/// Pool de páginas em memória sobre um arquivo de dados.
pub struct BufferPool {
    path: PathBuf,
    inner: Mutex<Inner>,
}

fn journal_path(path: &Path) -> PathBuf {
    path.with_extension("mdb.journal")
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

/// Cópia com o checksum recalculado: páginas em memória podem ter o checksum
/// defasado; tudo que vai para disco sai selado.
fn sealed(page: &Page, cipher: Option<&Cipher>) -> Page {
    let mut p = page.clone();
    match cipher {
        Some(c) => c.seal_page(&mut p),
        None => p.write_checksum(),
    }
    p
}

/// Lê um journal inteiro; `None` se estiver incompleto ou corrompido.
/// Imagens de página de um journal: `(page_id, bytes)`.
type JournalEntries = Vec<(u32, Vec<u8>)>;

fn read_journal(jpath: &Path) -> Result<Option<JournalEntries>> {
    let journal = File::open(jpath)?;
    let len = journal.metadata()?.len();
    let mut r = BufReader::new(journal);
    let parsed = (|| -> std::io::Result<Option<JournalEntries>> {
        let mut head = [0u8; 8];
        r.read_exact(&mut head)?;
        if &head[..4] != JOURNAL_MAGIC {
            return Ok(None);
        }
        let count = u32::from_le_bytes(head[4..8].try_into().expect("4")) as u64;
        if len != 8 + count * (4 + PAGE_SIZE as u64) + 8 {
            return Ok(None);
        }
        let mut crc = crc32_update(0xFFFF_FFFF, &head);
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut id = [0u8; 4];
            let mut page = vec![0u8; PAGE_SIZE];
            r.read_exact(&mut id)?;
            r.read_exact(&mut page)?;
            crc = crc32_update(crc, &id);
            crc = crc32_update(crc, &page);
            entries.push((u32::from_le_bytes(id), page));
        }
        let mut tail = [0u8; 8];
        r.read_exact(&mut tail)?;
        let ok = &tail[..4] == JOURNAL_END
            && u32::from_le_bytes(tail[4..8].try_into().expect("4")) == !crc;
        Ok(ok.then_some(entries))
    })();
    Ok(parsed.unwrap_or(None))
}

/// Reaplica um journal completo; descarta um incompleto. Devolve se aplicou.
fn recover_journal(path: &Path, file: &mut File) -> Result<bool> {
    let jpath = journal_path(path);
    if !jpath.exists() {
        return Ok(false);
    }
    let entries = read_journal(&jpath)?;
    if let Some(entries) = &entries {
        for (id, page) in entries {
            file.seek(SeekFrom::Start(*id as u64 * PAGE_SIZE as u64))?;
            file.write_all(page)?;
        }
        file.sync_all()?;
    }
    fs::remove_file(&jpath)?;
    sync_dir(path)?;
    Ok(entries.is_some())
}

impl BufferPool {
    pub fn open(path: impl AsRef<Path>, capacity: usize) -> Result<Self> {
        Self::open_with(path, capacity, None)
    }

    /// Com `cipher`, as imagens em disco (data.mdb, journal, spill) são cifradas.
    pub fn open_with(
        path: impl AsRef<Path>,
        capacity: usize,
        cipher: Option<Arc<Cipher>>,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        recover_journal(&path, &mut file)?;
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
            inner: Mutex::new(Inner {
                file,
                spill,
                spilled: HashSet::new(),
                frames: HashMap::new(),
                capacity: capacity.max(8),
                clock: 0,
                cipher,
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Cifra das imagens em disco (para abrir outros arquivos com a mesma chave).
    pub fn cipher(&self) -> Option<Arc<Cipher>> {
        self.lock().cipher.clone()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Um pânico no meio de uma leitura não deixa o cache inconsistente:
        // frames só mudam com a página inteira pronta.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn inner_mut(&mut self) -> &mut Inner {
        self.inner.get_mut().unwrap_or_else(|e| e.into_inner())
    }

    pub fn capacity(&self) -> usize {
        self.lock().capacity
    }

    /// Páginas atualmente em memória.
    pub fn cached_pages(&self) -> usize {
        self.lock().frames.len()
    }

    /// Página para leitura. Pode ser chamada por várias threads ao mesmo tempo.
    pub fn get_page(&self, page_id: u32) -> Result<Arc<Page>> {
        let mut inner = self.lock();
        inner.clock += 1;
        let now = inner.clock;
        if let Some(frame) = inner.frames.get_mut(&page_id) {
            frame.last_used = now;
            return Ok(Arc::clone(&frame.page));
        }
        inner.ensure_capacity()?;
        let page = Arc::new(inner.read_from_disk(page_id)?);
        inner.frames.insert(
            page_id,
            Frame {
                page: Arc::clone(&page),
                dirty: false,
                last_used: now,
            },
        );
        Ok(page)
    }

    /// Página para escrita (marca como suja).
    pub fn get_page_mut(&mut self, page_id: u32) -> Result<&mut Page> {
        let inner = self.inner_mut();
        inner.clock += 1;
        let now = inner.clock;
        if !inner.frames.contains_key(&page_id) {
            inner.ensure_capacity()?;
            let page = inner.read_from_disk(page_id)?;
            inner.frames.insert(
                page_id,
                Frame {
                    page: Arc::new(page),
                    dirty: false,
                    last_used: now,
                },
            );
        }
        let frame = inner.frames.get_mut(&page_id).expect("inserido acima");
        frame.last_used = now;
        frame.dirty = true;
        Ok(Arc::make_mut(&mut frame.page))
    }

    /// Aloca nova página (freelist ou high-water).
    pub fn allocate_page(&mut self, kind: PageKind, meta: &mut MetaInfo) -> Result<u32> {
        let id = if meta.freelist_head != 0 {
            let id = meta.freelist_head;
            let page = self.get_page(id)?;
            if page.kind() != PageKind::Free {
                return Err(Error::CorruptPage(id));
            }
            meta.freelist_head = page.right_sibling();
            id
        } else {
            let id = meta.next_page_id;
            meta.next_page_id = id
                .checked_add(1)
                .ok_or_else(|| Error::Other("arquivo de dados atingiu 2^32 páginas".into()))?;
            id
        };
        self.put_new_page(Page::zeroed(id, kind))?;
        Ok(id)
    }

    /// Devolve a página à freelist (reutilizada pela próxima alocação).
    pub fn free_page(&mut self, page_id: u32, meta: &mut MetaInfo) -> Result<()> {
        let mut page = Page::zeroed(page_id, PageKind::Free);
        page.set_right_sibling(meta.freelist_head);
        page.write_checksum();
        self.put_new_page(page)?;
        meta.freelist_head = page_id;
        Ok(())
    }

    /// Publica todas as páginas alteradas em `data.mdb` (via journal).
    pub fn flush_all(&mut self) -> Result<()> {
        let path = self.path.clone();
        let inner = self.inner_mut();
        let mut ids: Vec<u32> = inner
            .frames
            .iter()
            .filter(|(_, f)| f.dirty)
            .map(|(id, _)| *id)
            .chain(inner.spilled.iter().copied())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.is_empty() {
            return Ok(());
        }
        // 1. Journal com as imagens novas.
        let jpath = journal_path(&path);
        {
            let mut w = BufWriter::new(File::create(&jpath)?);
            let mut head = JOURNAL_MAGIC.to_vec();
            head.extend_from_slice(&(ids.len() as u32).to_le_bytes());
            let mut crc = crc32_update(0xFFFF_FFFF, &head);
            w.write_all(&head)?;
            for &id in &ids {
                let image = inner.image(id)?;
                let page = sealed(&image, inner.cipher.as_deref());
                let id_bytes = id.to_le_bytes();
                crc = crc32_update(crc, &id_bytes);
                crc = crc32_update(crc, &page.data);
                w.write_all(&id_bytes)?;
                w.write_all(&page.data)?;
            }
            w.write_all(JOURNAL_END)?;
            w.write_all(&(!crc).to_le_bytes())?;
            w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        }
        sync_dir(&path)?;
        // 2. Escrita no lugar.
        for &id in &ids {
            let image = inner.image(id)?;
            let page = sealed(&image, inner.cipher.as_deref());
            inner
                .file
                .seek(SeekFrom::Start(id as u64 * PAGE_SIZE as u64))?;
            inner.file.write_all(&page.data)?;
        }
        inner.file.sync_all()?;
        // 3. Checkpoint publicado: o journal não é mais necessário.
        fs::remove_file(&jpath)?;
        sync_dir(&path)?;
        inner.spilled.clear();
        inner.spill.set_len(0)?;
        for frame in inner.frames.values_mut() {
            frame.dirty = false;
        }
        Ok(())
    }

    /// Descarta frames e spill de páginas `>= first` (usado pelo VACUUM antes
    /// de reconstruir a árvore sobre os mesmos ids).
    pub fn discard_from(&mut self, first: u32) {
        let inner = self.inner_mut();
        inner.frames.retain(|id, _| *id < first);
        inner.spilled.retain(|id| *id < first);
    }

    /// Encolhe o arquivo publicado para `pages` páginas. Só remove páginas
    /// inalcançáveis; um crash no meio deixa apenas lixo além do high-water.
    pub fn truncate_pages(&mut self, pages: u32) -> Result<()> {
        self.discard_from(pages);
        let inner = self.inner_mut();
        let len = pages as u64 * PAGE_SIZE as u64;
        if inner.file.metadata()?.len() > len {
            inner.file.set_len(len)?;
            inner.file.sync_all()?;
        }
        Ok(())
    }

    pub fn sync_file(&mut self) -> Result<()> {
        self.inner_mut().file.sync_all()?;
        Ok(())
    }

    pub fn put_new_page(&mut self, page: Page) -> Result<()> {
        let inner = self.inner_mut();
        let id = page.page_id();
        if !inner.frames.contains_key(&id) {
            inner.ensure_capacity()?;
        }
        inner.clock += 1;
        let now = inner.clock;
        inner.frames.insert(
            id,
            Frame {
                page: Arc::new(page),
                dirty: true,
                last_used: now,
            },
        );
        Ok(())
    }
}

impl Inner {
    fn read_page_at(file: &mut File, page_id: u32, cipher: Option<&Cipher>) -> Result<Page> {
        file.seek(SeekFrom::Start(page_id as u64 * PAGE_SIZE as u64))?;
        let mut buf = [0u8; PAGE_SIZE];
        file.read_exact(&mut buf)?;
        let mut page = Page::from_bytes(&buf)?;
        if page.page_id() != page_id {
            return Err(Error::CorruptPage(page_id));
        }
        if let Some(c) = cipher {
            c.open_page(&mut page)?;
        }
        page.validate_header()?;
        Ok(page)
    }

    fn read_from_disk(&mut self, page_id: u32) -> Result<Page> {
        if self.spilled.contains(&page_id) {
            return Self::read_page_at(&mut self.spill, page_id, self.cipher.as_deref());
        }
        let offset = page_id as u64 * PAGE_SIZE as u64;
        if offset + PAGE_SIZE as u64 > self.file.metadata()?.len() {
            // Página ainda não alocada no arquivo — devolve zeroed Free.
            return Ok(Page::zeroed(page_id, PageKind::Free));
        }
        Self::read_page_at(&mut self.file, page_id, self.cipher.as_deref())
    }

    /// Imagem atual de uma página alterada (frame sujo ou spill).
    fn image(&mut self, id: u32) -> Result<Arc<Page>> {
        match self.frames.get(&id) {
            Some(frame) => Ok(Arc::clone(&frame.page)),
            None => Ok(Arc::new(Self::read_page_at(
                &mut self.spill,
                id,
                self.cipher.as_deref(),
            )?)),
        }
    }

    /// Expulsa frames LRU até caber mais um. Sujos vão para o spill (nunca
    /// para `data.mdb`: o checkpoint anterior precisa continuar intacto).
    fn ensure_capacity(&mut self) -> Result<()> {
        while self.frames.len() >= self.capacity {
            // ponytail: varredura O(n) por expulsão; lista LRU intrusiva se o
            // pool passar de dezenas de milhares de páginas.
            let Some(victim) = self
                .frames
                .iter()
                .min_by_key(|(_, f)| f.last_used)
                .map(|(id, _)| *id)
            else {
                return Ok(());
            };
            let frame = self.frames.remove(&victim).expect("existe");
            if frame.dirty {
                self.spill
                    .seek(SeekFrom::Start(victim as u64 * PAGE_SIZE as u64))?;
                self.spill
                    .write_all(&sealed(&frame.page, self.cipher.as_deref()).data)?;
                self.spilled.insert(victim);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("minidb-pool-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("data.mdb")
    }

    fn journal_for(pages: &[Page]) -> Vec<u8> {
        let mut body = JOURNAL_MAGIC.to_vec();
        body.extend_from_slice(&(pages.len() as u32).to_le_bytes());
        let mut crc = crc32_update(0xFFFF_FFFF, &body);
        for page in pages {
            let id = page.page_id().to_le_bytes();
            crc = crc32_update(crc, &id);
            crc = crc32_update(crc, &page.data);
            body.extend_from_slice(&id);
            body.extend_from_slice(&page.data);
        }
        body.extend_from_slice(JOURNAL_END);
        body.extend_from_slice(&(!crc).to_le_bytes());
        body
    }

    #[test]
    fn journal_is_replayed_when_complete_and_dropped_when_torn() {
        let path = tmp("journal");
        let mut pool = BufferPool::open(&path, 8).unwrap();
        let mut meta = MetaInfo::fresh();
        for _ in 0..20 {
            pool.allocate_page(PageKind::Leaf, &mut meta).unwrap();
        }
        pool.flush_all().unwrap();
        drop(pool);
        // Crash depois do journal completo e antes da escrita no lugar.
        let mut page = Page::zeroed(3, PageKind::Leaf);
        page.set_lsn(77);
        page.write_checksum();
        let body = journal_for(&[page.clone()]);
        fs::write(journal_path(&path), &body).unwrap();
        let pool = BufferPool::open(&path, 8).unwrap();
        assert_eq!(pool.get_page(3).unwrap().lsn(), 77, "journal reaplicado");
        assert!(!journal_path(&path).exists());
        drop(pool);
        // Journal rasgado: ignorado, arquivo intacto.
        page.set_lsn(99);
        page.write_checksum();
        let torn = journal_for(&[page]);
        fs::write(journal_path(&path), &torn[..torn.len() - 3]).unwrap();
        let pool = BufferPool::open(&path, 8).unwrap();
        assert_eq!(pool.get_page(3).unwrap().lsn(), 77);
        assert!(!journal_path(&path).exists());
    }

    #[test]
    fn eviction_spills_and_checkpoint_publishes_every_page() {
        let path = tmp("spill");
        let mut pool = BufferPool::open(&path, 8).unwrap();
        let mut meta = MetaInfo::fresh();
        let ids: Vec<u32> = (0..100)
            .map(|_| pool.allocate_page(PageKind::Leaf, &mut meta).unwrap())
            .collect();
        for &id in &ids {
            pool.get_page_mut(id).unwrap().set_lsn(id as u64);
        }
        let reader = pool.get_page(ids[0]).unwrap();
        pool.get_page_mut(ids[0]).unwrap().set_lsn(1000);
        assert_eq!(reader.lsn(), ids[0] as u64, "leitor mantém a versão antiga");
        pool.flush_all().unwrap();
        drop(pool);
        let pool = BufferPool::open(&path, 8).unwrap();
        assert_eq!(pool.get_page(ids[0]).unwrap().lsn(), 1000);
        assert_eq!(pool.get_page(ids[99]).unwrap().lsn(), ids[99] as u64);
    }
}
