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
//!
//! Em bancos cifrados v3 ([`crate::encryption`]) o nonce de cada página fica no
//! mapa `data.mdb.pages`, autenticado pela chave do banco. Cada checkpoint sela as
//! páginas com nonces novos, leva o mapa novo no journal e o publica (temporário +
//! fsync + rename) junto com as páginas; o mapa novo guarda o MAC do anterior, e um
//! journal só é reaplicado sobre o mapa de que descende (um journal antigo
//! reaplicado não volta páginas no tempo).

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::crypto::{constant_time_eq, random_bytes};
use crate::encryption::Cipher;
use crate::error::{Error, Result};
use crate::page::{MetaInfo, Page, PageKind, PAGE_SIZE};
use crate::wal::crc32_update;

const JOURNAL_MAGIC: &[u8; 4] = b"MJNL";
/// Journal de banco com mapa de páginas (v3): depois das imagens vem o mapa novo.
const JOURNAL_MAGIC_MAP: &[u8; 4] = b"MJN3";
const JOURNAL_END: &[u8; 4] = b"END!";
const MAP_MAGIC: &[u8; 4] = b"MDBP";

struct Frame {
    page: Arc<Page>,
    dirty: bool,
    last_used: u64,
}

struct Inner {
    file: File,
    spill: File,
    spilled: HashSet<u32>,
    /// Nonce de cada página no spill (v3: a imagem não guarda o nonce).
    spill_nonces: HashMap<u32, [u8; 8]>,
    frames: HashMap<u32, Frame>,
    capacity: usize,
    clock: u64,
    cipher: Option<Arc<Cipher>>,
    /// Mapa publicado de `data.mdb` (só em bancos cifrados v3).
    map: Option<PageMap>,
}

/// Pool de páginas em memória sobre um arquivo de dados.
pub struct BufferPool {
    path: PathBuf,
    inner: Mutex<Inner>,
}

fn journal_path(path: &Path) -> PathBuf {
    path.with_extension("mdb.journal")
}

/// Mapa de páginas (v3) do arquivo de dados `path`: `data.mdb.pages`.
pub(crate) fn map_path(path: &Path) -> PathBuf {
    path.with_extension("mdb.pages")
}

/// Mapa novo à espera da troca do arquivo de dados (VACUUM, conversão).
pub(crate) fn pending_map_path(path: &Path) -> PathBuf {
    path.with_extension("mdb.pages.next")
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

/// Cópia selada com `nonce` (com cifra) ou com o checksum recalculado (sem):
/// páginas em memória podem ter o checksum defasado; tudo que vai para disco sai
/// selado. O mesmo nonce dá a mesma imagem no journal e no arquivo.
fn sealed(page: &Page, cipher: Option<&Cipher>, nonce: &[u8; 8]) -> Page {
    let mut p = page.clone();
    match cipher {
        Some(c) => c.seal_page_with(&mut p, nonce),
        None => p.write_checksum(),
    }
    p
}

/// Nonce novo para selar uma página (sem cifra não é usado).
fn fresh_nonce(cipher: Option<&Cipher>) -> [u8; 8] {
    if cipher.is_some() {
        random_bytes()
    } else {
        [0; 8]
    }
}

fn read_image(file: &mut File, page_id: u32) -> Result<[u8; PAGE_SIZE]> {
    file.seek(SeekFrom::Start(page_id as u64 * PAGE_SIZE as u64))?;
    let mut buf = [0u8; PAGE_SIZE];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Mapa de páginas dos bancos cifrados v3: o nonce com que cada página de
/// `data.mdb` foi selada. Em disco: `MDBP ‖ MAC do mapa anterior(32) ‖ n(u32) ‖
/// n nonces de 8 bytes ‖ MAC(32)`, o MAC (HMAC-SHA256, subchave do banco) cobrindo
/// tudo antes dele.
// ponytail: o mapa inteiro é regravado a cada checkpoint (8 bytes por página, 2 MiB
// por GiB de dados); uma árvore de MACs por blocos se checkpoints de bancos enormes
// pesarem.
struct PageMap {
    prev: [u8; 32],
    nonces: Vec<[u8; 8]>,
    mac: [u8; 32],
}

impl PageMap {
    fn new(cipher: &Cipher, prev: [u8; 32], nonces: Vec<[u8; 8]>) -> Self {
        let mut map = Self {
            prev,
            nonces,
            mac: [0; 32],
        };
        map.mac = cipher.map_mac(&map.content());
        map
    }

    /// Bytes cobertos pelo MAC.
    fn content(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40 + self.nonces.len() * 8);
        out.extend_from_slice(MAP_MAGIC);
        out.extend_from_slice(&self.prev);
        out.extend_from_slice(&(self.nonces.len() as u32).to_le_bytes());
        for nonce in &self.nonces {
            out.extend_from_slice(nonce);
        }
        out
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = self.content();
        out.extend_from_slice(&self.mac);
        out
    }

    /// `None` se o formato ou o MAC não conferem.
    fn decode(bytes: &[u8], cipher: &Cipher) -> Option<Self> {
        if bytes.len() < 72 || &bytes[..4] != MAP_MAGIC {
            return None;
        }
        let count = u32::from_le_bytes(bytes[36..40].try_into().ok()?) as usize;
        if bytes.len() != count.checked_mul(8)?.checked_add(72)? {
            return None;
        }
        let (content, mac) = bytes.split_at(bytes.len() - 32);
        if !constant_time_eq(&cipher.map_mac(content), mac) {
            return None;
        }
        Some(Self {
            prev: bytes[4..36].try_into().ok()?,
            nonces: content[40..]
                .chunks_exact(8)
                .map(|c| c.try_into().expect("8 bytes"))
                .collect(),
            mac: mac.try_into().ok()?,
        })
    }

    /// Sucessor com os nonces de `updates` (cresce até a maior página).
    fn successor(&self, cipher: &Cipher, updates: &[(u32, [u8; 8])]) -> Self {
        let mut nonces = self.nonces.clone();
        for &(id, nonce) in updates {
            let id = id as usize;
            if id >= nonces.len() {
                nonces.resize(id + 1, [0; 8]);
            }
            nonces[id] = nonce;
        }
        Self::new(cipher, self.mac, nonces)
    }

    /// Publica em `path` de forma atômica (temporário + fsync + rename).
    fn publish(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("pages.tmp");
        let mut file = File::create(&tmp)?;
        file.write_all(&self.encode())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        sync_dir(path)
    }
}

/// Mapa instalado de `path`, ou o mapa vazio de um banco novo (ausente ou ilegível).
fn installed_map(path: &Path, cipher: &Cipher) -> PageMap {
    fs::read(map_path(path))
        .ok()
        .and_then(|bytes| PageMap::decode(&bytes, cipher))
        .unwrap_or_else(|| PageMap::new(cipher, [0; 32], Vec::new()))
}

/// Mapa instalado de `path`. Ausente só vale para arquivo vazio (banco novo);
/// ausente com dados, ou com MAC que não confere, é corrupção.
fn load_page_map(path: &Path, file: &File, cipher: &Cipher) -> Result<PageMap> {
    let empty = file.metadata()?.len() == 0;
    match fs::read(map_path(path)) {
        Ok(bytes) => PageMap::decode(&bytes, cipher).ok_or(Error::CorruptPage(0)),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        Err(_) if empty => Ok(PageMap::new(cipher, [0; 32], Vec::new())),
        Err(_) => Err(Error::CorruptPage(0)),
    }
}

/// Grava em `path` um mapa novo (sem antecessor) com os nonces das páginas `0..n`.
pub(crate) fn write_page_map(path: &Path, cipher: &Cipher, nonces: Vec<[u8; 8]>) -> Result<()> {
    PageMap::new(cipher, [0; 32], nonces).publish(path)
}

/// Depois da troca de um arquivo de dados: instala o mapa pendente dele, se houver.
pub(crate) fn install_page_map(path: &Path) -> Result<()> {
    let pending = pending_map_path(path);
    if pending.exists() {
        fs::rename(&pending, map_path(path))?;
        sync_dir(path)?;
    }
    Ok(())
}

/// Publica o arquivo de dados `from` (fechado) no lugar de `to`, com o mapa de
/// páginas dele, se houver. O rename do arquivo é o commit: o mapa vai antes para
/// `to.pages.next` e só depois para o lugar; uma queda entre os dois é resolvida
/// na abertura (ver [`resolve_pending_map`]).
pub(crate) fn replace_data_file(from: &Path, to: &Path) -> Result<()> {
    let map = map_path(from);
    if map.exists() {
        fs::rename(&map, pending_map_path(to))?;
        sync_dir(to)?;
    }
    fs::rename(from, to)?;
    sync_dir(to)?;
    install_page_map(to)
}

/// Troca de arquivo de dados interrompida entre o rename do arquivo e o do mapa:
/// o mapa pendente vale se for o do `data.mdb` atual (a página 0 abre com ele) e o
/// instalado não for; senão é sobra de uma troca que não aconteceu.
fn resolve_pending_map(path: &Path, file: &mut File, cipher: &Cipher) -> Result<()> {
    let pending = pending_map_path(path);
    let Ok(bytes) = fs::read(&pending) else {
        return Ok(());
    };
    let len = file.metadata()?.len();
    let mut fits = |map: &PageMap| -> Result<bool> {
        if len < PAGE_SIZE as u64 {
            return Ok(map.nonces.is_empty());
        }
        let Some(nonce) = map.nonces.first() else {
            return Ok(false);
        };
        let image = read_image(file, 0)?;
        Ok(cipher.open_page(0, &image, Some(nonce)).is_ok())
    };
    let current = fs::read(map_path(path))
        .ok()
        .and_then(|b| PageMap::decode(&b, cipher));
    let current_fits = match &current {
        Some(map) => fits(map)?,
        None => false,
    };
    let pending_fits = match PageMap::decode(&bytes, cipher) {
        Some(map) if !current_fits => fits(&map)?,
        _ => false,
    };
    if pending_fits {
        fs::rename(&pending, map_path(path))?;
    } else {
        fs::remove_file(&pending)?;
    }
    sync_dir(path)
}

/// Imagens de página de um journal (`(page_id, bytes)`) e, na v3, o mapa novo.
struct Journal {
    pages: Vec<(u32, Vec<u8>)>,
    map: Option<Vec<u8>>,
}

/// Lê um journal inteiro; `None` se estiver incompleto ou corrompido.
fn read_journal(jpath: &Path) -> Result<Option<Journal>> {
    let journal = File::open(jpath)?;
    let len = journal.metadata()?.len();
    let mut r = BufReader::new(journal);
    let parsed = (|| -> std::io::Result<Option<Journal>> {
        let mut head = [0u8; 8];
        r.read_exact(&mut head)?;
        let with_map = if &head[..4] == JOURNAL_MAGIC_MAP {
            true
        } else if &head[..4] == JOURNAL_MAGIC {
            false
        } else {
            return Ok(None);
        };
        let count = u32::from_le_bytes(head[4..8].try_into().expect("4")) as u64;
        let pages_end = 8 + count * (4 + PAGE_SIZE as u64);
        if (with_map && len < pages_end + 12) || (!with_map && len != pages_end + 8) {
            return Ok(None);
        }
        let mut crc = crc32_update(0xFFFF_FFFF, &head);
        let mut pages = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut id = [0u8; 4];
            let mut page = vec![0u8; PAGE_SIZE];
            r.read_exact(&mut id)?;
            r.read_exact(&mut page)?;
            crc = crc32_update(crc, &id);
            crc = crc32_update(crc, &page);
            pages.push((u32::from_le_bytes(id), page));
        }
        let mut map = None;
        if with_map {
            let mut n = [0u8; 4];
            r.read_exact(&mut n)?;
            crc = crc32_update(crc, &n);
            let n = u32::from_le_bytes(n) as u64;
            if len != pages_end + 4 + n + 8 {
                return Ok(None);
            }
            let mut bytes = vec![0u8; n as usize];
            r.read_exact(&mut bytes)?;
            crc = crc32_update(crc, &bytes);
            map = Some(bytes);
        }
        let mut tail = [0u8; 8];
        r.read_exact(&mut tail)?;
        let ok = &tail[..4] == JOURNAL_END
            && u32::from_le_bytes(tail[4..8].try_into().expect("4")) == !crc;
        Ok(ok.then_some(Journal { pages, map }))
    })();
    Ok(parsed.unwrap_or(None))
}

/// Reaplica um journal completo; descarta um incompleto. Devolve se aplicou.
///
/// Na v3 o journal precisa trazer um mapa autêntico que descenda do mapa instalado
/// (ainda não publicado) ou que seja ele (publicado, faltou apagar o journal). Um
/// journal de outro ponto da história, ou de formato que não combina com a cifra,
/// é descartado sem tocar em nada.
fn recover_journal(path: &Path, file: &mut File, cipher: Option<&Cipher>) -> Result<bool> {
    let jpath = journal_path(path);
    if !jpath.exists() {
        return Ok(false);
    }
    let journal = read_journal(&jpath)?;
    let mut publish = None;
    let apply = match (&journal, cipher.filter(|c| c.uses_page_map())) {
        (None, _) => false,
        (Some(j), None) => j.map.is_none(),
        (Some(j), Some(c)) => match j.map.as_deref().and_then(|b| PageMap::decode(b, c)) {
            Some(new) => {
                let current = installed_map(path, c);
                if new.prev == current.mac {
                    publish = Some(new);
                    true
                } else {
                    new.mac == current.mac
                }
            }
            None => false,
        },
    };
    if let (true, Some(journal)) = (apply, &journal) {
        for (id, page) in &journal.pages {
            file.seek(SeekFrom::Start(*id as u64 * PAGE_SIZE as u64))?;
            file.write_all(page)?;
        }
        file.sync_all()?;
        if let Some(map) = publish {
            map.publish(&map_path(path))?;
        }
    }
    fs::remove_file(&jpath)?;
    sync_dir(path)?;
    Ok(apply)
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
        let map_cipher = cipher.as_deref().filter(|c| c.uses_page_map());
        if let Some(c) = map_cipher {
            resolve_pending_map(&path, &mut file, c)?;
        }
        recover_journal(&path, &mut file, cipher.as_deref())?;
        if file.metadata()?.len() % PAGE_SIZE as u64 != 0 {
            return Err(Error::CorruptPage(0));
        }
        let map = map_cipher
            .map(|c| load_page_map(&path, &file, c))
            .transpose()?;
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
                spill_nonces: HashMap::new(),
                frames: HashMap::new(),
                capacity: capacity.max(8),
                clock: 0,
                cipher,
                map,
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
        // Nonce de cada página: o mesmo no journal e no arquivo (a mesma imagem).
        let cipher = inner.cipher.clone();
        let nonces: Vec<(u32, [u8; 8])> = ids
            .iter()
            .map(|&id| (id, fresh_nonce(cipher.as_deref())))
            .collect();
        let new_map = match (&inner.map, cipher.as_deref()) {
            (Some(map), Some(c)) => Some(map.successor(c, &nonces)),
            _ => None,
        };
        // 1. Journal com as imagens novas (e, na v3, o mapa novo).
        let jpath = journal_path(&path);
        {
            let mut w = BufWriter::new(File::create(&jpath)?);
            let magic = match new_map {
                Some(_) => JOURNAL_MAGIC_MAP,
                None => JOURNAL_MAGIC,
            };
            let mut head = magic.to_vec();
            head.extend_from_slice(&(ids.len() as u32).to_le_bytes());
            let mut crc = crc32_update(0xFFFF_FFFF, &head);
            w.write_all(&head)?;
            for (id, nonce) in &nonces {
                let image = inner.image(*id)?;
                let page = sealed(&image, cipher.as_deref(), nonce);
                let id_bytes = id.to_le_bytes();
                crc = crc32_update(crc, &id_bytes);
                crc = crc32_update(crc, &page.data);
                w.write_all(&id_bytes)?;
                w.write_all(&page.data)?;
            }
            if let Some(map) = &new_map {
                let bytes = map.encode();
                let n = (bytes.len() as u32).to_le_bytes();
                crc = crc32_update(crc, &n);
                crc = crc32_update(crc, &bytes);
                w.write_all(&n)?;
                w.write_all(&bytes)?;
            }
            w.write_all(JOURNAL_END)?;
            w.write_all(&(!crc).to_le_bytes())?;
            w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        }
        sync_dir(&path)?;
        // 2. Escrita no lugar (e o mapa novo).
        for (id, nonce) in &nonces {
            let image = inner.image(*id)?;
            let page = sealed(&image, cipher.as_deref(), nonce);
            inner
                .file
                .seek(SeekFrom::Start(*id as u64 * PAGE_SIZE as u64))?;
            inner.file.write_all(&page.data)?;
        }
        inner.file.sync_all()?;
        if let Some(map) = new_map {
            map.publish(&map_path(&path))?;
            inner.map = Some(map);
        }
        // 3. Checkpoint publicado: o journal não é mais necessário.
        fs::remove_file(&jpath)?;
        sync_dir(&path)?;
        inner.spilled.clear();
        inner.spill_nonces.clear();
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
        inner.spill_nonces.retain(|id, _| *id < first);
    }

    /// Encolhe o arquivo publicado para `pages` páginas. Só remove páginas
    /// inalcançáveis; um crash no meio deixa apenas lixo além do high-water.
    pub fn truncate_pages(&mut self, pages: u32) -> Result<()> {
        self.discard_from(pages);
        let path = self.path.clone();
        let inner = self.inner_mut();
        // v3: o mapa encolhe antes do arquivo; uma queda entre os dois só deixa no
        // fim do arquivo páginas que o mapa já não conhece (lidas como livres).
        let shorter = match (&inner.map, inner.cipher.as_deref()) {
            (Some(map), Some(c)) if map.nonces.len() > pages as usize => {
                let nonces = map.nonces[..pages as usize].to_vec();
                Some(PageMap::new(c, map.mac, nonces))
            }
            _ => None,
        };
        if let Some(map) = shorter {
            map.publish(&map_path(&path))?;
            inner.map = Some(map);
        }
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
    fn read_page_at(
        file: &mut File,
        page_id: u32,
        cipher: Option<&Cipher>,
        nonce: Option<&[u8; 8]>,
    ) -> Result<Page> {
        let buf = read_image(file, page_id)?;
        let page = match cipher {
            // Páginas cifradas: a posição lida é o id esperado (a etiqueta o autentica).
            Some(c) => c.open_page(page_id, &buf, nonce)?,
            None => {
                let page = Page::from_bytes(&buf)?;
                if page.page_id() != page_id {
                    return Err(Error::CorruptPage(page_id));
                }
                page
            }
        };
        page.validate_header()?;
        Ok(page)
    }

    fn read_from_disk(&mut self, page_id: u32) -> Result<Page> {
        let cipher = self.cipher.as_deref();
        if self.spilled.contains(&page_id) {
            let nonce = self.spill_nonces.get(&page_id);
            return Self::read_page_at(&mut self.spill, page_id, cipher, nonce);
        }
        let end = page_id as u64 * PAGE_SIZE as u64 + PAGE_SIZE as u64;
        let len = self.file.metadata()?.len();
        if let Some(map) = &self.map {
            // v3: o mapa diz quais páginas existem. Uma que ele conhece e o arquivo
            // não tem é truncamento, não página nova.
            return match map.nonces.get(page_id as usize) {
                Some(nonce) if end <= len => {
                    Self::read_page_at(&mut self.file, page_id, cipher, Some(nonce))
                }
                Some(_) => Err(Error::CorruptPage(page_id)),
                None => Ok(Page::zeroed(page_id, PageKind::Free)),
            };
        }
        if end > len {
            // Página ainda não alocada no arquivo — devolve zeroed Free.
            return Ok(Page::zeroed(page_id, PageKind::Free));
        }
        Self::read_page_at(&mut self.file, page_id, cipher, None)
    }

    /// Imagem atual de uma página alterada (frame sujo ou spill).
    fn image(&mut self, id: u32) -> Result<Arc<Page>> {
        match self.frames.get(&id) {
            Some(frame) => Ok(Arc::clone(&frame.page)),
            None => {
                let nonce = self.spill_nonces.get(&id);
                let cipher = self.cipher.as_deref();
                let page = Self::read_page_at(&mut self.spill, id, cipher, nonce)?;
                Ok(Arc::new(page))
            }
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
                let cipher = self.cipher.as_deref();
                let nonce = fresh_nonce(cipher);
                self.spill
                    .seek(SeekFrom::Start(victim as u64 * PAGE_SIZE as u64))?;
                self.spill
                    .write_all(&sealed(&frame.page, cipher, &nonce).data)?;
                self.spilled.insert(victim);
                self.spill_nonces.insert(victim, nonce);
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
