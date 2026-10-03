//! Criptografia em repouso: páginas de `data.mdb` (e spill/journal) e frames
//! do WAL cifrados com ChaCha20, chave derivada da senha por PBKDF2-HMAC-SHA256.
//!
//! Há três formatos de página, escolhidos pela versão do `data.mdb.key`:
//!
//! - **v3 (bancos novos; chave de versão 3)**: cada página é um ChaCha20-Poly1305
//!   (RFC 8439) com etiqueta inteira de 128 bits e AAD com o id da posição. A
//!   imagem em disco é `etiqueta(16) ‖ campos do cabeçalho cifrados(14) ‖ 2 bytes
//!   ‖ corpo cifrado(4064)`. O nonce não fica na página: fica no **mapa de
//!   páginas** `data.mdb.pages` (ver [`crate::buffer`]), que guarda o nonce atual de
//!   cada página e é autenticado por HMAC-SHA256 com uma subchave do banco. Cada
//!   gravação sorteia um nonce novo, então devolver uma versão antiga e válida de
//!   uma página (*replay*) falha como [`Error::CorruptPage`]: o mapa já aponta para
//!   o nonce novo. Também falham byte alterado, página trocada de lugar e arquivo
//!   truncado. Só o retorno do diretório inteiro a um estado anterior (todas as
//!   páginas, o mapa e o WAL juntos, como restaurar um backup) não é detectável sem
//!   uma âncora externa.
//! - **v2 (chave de versão 2)**: `nonce(8) ‖ etiqueta(10) ‖ campos(14) ‖ corpo`,
//!   etiqueta truncada em 80 bits e sem mapa (não detecta replay).
//! - **v1 (legado, chave de versão 1)**: cabeçalho em claro, corpo cifrado com
//!   nonce aleatório de 8 bytes no campo `lsn`; o checksum CRC16 do texto claro
//!   só detecta senha errada ou corrupção acidental.
//!
//! Bancos v1 e v2 são migrados para v3 automaticamente na primeira abertura com
//! a senha ([`upgrade`]), mantendo a mesma chave: o WAL arquivado continua
//! valendo (na v1, os segmentos são regravados no formato autenticado).
//!
//! No WAL, as cifras v2 e v3 gravam cada payload como ChaCha20-Poly1305 com uma
//! subchave só do WAL, nonce aleatório de 12 bytes e AAD com o LSN do frame
//! anterior no arquivo, o LSN e o tipo do registro: frame alterado, removido,
//! repetido ou fora de ordem dá [`Error::CorruptWal`]. Na v1 cada frame leva 4
//! bytes de sal + LSN como nonce, sem etiqueta; a integridade fica a cargo do CRC.
//!
//! O arquivo `data.mdb.key` guarda sal, iterações e um verificador da chave
//! (nunca a chave). Sem ele o banco não é criptografado.

use crate::crypto::{
    aead_open, aead_seal, aead_tag_of, chacha20_xor, constant_time_eq, hmac_sha256, pbkdf2_sha256,
    random_bytes,
};
use crate::error::{Error, Result};
use crate::page::{Page, PageKind, PAGE_HEADER_SIZE, PAGE_SIZE};
use std::fs;
use std::path::{Path, PathBuf};

const KEY_MAGIC: &[u8; 4] = b"MDBK";
/// Versão da chave de bancos com páginas v1 (sem etiqueta).
const KEY_VERSION_LEGACY: u8 = 1;
/// Versão da chave de bancos com páginas v2 (etiqueta de 80 bits, sem mapa).
const KEY_VERSION_V2: u8 = 2;
/// Versão da chave de bancos com páginas v3 (etiqueta de 128 bits e mapa).
const KEY_VERSION: u8 = 3;
/// Iterações do PBKDF2 para a chave do banco (senha → chave, uma vez por abertura).
pub const KEY_ITERATIONS: u32 = 20_000;

/// Bytes da etiqueta Poly1305 guardados no cabeçalho de cada página v2 (80 bits).
const PAGE_TAG_LEN: usize = 10;
/// Fim da etiqueta na imagem v2: `nonce(8) ‖ etiqueta`.
const TAG_END: usize = 8 + PAGE_TAG_LEN;
/// Campos do cabeçalho em memória (`kind` … `extra`, bytes 8..22) que as imagens
/// v2 e v3 guardam cifrados logo após a etiqueta.
const FIELDS_START: usize = 8;
const FIELDS_END: usize = 22;
const _: () = assert!(TAG_END + FIELDS_END - FIELDS_START == PAGE_HEADER_SIZE);
/// Imagem v3: `etiqueta(16) ‖ campos(14) ‖ 2 bytes ‖ corpo`.
const V3_TAG_END: usize = 16;
const _: () = assert!(V3_TAG_END + FIELDS_END - FIELDS_START + 2 == PAGE_HEADER_SIZE);

pub struct Cipher {
    key: [u8; 32],
    /// Subchave dos frames autenticados do WAL (v2 e v3): os nonces do WAL nunca
    /// concorrem com os das páginas.
    wal_key: [u8; 32],
    /// Subchave do MAC do mapa de páginas (v3).
    map_key: [u8; 32],
    /// Formato das páginas: 1 (legado), 2 ou 3.
    version: u8,
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cipher(..)")
    }
}

impl Cipher {
    /// Cifra com páginas v3: é o formato de todo banco novo.
    pub fn from_passphrase(passphrase: &str, salt: &[u8], iterations: u32) -> Self {
        let key = pbkdf2_sha256(passphrase.as_bytes(), salt, iterations);
        Self {
            wal_key: hmac_sha256(&key, &[b"minidb wal v2 key"]),
            map_key: hmac_sha256(&key, &[b"minidb page map v3 key"]),
            key,
            version: KEY_VERSION,
        }
    }

    /// Mesma chave no formato de página legado (v1, sem etiqueta), para abrir
    /// bancos criados antes da autenticação de páginas.
    pub fn legacy(self) -> Self {
        self.with_page_format(KEY_VERSION_LEGACY)
    }

    /// Mesma chave com outro formato de página (1, 2 ou 3).
    pub fn with_page_format(mut self, version: u8) -> Self {
        self.version = version.clamp(KEY_VERSION_LEGACY, KEY_VERSION);
        self
    }

    /// Formato das páginas (1, 2 ou 3).
    pub fn page_format(&self) -> u8 {
        self.version
    }

    /// `true` se as páginas levam etiqueta Poly1305 (v2 e v3) e os frames do WAL
    /// são autenticados.
    pub fn is_authenticated(&self) -> bool {
        self.version >= KEY_VERSION_V2
    }

    /// `true` se o nonce das páginas fica no mapa `data.mdb.pages` (v3).
    pub fn uses_page_map(&self) -> bool {
        self.version >= KEY_VERSION
    }

    fn check(&self) -> [u8; 32] {
        hmac_sha256(&self.key, &[b"minidb key check"])
    }

    /// MAC do conteúdo do mapa de páginas (v3).
    pub fn map_mac(&self, content: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.map_key, &[b"minidb page map v3", content])
    }

    /// Transforma a página (formato de memória) na imagem de disco, em `page.data`,
    /// com um nonce novo, e devolve esse nonce (na v3 é o mapa que o guarda).
    pub fn seal_page(&self, page: &mut Page) -> [u8; 8] {
        let nonce8 = random_bytes::<8>();
        self.seal_page_with(page, &nonce8);
        nonce8
    }

    /// Como [`Cipher::seal_page`], com o nonce dado: o mesmo nonce e a mesma página
    /// dão a mesma imagem. Um nonce nunca deve selar duas páginas diferentes.
    pub fn seal_page_with(&self, page: &mut Page, nonce8: &[u8; 8]) {
        match self.version {
            KEY_VERSION_LEGACY => self.seal_page_v1(page, nonce8),
            KEY_VERSION_V2 => self.seal_page_v2(page, nonce8),
            _ => self.seal_page_v3(page, nonce8),
        }
    }

    /// v1: nonce no campo `lsn`, checksum sobre o texto claro, corpo cifrado.
    fn seal_page_v1(&self, page: &mut Page, nonce8: &[u8; 8]) {
        page.set_lsn(u64::from_le_bytes(*nonce8));
        page.write_checksum();
        let nonce = page_nonce(page.page_id(), nonce8);
        chacha20_xor(&self.key, &nonce, 0, &mut page.data[PAGE_HEADER_SIZE..]);
    }

    /// v2: `nonce(8) ‖ etiqueta(10) ‖ cifra(campos do cabeçalho ‖ corpo)`.
    fn seal_page_v2(&self, page: &mut Page, nonce8: &[u8; 8]) {
        let id = page.page_id();
        let nonce = page_nonce(id, nonce8);
        let mut body = Vec::with_capacity(PAGE_SIZE - TAG_END);
        body.extend_from_slice(&page.data[FIELDS_START..FIELDS_END]);
        body.extend_from_slice(&page.data[PAGE_HEADER_SIZE..]);
        chacha20_xor(&self.key, &nonce, 1, &mut body);
        let tag = aead_tag_of(&self.key, &nonce, &page_aad(PAGE_V2, id), &body);
        page.data[..8].copy_from_slice(nonce8);
        page.data[8..TAG_END].copy_from_slice(&tag[..PAGE_TAG_LEN]);
        page.data[TAG_END..].copy_from_slice(&body);
    }

    /// v3: `etiqueta(16) ‖ cifra(campos do cabeçalho ‖ 2 zeros ‖ corpo)`.
    fn seal_page_v3(&self, page: &mut Page, nonce8: &[u8; 8]) {
        let id = page.page_id();
        let nonce = page_nonce(id, nonce8);
        let mut body = Vec::with_capacity(PAGE_SIZE - V3_TAG_END);
        body.extend_from_slice(&page.data[FIELDS_START..FIELDS_END]);
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&page.data[PAGE_HEADER_SIZE..]);
        chacha20_xor(&self.key, &nonce, 1, &mut body);
        let tag = aead_tag_of(&self.key, &nonce, &page_aad(PAGE_V3, id), &body);
        page.data[..V3_TAG_END].copy_from_slice(&tag);
        page.data[V3_TAG_END..].copy_from_slice(&body);
    }

    /// Lê a imagem de disco da página `page_id` (a posição onde ela foi lida).
    /// Na v3, `nonce8` é o nonce que o mapa guarda para a página (`None` = o mapa
    /// não a conhece: corrupção); v1 e v2 o ignoram (o nonce está na imagem).
    /// v2 e v3 conferem a etiqueta (alteração, troca de posição, versão antiga ou
    /// chave errada dão [`Error::CorruptPage`]); a v1 só o checksum.
    pub fn open_page(&self, page_id: u32, image: &[u8], nonce8: Option<&[u8; 8]>) -> Result<Page> {
        if image.len() != PAGE_SIZE {
            return Err(Error::CorruptPage(page_id));
        }
        match (self.version, nonce8) {
            (KEY_VERSION_LEGACY, _) => self.open_page_v1(page_id, image),
            (KEY_VERSION_V2, _) => self.open_page_v2(page_id, image),
            (_, Some(nonce8)) => self.open_page_v3(page_id, image, nonce8),
            (_, None) => Err(Error::CorruptPage(page_id)),
        }
    }

    fn open_page_v1(&self, page_id: u32, image: &[u8]) -> Result<Page> {
        let mut page = Page::from_bytes(image)?;
        if page.page_id() != page_id {
            return Err(Error::CorruptPage(page_id));
        }
        let nonce8 = page.lsn().to_le_bytes();
        let nonce = page_nonce(page_id, &nonce8);
        chacha20_xor(&self.key, &nonce, 0, &mut page.data[PAGE_HEADER_SIZE..]);
        if page.stored_checksum() != 0 && page.compute_checksum() != page.stored_checksum() {
            return Err(Error::Other(format!(
                "página {page_id} não decifra: senha incorreta ou arquivo corrompido"
            )));
        }
        Ok(page)
    }

    fn open_page_v2(&self, page_id: u32, image: &[u8]) -> Result<Page> {
        let nonce8: [u8; 8] = image[..8].try_into().expect("8 bytes");
        let nonce = page_nonce(page_id, &nonce8);
        let mut body = image[TAG_END..].to_vec();
        let tag = aead_tag_of(&self.key, &nonce, &page_aad(PAGE_V2, page_id), &body);
        if !constant_time_eq(&tag[..PAGE_TAG_LEN], &image[8..TAG_END]) {
            return Err(Error::CorruptPage(page_id));
        }
        chacha20_xor(&self.key, &nonce, 1, &mut body);
        let (fields, rest) = body.split_at(FIELDS_END - FIELDS_START);
        Ok(plain_page(page_id, fields, rest))
    }

    fn open_page_v3(&self, page_id: u32, image: &[u8], nonce8: &[u8; 8]) -> Result<Page> {
        let nonce = page_nonce(page_id, nonce8);
        let mut body = image[V3_TAG_END..].to_vec();
        let tag = aead_tag_of(&self.key, &nonce, &page_aad(PAGE_V3, page_id), &body);
        if !constant_time_eq(&tag, &image[..V3_TAG_END]) {
            return Err(Error::CorruptPage(page_id));
        }
        chacha20_xor(&self.key, &nonce, 1, &mut body);
        let (fields, rest) = body.split_at(FIELDS_END - FIELDS_START);
        Ok(plain_page(page_id, fields, &rest[2..]))
    }

    /// Cifra o payload de um frame do WAL.
    ///
    /// - v2/v3: `nonce(12) ‖ texto cifrado ‖ etiqueta(16)`. O nonce é aleatório porque
    ///   um LSN pode voltar a ser usado com outro conteúdo (cauda descartada no
    ///   recovery, restauração até um ponto). O AAD leva `prev_lsn` (LSN do frame
    ///   anterior no arquivo, 0 no primeiro), o LSN e o tipo `ty`.
    /// - v1: `sal(4) ‖ texto cifrado`, sem etiqueta; `prev_lsn` e `ty` não entram.
    pub fn seal_wal(&self, prev_lsn: u64, lsn: u64, ty: u8, payload: &[u8]) -> Vec<u8> {
        if self.is_authenticated() {
            let nonce = random_bytes::<12>();
            let aad = wal_aad(prev_lsn, lsn, ty);
            let mut out = nonce.to_vec();
            out.extend_from_slice(&aead_seal(&self.wal_key, &nonce, &aad, payload));
            return out;
        }
        let salt = random_bytes::<4>();
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(payload);
        chacha20_xor(&self.key, &wal_nonce(lsn, &salt), 0, &mut out[4..]);
        out
    }

    /// Abre o payload gravado por [`Cipher::seal_wal`]. Na v2/v3, etiqueta que não
    /// confere (byte alterado, outro frame anterior, LSN ou tipo trocados) dá
    /// [`Error::CorruptWal`].
    pub fn open_wal(&self, prev_lsn: u64, lsn: u64, ty: u8, data: &[u8]) -> Result<Vec<u8>> {
        if self.is_authenticated() {
            if data.len() < 12 {
                return Err(Error::CorruptWal(lsn));
            }
            let (nonce, sealed) = data.split_at(12);
            let nonce: [u8; 12] = nonce.try_into().expect("12 bytes");
            let aad = wal_aad(prev_lsn, lsn, ty);
            let plain = aead_open(&self.wal_key, &nonce, &aad, sealed);
            return plain.ok_or(Error::CorruptWal(lsn));
        }
        if data.len() < 4 {
            return Err(Error::CorruptWal(lsn));
        }
        let salt: [u8; 4] = data[..4].try_into().expect("4 bytes");
        let mut out = data[4..].to_vec();
        chacha20_xor(&self.key, &wal_nonce(lsn, &salt), 0, &mut out);
        Ok(out)
    }
}

/// Rótulos dos dados autenticados das páginas v2 e v3.
const PAGE_V2: &[u8; 14] = b"minidb page v2";
const PAGE_V3: &[u8; 14] = b"minidb page v3";

/// Página em memória a partir dos campos do cabeçalho e do corpo decifrados.
fn plain_page(page_id: u32, fields: &[u8], body: &[u8]) -> Page {
    let mut page = Page::zeroed(page_id, PageKind::Free);
    page.data[FIELDS_START..FIELDS_END].copy_from_slice(fields);
    page.data[PAGE_HEADER_SIZE..].copy_from_slice(body);
    page.write_checksum();
    page
}

fn page_nonce(page_id: u32, nonce8: &[u8; 8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&page_id.to_le_bytes());
    n[4..].copy_from_slice(nonce8);
    n
}

/// Dados autenticados de uma página v2/v3: rótulo do formato e a posição (id).
fn page_aad(label: &[u8; 14], page_id: u32) -> [u8; 18] {
    let mut aad = [0u8; 18];
    aad[..14].copy_from_slice(label);
    aad[14..].copy_from_slice(&page_id.to_le_bytes());
    aad
}

/// Dados autenticados de um frame v2 do WAL: rótulo do formato, LSN do frame
/// anterior no arquivo (0 no primeiro), LSN e tipo do registro.
fn wal_aad(prev_lsn: u64, lsn: u64, ty: u8) -> [u8; 30] {
    let mut aad = [0u8; 30];
    aad[..13].copy_from_slice(b"minidb wal v2");
    aad[13..21].copy_from_slice(&prev_lsn.to_le_bytes());
    aad[21..29].copy_from_slice(&lsn.to_le_bytes());
    aad[29] = ty;
    aad
}

fn wal_nonce(lsn: u64, salt: &[u8; 4]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(salt);
    n[4..].copy_from_slice(&lsn.to_le_bytes());
    n
}

pub fn keyfile_path(dir: &Path) -> PathBuf {
    dir.join("data.mdb.key")
}

/// Abre a chave do banco em `dir`:
/// - sem `data.mdb.key` e sem senha → banco em claro (`None`);
/// - sem `data.mdb.key`, com senha → cria a chave (só para banco novo/vazio);
/// - com `data.mdb.key` → exige a senha e confere o verificador.
pub fn open_key(dir: &Path, passphrase: Option<&str>, has_data: bool) -> Result<Option<Cipher>> {
    let path = keyfile_path(dir);
    match (fs::read(&path).ok(), passphrase) {
        (None, None) => Ok(None),
        (None, Some(pass)) => {
            if has_data {
                return Err(Error::Other(
                    "o banco existente não é criptografado: crie um banco novo com senha e \
                     restaure um backup/export nele"
                        .into(),
                ));
            }
            let salt = random_bytes::<16>();
            let cipher = Cipher::from_passphrase(pass, &salt, KEY_ITERATIONS);
            let mut raw = KEY_MAGIC.to_vec();
            raw.push(KEY_VERSION);
            raw.extend_from_slice(&KEY_ITERATIONS.to_le_bytes());
            raw.extend_from_slice(&salt);
            raw.extend_from_slice(&cipher.check());
            write_key_file(&path, &raw)?;
            Ok(Some(cipher))
        }
        (Some(_), None) => Err(Error::Other(
            "banco criptografado: informe a senha (MINIDB_PASSPHRASE ou passphrase no minidb.toml)"
                .into(),
        )),
        (Some(raw), Some(pass)) => {
            let version = raw.get(4).copied().unwrap_or(0);
            if raw.len() != 57
                || &raw[..4] != KEY_MAGIC
                || !(KEY_VERSION_LEGACY..=KEY_VERSION).contains(&version)
            {
                return Err(Error::Other("data.mdb.key inválido".into()));
            }
            let iterations = u32::from_le_bytes(raw[5..9].try_into().expect("4"));
            let cipher = Cipher::from_passphrase(pass, &raw[9..25], iterations);
            let cipher = cipher.with_page_format(version);
            if !constant_time_eq(&cipher.check(), &raw[25..57]) {
                return Err(Error::Other(
                    "senha incorreta para o banco criptografado".into(),
                ));
            }
            Ok(Some(cipher))
        }
    }
}

const CONVERT_TMP: &str = "data.mdb.convert";
const CONVERT_OLD_KEY: &str = "data.mdb.key.old";
const CONVERT_STATE: &str = "data.mdb.convert.state";
const STATE_ENCRYPTED: &[u8] = b"encrypted";
const STATE_PLAIN: &[u8] = b"plain";
/// Migração de formato com a mesma chave ([`upgrade`]): o WAL arquivado fica.
const STATE_UPGRADE: &[u8] = b"upgrade";
/// Extensão dos segmentos do WAL arquivado regravados por [`upgrade`] (banco v1):
/// só substituem os originais depois do commit.
const UPGRADED_SEGMENT: &str = "upgrade";

/// Grava o arquivo de chave com `sync_all`: ele guarda o sal; sem ele a senha não
/// abre mais nada.
fn write_key_file(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = fs::File::create(path)?;
    std::io::Write::write_all(&mut file, raw)?;
    file.sync_all()?;
    Ok(())
}

/// Arquivos do WAL arquivado com a extensão `ext`, em ordem.
fn archive_files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(crate::Db::archive_dir(dir))
        .map(|entries| {
            entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == ext))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

/// Troca os segmentos originais pelos regravados por [`upgrade`].
fn publish_upgraded_segments(dir: &Path) -> Result<()> {
    for path in archive_files(dir, UPGRADED_SEGMENT) {
        fs::rename(&path, path.with_extension("wal"))?;
    }
    Ok(())
}

/// Sobras de uma conversão que não chegou ao commit: o mapa novo e os segmentos
/// regravados. O `data.mdb`, o mapa e o WAL originais continuam valendo.
fn discard_convert_leftovers(dir: &Path) -> Result<()> {
    let pending = crate::buffer::pending_map_path(&crate::Db::data_path(dir));
    if pending.exists() {
        fs::remove_file(pending)?;
    }
    for path in archive_files(dir, UPGRADED_SEGMENT) {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Desfaz ou conclui um [`convert`]/[`upgrade`] interrompido (crash no meio).
/// Chamado na abertura do banco, antes de ler a chave:
/// - temporário ainda presente → a troca não aconteceu: `data.mdb` é o original
///   e a chave original volta ao lugar;
/// - temporário ausente → a troca aconteceu: só termina a limpeza (o mapa novo de
///   páginas, se ficou pendente, é instalado na abertura do buffer pool).
pub fn recover_convert(dir: &Path) -> Result<()> {
    let state_path = dir.join(CONVERT_STATE);
    let tmp = dir.join(CONVERT_TMP);
    let old_key = dir.join(CONVERT_OLD_KEY);
    let state = match fs::read(&state_path) {
        Ok(state) => state,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Sem estado gravado nada foi trocado: no máximo sobrou o temporário vazio.
            let _ = fs::remove_file(&tmp);
            return Ok(());
        }
        // Erro de leitura não decide nada: apagar o temporário aqui faria a próxima
        // abertura concluir que a troca aconteceu.
        Err(e) => return Err(e.into()),
    };
    if state != STATE_ENCRYPTED && state != STATE_PLAIN && state != STATE_UPGRADE {
        // Estado incompleto: a queda foi durante a gravação dele, antes de qualquer
        // troca. A chave e o `data.mdb` são os originais; só limpa os marcadores.
        let _ = fs::remove_file(&tmp);
        fs::remove_file(&state_path)?;
        return Ok(());
    }
    if tmp.exists() {
        if state == STATE_PLAIN {
            // O banco era em claro: a chave criada para a conversão não vale.
            let _ = fs::remove_file(keyfile_path(dir));
        } else if old_key.exists() {
            // A chave original pode já ter sido movida; a nova (se houver) é descartada.
            fs::rename(&old_key, keyfile_path(dir))?;
        }
        discard_convert_leftovers(dir)?;
        fs::remove_file(&tmp)?;
    } else {
        let _ = fs::remove_file(&old_key);
        if state == STATE_UPGRADE {
            publish_upgraded_segments(dir)?;
        } else {
            let _ = fs::remove_dir_all(crate::Db::archive_dir(dir));
        }
        let data = crate::Db::data_path(dir);
        crate::buffer::install_page_map(&data)?;
        if !keyfile_path(dir).exists() {
            // Virou banco em claro: o mapa de páginas da cifra antiga não vale mais.
            let _ = fs::remove_file(crate::buffer::map_path(&data));
        }
    }
    fs::remove_file(&state_path)?;
    Ok(())
}

/// Converte um banco fechado no lugar: `from` é a senha atual (`None` = em
/// claro) e `to` a nova (`None` = remover a cifra). Faz checkpoint (WAL vazio),
/// reescreve `data.mdb` página a página e troca `data.mdb.key`. O arquivo de
/// WAL arquivado (`wal-archive/`) é descartado: continha frames na cifra antiga.
///
/// O lock do diretório (o mesmo de [`crate::Db::open`]) fica preso do início ao
/// fim: com o banco aberto por outro handle ou processo a conversão falha sem
/// tocar em nada, e ninguém abre o banco enquanto ela roda.
pub fn convert(dir: &Path, from: Option<&str>, to: Option<&str>) -> Result<String> {
    convert_impl(dir, from, to, false)
}

/// Migra um banco cifrado v1/v2 (fechado) para o formato de página v3 com a
/// **mesma chave**: o arquivo de chave só muda de versão, o WAL arquivado continua
/// valendo (num banco v1 os segmentos são regravados com frames autenticados) e
/// réplicas e backups incrementais seguem. [`crate::Db::open_encrypted`] chama na
/// primeira abertura de um banco antigo. Interrompida, é desfeita ou concluída por
/// [`recover_convert`] como uma conversão.
pub fn upgrade(dir: &Path, passphrase: &str) -> Result<String> {
    convert_impl(dir, Some(passphrase), Some(passphrase), true)
}

fn convert_impl(
    dir: &Path,
    from: Option<&str>,
    to: Option<&str>,
    keep_key: bool,
) -> Result<String> {
    use crate::buffer::{install_page_map, map_path, pending_map_path, write_page_map, BufferPool};
    use std::io::Write;
    // Solto só no retorno (sucesso ou erro). Sem ele, um `Db::open` concorrente rodaria
    // `recover_convert`, tomaria a conversão em andamento por interrompida e a desfaria.
    let _lock = {
        // Checkpoint com WAL vazio: tudo fica em data.mdb. Na migração com a mesma
        // chave, um banco que arquiva o WAL arquiva também o atual (o histórico de
        // réplicas e do PITR continua inteiro).
        let mut db = crate::Db::open_without_upgrade(dir, 64, true, from)?;
        let keep_archive = keep_key && crate::Db::archive_dir(dir).exists();
        db.set_wal_retention(if keep_archive { u64::MAX } else { 0 });
        let lock = db.take_lock();
        db.close()?;
        lock
    };
    let data = crate::Db::data_path(dir);
    let old = open_key(dir, from, true)?;
    let key = keyfile_path(dir);
    let backup_key = dir.join(CONVERT_OLD_KEY);
    let tmp = dir.join(CONVERT_TMP);
    let state_path = dir.join(CONVERT_STATE);
    // Marcas para `recover_convert`: o temporário (vazio) e o estado original são
    // gravados antes de qualquer troca. Enquanto o temporário existir, `data.mdb`
    // ainda é o original e a chave pode ser devolvida; o rename final é o commit.
    fs::File::create(&tmp)?.sync_all()?;
    {
        let state: &[u8] = if keep_key {
            STATE_UPGRADE
        } else if key.exists() {
            STATE_ENCRYPTED
        } else {
            STATE_PLAIN
        };
        let mut file = fs::File::create(&state_path)?;
        file.write_all(state)?;
        file.sync_all()?;
    }
    let old_raw = fs::read(&key).ok();
    if key.exists() {
        fs::rename(&key, &backup_key)?;
    }
    let new = match (to, old_raw) {
        (Some(pass), Some(mut raw)) if keep_key => {
            // Mesmo sal e mesmas iterações (mesma chave); só a versão muda.
            raw[4] = KEY_VERSION;
            write_key_file(&key, &raw)?;
            open_key(dir, Some(pass), true)?
        }
        (Some(pass), _) => open_key(dir, Some(pass), false)?,
        (None, _) => None,
    };
    if let (true, Some(old), Some(new)) = (keep_key, &old, &new) {
        if !old.is_authenticated() {
            // Frames v1 (sem etiqueta) viram frames autenticados, com os mesmos LSNs.
            for segment in archive_files(dir, "wal") {
                let dest = segment.with_extension(UPGRADED_SEGMENT);
                crate::wal::rewrite_segment(&segment, &dest, old, new)?;
            }
        }
    }
    let pages = fs::metadata(&data)?.len() / PAGE_SIZE as u64;
    {
        let pool = BufferPool::open_with(&data, 64, old.map(std::sync::Arc::new))?;
        let mut nonces = Vec::with_capacity(pages as usize);
        let mut out = std::io::BufWriter::new(fs::File::create(&tmp)?);
        for id in 0..pages as u32 {
            let mut page = (*pool.get_page(id)?).clone();
            match &new {
                Some(c) => nonces.push(c.seal_page(&mut page)),
                None => page.write_checksum(),
            }
            out.write_all(&page.data)?;
        }
        out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        if let Some(c) = new.as_ref().filter(|c| c.uses_page_map()) {
            // Mapa do arquivo novo, pendente até o commit.
            write_page_map(&pending_map_path(&data), c, nonces)?;
        }
    }
    let _ = fs::remove_file(data.with_extension("mdb.spill"));
    fs::rename(&tmp, &data)?;
    install_page_map(&data)?;
    if new.is_none() {
        let _ = fs::remove_file(map_path(&data));
    }
    if keep_key {
        publish_upgraded_segments(dir)?;
    } else {
        let _ = fs::remove_dir_all(crate::Db::archive_dir(dir));
    }
    let _ = fs::remove_file(backup_key);
    let _ = fs::remove_file(state_path);
    Ok(format!(
        "{} páginas reescritas ({})",
        pages,
        if to.is_some() {
            "banco cifrado"
        } else {
            "banco em claro"
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_and_wal_roundtrip_detect_wrong_key() {
        let c = Cipher::from_passphrase("senha", b"sal", 10);
        assert!(c.is_authenticated() && c.uses_page_map());
        let mut page = Page::zeroed(7, PageKind::Leaf);
        page.set_right_sibling(9);
        page.data[100..104].copy_from_slice(b"jogo");
        let plain = page.clone();
        let nonce = c.seal_page(&mut page);
        assert_ne!(&page.data[100..104], b"jogo");
        let image = page.data;
        let opened = c.open_page(7, &image, Some(&nonce)).unwrap();
        assert_eq!(opened.page_id(), 7);
        assert_eq!(opened.right_sibling(), 9);
        assert_eq!(&opened.data[8..22], &plain.data[8..22]);
        assert_eq!(&opened.data[32..], &plain.data[32..]);
        // Chave errada, outra posição, nonce ausente ou qualquer byte alterado: recusa.
        let wrong = Cipher::from_passphrase("outra", b"sal", 10);
        assert!(wrong.open_page(7, &image, Some(&nonce)).is_err());
        assert!(c.open_page(8, &image, Some(&nonce)).is_err());
        assert!(c.open_page(7, &image, None).is_err());
        for at in [0, 8, 15, 16, 25, 30, 31, 32, 2000, PAGE_SIZE - 1] {
            let mut bad = image;
            bad[at] ^= 1;
            assert!(c.open_page(7, &bad, Some(&nonce)).is_err(), "byte {at}");
        }
        // Replay: a página regravada ganha nonce novo; a imagem antiga, com o nonce
        // que o mapa passa a guardar, não abre mais.
        let mut again = plain.clone();
        let newer = c.seal_page(&mut again);
        assert_ne!(newer, nonce);
        assert!(c.open_page(7, &again.data, Some(&newer)).is_ok());
        assert!(c.open_page(7, &image, Some(&newer)).is_err(), "replay");
        // Mesmo nonce e mesma página: mesma imagem (o journal e o arquivo coincidem).
        let mut twice = plain.clone();
        c.seal_page_with(&mut twice, &nonce);
        assert_eq!(twice.data, image);
        // Formato v2: nonce na própria imagem, etiqueta de 80 bits.
        let v2 = Cipher::from_passphrase("senha", b"sal", 10).with_page_format(2);
        assert!(v2.is_authenticated() && !v2.uses_page_map());
        let mut p2 = plain.clone();
        v2.seal_page(&mut p2);
        assert_eq!(&v2.open_page(7, &p2.data, None).unwrap().data[32..], &plain.data[32..]);
        assert!(v2.open_page(8, &p2.data, None).is_err());
        // Formato legado (v1): continua abrindo, só com checksum.
        let old = Cipher::from_passphrase("senha", b"sal", 10).legacy();
        assert!(!old.is_authenticated());
        let mut v1 = Page::zeroed(7, PageKind::Leaf);
        v1.data[100..104].copy_from_slice(b"jogo");
        old.seal_page(&mut v1);
        assert_ne!(&v1.data[100..104], b"jogo");
        let back = old.open_page(7, &v1.data, None).unwrap();
        assert_eq!(&back.data[100..104], b"jogo");
        assert!(wrong.legacy().open_page(7, &v1.data, None).is_err());
        // WAL v2: etiqueta presa ao frame anterior, ao LSN e ao tipo.
        let sealed = c.seal_wal(41, 42, 1, b"payload");
        assert_eq!(sealed.len(), 12 + 7 + 16);
        assert_eq!(c.open_wal(41, 42, 1, &sealed).unwrap(), b"payload");
        assert!(c.open_wal(41, 43, 1, &sealed).is_err(), "outro LSN");
        assert!(
            c.open_wal(40, 42, 1, &sealed).is_err(),
            "outro frame anterior"
        );
        assert!(c.open_wal(41, 42, 2, &sealed).is_err(), "outro tipo");
        assert!(c.open_wal(41, 42, 1, &sealed[..20]).is_err(), "curto");
        let other = Cipher::from_passphrase("outra", b"sal", 10);
        assert!(other.open_wal(41, 42, 1, &sealed).is_err(), "outra chave");
        for at in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[at] ^= 1;
            assert!(c.open_wal(41, 42, 1, &bad).is_err(), "byte {at}");
        }
        // WAL v1 (legado): sem etiqueta, como antes.
        let sealed = old.seal_wal(0, 42, 1, b"payload");
        assert_ne!(&sealed[4..], b"payload");
        assert_eq!(old.open_wal(0, 42, 1, &sealed).unwrap(), b"payload");
        assert_ne!(old.open_wal(0, 43, 1, &sealed).unwrap(), b"payload");
    }

    #[test]
    fn legacy_keyfile_opens_as_v1_and_new_keyfile_is_v3() {
        let dir = std::env::temp_dir().join(format!("minidb-keyv1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let salt = [7u8; 16];
        let c = Cipher::from_passphrase("s", &salt, 10);
        let mut raw = KEY_MAGIC.to_vec();
        raw.push(KEY_VERSION_LEGACY);
        raw.extend_from_slice(&10u32.to_le_bytes());
        raw.extend_from_slice(&salt);
        raw.extend_from_slice(&c.check());
        fs::write(keyfile_path(&dir), raw).unwrap();
        let old = open_key(&dir, Some("s"), true).unwrap().unwrap();
        assert_eq!(old.page_format(), 1);
        fs::remove_file(keyfile_path(&dir)).unwrap();
        let new = open_key(&dir, Some("s"), false).unwrap().unwrap();
        assert!(new.uses_page_map());
        assert_eq!(fs::read(keyfile_path(&dir)).unwrap()[4], KEY_VERSION);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keyfile_lifecycle() {
        let dir = std::env::temp_dir().join(format!("minidb-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(open_key(&dir, None, false).unwrap().is_none());
        assert!(
            open_key(&dir, Some("s"), true).is_err(),
            "banco existente em claro"
        );
        assert!(open_key(&dir, Some("s"), false).unwrap().is_some());
        assert!(open_key(&dir, None, true).is_err(), "senha obrigatória");
        assert!(open_key(&dir, Some("errada"), true).is_err());
        assert!(open_key(&dir, Some("s"), true).unwrap().is_some());
        fs::remove_dir_all(&dir).unwrap();
    }
}
