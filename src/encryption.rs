//! Criptografia em repouso: páginas de `data.mdb` (e spill/journal) e frames
//! do WAL cifrados com ChaCha20, chave derivada da senha por PBKDF2-HMAC-SHA256.
//!
//! Há dois formatos de página, escolhidos pela versão do `data.mdb.key`:
//!
//! - **v2 (autenticado, bancos novos; chave de versão 2)**: cada página é um
//!   ChaCha20-Poly1305 (RFC 8439) com nonce `id ‖ 8 bytes aleatórios` e AAD com o
//!   id da posição. A imagem em disco é `nonce(8) ‖ etiqueta(10) ‖ campos do
//!   cabeçalho cifrados(14) ‖ corpo cifrado(4064)`: o magic e o id não são
//!   gravados (o id vem da posição lida) e o CRC16 deixou de existir. Qualquer
//!   bit alterado, página trocada de lugar ou cabeçalho adulterado falha com
//!   [`Error::CorruptPage`]. A etiqueta é a Poly1305 truncada em 80 bits. O LSN
//!   da página não é guardado (não tem uso funcional) e volta como 0.
//!   Não protege contra *replay*: devolver uma versão antiga e válida da mesma
//!   página (ver `docs/RECOVERY.md`).
//! - **v1 (legado, chave de versão 1)**: cabeçalho em claro, corpo cifrado com
//!   nonce aleatório de 8 bytes no campo `lsn`; o checksum CRC16 do texto claro
//!   só detecta senha errada ou corrupção acidental (um atacante refaz o CRC ou o
//!   zera). Bancos antigos continuam abrindo assim, sem migração automática;
//!   [`convert`] com a mesma senha reescreve tudo em v2.
//!
//! No WAL, a cifra v2 grava cada payload como ChaCha20-Poly1305 com uma subchave
//! só do WAL, nonce aleatório de 12 bytes e AAD com o LSN do frame anterior no
//! arquivo, o LSN e o tipo do registro: frame alterado, removido, repetido ou fora
//! de ordem dá [`Error::CorruptWal`]. Na v1 cada frame leva 4 bytes de sal + LSN
//! como nonce, sem etiqueta; a integridade fica a cargo do CRC do WAL.
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
/// Versão da chave de bancos com páginas autenticadas (v2).
const KEY_VERSION: u8 = 2;
/// Iterações do PBKDF2 para a chave do banco (senha → chave, uma vez por abertura).
pub const KEY_ITERATIONS: u32 = 20_000;

/// Bytes da etiqueta Poly1305 guardados no cabeçalho de cada página v2 (80 bits).
const PAGE_TAG_LEN: usize = 10;
/// Fim da etiqueta na imagem v2: `nonce(8) ‖ etiqueta`.
const TAG_END: usize = 8 + PAGE_TAG_LEN;
/// Campos do cabeçalho em memória (`kind` … `extra`, bytes 8..22) que a imagem v2
/// guarda cifrados logo após a etiqueta.
const FIELDS_START: usize = 8;
const FIELDS_END: usize = 22;
const _: () = assert!(TAG_END + FIELDS_END - FIELDS_START == PAGE_HEADER_SIZE);

pub struct Cipher {
    key: [u8; 32],
    /// Subchave dos frames autenticados do WAL (v2): os nonces do WAL nunca
    /// concorrem com os das páginas.
    wal_key: [u8; 32],
    /// `true`: páginas v2 com etiqueta; `false`: formato legado (v1).
    authenticated: bool,
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cipher(..)")
    }
}

impl Cipher {
    /// Cifra com páginas autenticadas (v2): é o formato de todo banco novo.
    pub fn from_passphrase(passphrase: &str, salt: &[u8], iterations: u32) -> Self {
        let key = pbkdf2_sha256(passphrase.as_bytes(), salt, iterations);
        Self {
            wal_key: hmac_sha256(&key, &[b"minidb wal v2 key"]),
            key,
            authenticated: true,
        }
    }

    /// Mesma chave no formato de página legado (v1, sem etiqueta), para abrir
    /// bancos criados antes da autenticação de páginas.
    pub fn legacy(mut self) -> Self {
        self.authenticated = false;
        self
    }

    /// `true` se as páginas levam etiqueta Poly1305 (v2).
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    fn check(&self) -> [u8; 32] {
        hmac_sha256(&self.key, &[b"minidb key check"])
    }

    /// Transforma a página (formato de memória) na imagem de disco, em `page.data`.
    /// A imagem só é legível por [`Cipher::open_page`].
    pub fn seal_page(&self, page: &mut Page) {
        if self.authenticated {
            self.seal_page_v2(page);
        } else {
            self.seal_page_v1(page);
        }
    }

    /// v1: nonce novo no campo `lsn`, checksum sobre o texto claro, corpo cifrado.
    fn seal_page_v1(&self, page: &mut Page) {
        let nonce8 = random_bytes::<8>();
        page.set_lsn(u64::from_le_bytes(nonce8));
        page.write_checksum();
        let nonce = page_nonce(page.page_id(), &nonce8);
        chacha20_xor(&self.key, &nonce, 0, &mut page.data[PAGE_HEADER_SIZE..]);
    }

    /// v2: `nonce(8) ‖ etiqueta(10) ‖ cifra(campos do cabeçalho ‖ corpo)`.
    fn seal_page_v2(&self, page: &mut Page) {
        let id = page.page_id();
        let nonce8 = random_bytes::<8>();
        let nonce = page_nonce(id, &nonce8);
        let mut body = Vec::with_capacity(PAGE_SIZE - TAG_END);
        body.extend_from_slice(&page.data[FIELDS_START..FIELDS_END]);
        body.extend_from_slice(&page.data[PAGE_HEADER_SIZE..]);
        chacha20_xor(&self.key, &nonce, 1, &mut body);
        let tag = aead_tag_of(&self.key, &nonce, &page_aad(id), &body);
        page.data[..8].copy_from_slice(&nonce8);
        page.data[8..TAG_END].copy_from_slice(&tag[..PAGE_TAG_LEN]);
        page.data[TAG_END..].copy_from_slice(&body);
    }

    /// Lê a imagem de disco da página `page_id` (a posição onde ela foi lida).
    /// No formato v2 confere a etiqueta (alteração, troca de posição ou chave
    /// errada dão [`Error::CorruptPage`]); no v1 só o checksum.
    pub fn open_page(&self, page_id: u32, image: &[u8]) -> Result<Page> {
        if image.len() != PAGE_SIZE {
            return Err(Error::CorruptPage(page_id));
        }
        if self.authenticated {
            self.open_page_v2(page_id, image)
        } else {
            self.open_page_v1(page_id, image)
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
        let tag = aead_tag_of(&self.key, &nonce, &page_aad(page_id), &body);
        if !constant_time_eq(&tag[..PAGE_TAG_LEN], &image[8..TAG_END]) {
            return Err(Error::CorruptPage(page_id));
        }
        chacha20_xor(&self.key, &nonce, 1, &mut body);
        let (fields, rest) = body.split_at(FIELDS_END - FIELDS_START);
        let mut page = Page::zeroed(page_id, PageKind::Free);
        page.data[FIELDS_START..FIELDS_END].copy_from_slice(fields);
        page.data[PAGE_HEADER_SIZE..].copy_from_slice(rest);
        page.write_checksum();
        Ok(page)
    }

    /// Cifra o payload de um frame do WAL.
    ///
    /// - v2: `nonce(12) ‖ texto cifrado ‖ etiqueta(16)`. O nonce é aleatório porque
    ///   um LSN pode voltar a ser usado com outro conteúdo (cauda descartada no
    ///   recovery, restauração até um ponto). O AAD leva `prev_lsn` (LSN do frame
    ///   anterior no arquivo, 0 no primeiro), o LSN e o tipo `ty`.
    /// - v1: `sal(4) ‖ texto cifrado`, sem etiqueta; `prev_lsn` e `ty` não entram.
    pub fn seal_wal(&self, prev_lsn: u64, lsn: u64, ty: u8, payload: &[u8]) -> Vec<u8> {
        if self.authenticated {
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

    /// Abre o payload gravado por [`Cipher::seal_wal`]. Na v2, etiqueta que não confere
    /// (byte alterado, outro frame anterior, LSN ou tipo trocados) dá [`Error::CorruptWal`].
    pub fn open_wal(&self, prev_lsn: u64, lsn: u64, ty: u8, data: &[u8]) -> Result<Vec<u8>> {
        if self.authenticated {
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

fn page_nonce(page_id: u32, nonce8: &[u8; 8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&page_id.to_le_bytes());
    n[4..].copy_from_slice(nonce8);
    n
}

/// Dados autenticados de uma página v2: rótulo do formato e a posição (id).
fn page_aad(page_id: u32) -> [u8; 18] {
    let mut aad = [0u8; 18];
    aad[..14].copy_from_slice(b"minidb page v2");
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
            // Com `sync_all`: o arquivo guarda o sal; sem ele a senha não abre mais nada.
            let mut file = fs::File::create(&path)?;
            std::io::Write::write_all(&mut file, &raw)?;
            file.sync_all()?;
            Ok(Some(cipher))
        }
        (Some(_), None) => Err(Error::Other(
            "banco criptografado: informe a senha (MINIDB_PASSPHRASE ou passphrase no minidb.toml)"
                .into(),
        )),
        (Some(raw), Some(pass)) => {
            let version = raw.get(4).copied();
            if raw.len() != 57
                || &raw[..4] != KEY_MAGIC
                || (version != Some(KEY_VERSION) && version != Some(KEY_VERSION_LEGACY))
            {
                return Err(Error::Other("data.mdb.key inválido".into()));
            }
            let iterations = u32::from_le_bytes(raw[5..9].try_into().expect("4"));
            let mut cipher = Cipher::from_passphrase(pass, &raw[9..25], iterations);
            if version == Some(KEY_VERSION_LEGACY) {
                cipher = cipher.legacy();
            }
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

/// Desfaz ou conclui um [`convert`] interrompido (crash no meio). Chamado na
/// abertura do banco, antes de ler a chave:
/// - temporário ainda presente → a troca não aconteceu: `data.mdb` é o original
///   e a chave original volta ao lugar;
/// - temporário ausente → a troca aconteceu: só termina a limpeza.
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
    if state != STATE_ENCRYPTED && state != STATE_PLAIN {
        // Estado incompleto: a queda foi durante a gravação dele, antes de qualquer
        // troca. A chave e o `data.mdb` são os originais; só limpa os marcadores.
        let _ = fs::remove_file(&tmp);
        fs::remove_file(&state_path)?;
        return Ok(());
    }
    if tmp.exists() {
        if state == STATE_ENCRYPTED {
            // A chave original pode já ter sido movida; a nova (se houver) é descartada.
            if old_key.exists() {
                fs::rename(&old_key, keyfile_path(dir))?;
            }
        } else {
            // O banco era em claro: a chave criada para a conversão não vale.
            let _ = fs::remove_file(keyfile_path(dir));
        }
        fs::remove_file(&tmp)?;
    } else {
        let _ = fs::remove_file(&old_key);
        let _ = fs::remove_dir_all(crate::Db::archive_dir(dir));
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
    use crate::buffer::BufferPool;
    use std::io::Write;
    // Solto só no retorno (sucesso ou erro). Sem ele, um `Db::open` concorrente rodaria
    // `recover_convert`, tomaria a conversão em andamento por interrompida e a desfaria.
    let _lock = {
        // Checkpoint com WAL truncado: tudo fica em data.mdb.
        let mut db = crate::Db::open_encrypted(dir, 64, true, from)?;
        db.set_wal_retention(0);
        let lock = db.take_lock();
        db.close()?;
        lock
    };
    let data = crate::Db::data_path(dir);
    let old = open_key(dir, from, true)?.map(std::sync::Arc::new);
    let key = keyfile_path(dir);
    let backup_key = dir.join(CONVERT_OLD_KEY);
    let tmp = dir.join(CONVERT_TMP);
    let state_path = dir.join(CONVERT_STATE);
    // Marcas para `recover_convert`: o temporário (vazio) e o estado original são
    // gravados antes de qualquer troca. Enquanto o temporário existir, `data.mdb`
    // ainda é o original e a chave pode ser devolvida; o rename final é o commit.
    fs::File::create(&tmp)?.sync_all()?;
    {
        let state: &[u8] = if key.exists() {
            STATE_ENCRYPTED
        } else {
            STATE_PLAIN
        };
        let mut file = fs::File::create(&state_path)?;
        file.write_all(state)?;
        file.sync_all()?;
    }
    if key.exists() {
        fs::rename(&key, &backup_key)?;
    }
    let new = match to {
        Some(pass) => open_key(dir, Some(pass), false)?,
        None => None,
    };
    let pages = fs::metadata(&data)?.len() / PAGE_SIZE as u64;
    {
        let pool = BufferPool::open_with(&data, 64, old)?;
        let mut out = std::io::BufWriter::new(fs::File::create(&tmp)?);
        for id in 0..pages as u32 {
            let mut page = (*pool.get_page(id)?).clone();
            match &new {
                Some(c) => c.seal_page(&mut page),
                None => page.write_checksum(),
            }
            out.write_all(&page.data)?;
        }
        out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    }
    let _ = fs::remove_file(data.with_extension("mdb.spill"));
    fs::rename(&tmp, &data)?;
    let _ = fs::remove_dir_all(crate::Db::archive_dir(dir));
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
        assert!(c.is_authenticated());
        let mut page = Page::zeroed(7, PageKind::Leaf);
        page.set_right_sibling(9);
        page.data[100..104].copy_from_slice(b"jogo");
        let plain = page.data;
        c.seal_page(&mut page);
        assert_ne!(&page.data[100..104], b"jogo");
        let image = page.data;
        let opened = c.open_page(7, &image).unwrap();
        assert_eq!(opened.page_id(), 7);
        assert_eq!(opened.right_sibling(), 9);
        assert_eq!(&opened.data[8..22], &plain[8..22]);
        assert_eq!(&opened.data[32..], &plain[32..]);
        // Chave errada, outra posição ou qualquer byte alterado: recusa.
        let wrong = Cipher::from_passphrase("outra", b"sal", 10);
        assert!(wrong.open_page(7, &image).is_err());
        assert!(c.open_page(8, &image).is_err());
        for at in [0, 8, 17, 18, 25, 32, 2000, PAGE_SIZE - 1] {
            let mut bad = image;
            bad[at] ^= 1;
            assert!(c.open_page(7, &bad).is_err(), "byte {at}");
        }
        // Formato legado (v1): continua abrindo, só com checksum.
        let old = Cipher::from_passphrase("senha", b"sal", 10).legacy();
        assert!(!old.is_authenticated());
        let mut v1 = Page::zeroed(7, PageKind::Leaf);
        v1.data[100..104].copy_from_slice(b"jogo");
        old.seal_page(&mut v1);
        assert_ne!(&v1.data[100..104], b"jogo");
        let back = old.open_page(7, &v1.data).unwrap();
        assert_eq!(&back.data[100..104], b"jogo");
        assert!(wrong.legacy().open_page(7, &v1.data).is_err());
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
    fn legacy_keyfile_opens_as_v1_and_new_keyfile_is_v2() {
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
        assert!(!old.is_authenticated());
        fs::remove_file(keyfile_path(&dir)).unwrap();
        let new = open_key(&dir, Some("s"), false).unwrap().unwrap();
        assert!(new.is_authenticated());
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
