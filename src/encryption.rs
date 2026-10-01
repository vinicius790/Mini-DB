//! Criptografia em repouso: páginas de `data.mdb` (e spill/journal) e frames
//! do WAL cifrados com ChaCha20, chave derivada da senha por PBKDF2-HMAC-SHA256.
//!
//! O cabeçalho da página (32 bytes: magic, id, tipo, contadores) fica em claro
//! para recuperação e validação; o corpo é cifrado com um nonce aleatório de
//! 8 bytes gravado no campo `lsn` do cabeçalho (o LSN da página não tem uso
//! funcional). No WAL, cada frame leva 4 bytes de sal + LSN como nonce. O
//! checksum da página (calculado sobre o texto claro) detecta senha errada ou
//! corrupção; a integridade forte fica a cargo do CRC do WAL/journal.
//!
//! O arquivo `data.mdb.key` guarda sal, iterações e um verificador da chave
//! (nunca a chave). Sem ele o banco não é criptografado.

use crate::crypto::{chacha20_xor, hmac_sha256, pbkdf2_sha256, random_bytes};
use crate::error::{Error, Result};
use crate::page::{Page, PAGE_HEADER_SIZE};
use std::fs;
use std::path::{Path, PathBuf};

const KEY_MAGIC: &[u8; 4] = b"MDBK";
const KEY_VERSION: u8 = 1;
/// Iterações do PBKDF2 para a chave do banco (senha → chave, uma vez por abertura).
pub const KEY_ITERATIONS: u32 = 20_000;

pub struct Cipher {
    key: [u8; 32],
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cipher(..)")
    }
}

impl Cipher {
    pub fn from_passphrase(passphrase: &str, salt: &[u8], iterations: u32) -> Self {
        Self {
            key: pbkdf2_sha256(passphrase.as_bytes(), salt, iterations),
        }
    }

    fn check(&self) -> [u8; 32] {
        hmac_sha256(&self.key, &[b"minidb key check"])
    }

    /// Cifra a imagem de disco de uma página: nonce novo no campo `lsn`,
    /// checksum sobre o texto claro, corpo cifrado.
    pub fn seal_page(&self, page: &mut Page) {
        let nonce8 = random_bytes::<8>();
        page.set_lsn(u64::from_le_bytes(nonce8));
        page.write_checksum();
        let nonce = page_nonce(page.page_id(), &nonce8);
        chacha20_xor(&self.key, &nonce, 0, &mut page.data[PAGE_HEADER_SIZE..]);
    }

    /// Decifra uma página lida do disco e confere o checksum.
    pub fn open_page(&self, page: &mut Page) -> Result<()> {
        let nonce8 = page.lsn().to_le_bytes();
        let nonce = page_nonce(page.page_id(), &nonce8);
        chacha20_xor(&self.key, &nonce, 0, &mut page.data[PAGE_HEADER_SIZE..]);
        if page.stored_checksum() != 0 && page.compute_checksum() != page.stored_checksum() {
            return Err(Error::Other(format!(
                "página {} não decifra: senha incorreta ou arquivo corrompido",
                page.page_id()
            )));
        }
        Ok(())
    }

    /// Cifra o payload de um frame do WAL: `sal(4) ‖ texto cifrado`.
    pub fn seal_wal(&self, lsn: u64, payload: &[u8]) -> Vec<u8> {
        let salt = random_bytes::<4>();
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(payload);
        chacha20_xor(&self.key, &wal_nonce(lsn, &salt), 0, &mut out[4..]);
        out
    }

    pub fn open_wal(&self, lsn: u64, data: &[u8]) -> Result<Vec<u8>> {
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
            if raw.len() != 57 || &raw[..4] != KEY_MAGIC || raw[4] != KEY_VERSION {
                return Err(Error::Other("data.mdb.key inválido".into()));
            }
            let iterations = u32::from_le_bytes(raw[5..9].try_into().expect("4"));
            let cipher = Cipher::from_passphrase(pass, &raw[9..25], iterations);
            if !crate::crypto::constant_time_eq(&cipher.check(), &raw[25..57]) {
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
    use crate::page::PAGE_SIZE;
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
    use crate::page::PageKind;

    #[test]
    fn page_and_wal_roundtrip_detect_wrong_key() {
        let c = Cipher::from_passphrase("senha", b"sal", 10);
        let mut page = Page::zeroed(7, PageKind::Leaf);
        page.data[100..104].copy_from_slice(b"jogo");
        let plain = page.data;
        c.seal_page(&mut page);
        assert_ne!(&page.data[100..104], b"jogo");
        assert_eq!(page.page_id(), 7);
        c.open_page(&mut page).unwrap();
        assert_eq!(&page.data[32..], &plain[32..]);
        let mut again = page.clone();
        c.seal_page(&mut again);
        let wrong = Cipher::from_passphrase("outra", b"sal", 10);
        assert!(wrong.open_page(&mut again).is_err());
        let sealed = c.seal_wal(42, b"payload");
        assert_ne!(&sealed[4..], b"payload");
        assert_eq!(c.open_wal(42, &sealed).unwrap(), b"payload");
        assert_ne!(c.open_wal(43, &sealed).unwrap(), b"payload");
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
