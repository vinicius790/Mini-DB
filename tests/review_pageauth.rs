//! Autenticação das páginas cifradas (ChaCha20-Poly1305 por página, nonce no mapa
//! `data.mdb.pages`): alterar um byte, trocar páginas de lugar, devolver uma versão
//! antiga de uma página ou mexer no mapa precisa falhar como corrupção, nunca
//! devolver dado errado.

use mini_db::backup::{backup, restore, RestoreTarget};
use mini_db::crypto::{hmac_sha256, pbkdf2_sha256};
use mini_db::encryption::{convert, keyfile_path, Cipher};
use mini_db::error::Error;
use mini_db::page::{Page, PAGE_SIZE};
use mini_db::Db;
use std::fs;
use std::path::{Path, PathBuf};

/// Sufixo único por processo: só pid + relógio colide entre testes paralelos.
static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmpdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-test-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

const PASS: &str = "senha de teste";
const N: usize = 400;

fn key(i: usize) -> Vec<u8> {
    format!("chave-{i:05}").into_bytes()
}

fn val(i: usize) -> Vec<u8> {
    format!("valor-{i:05}-{}", "x".repeat(100)).into_bytes()
}

/// Grava `N` chaves e fecha (checkpoint): tudo fica em `data.mdb`.
fn fill(dir: &Path) {
    let mut db = Db::open_encrypted(dir, 64, true, Some(PASS)).unwrap();
    for i in 0..N {
        db.put(&key(i), &val(i)).unwrap();
    }
    db.checkpoint().unwrap();
    db.close().unwrap();
}

/// Abre e lê todas as chaves; erro se algo falhar ou voltar valor diferente.
fn read_all(dir: &Path) -> Result<(), Error> {
    let db = Db::open_encrypted(dir, 64, true, Some(PASS))?;
    for i in 0..N {
        if db.get(&key(i))?.as_deref() != Some(val(i).as_slice()) {
            return Err(Error::Other(format!("valor errado na chave {i}")));
        }
    }
    Ok(())
}

fn assert_corrupt(dir: &Path, what: &str) {
    match read_all(dir) {
        Err(Error::CorruptPage(_)) => {}
        other => panic!("{what}: esperava CorruptPage, veio {other:?}"),
    }
}

/// Cópia do diretório do banco (fechado) para adulterar sem perder o original.
fn copy_db(from: &Path) -> PathBuf {
    let to = tmpdir();
    for entry in fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            fs::copy(&path, to.join(path.file_name().unwrap())).unwrap();
        }
    }
    to
}

/// Reescreve `data.mdb` do diretório depois de `edit` alterar os bytes.
fn patch(dir: &Path, edit: impl FnOnce(&mut Vec<u8>)) {
    let path = Db::data_path(dir);
    let mut bytes = fs::read(&path).unwrap();
    edit(&mut bytes);
    fs::write(path, bytes).unwrap();
}

#[test]
fn new_encrypted_db_uses_authenticated_pages_and_reopens() {
    let dir = tmpdir();
    fill(&dir);
    assert_eq!(fs::read(keyfile_path(&dir)).unwrap()[4], 3, "chave v3");
    assert!(map_path(&dir).exists(), "mapa de páginas");
    let bytes = fs::read(Db::data_path(&dir)).unwrap();
    assert!(bytes.len() >= 4 * PAGE_SIZE, "poucas páginas");
    assert_ne!(&bytes[..4], b"MDB1", "o cabeçalho não fica em claro");
    read_all(&dir).unwrap();
    {
        let mut db = Db::open_encrypted(&dir, 64, true, Some(PASS)).unwrap();
        db.put(b"extra", b"1").unwrap();
        db.close().unwrap();
    }
    let db = Db::open_encrypted(&dir, 64, true, Some(PASS)).unwrap();
    assert_eq!(db.get(b"extra").unwrap().as_deref(), Some(b"1".as_ref()));
    assert_eq!(db.get(&key(7)).unwrap().unwrap(), val(7));
}

#[test]
fn flipping_one_ciphertext_byte_is_detected() {
    let dir = tmpdir();
    fill(&dir);
    read_all(&copy_db(&dir)).unwrap();
    let pages = fs::metadata(Db::data_path(&dir)).unwrap().len() as usize / PAGE_SIZE;
    assert!(pages >= 4, "poucas páginas");
    // Corpo, campos do cabeçalho, etiqueta e nonce, em páginas diferentes
    // (inclusive a meta, página 0).
    let targets = [
        (0, 100),
        (1, 2000),
        (pages - 1, 4000),
        (1, 3),
        (1, 12),
        (2, 20),
        (2, 31),
    ];
    for (page, offset) in targets {
        let copy = copy_db(&dir);
        patch(&copy, |b| b[page * PAGE_SIZE + offset] ^= 0x01);
        assert_corrupt(&copy, &format!("página {page} byte {offset}"));
    }
}

#[test]
fn swapping_or_duplicating_pages_is_detected() {
    let dir = tmpdir();
    fill(&dir);
    for (a, b) in [(1, 2), (0, 1)] {
        let copy = copy_db(&dir);
        patch(&copy, |bytes| {
            let (x, y) = (a * PAGE_SIZE, b * PAGE_SIZE);
            let first = bytes[x..x + PAGE_SIZE].to_vec();
            bytes.copy_within(y..y + PAGE_SIZE, x);
            bytes[y..y + PAGE_SIZE].copy_from_slice(&first);
        });
        assert_corrupt(&copy, &format!("troca das páginas {a} e {b}"));
    }
    // Página 2 copiada por cima da 1.
    let copy = copy_db(&dir);
    patch(&copy, |bytes| {
        bytes.copy_within(2 * PAGE_SIZE..3 * PAGE_SIZE, PAGE_SIZE);
    });
    assert_corrupt(&copy, "página 2 copiada sobre a 1");
}

fn map_path(dir: &Path) -> PathBuf {
    dir.join("data.mdb.pages")
}

fn page_range(page: usize) -> std::ops::Range<usize> {
    page * PAGE_SIZE..(page + 1) * PAGE_SIZE
}

/// Banco cifrado no formato antigo `version` (1 ou 2), montado a partir de um banco
/// em claro: cada página é selada como um banco daquela versão a gravaria.
fn legacy_db(version: u8) -> PathBuf {
    let dir = tmpdir();
    {
        let mut db = Db::open(&dir).unwrap();
        for i in 0..N {
            db.put(&key(i), &val(i)).unwrap();
        }
        db.checkpoint().unwrap();
        db.close().unwrap();
    }
    let salt = [9u8; 16];
    let iterations = 10u32;
    let cipher = Cipher::from_passphrase(PASS, &salt, iterations).with_page_format(version);
    patch(&dir, |bytes| {
        for chunk in bytes.chunks_exact_mut(PAGE_SIZE) {
            let mut page = Page::from_bytes(chunk).unwrap();
            cipher.seal_page(&mut page);
            chunk.copy_from_slice(&page.data);
        }
    });
    let derived = pbkdf2_sha256(PASS.as_bytes(), &salt, iterations);
    let mut raw = b"MDBK".to_vec();
    raw.push(version);
    raw.extend_from_slice(&iterations.to_le_bytes());
    raw.extend_from_slice(&salt);
    raw.extend_from_slice(&hmac_sha256(&derived, &[b"minidb key check"]));
    fs::write(keyfile_path(&dir), raw).unwrap();
    dir
}

#[test]
fn legacy_databases_are_upgraded_to_v3_on_open_keeping_the_key() {
    for version in [1u8, 2] {
        let dir = legacy_db(version);
        let before = fs::read(keyfile_path(&dir)).unwrap();
        if version == 1 {
            let bytes = fs::read(Db::data_path(&dir)).unwrap();
            assert_eq!(&bytes[..4], b"MDB1", "v1 mantém o cabeçalho em claro");
        }
        read_all(&dir).unwrap();
        let after = fs::read(keyfile_path(&dir)).unwrap();
        assert_eq!(after[4], 3, "v{version} migrado para v3");
        assert_eq!(&after[5..], &before[5..], "mesmo sal, mesma chave");
        assert!(map_path(&dir).exists());
        let bytes = fs::read(Db::data_path(&dir)).unwrap();
        assert_ne!(&bytes[..4], b"MDB1");
        read_all(&dir).unwrap();
        let copy = copy_db(&dir);
        patch(&copy, |b| b[PAGE_SIZE + 2000] ^= 0x01);
        assert_corrupt(&copy, "depois da migração");
    }
}

#[test]
fn replaying_an_old_version_of_a_page_or_of_the_map_is_detected() {
    let dir = tmpdir();
    fill(&dir);
    let old = fs::read(Db::data_path(&dir)).unwrap();
    let old_map = fs::read(map_path(&dir)).unwrap();
    {
        // Regrava tudo e volta ao mesmo conteúdo: as versões antigas das páginas
        // continuam válidas para a chave e têm o mesmo texto claro.
        let mut db = Db::open_encrypted(&dir, 64, true, Some(PASS)).unwrap();
        for i in 0..N {
            db.put(&key(i), b"outro").unwrap();
        }
        db.checkpoint().unwrap();
        for i in 0..N {
            db.put(&key(i), &val(i)).unwrap();
        }
        db.close().unwrap();
    }
    read_all(&dir).unwrap();
    let new = fs::read(Db::data_path(&dir)).unwrap();
    let pages = old.len().min(new.len()) / PAGE_SIZE;
    let changed: Vec<usize> = (0..pages)
        .filter(|&p| old[page_range(p)] != new[page_range(p)])
        .collect();
    assert!(changed.contains(&0), "a meta muda a cada checkpoint");
    let mut detected = 0;
    for &page in &changed {
        let copy = copy_db(&dir);
        patch(&copy, |b| {
            b[page_range(page)].copy_from_slice(&old[page_range(page)])
        });
        match read_all(&copy) {
            Err(Error::CorruptPage(_)) => detected += 1,
            // Página fora da árvore (livre): a leitura não passa por ela.
            Ok(()) => {}
            other => panic!("versão antiga da página {page}: {other:?}"),
        }
    }
    assert!(detected >= 2, "replay detectado em {detected} páginas");
    // Mapa antigo com as páginas novas.
    let copy = copy_db(&dir);
    fs::write(map_path(&copy), &old_map).unwrap();
    assert_corrupt(&copy, "mapa antigo");
}

#[test]
fn tampering_with_the_page_map_or_truncating_data_is_detected() {
    let dir = tmpdir();
    fill(&dir);
    let len = fs::read(map_path(&dir)).unwrap().len();
    for at in [0, 10, 40, len - 40, len - 1] {
        let copy = copy_db(&dir);
        let mut bytes = fs::read(map_path(&copy)).unwrap();
        bytes[at] ^= 1;
        fs::write(map_path(&copy), bytes).unwrap();
        assert_corrupt(&copy, &format!("mapa, byte {at}"));
    }
    let copy = copy_db(&dir);
    fs::remove_file(map_path(&copy)).unwrap();
    assert_corrupt(&copy, "mapa apagado");
    // O mapa conhece páginas que sumiram do arquivo.
    let copy = copy_db(&dir);
    patch(&copy, |b| b.truncate(2 * PAGE_SIZE));
    assert_corrupt(&copy, "arquivo truncado");
}

#[test]
fn interrupted_data_file_swap_is_resolved_on_open() {
    let dir = tmpdir();
    fill(&dir);
    let old_map = fs::read(map_path(&dir)).unwrap();
    {
        let mut db = Db::open_encrypted(&dir, 64, true, Some(PASS)).unwrap();
        db.put(b"extra", b"1").unwrap();
        db.close().unwrap();
    }
    // Queda depois do rename do arquivo e antes do rename do mapa: o mapa novo
    // ficou pendente e o instalado é o anterior.
    let copy = copy_db(&dir);
    fs::rename(map_path(&copy), copy.join("data.mdb.pages.next")).unwrap();
    fs::write(map_path(&copy), &old_map).unwrap();
    read_all(&copy).unwrap();
    assert!(!copy.join("data.mdb.pages.next").exists());
    // Sobra de uma troca que não aconteceu: o pendente não vale e é descartado.
    let copy = copy_db(&dir);
    fs::write(copy.join("data.mdb.pages.next"), &old_map).unwrap();
    read_all(&copy).unwrap();
    assert!(!copy.join("data.mdb.pages.next").exists());
}

#[test]
fn vacuum_rekey_backup_and_decrypt_keep_the_page_map_consistent() {
    let dir = tmpdir();
    fill(&dir);
    {
        let mut db = Db::open_encrypted(&dir, 64, true, Some(PASS)).unwrap();
        for i in N..2 * N {
            db.put(&key(i), &val(i)).unwrap();
        }
        for i in N..2 * N {
            db.delete(&key(i)).unwrap();
        }
        db.vacuum().unwrap();
        db.close().unwrap();
    }
    assert!(!dir.join("data.mdb.pages.next").exists());
    assert!(!dir.join("vacuum.mdb.pages").exists());
    read_all(&dir).unwrap();
    let dest = tmpdir().join("backup");
    {
        let mut db = Db::open_encrypted(&dir, 64, true, Some(PASS)).unwrap();
        backup(&mut db, &dest).unwrap();
        db.close().unwrap();
    }
    assert!(dest.join("base/data.mdb.pages").exists());
    let restored = tmpdir().join("restaurado");
    restore(&dest, &restored, RestoreTarget::Latest, Some(PASS)).unwrap();
    read_all(&restored).unwrap();
    // Troca de senha (ida e volta): mapa refeito com a chave nova a cada vez.
    convert(&dir, Some(PASS), Some("outra senha")).unwrap();
    assert!(map_path(&dir).exists());
    convert(&dir, Some("outra senha"), Some(PASS)).unwrap();
    read_all(&dir).unwrap();
    // A chave mudou desde a base: o próximo backup recomeça completo.
    {
        let mut db = Db::open_encrypted(&dir, 64, true, Some(PASS)).unwrap();
        let report = backup(&mut db, &dest).unwrap();
        assert!(report.starts_with("backup completo"), "{report}");
        db.close().unwrap();
    }
    let restored = tmpdir().join("restaurado2");
    restore(&dest, &restored, RestoreTarget::Latest, Some(PASS)).unwrap();
    read_all(&restored).unwrap();
    // Sem cifra: o mapa sai junto com a chave.
    convert(&dir, Some(PASS), None).unwrap();
    assert!(!map_path(&dir).exists());
    let db = Db::open(&dir).unwrap();
    assert_eq!(db.get(&key(3)).unwrap().unwrap(), val(3));
}
