//! Autenticação das páginas cifradas (ChaCha20-Poly1305 por página): alterar um
//! byte ou trocar páginas de lugar em `data.mdb` precisa falhar como corrupção,
//! nunca devolver dado errado.

use mini_db::crypto::{hmac_sha256, pbkdf2_sha256};
use mini_db::encryption::{convert, keyfile_path};
use mini_db::error::Error;
use mini_db::page::PAGE_SIZE;
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
    assert_eq!(fs::read(keyfile_path(&dir)).unwrap()[4], 2, "chave v2");
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

#[test]
fn legacy_v1_database_still_opens_and_convert_migrates_to_v2() {
    let dir = tmpdir();
    // Chave de versão 1, como a de um banco criado antes da autenticação.
    let salt = [9u8; 16];
    let iterations = 10u32;
    let derived = pbkdf2_sha256(PASS.as_bytes(), &salt, iterations);
    let mut raw = b"MDBK".to_vec();
    raw.push(1);
    raw.extend_from_slice(&iterations.to_le_bytes());
    raw.extend_from_slice(&salt);
    raw.extend_from_slice(&hmac_sha256(&derived, &[b"minidb key check"]));
    fs::write(keyfile_path(&dir), raw).unwrap();
    fill(&dir);
    let bytes = fs::read(Db::data_path(&dir)).unwrap();
    assert_eq!(&bytes[..4], b"MDB1", "v1 mantém o cabeçalho em claro");
    read_all(&dir).unwrap();
    // `convert` com a mesma senha reescreve tudo no formato autenticado.
    convert(&dir, Some(PASS), Some(PASS)).unwrap();
    assert_eq!(fs::read(keyfile_path(&dir)).unwrap()[4], 2, "chave v2");
    let bytes = fs::read(Db::data_path(&dir)).unwrap();
    assert_ne!(&bytes[..4], b"MDB1");
    read_all(&dir).unwrap();
    let copy = copy_db(&dir);
    patch(&copy, |b| b[PAGE_SIZE + 2000] ^= 0x01);
    assert_corrupt(&copy, "depois da migração");
}
