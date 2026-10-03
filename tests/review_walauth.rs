//! Autenticação dos frames do WAL em bancos cifrados v2 (ChaCha20-Poly1305 por frame,
//! encadeado pelo LSN do frame anterior): alterar, trocar de lugar, remover ou repetir
//! um frame precisa falhar com `CorruptWal`, nunca aplicar dado errado. Banco em claro,
//! cifra v1 e cauda rasgada continuam como antes.

use mini_db::crypto::{hmac_sha256, pbkdf2_sha256};
use mini_db::encryption::keyfile_path;
use mini_db::error::Error;
use mini_db::wal::crc32;
use mini_db::Db;
use std::fs;
use std::path::{Path, PathBuf};

/// Sufixo único por processo: só pid + relógio colide entre testes paralelos.
static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmpdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "minidb-walauth-{}-{}-{}",
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
const N: usize = 12;

fn key(i: usize) -> Vec<u8> {
    format!("chave-{i:03}").into_bytes()
}

fn val(i: usize) -> Vec<u8> {
    format!("valor-{i:03}").into_bytes()
}

/// `data.mdb.key` montado à mão, com poucas iterações: versão 1 = cifra legada (sem
/// etiqueta), versão 2 = cifra autenticada.
fn write_key(dir: &Path, version: u8) {
    let salt = [9u8; 16];
    let iterations = 10u32;
    let derived = pbkdf2_sha256(PASS.as_bytes(), &salt, iterations);
    let mut raw = b"MDBK".to_vec();
    raw.push(version);
    raw.extend_from_slice(&iterations.to_le_bytes());
    raw.extend_from_slice(&salt);
    raw.extend_from_slice(&hmac_sha256(&derived, &[b"minidb key check"]));
    fs::write(keyfile_path(dir), raw).unwrap();
}

/// Grava `base`, faz checkpoint e depois `N` chaves que ficam só no WAL: o handle é
/// abandonado sem checkpoint, como numa queda.
fn fill(dir: &Path, pass: Option<&str>) {
    let mut db = Db::open_encrypted(dir, 64, true, pass).unwrap();
    db.put(b"base", b"0").unwrap();
    db.checkpoint().unwrap();
    for i in 0..N {
        db.put(&key(i), &val(i)).unwrap();
    }
    db.drop_without_checkpoint();
}

/// Abre o banco e confere `base` e as `n` primeiras chaves; as demais devem faltar.
fn check(dir: &Path, pass: Option<&str>, n: usize) -> Result<(), Error> {
    let db = Db::open_encrypted(dir, 64, true, pass)?;
    if db.get(b"base")?.as_deref() != Some(&b"0"[..]) {
        return Err(Error::Other("chave base ausente".into()));
    }
    for i in 0..N {
        let want = (i < n).then(|| val(i));
        if db.get(&key(i))? != want {
            return Err(Error::Other(format!("chave {i}: valor inesperado")));
        }
    }
    Ok(())
}

fn assert_corrupt(dir: &Path, what: &str) {
    match check(dir, Some(PASS), N) {
        Err(Error::CorruptWal(_)) => {}
        other => panic!("{what}: esperava CorruptWal, veio {other:?}"),
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

/// Limites `(início, fim)` dos frames de um `wal.log` inteiro (cabeçalho de 8 bytes antes).
fn frames(wal: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = 8;
    while at + 8 <= wal.len() {
        let len = u32::from_le_bytes(wal[at..at + 4].try_into().unwrap()) as usize;
        out.push((at, at + 8 + len));
        at += 8 + len;
    }
    assert_eq!(at, wal.len(), "WAL com cauda incompleta");
    out
}

/// Junta os trechos `(início, fim)` de `wal` na ordem dada.
fn splice(wal: &[u8], parts: &[(usize, usize)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(from, to) in parts {
        out.extend_from_slice(&wal[from..to]);
    }
    out
}

/// Reescreve o `wal.log` do diretório depois de `edit` alterar os bytes.
fn patch_wal(dir: &Path, edit: impl FnOnce(&mut Vec<u8>)) {
    let path = Db::wal_path(dir);
    let mut bytes = fs::read(&path).unwrap();
    edit(&mut bytes);
    fs::write(path, bytes).unwrap();
}

/// Refaz o CRC32 do frame `start..end`, como faria quem altera o arquivo.
fn fix_crc(wal: &mut [u8], start: usize, end: usize) {
    let crc = crc32(&wal[start + 8..end]);
    wal[start + 4..start + 8].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn new_encrypted_db_recovers_authenticated_wal_after_crash() {
    let dir = tmpdir();
    fill(&dir, Some(PASS));
    assert_eq!(fs::read(keyfile_path(&dir)).unwrap()[4], 2, "chave v2");
    let wal = fs::read(Db::wal_path(&dir)).unwrap();
    let all = frames(&wal);
    assert!(all.len() >= N, "um frame por put");
    let (start, end) = *all.last().unwrap();
    // cabeçalho(8) lsn(8) tipo(1) nonce(12) payload do Insert etiqueta(16)
    let insert = 8 + key(0).len() + val(0).len();
    assert_eq!(end - start, 8 + 9 + 12 + insert + 16);
    check(&copy_db(&dir), Some(PASS), N).unwrap();
    // Reabre sem checkpoint, grava mais (encadeado no último frame) e cai de novo.
    {
        let mut db = Db::open_encrypted(&dir, 64, true, Some(PASS)).unwrap();
        db.put(b"depois", b"1").unwrap();
        db.drop_without_checkpoint();
    }
    let db = Db::open_encrypted(&dir, 64, true, Some(PASS)).unwrap();
    assert_eq!(db.get(b"depois").unwrap().as_deref(), Some(&b"1"[..]));
    assert_eq!(db.get(&key(N - 1)).unwrap().unwrap(), val(N - 1));
}

#[test]
fn flipped_byte_in_middle_frame_fails_even_with_crc_fixed() {
    let dir = tmpdir();
    write_key(&dir, 2);
    fill(&dir, Some(PASS));
    check(&copy_db(&dir), Some(PASS), N).unwrap();
    let wal = fs::read(Db::wal_path(&dir)).unwrap();
    let all = frames(&wal);
    let (start, end) = all[all.len() / 2];
    // Corpo do frame: lsn(8) tipo(1) nonce(12) texto cifrado etiqueta(16).
    let targets = [
        (start + 8, "lsn"),
        (start + 16, "tipo"),
        (start + 17, "nonce"),
        (start + 30, "texto cifrado"),
        (end - 1, "etiqueta"),
    ];
    for (at, what) in targets {
        for refix in [false, true] {
            let copy = copy_db(&dir);
            patch_wal(&copy, |b| {
                b[at] ^= 0x01;
                if refix {
                    fix_crc(b, start, end);
                }
            });
            assert_corrupt(&copy, &format!("{what} (CRC refeito: {refix})"));
        }
    }
}

#[test]
fn swapped_removed_or_repeated_frames_fail() {
    let dir = tmpdir();
    write_key(&dir, 2);
    fill(&dir, Some(PASS));
    let wal = fs::read(Db::wal_path(&dir)).unwrap();
    let all = frames(&wal);
    let (a, b) = (all[all.len() / 2], all[all.len() / 2 + 1]);
    assert!(b.1 < wal.len(), "os dois frames ficam no meio");
    let cases = [
        ("troca", splice(&wal, &[(0, a.0), b, a, (b.1, wal.len())])),
        ("remoção", splice(&wal, &[(0, a.0), (b.0, wal.len())])),
        ("repetição", splice(&wal, &[(0, b.1), a, (b.1, wal.len())])),
    ];
    for (what, bytes) in cases {
        let copy = copy_db(&dir);
        fs::write(Db::wal_path(&copy), bytes).unwrap();
        assert_corrupt(&copy, what);
    }
}

#[test]
fn torn_tail_is_ignored_but_forged_last_frame_is_not() {
    let dir = tmpdir();
    write_key(&dir, 2);
    fill(&dir, Some(PASS));
    let wal = fs::read(Db::wal_path(&dir)).unwrap();
    let (start, end) = *frames(&wal).last().unwrap();
    // Escrita interrompida: os últimos bytes não chegaram ao disco.
    let copy = copy_db(&dir);
    patch_wal(&copy, |b| b.truncate(end - 7));
    check(&copy, Some(PASS), N - 1).unwrap();
    // Último frame com CRC ruim: indistinguível de escrita interrompida, é ignorado.
    let copy = copy_db(&dir);
    patch_wal(&copy, |b| b[end - 20] ^= 0x01);
    check(&copy, Some(PASS), N - 1).unwrap();
    // Último frame inteiro (CRC refeito) com etiqueta que não confere: adulteração.
    let copy = copy_db(&dir);
    patch_wal(&copy, |b| {
        b[end - 20] ^= 0x01;
        fix_crc(b, start, end);
    });
    assert_corrupt(&copy, "último frame adulterado");
    // Depois da cauda descartada o LSN perdido é reutilizado (nonce novo) e recupera.
    let copy = copy_db(&dir);
    patch_wal(&copy, |b| b.truncate(end - 7));
    {
        let mut db = Db::open_encrypted(&copy, 64, true, Some(PASS)).unwrap();
        db.put(b"depois", b"1").unwrap();
        db.drop_without_checkpoint();
    }
    let db = Db::open_encrypted(&copy, 64, true, Some(PASS)).unwrap();
    assert_eq!(db.get(b"depois").unwrap().as_deref(), Some(&b"1"[..]));
    assert_eq!(db.get(&key(N - 1)).unwrap(), None);
    assert_eq!(db.get(&key(N - 2)).unwrap().unwrap(), val(N - 2));
}

#[test]
fn plaintext_wal_keeps_format_and_tail_semantics() {
    let dir = tmpdir();
    fill(&dir, None);
    let wal = fs::read(Db::wal_path(&dir)).unwrap();
    let all = frames(&wal);
    let (start, end) = *all.last().unwrap();
    // Frame em claro: cabeçalho(8) lsn(8) tipo(1) e o payload, sem nonce nem etiqueta.
    assert_eq!(end - start, 8 + 9 + 8 + key(0).len() + val(0).len());
    check(&copy_db(&dir), None, N).unwrap();
    let copy = copy_db(&dir);
    patch_wal(&copy, |b| b.truncate(end - 7));
    check(&copy, None, N - 1).unwrap();
    let (mid, _) = all[all.len() / 2];
    let copy = copy_db(&dir);
    patch_wal(&copy, |b| b[mid + 20] ^= 0x01);
    match check(&copy, None, N) {
        Err(Error::CorruptWal(_)) => {}
        other => panic!("CRC ruim no meio do WAL em claro: veio {other:?}"),
    }
}

#[test]
fn legacy_v1_cipher_keeps_unauthenticated_frames_and_recovers() {
    let dir = tmpdir();
    write_key(&dir, 1);
    fill(&dir, Some(PASS));
    let wal = fs::read(Db::wal_path(&dir)).unwrap();
    let (start, end) = *frames(&wal).last().unwrap();
    // v1: sal(4) + texto cifrado, sem etiqueta.
    assert_eq!(end - start, 8 + 9 + 4 + 8 + key(0).len() + val(0).len());
    check(&copy_db(&dir), Some(PASS), N).unwrap();
    let copy = copy_db(&dir);
    patch_wal(&copy, |b| b.truncate(end - 7));
    check(&copy, Some(PASS), N - 1).unwrap();
}
