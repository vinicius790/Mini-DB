//! ABI C estável para consumir o Mini-DB a partir de C, C++ ou qualquer linguagem com FFI.
//!
//! Todas as funções exportadas são `unsafe`: o chamador C garante o contrato
//! documentado em `include/minidb.h`.
//!
//! ```c
//! void* minidb_open(const char* dir);
//! int   minidb_put(void* db, const char* k, const char* v);
//! int   minidb_get(void* db, const char* k, char* out, int out_len);
//! int   minidb_delete(void* db, const char* k);
//! void  minidb_close(void* db);
//! ```

use crate::db::Db;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::ptr;

unsafe fn db_mut<'a>(handle: *mut Db) -> Option<&'a mut Db> {
    if handle.is_null() {
        None
    } else {
        Some(&mut *handle)
    }
}

unsafe fn close_handle(handle: *mut Db) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let mut db = unsafe { Box::from_raw(handle) };
    match db.close() {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
#[no_mangle]
pub unsafe extern "C" fn minidb_open(dir: *const c_char) -> *mut Db {
    if dir.is_null() {
        return ptr::null_mut();
    }
    let c = unsafe { CStr::from_ptr(dir) };
    let s = match c.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    match Db::open(s) {
        Ok(db) => Box::into_raw(Box::new(db)),
        Err(_) => ptr::null_mut(),
    }
}

/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
#[no_mangle]
pub unsafe extern "C" fn minidb_close(handle: *mut Db) {
    if !handle.is_null() {
        let _ = close_handle(handle);
    }
}

/// Fecha o handle e retorna 0 em sucesso, -1 para handle nulo, -2 se o close falhar.
/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
#[no_mangle]
pub unsafe extern "C" fn minidb_close_checked(handle: *mut Db) -> c_int {
    close_handle(handle)
}

/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
#[no_mangle]
pub unsafe extern "C" fn minidb_put(
    handle: *mut Db,
    key: *const c_char,
    val: *const c_char,
) -> c_int {
    if key.is_null() || val.is_null() {
        return -1;
    }
    let k = unsafe { CStr::from_ptr(key) }.to_bytes();
    let v = unsafe { CStr::from_ptr(val) }.to_bytes();
    minidb_put_bytes(handle, k.as_ptr(), k.len(), v.as_ptr(), v.len())
}

/// Insere bytes arbitrários. Retorno: 0 sucesso, -1 argumentos inválidos, -2 erro do banco.
/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
#[no_mangle]
pub unsafe extern "C" fn minidb_put_bytes(
    handle: *mut Db,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
) -> c_int {
    let db = match unsafe { db_mut(handle) } {
        Some(d) => d,
        None => return -1,
    };
    if key.is_null() || (value.is_null() && value_len != 0) {
        return -1;
    }
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };
    let value = if value_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(value, value_len) }
    };
    if crate::btree::validate_user_key(key).is_err() || crate::btree::validate_value(value).is_err()
    {
        return -1;
    }
    match db.put(key, value) {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

/// Copia bytes para `out`, acrescenta NUL e retorna o tamanho sem o terminador.
/// Não converte nem valida UTF-8; retorna 0 para miss ou valor vazio, <0 em erro.
/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
#[no_mangle]
pub unsafe extern "C" fn minidb_get(
    handle: *mut Db,
    key: *const c_char,
    out: *mut c_char,
    out_len: c_int,
) -> c_int {
    if key.is_null() || out.is_null() || out_len < 1 {
        return -1;
    }
    let k = unsafe { CStr::from_ptr(key) }.to_bytes();
    if crate::btree::validate_user_key(k).is_err() {
        return -1;
    }
    let result = minidb_get_bytes(
        handle,
        k.as_ptr(),
        k.len(),
        out as *mut u8,
        out_len as usize - 1,
    );
    if result < 0 {
        return result as c_int;
    }
    unsafe { *out.add(result as usize) = 0 };
    result as c_int
}

/// Retorna o tamanho do valor: 0 se ausente, -1 argumentos inválidos, -2 erro do banco.
/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
#[no_mangle]
pub unsafe extern "C" fn minidb_get_size(handle: *mut Db, key: *const u8, key_len: usize) -> isize {
    let db = match unsafe { db_mut(handle) } {
        Some(d) => d,
        None => return -1,
    };
    if key.is_null() {
        return -1;
    }
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };
    if crate::btree::validate_user_key(key).is_err() {
        return -1;
    }
    match db.get(key) {
        Ok(Some(value)) => value.len() as isize,
        Ok(None) => 0,
        Err(_) => -2,
    }
}

/// Retorna 1 se a chave existe, 0 se está ausente, -1 em argumentos inválidos,
/// -2 em erro do banco. Útil para distinguir valor vazio de chave ausente.
/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
#[no_mangle]
pub unsafe extern "C" fn minidb_exists(handle: *mut Db, key: *const u8, key_len: usize) -> c_int {
    let db = match unsafe { db_mut(handle) } {
        Some(d) => d,
        None => return -1,
    };
    if key.is_null() {
        return -1;
    }
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };
    if crate::btree::validate_user_key(key).is_err() {
        return -1;
    }
    match db.get(key) {
        Ok(Some(_)) => 1,
        Ok(None) => 0,
        Err(_) => -2,
    }
}

/// Copia bytes sem terminador NUL. Retorno: bytes copiados, 0 se ausente,
/// -1 argumentos inválidos, -2 erro do banco, -3 buffer insuficiente.
/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
#[no_mangle]
pub unsafe extern "C" fn minidb_get_bytes(
    handle: *mut Db,
    key: *const u8,
    key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> isize {
    let db = match unsafe { db_mut(handle) } {
        Some(d) => d,
        None => return -1,
    };
    if key.is_null() || (out.is_null() && out_len != 0) {
        return -1;
    }
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };
    if crate::btree::validate_user_key(key).is_err() {
        return -1;
    }
    match db.get(key) {
        Ok(None) => 0,
        Ok(Some(value)) => {
            if value.len() > out_len {
                return -3;
            }
            if !value.is_empty() {
                unsafe { ptr::copy_nonoverlapping(value.as_ptr(), out, value.len()) };
            }
            value.len() as isize
        }
        Err(_) => -2,
    }
}

/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
#[no_mangle]
pub unsafe extern "C" fn minidb_delete(handle: *mut Db, key: *const c_char) -> c_int {
    let db = match unsafe { db_mut(handle) } {
        Some(d) => d,
        None => return -1,
    };
    if key.is_null() {
        return -1;
    }
    let k = unsafe { CStr::from_ptr(key) }.to_bytes();
    if crate::btree::validate_user_key(k).is_err() {
        return -1;
    }
    match db.delete(k) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -2,
    }
}

/// # Safety
/// Contrato de `include/minidb.h`: ponteiros e comprimentos válidos, handle
/// aberto por `minidb_open` e uso exclusivo (sem chamadas concorrentes).
/// Grava com expiração em `ttl_ms` milissegundos (> 0). Retorno como
/// `minidb_put_bytes`.
#[no_mangle]
pub unsafe extern "C" fn minidb_put_ttl_bytes(
    handle: *mut Db,
    key: *const u8,
    key_len: usize,
    value: *const u8,
    value_len: usize,
    ttl_ms: u64,
) -> c_int {
    let Some(db) = db_mut(handle) else {
        return -1;
    };
    if key.is_null() || (value.is_null() && value_len != 0) || ttl_ms == 0 {
        return -1;
    }
    let key = std::slice::from_raw_parts(key, key_len);
    let value = if value_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(value, value_len)
    };
    match db.put_with_ttl(key, value, std::time::Duration::from_millis(ttl_ms)) {
        Ok(()) => 0,
        Err(e) if e.is_client_error() => -1,
        Err(_) => -2,
    }
}

/// # Safety
/// Contrato de `include/minidb.h`. Conta as chaves visíveis em
/// `[start, end)`; `end == NULL` significa sem limite superior. Devolve a
/// contagem ou -1 (argumento inválido) / -2 (erro do banco).
#[no_mangle]
pub unsafe extern "C" fn minidb_count(
    handle: *mut Db,
    start: *const u8,
    start_len: usize,
    end: *const u8,
    end_len: usize,
) -> i64 {
    let Some(db) = db_mut(handle) else {
        return -1;
    };
    if start.is_null() {
        return -1;
    }
    let start = std::slice::from_raw_parts(start, start_len);
    let end = (!end.is_null()).then(|| std::slice::from_raw_parts(end, end_len));
    match db.count(start, end) {
        Ok(n) => i64::try_from(n).unwrap_or(i64::MAX),
        Err(e) if e.is_client_error() => -1,
        Err(_) => -2,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        minidb_close_checked, minidb_count, minidb_exists, minidb_get, minidb_get_bytes,
        minidb_get_size, minidb_open, minidb_put_bytes, minidb_put_ttl_bytes,
    };
    use std::ffi::CString;
    use std::fs;

    #[test]
    fn binary_ffi_roundtrip_reports_required_capacity() {
        unsafe { roundtrip() }
    }
    unsafe fn roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "minidb-ffi-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let c_dir = CString::new(dir.to_str().unwrap()).unwrap();
        let handle = minidb_open(c_dir.as_ptr());
        assert!(!handle.is_null());

        let key = b"binary";
        let value = [0u8, 1, 2, 255, 0];
        assert_eq!(
            minidb_put_bytes(handle, key.as_ptr(), key.len(), value.as_ptr(), value.len()),
            0
        );
        assert_eq!(minidb_exists(handle, key.as_ptr(), key.len()), 1);
        assert_eq!(minidb_exists(handle, b"missing".as_ptr(), 7), 0);
        assert_eq!(
            minidb_get_size(handle, key.as_ptr(), key.len()),
            value.len() as isize
        );

        let mut short = [0u8; 2];
        assert_eq!(
            minidb_get_bytes(
                handle,
                key.as_ptr(),
                key.len(),
                short.as_mut_ptr(),
                short.len()
            ),
            -3
        );
        let mut out = [0u8; 5];
        assert_eq!(
            minidb_get_bytes(handle, key.as_ptr(), key.len(), out.as_mut_ptr(), out.len()),
            5
        );
        assert_eq!(out, value);

        let empty_key = b"empty";
        assert_eq!(
            minidb_put_bytes(
                handle,
                empty_key.as_ptr(),
                empty_key.len(),
                std::ptr::null(),
                0
            ),
            0
        );
        assert_eq!(
            minidb_get_size(handle, empty_key.as_ptr(), empty_key.len()),
            0
        );
        assert_eq!(
            minidb_exists(handle, empty_key.as_ptr(), empty_key.len()),
            1
        );
        assert_eq!(
            minidb_get_bytes(
                handle,
                empty_key.as_ptr(),
                empty_key.len(),
                std::ptr::null_mut(),
                0
            ),
            0
        );
        let empty_key = CString::new("empty").unwrap();
        let mut empty_text = [0i8; 1];
        assert_eq!(
            minidb_get(handle, empty_key.as_ptr(), empty_text.as_mut_ptr(), 1),
            0
        );
        assert_eq!(empty_text[0], 0);

        let oversized_key = [b'k'; crate::page::MAX_KEY_LEN + 1];
        assert_eq!(
            minidb_put_bytes(
                handle,
                oversized_key.as_ptr(),
                oversized_key.len(),
                value.as_ptr(),
                value.len()
            ),
            -1
        );
        assert_eq!(minidb_get_size(handle, b"".as_ptr(), 0), -1);

        let ttl_key = b"ttl";
        assert_eq!(
            minidb_put_ttl_bytes(handle, ttl_key.as_ptr(), 3, value.as_ptr(), 1, 60_000),
            0
        );
        assert_eq!(
            minidb_put_ttl_bytes(handle, ttl_key.as_ptr(), 3, value.as_ptr(), 1, 0),
            -1
        );
        let from = [0u8];
        assert_eq!(
            minidb_count(handle, from.as_ptr(), 1, std::ptr::null(), 0),
            3
        );
        assert_eq!(minidb_close_checked(handle), 0);
        fs::remove_dir_all(dir).unwrap();
    }
}
