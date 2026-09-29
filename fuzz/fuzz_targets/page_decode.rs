#![no_main]
//! Página arbitrária de 4 KiB: validação e dump nunca entram em pânico.
use libfuzzer_sys::fuzz_target;
use mini_db::page::{Page, PageKind, PAGE_SIZE};

fuzz_target!(|data: &[u8]| {
    let mut bytes = [0u8; PAGE_SIZE];
    let n = data.len().min(PAGE_SIZE);
    bytes[..n].copy_from_slice(&data[..n]);
    if let Ok(page) = Page::from_bytes(&bytes) {
        if page.validate_header().is_ok() && page.kind() == PageKind::Leaf {
            for i in 0..page.n_slots() as usize {
                let _ = page.leaf_cell(i);
            }
        }
    }
});
