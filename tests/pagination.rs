use mini_db::db::Db;

/// Sufixo único por processo: só pid + relógio colide entre testes paralelos.
static NEXT_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[test]
fn cursor_does_not_repeat_boundary() {
    let path = std::env::temp_dir().join(format!(
        "minidb-page-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    {
        let mut db = Db::open(&path).unwrap();
        for key in [b"a", b"b", b"c"] {
            db.put(key, b"value").unwrap();
        }
        let page = db.scan_page(b"", None, None, 2).unwrap();
        assert_eq!(page.len(), 2);
        let next = db.scan_page(b"", None, Some(&page[1].0), 2).unwrap();
        assert_eq!(next[0].0, b"c");
        assert_eq!(next.len(), 1);
    }
    std::fs::remove_dir_all(path).unwrap();
}
