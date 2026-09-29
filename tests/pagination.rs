use mini_db::db::Db;
#[test]
fn cursor_does_not_repeat_boundary() {
    let path = std::env::temp_dir().join(format!(
        "minidb-page-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
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
