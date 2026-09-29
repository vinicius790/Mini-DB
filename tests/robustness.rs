//! Robustez dos decodificadores com entrada arbitrária: nenhum pode entrar em
//! pânico. É a versão estável (roda no `cargo test`) dos alvos de `fuzz/`.
use mini_db::json::Json;
use mini_db::page::{Page, PAGE_SIZE};
use mini_db::wal::{Wal, WalRecord};
use mini_db::{parse_sql, Db};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, max: usize, alphabet: &[u8]) -> Vec<u8> {
        let len = (self.next() as usize) % (max + 1);
        (0..len)
            .map(|_| {
                if alphabet.is_empty() {
                    self.next() as u8
                } else {
                    alphabet[(self.next() as usize) % alphabet.len()]
                }
            })
            .collect()
    }
}

const ITERS: usize = 20_000;

#[test]
fn sql_parser_never_panics() {
    let mut rng = Rng(7);
    let tokens: &[u8] = b"SELECT*FROMkvWHEREkey=<>'\"()%,; LIKECOUNTINSERTVALUESTTL0123\\";
    for _ in 0..ITERS {
        let raw = rng.bytes(80, tokens);
        let _ = parse_sql(&String::from_utf8_lossy(&raw));
    }
}

#[test]
fn json_parser_never_panics_and_roundtrips_valid_input() {
    let mut rng = Rng(11);
    let alphabet: &[u8] = b"{}[]\":,0123456789-+.eEtrufalsn\\u \x01\xc3\xa9";
    for _ in 0..ITERS {
        let raw = rng.bytes(64, alphabet);
        if let Ok(value) = Json::parse(&String::from_utf8_lossy(&raw)) {
            assert_eq!(Json::parse(&value.stringify()).unwrap(), value);
        }
    }
    let deep = "[".repeat(100_000);
    assert!(Json::parse(&deep).is_err());
}

#[test]
fn wal_decoder_never_panics() {
    let mut rng = Rng(13);
    for _ in 0..ITERS {
        let mut body = rng.bytes(48, &[]);
        if body.len() > 8 {
            body[8] = (rng.next() % 9) as u8; // tipos válidos com payload aleatório
        }
        if let Ok(record) = WalRecord::decode_body(&body) {
            let frame = record.encode_frame();
            assert_eq!(&frame[8..], body.as_slice(), "reencode idêntico");
        }
    }
}

#[test]
fn page_validation_never_panics() {
    let mut rng = Rng(17);
    let template = Page::zeroed(1, mini_db::page::PageKind::Leaf);
    for _ in 0..2_000 {
        let mut data = template.data;
        for _ in 0..(rng.next() % 32) {
            let at = (rng.next() as usize) % PAGE_SIZE;
            data[at] = rng.next() as u8;
        }
        if let Ok(page) = Page::from_bytes(&data) {
            let _ = page.validate_header();
        }
    }
}

#[test]
fn garbage_wal_tail_is_ignored_on_open() {
    let dir = std::env::temp_dir().join(format!("minidb-robust-wal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    {
        let mut db = Db::open(&dir).unwrap();
        db.put(b"k", b"v").unwrap();
        db.drop_without_checkpoint();
    }
    let mut rng = Rng(19);
    let mut wal = std::fs::read(Db::wal_path(&dir)).unwrap();
    wal.extend(rng.bytes(300, &[]));
    std::fs::write(Db::wal_path(&dir), &wal).unwrap();
    let (_, records) = Wal::read_all(Db::wal_path(&dir)).unwrap();
    assert!(!records.is_empty());
    let mut db = Db::open(&dir).unwrap();
    assert_eq!(db.get(b"k").unwrap().as_deref(), Some(b"v".as_ref()));
    drop(db);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn relational_parser_and_codec_never_panic() {
    let mut rng = Rng(23);
    let tokens: &[u8] = b"SELECT*FROM t JOIN ON WHERE GROUP BY ORDER LIMIT ()',.=<>+-|%_ AND OR NOT NULL IN 0123 'x'";
    for _ in 0..ITERS {
        let raw = rng.bytes(80, tokens);
        let _ = mini_db::rel::parser::parse(&String::from_utf8_lossy(&raw));
        let blob = rng.bytes(200, b"ab\x00\x01\x80\xff");
        assert_eq!(
            mini_db::codec::decode_value(&mini_db::codec::encode_value(&blob)).unwrap(),
            blob
        );
        let _ = mini_db::codec::decode_value(&blob);
    }
}
