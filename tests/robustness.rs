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
    let db = Db::open(&dir).unwrap();
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

#[test]
fn regex_compiler_and_matcher_never_panic() {
    use mini_db::rel::regex::Regex;
    let mut rng = Rng(29);
    let alphabet: &[u8] = b"ab01.*+?|()[]{}^$\\:-,dws alphnum";
    for _ in 0..ITERS {
        let raw = rng.bytes(24, alphabet);
        let pattern = String::from_utf8_lossy(&raw);
        if let Ok(re) = Regex::new(&pattern, "") {
            let _ = re.is_match("ab01 ab0");
        }
    }
    // Classe POSIX sem nome já causou pânico (fatia invertida).
    assert!(Regex::new("[[:]", "").is_err());
    assert!(Regex::new("[[:alpha:]]+", "").unwrap().is_match("abc"));
    assert!(!Regex::new("^[[:digit:]]+$", "").unwrap().is_match("abc"));
    // Texto no tamanho máximo: o casador usa uma pilha de retrocesso no heap, então nem
    // `.*` nem um grupo repetido gastam pilha nativa por caractere ou por volta.
    let long = "a".repeat(50_000);
    assert!(Regex::new("^.*$", "").unwrap().is_match(&long));
    assert!(Regex::new("(a)*$", "").unwrap().is_match(&long));
    assert!(!Regex::new("^((a|b))+c", "").unwrap().is_match(&long));
    // Orçamento da varredura: uma busca quadrática legítima (`[a-z]+` recua em cada uma
    // das 5 mil posições, uns 2,5e7 passos) ainda casa; as patológicas desistem logo.
    let letters = format!("{} foo1", "a".repeat(5_000));
    assert!(Regex::new("[a-z]+\\d", "").unwrap().is_match(&letters));
    // `(a|aa)+$` casa sem recuar; em `(a*)*b` (sem 'b' no texto) o orçamento de passos
    // corta a busca exponencial.
    assert!(Regex::new("(a|aa)+$", "").unwrap().is_match(&long));
    assert!(!Regex::new("(a*)*b", "").unwrap().is_match(&long));
}

#[test]
fn regex_has_no_practical_depth_limit() {
    use mini_db::rel::regex::Regex;
    let re = |p: &str| Regex::new(p, "").unwrap();
    // Grupo repetido milhares de vezes e padrão com milhares de átomos em sequência.
    let ab = "ab".repeat(10_000);
    assert!(re("(ab)*c").is_match(&format!("{ab}c")));
    assert!(re("^(a|b)+$").is_match(&ab.repeat(2)));
    let literal = "ab".repeat(1_000);
    let exact = re(&format!("^{literal}$"));
    assert!(exact.is_match(&literal));
    assert!(!exact.is_match(&format!("{literal}x")));
    // Capturas e preguiça seguem a mesma ordem de tentativas de sempre.
    let chars: Vec<char> = "ab".chars().collect();
    let (_, _, caps) = re("(a)(b)?").find_at(&chars, 0).unwrap();
    assert_eq!(caps, vec![Some((0, 2)), Some((0, 1)), Some((1, 2))]);
    let chars: Vec<char> = "aaab".chars().collect();
    let (start, end, _) = re("a+?b").find_at(&chars, 0).unwrap();
    assert_eq!((start, end), (0, 4));
}

#[test]
fn pem_and_certificate_decoders_never_panic() {
    let mut rng = Rng(31);
    for _ in 0..ITERS {
        let raw = rng.bytes(96, &[]);
        let _ = mini_db::x509::Cert::parse(&raw);
        let pem = rng.bytes(96, b"-BEGINDCRTFAK \nabc+/=");
        let text = String::from_utf8_lossy(&pem);
        let _ = mini_db::x509::pem_all(&text, "CERTIFICATE");
        let _ = mini_db::pubkey::PrivateKey::from_pem(&text);
    }
}
