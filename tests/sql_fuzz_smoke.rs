//! Mutações aleatórias de SQL válido: parser e executor devolvem erro, nunca entram em pânico.
use mini_db::Db;
const CORPUS: &[&str] = &[
    "CREATE TABLE a (id SERIAL PRIMARY KEY, x INT CHECK (x > 0), y TEXT DEFAULT now(), p INT REFERENCES a ON DELETE SET NULL)",
    "INSERT INTO a (x, y) VALUES (1, 'q'), (2, NULL) RETURNING *",
    "SELECT x, SUM(x) OVER (ORDER BY id ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING), lag(y, 1, 'z') OVER (PARTITION BY x % 2 ORDER BY id) FROM a WHERE x > ALL (SELECT 0) ORDER BY 1 NULLS LAST LIMIT 5 OFFSET 1",
    "WITH RECURSIVE n(k) AS (SELECT 1 UNION ALL SELECT k + 1 FROM n WHERE k < 9) SELECT group_concat(k, '-'), stddev(k) FROM n",
    "UPDATE a SET x = x * 2, y = upper(y) || printf('%03d', x) WHERE id IN (SELECT id FROM a) RETURNING id",
    "SELECT * FROM (VALUES (1, 'a'), (2, 'b')) AS v (n, s) JOIN a USING (id) WHERE s GLOB '[ab]*' AND n IS NOT DISTINCT FROM 1",
    "ALTER TABLE a RENAME COLUMN y TO yy; ALTER TABLE a ALTER COLUMN x SET DEFAULT (3 + 4); CREATE VIEW v AS SELECT yy FROM a",
    "DELETE FROM a WHERE json_extract('{\"a\":[1]}', '$.a[0]') = x OR date('2024-02-29', '+1 year') < yy RETURNING x",
    "SHOW CREATE TABLE a; DESCRIBE v; EXPLAIN SELECT rank() OVER () FROM a",
    "BEGIN; SAVEPOINT s; INSERT INTO a DEFAULT VALUES; ROLLBACK TO s; COMMIT",
];
const ROUNDS: usize = 3000;
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}
#[test]
fn mutated_sql_never_panics() {
    let dir = std::env::temp_dir().join(format!("minidb-panic-hunt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut db = Db::open(&dir).unwrap();
    let mut rng = Lcg(std::env::var("SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(42));
    let alphabet: Vec<char> =
        "()[],;.'\"*+-/%<>=|&~?$: abcxyzAND OR NOT NULL SELECT FROM WHERE OVER 019"
            .chars()
            .collect();
    let mut ran = 0usize;
    for round in 0..ROUNDS {
        let base = CORPUS[round % CORPUS.len()];
        let mut chars: Vec<char> = base.chars().collect();
        let edits = (rng.next() % 4) as usize;
        for _ in 0..edits {
            if chars.is_empty() {
                break;
            }
            let i = (rng.next() as usize) % chars.len();
            match rng.next() % 3 {
                0 => {
                    chars.remove(i);
                }
                1 => {
                    chars.insert(i, alphabet[(rng.next() as usize) % alphabet.len()]);
                }
                _ => {
                    chars[i] = alphabet[(rng.next() as usize) % alphabet.len()];
                }
            }
        }
        if rng.next().is_multiple_of(5) {
            let cut = (rng.next() as usize) % (chars.len() + 1);
            chars.truncate(cut);
        }
        let sql: String = chars.into_iter().collect();
        let _ = mini_db::rel::parser::parse(&sql);
        let _ = db.execute_sql(&sql);
        if db.execute_sql("SELECT 1").is_err() {
            let _ = db.execute_sql("ROLLBACK");
        }
        ran += 1;
    }
    assert_eq!(ran, ROUNDS);
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
