//! Teste baseado em modelo: sequências pseudoaleatórias de operações são
//! aplicadas ao `Db` e a um `BTreeMap` de referência, com crashes, reaberturas,
//! checkpoints, transações e vacuum no meio. Qualquer divergência falha.
//!
//! Semente e tamanho ajustáveis: `MINIDB_MODEL_SEED`, `MINIDB_MODEL_STEPS`.
use mini_db::Db;
use std::collections::BTreeMap;
use std::time::Duration;

/// xorshift64* — determinístico e sem dependências.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn key(rng: &mut Rng) -> Vec<u8> {
    // Espaço pequeno de chaves força upserts, deletes de chaves existentes e
    // folhas que esvaziam e voltam a encher.
    let n = rng.below(400);
    let mut k = format!("key{n:04}").into_bytes();
    if n.is_multiple_of(7) {
        k.push(0); // bytes não textuais também
        k.push(0xff);
    }
    k
}

fn value(rng: &mut Rng) -> Vec<u8> {
    let len = rng.below(260) as usize;
    (0..len).map(|_| rng.below(256) as u8).collect()
}

fn run(seed: u64, steps: u64) {
    let dir = std::env::temp_dir().join(format!("minidb-model-{seed}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut rng = Rng(seed.max(1));
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut db = Some(Db::open_with_capacity(&dir, 6).unwrap());
    for step in 0..steps {
        let handle = db.as_mut().unwrap();
        let ctx = format!("seed={seed} step={step}");
        match rng.below(100) {
            0..=44 => {
                let (k, v) = (key(&mut rng), value(&mut rng));
                if rng.below(5) == 0 {
                    // TTL longo: não expira no teste, mas exercita a árvore de
                    // TTL em crashes, deletes, upserts e vacuum (verify confere).
                    handle
                        .put_with_ttl(&k, &v, Duration::from_secs(3600))
                        .unwrap();
                } else {
                    handle.put(&k, &v).unwrap();
                }
                model.insert(k, v);
            }
            45..=64 => {
                let k = key(&mut rng);
                assert_eq!(
                    handle.delete(&k).unwrap(),
                    model.remove(&k).is_some(),
                    "{ctx}"
                );
            }
            65..=79 => {
                let k = key(&mut rng);
                assert_eq!(handle.get(&k).unwrap(), model.get(&k).cloned(), "{ctx}");
            }
            80..=85 => {
                let (a, b) = (key(&mut rng), key(&mut rng));
                let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                let got = handle.scan(&lo, Some(&hi)).unwrap();
                let want: Vec<_> = model
                    .range(lo.clone()..hi.clone())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                assert_eq!(got, want, "{ctx}");
            }
            86..=89 => {
                // Transação: commit ou rollback aleatório.
                handle.begin().unwrap();
                let mut staged = model.clone();
                for _ in 0..rng.below(20) {
                    let k = key(&mut rng);
                    if rng.below(3) == 0 {
                        handle.delete(&k).unwrap();
                        staged.remove(&k);
                    } else {
                        let v = value(&mut rng);
                        handle.put(&k, &v).unwrap();
                        staged.insert(k, v);
                    }
                }
                if rng.below(2) == 0 {
                    handle.commit().unwrap();
                    model = staged;
                } else {
                    handle.rollback().unwrap();
                }
            }
            90..=93 => {
                // Crash: abandona sem checkpoint e reabre (recovery pelo WAL).
                db.take().unwrap().drop_without_checkpoint();
                db = Some(Db::open_with_capacity(&dir, 6).unwrap());
            }
            94..=96 => handle.checkpoint().unwrap(),
            97 => {
                handle.vacuum().unwrap();
            }
            _ => {
                let mut closing = db.take().unwrap();
                closing.close().unwrap();
                drop(closing);
                db = Some(Db::open_with_capacity(&dir, 6).unwrap());
            }
        }
    }
    let handle = db.as_mut().unwrap();
    let all = handle.scan(b"\0", None).unwrap();
    let want: Vec<_> = model.into_iter().collect();
    assert_eq!(all.len(), want.len(), "seed={seed} tamanho final");
    assert_eq!(all, want, "seed={seed} conteúdo final");
    handle.verify().unwrap();
    drop(db);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn random_operations_match_btreemap_model() {
    let steps = env("MINIDB_MODEL_STEPS", 600);
    match std::env::var("MINIDB_MODEL_SEED") {
        Ok(seed) => run(seed.parse().expect("semente numérica"), steps),
        Err(_) => {
            for seed in [1, 42, 1337, 0xDEAD_BEEF] {
                run(seed, steps);
            }
        }
    }
}
