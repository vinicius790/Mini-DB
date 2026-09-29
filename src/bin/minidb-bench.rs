//! Microbenchmark local do Mini-DB.
//!
//! Mede cargas típicas com latência por operação (p50/p99/máx) e vazão. Os
//! números valem só para a máquina e o disco onde rodaram — o projeto não
//! publica resultados de propósito.
//!
//! Uso: `minidb-bench [n] [--no-fsync] [--json]`
use mini_db::{BatchOp, Db};
use std::env;
use std::fs;
use std::time::{Duration, Instant};

struct Sample {
    name: &'static str,
    ops: usize,
    total: Duration,
    latencies: Vec<Duration>,
}

impl Sample {
    fn percentile(&self, p: f64) -> Duration {
        if self.latencies.is_empty() {
            return Duration::ZERO;
        }
        let idx = ((self.latencies.len() - 1) as f64 * p).round() as usize;
        self.latencies[idx]
    }

    fn ops_per_sec(&self) -> f64 {
        self.ops as f64 / self.total.as_secs_f64().max(f64::EPSILON)
    }
}

/// Executa `op` `n` vezes medindo cada chamada.
fn measure(
    name: &'static str,
    n: usize,
    mut op: impl FnMut(usize) -> mini_db::Result<()>,
) -> mini_db::Result<Sample> {
    let mut latencies = Vec::with_capacity(n);
    let start = Instant::now();
    for i in 0..n {
        let t = Instant::now();
        op(i)?;
        latencies.push(t.elapsed());
    }
    let total = start.elapsed();
    latencies.sort_unstable();
    Ok(Sample {
        name,
        ops: n,
        total,
        latencies,
    })
}

/// Permutação determinística de `0..n` (LCG), para leituras aleatórias.
fn shuffled(n: usize) -> Vec<usize> {
    let mut v: Vec<usize> = (0..n).collect();
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    for i in (1..n).rev() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        v.swap(i, (s >> 33) as usize % (i + 1));
    }
    v
}

fn key(i: usize) -> Vec<u8> {
    format!("user:{i:08}").into_bytes()
}

fn main() -> mini_db::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let n: usize = args
        .iter()
        .find_map(|a| a.parse().ok())
        .unwrap_or(2000)
        .max(1);
    let fsync = !args.iter().any(|a| a == "--no-fsync");
    let json = args.iter().any(|a| a == "--json");
    let dir = env::temp_dir().join(format!("minidb-bench-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let value = vec![b'v'; 100];
    let order = shuffled(n);
    let mut results = Vec::new();
    {
        let mut db = Db::open_with_options(&dir, 256, fsync)?;
        results.push(measure("put_seq", n, |i| db.put(&key(i), &value))?);
        results.push(measure("get_random_hit", n, |i| {
            db.get(&key(order[i])).map(|v| assert!(v.is_some()))
        })?);
        results.push(measure("get_miss_bloom", n, |i| {
            db.get(format!("miss:{i}").as_bytes())
                .map(|v| assert!(v.is_none()))
        })?);
        let batches = n.div_ceil(100);
        results.push(measure("batch_100_puts", batches, |b| {
            let ops: Vec<BatchOp> = (b * 100..((b + 1) * 100).min(n))
                .map(|i| BatchOp::Put {
                    key: format!("batch:{i:08}").into_bytes(),
                    value: value.clone(),
                })
                .collect();
            db.write_batch(&ops)
        })?);
        results.push(measure("scan_prefix_100", 100, |_| {
            db.scan_prefix(b"user:")?
                .take(100)
                .try_for_each(|r| r.map(drop))
        })?);
        results.push(measure("count_all", 5, |_| {
            db.count(b"\0", None).map(drop)
        })?);
        results.push(measure("delete_random", n / 2, |i| {
            db.delete(&key(order[i])).map(drop)
        })?);
        results.push(measure("checkpoint", 1, |_| db.checkpoint())?);
        results.push(measure("vacuum", 1, |_| db.vacuum().map(drop))?);
        for i in 0..n / 4 {
            db.put(format!("tail:{i}").as_bytes(), &value)?;
        }
        db.drop_without_checkpoint();
    }
    results.push(measure("reopen_with_recovery", 1, |_| {
        Db::open(&dir)?.close()
    })?);
    let _ = fs::remove_dir_all(&dir);

    if json {
        let rows: Vec<String> = results
            .iter()
            .map(|s| {
                format!(
                    "{{\"name\":\"{}\",\"ops\":{},\"ops_per_sec\":{:.1},\"p50_us\":{},\"p99_us\":{},\"max_us\":{}}}",
                    s.name,
                    s.ops,
                    s.ops_per_sec(),
                    s.percentile(0.50).as_micros(),
                    s.percentile(0.99).as_micros(),
                    s.percentile(1.0).as_micros()
                )
            })
            .collect();
        println!(
            "{{\"n\":{n},\"fsync\":{fsync},\"results\":[{}]}}",
            rows.join(",")
        );
        return Ok(());
    }
    println!(
        "minidb-bench n={n} fsync={fsync} (resultados locais, não comparáveis entre máquinas)"
    );
    println!(
        "{:<22} {:>8} {:>12} {:>10} {:>10} {:>10}",
        "carga", "ops", "ops/s", "p50 µs", "p99 µs", "máx µs"
    );
    for s in &results {
        println!(
            "{:<22} {:>8} {:>12.0} {:>10} {:>10} {:>10}",
            s.name,
            s.ops,
            s.ops_per_sec(),
            s.percentile(0.50).as_micros(),
            s.percentile(0.99).as_micros(),
            s.percentile(1.0).as_micros()
        );
    }
    Ok(())
}
