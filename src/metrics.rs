//! Métricas in-process no formato Prometheus text exposition.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub struct Metrics {
    pub puts: AtomicU64,
    pub gets: AtomicU64,
    pub get_hits: AtomicU64,
    pub deletes: AtomicU64,
    pub sql: AtomicU64,
    pub http_requests: AtomicU64,
    pub errors: AtomicU64,
    pub wal_records: AtomicU64,
    pub batch_ops: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_put(&self) {
        self.puts.fetch_add(1, Ordering::Relaxed);
        self.wal_records.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_get(&self, hit: bool) {
        self.gets.fetch_add(1, Ordering::Relaxed);
        if hit {
            self.get_hits.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn inc_delete(&self) {
        self.deletes.fetch_add(1, Ordering::Relaxed);
        self.wal_records.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_batch(&self, ops: u64) {
        self.batch_ops.fetch_add(ops, Ordering::Relaxed);
        self.wal_records.fetch_add(ops, Ordering::Relaxed);
    }
    pub fn inc_sql(&self) {
        self.sql.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_http(&self) {
        self.http_requests.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_err(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        format!(
            "# HELP minidb_puts_total PUT/INSERT aplicados\n\
             # TYPE minidb_puts_total counter\n\
             minidb_puts_total {}\n\
             # TYPE minidb_gets_total counter\n\
             minidb_gets_total {}\n\
             # TYPE minidb_get_hits_total counter\n\
             minidb_get_hits_total {}\n\
             # TYPE minidb_deletes_total counter\n\
             minidb_deletes_total {}\n\
             # TYPE minidb_sql_total counter\n\
             minidb_sql_total {}\n\
             # TYPE minidb_http_requests_total counter\n\
             minidb_http_requests_total {}\n\
             # TYPE minidb_errors_total counter\n\
             minidb_errors_total {}\n\
             # TYPE minidb_wal_records_total counter\n\
             minidb_wal_records_total {}\n\
             # TYPE minidb_batch_ops_total counter\n\
             minidb_batch_ops_total {}\n\
             # TYPE minidb_scrape_ts gauge\n\
             minidb_scrape_ts {}\n",
            self.puts.load(Ordering::Relaxed),
            self.gets.load(Ordering::Relaxed),
            self.get_hits.load(Ordering::Relaxed),
            self.deletes.load(Ordering::Relaxed),
            self.sql.load(Ordering::Relaxed),
            self.http_requests.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.wal_records.load(Ordering::Relaxed),
            self.batch_ops.load(Ordering::Relaxed),
            ts
        )
    }
}
