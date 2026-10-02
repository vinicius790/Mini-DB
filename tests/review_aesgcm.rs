//! TLS 1.3 com TLS_AES_128_GCM_SHA256 e TLS_CHACHA20_POLY1305_SHA256 contra o
//! `openssl s_client` (implementação independente): o servidor interno escolhe a
//! suíte preferida do cliente e a conexão HTTPS completa troca dados.
//! O teste é ignorado (retorna) se o `openssl` não estiver instalado.

use mini_db::config::NetOptions;
use mini_db::metrics::Metrics;
use mini_db::mvcc::SharedDb;
use mini_db::tls::Identity;
use mini_db::Db;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const AES: &str = "TLS_AES_128_GCM_SHA256";
const CHACHA: &str = "TLS_CHACHA20_POLY1305_SHA256";

fn free_addr() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

fn have_openssl() -> bool {
    Command::new("openssl").arg("version").output().is_ok()
}

/// Copia tudo o que `r` produz para `out` (stdout e stderr do openssl juntos).
fn pump(mut r: impl Read + Send + 'static, out: Arc<Mutex<Vec<u8>>>) {
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
}

/// Conecta com `openssl s_client -tls1_3`, oferecendo só `suites`, manda um GET e
/// devolve a saída (stdout + stderr) assim que a resposta chega (ou após 20 s).
fn s_client(addr: &str, suites: &str) -> String {
    let mut cmd = Command::new("openssl");
    cmd.args(["s_client", "-connect", addr]);
    cmd.args(["-tls1_3", "-ciphersuites", suites]);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let out = Arc::new(Mutex::new(Vec::new()));
    pump(child.stdout.take().unwrap(), out.clone());
    pump(child.stderr.take().unwrap(), out.clone());
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n");
    let _ = stdin.flush();
    let start = Instant::now();
    let text = loop {
        let text = String::from_utf8_lossy(&out.lock().unwrap()).into_owned();
        if text.contains("\"ok\":true") || start.elapsed() > Duration::from_secs(20) {
            break text;
        }
        thread::sleep(Duration::from_millis(50));
    };
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    text
}

/// O openssl 1.1/3 imprime "Cipher is X" (linha `New,`) e "Cipher    : X" (sessão).
fn negotiated(text: &str, suite: &str) -> bool {
    let is_form = format!("Cipher is {suite}");
    let session_form = format!("Cipher    : {suite}");
    text.contains(&is_form) || text.contains(&session_form)
}

#[test]
fn openssl_negotiates_aes128gcm_and_chacha20_over_https() {
    if !have_openssl() {
        eprintln!("openssl ausente: teste ignorado");
        return;
    }
    // Uma pasta por execução: o servidor fica com o banco aberto até o fim.
    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
    let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("minidb-aesgcm-{n}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let db = Db::open(&dir).unwrap();
    let identity = Identity::load_or_create(&dir, "127.0.0.1").unwrap();
    let opts = NetOptions {
        tls: Some(identity),
        ..NetOptions::default()
    };
    let addr = free_addr();
    {
        let (db, addr) = (SharedDb::new(db), addr.clone());
        let metrics = Arc::new(Metrics::new());
        thread::spawn(move || mini_db::http::serve_http_with(db, metrics, &addr, opts));
    }
    let start = Instant::now();
    while TcpStream::connect(&addr).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "servidor não subiu"
        );
        thread::sleep(Duration::from_millis(20));
    }
    // (suítes oferecidas, suíte esperada): o servidor segue a ordem do cliente.
    let cases = [
        (AES.to_string(), AES),
        (CHACHA.to_string(), CHACHA),
        (format!("{CHACHA}:{AES}"), CHACHA),
        (format!("{AES}:{CHACHA}"), AES),
    ];
    for (offer, expected) in &cases {
        let text = s_client(&addr, offer);
        assert!(negotiated(&text, expected), "oferta {offer}: {text}");
        assert!(text.contains("\"ok\":true"), "oferta {offer}: {text}");
    }
}
