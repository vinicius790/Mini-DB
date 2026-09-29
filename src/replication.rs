//! Replicação lógica primário → réplicas por streaming do log de commits.
//!
//! O primário mantém em memória um [`ChangeFeed`] com os últimos lotes
//! confirmados (cada um identificado pelo LSN do commit). A réplica conecta,
//! envia `SYNC <lsn>\n` com o último LSN do primário que já aplicou e recebe:
//!
//! - `BATCH` — um commit do primário, aplicado atomicamente junto com o novo
//!   LSN (gravado na chave interna [`APPLIED_KEY`]), então um crash da réplica
//!   nunca aplica um lote duas vezes nem pula um lote;
//! - `SNAPSHOT` — estado completo, quando o LSN pedido já saiu do feed (réplica
//!   nova, muito atrasada, ou primário reiniciado);
//! - `HEARTBEAT` — mantém a conexão viva e detecta quedas.
//!
//! Quadro: `[len:u32 LE][tipo:u8][lsn:u64 LE][ops]`; op: `[1][klen:u16][key]
//! [vlen:u16][val]` (put), `[2][klen][key]` (delete), `[3][klen][key][at:u64]`
//! (expiração absoluta em ms). Tabelas SQL são replicadas junto (são chaves).

use crate::db::{Db, Op, RESERVED_PREFIX};
use crate::error::{Error, Result};
use crate::mvcc::SharedDb;
use std::collections::{BTreeSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Chave interna onde a réplica guarda o último LSN do primário aplicado.
pub const APPLIED_KEY: &[u8] = &[RESERVED_PREFIX, b'r', b'l', b's', b'n'];

const T_BATCH: u8 = 1;
const T_SNAPSHOT: u8 = 2;
const T_HEARTBEAT: u8 = 3;
const POLL: Duration = Duration::from_millis(20);
const HEARTBEAT_EVERY: Duration = Duration::from_secs(1);
/// Quadros maiores que isso são rejeitados (proteção contra lixo na rede).
const MAX_FRAME: usize = 256 << 20;

/// Lotes confirmados recentes, completos para todo LSN `> base`.
pub struct ChangeFeed {
    base: u64,
    batches: VecDeque<(u64, Vec<Op>)>,
    ops: usize,
    max_ops: usize,
}

impl ChangeFeed {
    fn new(base: u64, max_ops: usize) -> Self {
        Self {
            base,
            batches: VecDeque::new(),
            ops: 0,
            max_ops: max_ops.max(1),
        }
    }

    pub(crate) fn push(&mut self, lsn: u64, ops: &[Op]) {
        self.ops += ops.len();
        self.batches.push_back((lsn, ops.to_vec()));
        while self.ops > self.max_ops && self.batches.len() > 1 {
            let (lsn, old) = self.batches.pop_front().expect("len > 1");
            self.ops -= old.len();
            self.base = lsn;
        }
    }

    /// Lotes com LSN `> after`, ou `None` se o feed não cobre mais esse ponto.
    fn since(&self, after: u64) -> Option<Vec<(u64, Vec<Op>)>> {
        if after < self.base {
            return None;
        }
        Some(
            self.batches
                .iter()
                .filter(|(lsn, _)| *lsn > after)
                .cloned()
                .collect(),
        )
    }
}

// ---------------------------------------------------------------------------
// Codificação
// ---------------------------------------------------------------------------

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}

fn encode_frame(kind: u8, lsn: u64, ops: &[Op]) -> Vec<u8> {
    let mut body = vec![kind];
    body.extend_from_slice(&lsn.to_le_bytes());
    for op in ops {
        match op {
            Op::Put { key, value } => {
                body.push(1);
                put_bytes(&mut body, key);
                put_bytes(&mut body, value);
            }
            Op::Delete { key } => {
                body.push(2);
                put_bytes(&mut body, key);
            }
            Op::Expire { key, at } => {
                body.push(3);
                put_bytes(&mut body, key);
                body.extend_from_slice(&at.to_le_bytes());
            }
        }
    }
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend(body);
    frame
}

struct Cursor<'a> {
    body: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let slice = self
            .body
            .get(self.at..self.at + n)
            .ok_or_else(|| Error::Other("quadro de replicação malformado".into()))?;
        self.at += n;
        Ok(slice)
    }

    fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.take(2)?;
        let n = u16::from_le_bytes([n[0], n[1]]) as usize;
        Ok(self.take(n)?.to_vec())
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
}

fn decode_body(body: &[u8]) -> Result<(u8, u64, Vec<Op>)> {
    let mut cur = Cursor { body, at: 0 };
    let kind = cur.take(1)?[0];
    let lsn = cur.u64()?;
    let mut ops = Vec::new();
    while cur.at < body.len() {
        let tag = cur.take(1)?[0];
        let key = cur.bytes()?;
        ops.push(match tag {
            1 => Op::Put {
                key,
                value: cur.bytes()?,
            },
            2 => Op::Delete { key },
            3 => Op::Expire {
                key,
                at: cur.u64()?,
            },
            _ => return Err(Error::Other("operação de replicação desconhecida".into())),
        });
    }
    Ok((kind, lsn, ops))
}

fn read_frame(r: &mut impl Read) -> Result<(u8, u64, Vec<Op>)> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if !(9..=MAX_FRAME).contains(&len) {
        return Err(Error::Other(format!(
            "quadro de replicação inválido ({len} bytes)"
        )));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    decode_body(&body)
}

// ---------------------------------------------------------------------------
// Primário
// ---------------------------------------------------------------------------

/// Liga o feed (retendo até `max_ops` operações) e aceita réplicas em `addr`.
/// Bloqueia; rode em uma thread própria ao lado do servidor HTTP/TCP.
pub fn serve_primary(shared: SharedDb, addr: &str, max_ops: usize) -> Result<()> {
    enable_feed(&shared, max_ops)?;
    let listener = TcpListener::bind(addr)?;
    eprintln!("minidb replicação: primário em {addr}");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let shared = shared.clone();
        thread::spawn(move || {
            let peer = stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_default();
            if let Err(e) = stream_to_replica(&shared, stream) {
                eprintln!("minidb replicação: réplica {peer} desconectou: {e}");
            }
        });
    }
    Ok(())
}

/// Liga o feed de mudanças sem abrir porta (testes e embutidos).
pub fn enable_feed(shared: &SharedDb, max_ops: usize) -> Result<()> {
    let mut db = shared.lock()?;
    if db.feed.is_none() {
        let base = db.last_lsn();
        db.feed = Some(ChangeFeed::new(base, max_ops));
    }
    Ok(())
}

fn snapshot_ops(db: &mut Db) -> Result<Vec<Op>> {
    let rows: Vec<_> = db.iter_raw(&[0], None)?.collect::<Result<_>>()?;
    let mut ops = Vec::with_capacity(rows.len());
    for (key, value) in rows {
        let at = db.expiry_of(&key)?;
        ops.push(Op::Put {
            key: key.clone(),
            value,
        });
        if let Some(at) = at {
            ops.push(Op::Expire { key, at });
        }
    }
    Ok(ops)
}

fn stream_to_replica(shared: &SharedDb, stream: TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut after: u64 = line
        .trim()
        .strip_prefix("SYNC ")
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| Error::Other(format!("handshake inválido: {line:?}")))?;
    let mut out = stream;
    let mut last_send = Instant::now();
    loop {
        let frames = {
            let mut db = shared.lock()?;
            let head = db.last_lsn();
            let pending = match &db.feed {
                Some(feed) if after <= head => feed.since(after),
                _ => None,
            };
            match pending {
                Some(batches) => batches
                    .into_iter()
                    .map(|(lsn, ops)| {
                        after = lsn;
                        encode_frame(T_BATCH, lsn, &ops)
                    })
                    .collect::<Vec<_>>(),
                None => {
                    // ponytail: snapshot inteiro em um quadro (memória O(banco));
                    // fatiar por faixa de chaves se o banco não couber na RAM.
                    let ops = snapshot_ops(&mut db)?;
                    after = head;
                    vec![encode_frame(T_SNAPSHOT, head, &ops)]
                }
            }
        };
        if frames.is_empty() {
            if last_send.elapsed() >= HEARTBEAT_EVERY {
                out.write_all(&encode_frame(T_HEARTBEAT, after, &[]))?;
                last_send = Instant::now();
            }
            // ponytail: polling de 20 ms; Condvar no commit se a latência importar.
            thread::sleep(POLL);
            continue;
        }
        for frame in frames {
            out.write_all(&frame)?;
        }
        last_send = Instant::now();
    }
}

// ---------------------------------------------------------------------------
// Réplica
// ---------------------------------------------------------------------------

/// Último LSN do primário aplicado nesta réplica (0 = nunca sincronizou).
pub fn applied_lsn(db: &mut Db) -> Result<u64> {
    Ok(db
        .get_raw(APPLIED_KEY)?
        .and_then(|v| v.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0))
}

fn applied_op(lsn: u64) -> Op {
    Op::Put {
        key: APPLIED_KEY.to_vec(),
        value: lsn.to_le_bytes().to_vec(),
    }
}

/// Aplica um quadro recebido. Público para testes de protocolo.
fn apply_frame(db: &mut Db, kind: u8, lsn: u64, mut ops: Vec<Op>) -> Result<()> {
    match kind {
        T_HEARTBEAT => return Ok(()),
        T_BATCH => {}
        T_SNAPSHOT => {
            // Remove o que não existe mais no primário, no mesmo lote atômico.
            let keep: BTreeSet<&[u8]> = ops.iter().map(Op::key).collect();
            let stale: Vec<Op> = db
                .iter_raw(&[0], None)?
                .filter_map(|row| match row {
                    Ok((key, _)) if key != APPLIED_KEY && !keep.contains(key.as_slice()) => {
                        Some(Ok(Op::Delete { key }))
                    }
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                })
                .collect::<Result<_>>()?;
            ops.splice(0..0, stale);
        }
        other => return Err(Error::Other(format!("tipo de quadro desconhecido {other}"))),
    }
    ops.push(applied_op(lsn));
    db.write_internal(ops)
}

/// Conecta ao primário e aplica o fluxo até `stop` virar `true`, reconectando
/// com backoff em falhas. O `Db` fica em modo somente leitura para clientes.
pub fn run_replica(db: Arc<Mutex<Db>>, primary: &str, stop: Arc<AtomicBool>) -> Result<()> {
    db.lock()
        .map_err(|e| Error::Server(e.to_string()))?
        .set_read_only(true);
    let mut backoff = Duration::from_millis(100);
    while !stop.load(Ordering::Relaxed) {
        match follow(&db, primary, &stop) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("minidb réplica: {e}; reconectando em {backoff:?}");
                thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        }
    }
    Ok(())
}

fn follow(db: &Arc<Mutex<Db>>, primary: &str, stop: &AtomicBool) -> Result<()> {
    let lock = || db.lock().map_err(|e| Error::Server(e.to_string()));
    let after = applied_lsn(&mut *lock()?)?;
    let mut stream = TcpStream::connect(primary)?;
    stream.set_read_timeout(Some(HEARTBEAT_EVERY * 5))?;
    stream.write_all(format!("SYNC {after}\n").as_bytes())?;
    let mut reader = BufReader::new(stream);
    while !stop.load(Ordering::Relaxed) {
        let (kind, lsn, ops) = read_frame(&mut reader)?;
        apply_frame(&mut *lock()?, kind, lsn, ops)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_and_reject_garbage() {
        let ops = vec![
            Op::Put {
                key: b"k".to_vec(),
                value: vec![0, 1, 2],
            },
            Op::Delete { key: b"d".to_vec() },
            Op::Expire {
                key: b"k".to_vec(),
                at: 42,
            },
        ];
        let frame = encode_frame(T_BATCH, 7, &ops);
        assert_eq!(read_frame(&mut &frame[..]).unwrap(), (T_BATCH, 7, ops));
        for cut in 4..frame.len() {
            let mut bad = frame[..cut].to_vec();
            bad[..4].copy_from_slice(&((cut - 4) as u32).to_le_bytes());
            let _ = read_frame(&mut &bad[..]); // nunca entra em pânico
        }
    }

    #[test]
    fn feed_trims_and_reports_gaps() {
        let op = || vec![Op::Delete { key: b"x".to_vec() }];
        let mut feed = ChangeFeed::new(10, 2);
        feed.push(11, &op());
        feed.push(12, &op());
        assert_eq!(feed.since(10).unwrap().len(), 2);
        feed.push(13, &op());
        assert!(feed.since(10).is_none(), "lote 11 saiu do feed");
        assert_eq!(feed.since(11).unwrap().len(), 2);
    }
}
