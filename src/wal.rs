//! Write-Ahead Log com recover após crash (incluindo registro truncado).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::encryption::Cipher;
use crate::error::{Error, Result};
use std::sync::Arc;

pub const WAL_MAGIC: [u8; 4] = *b"MWAL";
/// Maior corpo de frame aceito na leitura: um valor máximo com chave e cabeçalhos.
const MAX_FRAME_BODY: u64 = (crate::page::MAX_VALUE_LEN + crate::page::MAX_KEY_LEN + 64) as u64;
pub const WAL_VERSION: u32 = 1;

pub const REC_INSERT: u8 = 1;
pub const REC_DELETE: u8 = 2;
pub const REC_CHECKPOINT: u8 = 3;
pub const REC_BEGIN: u8 = 4;
pub const REC_COMMIT: u8 = 5;
pub const REC_ABORT: u8 = 6;
/// Define (`expires_at > 0`) ou remove (`0`) a expiração de uma chave.
pub const REC_EXPIRE: u8 = 7;
/// Marca de relógio (ms Unix): permite restaurar até um instante (PITR).
pub const REC_TIME: u8 = 8;

/// Registro lógico do WAL.
#[derive(Debug, Clone)]
pub enum WalRecord {
    Insert {
        lsn: u64,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        lsn: u64,
        key: Vec<u8>,
    },
    Checkpoint {
        lsn: u64,
        root_page: u32,
        freelist_head: u32,
        next_page_id: u32,
        checkpoint_lsn: u64,
    },
    Begin {
        lsn: u64,
        txn_id: u64,
    },
    Commit {
        lsn: u64,
        txn_id: u64,
    },
    Abort {
        lsn: u64,
        txn_id: u64,
    },
    Expire {
        lsn: u64,
        key: Vec<u8>,
        /// Milissegundos desde a época Unix; 0 remove o TTL.
        expires_at: u64,
    },
    /// Relógio de parede no momento do registro seguinte (ms Unix).
    Time {
        lsn: u64,
        unix_ms: u64,
    },
}

impl WalRecord {
    pub fn lsn(&self) -> u64 {
        match self {
            Self::Insert { lsn, .. }
            | Self::Delete { lsn, .. }
            | Self::Checkpoint { lsn, .. }
            | Self::Begin { lsn, .. }
            | Self::Commit { lsn, .. }
            | Self::Abort { lsn, .. }
            | Self::Expire { lsn, .. }
            | Self::Time { lsn, .. } => *lsn,
        }
    }

    fn encode_payload(&self) -> (u8, Vec<u8>) {
        match self {
            Self::Insert { key, value, .. } => {
                let mut p = Vec::with_capacity(8 + key.len() + value.len());
                p.extend_from_slice(&(key.len() as u32).to_le_bytes());
                p.extend_from_slice(key);
                p.extend_from_slice(&(value.len() as u32).to_le_bytes());
                p.extend_from_slice(value);
                (REC_INSERT, p)
            }
            Self::Delete { key, .. } => {
                let mut p = Vec::with_capacity(4 + key.len());
                p.extend_from_slice(&(key.len() as u32).to_le_bytes());
                p.extend_from_slice(key);
                (REC_DELETE, p)
            }
            Self::Checkpoint {
                root_page,
                freelist_head,
                next_page_id,
                checkpoint_lsn,
                ..
            } => {
                let mut p = Vec::with_capacity(20);
                p.extend_from_slice(&root_page.to_le_bytes());
                p.extend_from_slice(&freelist_head.to_le_bytes());
                p.extend_from_slice(&next_page_id.to_le_bytes());
                p.extend_from_slice(&checkpoint_lsn.to_le_bytes());
                (REC_CHECKPOINT, p)
            }
            Self::Begin { txn_id, .. } => (REC_BEGIN, txn_id.to_le_bytes().to_vec()),
            Self::Commit { txn_id, .. } => (REC_COMMIT, txn_id.to_le_bytes().to_vec()),
            Self::Abort { txn_id, .. } => (REC_ABORT, txn_id.to_le_bytes().to_vec()),
            Self::Expire {
                key, expires_at, ..
            } => {
                let mut p = Vec::with_capacity(12 + key.len());
                p.extend_from_slice(&(key.len() as u32).to_le_bytes());
                p.extend_from_slice(key);
                p.extend_from_slice(&expires_at.to_le_bytes());
                (REC_EXPIRE, p)
            }
            Self::Time { unix_ms, .. } => (REC_TIME, unix_ms.to_le_bytes().to_vec()),
        }
    }

    /// Frame: `[payload_len:u32][crc32:u32][lsn:u64][type:u8][payload...]`
    pub fn encode_frame(&self) -> Vec<u8> {
        self.encode_frame_with(None)
    }

    /// Com `cipher`, o payload vai cifrado (`sal ‖ texto cifrado`); o CRC
    /// cobre o frame como gravado, então a leitura valida sem a chave.
    pub fn encode_frame_with(&self, cipher: Option<&Cipher>) -> Vec<u8> {
        let lsn = self.lsn();
        let (ty, payload) = self.encode_payload();
        let payload = match cipher {
            Some(c) => c.seal_wal(lsn, &payload),
            None => payload,
        };
        let mut body = Vec::with_capacity(9 + payload.len());
        body.extend_from_slice(&lsn.to_le_bytes());
        body.push(ty);
        body.extend_from_slice(&payload);
        let crc = crc32(&body);
        let mut frame = Vec::with_capacity(8 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
        frame.extend_from_slice(&crc.to_le_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    /// Decodifica o corpo de um frame (`lsn + type + payload`). Público para
    /// testes de robustez e fuzzing; nunca entra em pânico com entrada arbitrária.
    pub fn decode_body(body: &[u8]) -> Result<Self> {
        if body.len() < 9 {
            return Err(Error::CorruptWal(0));
        }
        let lsn = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let ty = body[8];
        let payload = &body[9..];
        match ty {
            REC_INSERT => {
                if payload.len() < 4 {
                    return Err(Error::CorruptWal(lsn));
                }
                let klen = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
                if payload.len() < 4 + klen + 4 {
                    return Err(Error::CorruptWal(lsn));
                }
                let key = payload[4..4 + klen].to_vec();
                let vlen =
                    u32::from_le_bytes(payload[4 + klen..8 + klen].try_into().unwrap()) as usize;
                if payload.len() != 8 + klen + vlen {
                    return Err(Error::CorruptWal(lsn));
                }
                let value = payload[8 + klen..8 + klen + vlen].to_vec();
                Ok(Self::Insert { lsn, key, value })
            }
            REC_DELETE => {
                if payload.len() < 4 {
                    return Err(Error::CorruptWal(lsn));
                }
                let klen = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
                if payload.len() != 4 + klen {
                    return Err(Error::CorruptWal(lsn));
                }
                let key = payload[4..4 + klen].to_vec();
                Ok(Self::Delete { lsn, key })
            }
            REC_CHECKPOINT => {
                if payload.len() != 20 {
                    return Err(Error::CorruptWal(lsn));
                }
                let root_page = u32::from_le_bytes(payload[0..4].try_into().unwrap());
                let freelist_head = u32::from_le_bytes(payload[4..8].try_into().unwrap());
                let next_page_id = u32::from_le_bytes(payload[8..12].try_into().unwrap());
                let checkpoint_lsn = u64::from_le_bytes(payload[12..20].try_into().unwrap());
                Ok(Self::Checkpoint {
                    lsn,
                    root_page,
                    freelist_head,
                    next_page_id,
                    checkpoint_lsn,
                })
            }
            REC_BEGIN | REC_COMMIT | REC_ABORT => {
                if payload.len() != 8 {
                    return Err(Error::CorruptWal(lsn));
                }
                let txn_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
                Ok(match ty {
                    REC_BEGIN => Self::Begin { lsn, txn_id },
                    REC_COMMIT => Self::Commit { lsn, txn_id },
                    _ => Self::Abort { lsn, txn_id },
                })
            }
            REC_TIME => {
                if payload.len() != 8 {
                    return Err(Error::CorruptWal(lsn));
                }
                Ok(Self::Time {
                    lsn,
                    unix_ms: u64::from_le_bytes(payload.try_into().expect("8")),
                })
            }
            REC_EXPIRE => {
                if payload.len() < 4 {
                    return Err(Error::CorruptWal(lsn));
                }
                let klen = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
                if payload.len() != 4 + klen + 8 {
                    return Err(Error::CorruptWal(lsn));
                }
                let key = payload[4..4 + klen].to_vec();
                let expires_at = u64::from_le_bytes(payload[4 + klen..].try_into().unwrap());
                Ok(Self::Expire {
                    lsn,
                    key,
                    expires_at,
                })
            }
            _ => Err(Error::CorruptWal(lsn)),
        }
    }
}

const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
            bit += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// CRC32 IEEE (refletido, polinômio 0xEDB88320), por tabela.
pub fn crc32(data: &[u8]) -> u32 {
    !crc32_update(0xFFFF_FFFF, data)
}

/// Passo incremental do CRC32: comece com `0xFFFF_FFFF` e inverta no fim.
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    data.iter().fold(crc, |crc, &b| {
        (crc >> 8) ^ CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize]
    })
}

pub struct Wal {
    path: PathBuf,
    file: File,
    cipher: Option<Arc<Cipher>>,
    next_lsn: u64,
    /// Tamanho do arquivo (cabeçalho + frames válidos).
    len: u64,
    /// LSN do primeiro registro no arquivo atual (`None` = só cabeçalho).
    first_lsn: Option<u64>,
}

impl Wal {
    pub fn open(path: impl AsRef<Path>, next_lsn: u64) -> Result<Self> {
        Self::open_with(path, next_lsn, None)
    }

    pub fn open_with(
        path: impl AsRef<Path>,
        next_lsn: u64,
        cipher: Option<Arc<Cipher>>,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let len = file.metadata()?.len();
        if len == 0 {
            file.write_all(&WAL_MAGIC)?;
            file.write_all(&WAL_VERSION.to_le_bytes())?;
            file.sync_all()?;
        } else {
            file.seek(SeekFrom::Start(0))?;
            let mut magic = [0u8; 4];
            file.read_exact(&mut magic)?;
            if magic != WAL_MAGIC {
                return Err(Error::CorruptWal(0));
            }
        }
        // Remove the invalid tail before appending: otherwise future records
        // would remain hidden behind it after a second crash.
        let (_, records) = Self::read_all_with(&path, cipher.as_deref())?;
        let valid_len = 8 + records
            .iter()
            .map(|r| r.encode_frame_with(cipher.as_deref()).len() as u64)
            .sum::<u64>();
        if file.metadata()?.len() != valid_len {
            file.set_len(valid_len)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            path,
            file,
            cipher,
            next_lsn,
            len: valid_len,
            first_lsn: records.first().map(WalRecord::lsn),
        })
    }

    pub fn cipher(&self) -> Option<Arc<Cipher>> {
        self.cipher.clone()
    }

    /// Bytes ocupados pelo WAL atual.
    pub fn size(&self) -> u64 {
        self.len
    }

    /// Move o WAL atual para `archive_dir` (nome `<primeiro>-<último>.wal`,
    /// ordenável) e recomeça um arquivo vazio. Usado no lugar do truncate
    /// quando réplicas precisam do histórico. Sem registros, só trunca.
    pub fn archive(&mut self, archive_dir: &Path, next_lsn: u64) -> Result<Option<PathBuf>> {
        let Some(first) = self.first_lsn else {
            self.truncate_after_checkpoint(next_lsn)?;
            return Ok(None);
        };
        self.file.sync_all()?;
        std::fs::create_dir_all(archive_dir)?;
        let last = self.next_lsn.saturating_sub(1);
        let dest = archive_dir.join(format!("{first:020}-{last:020}.wal"));
        std::fs::rename(&self.path, &dest)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)?;
        file.write_all(&WAL_MAGIC)?;
        file.write_all(&WAL_VERSION.to_le_bytes())?;
        file.sync_all()?;
        #[cfg(unix)]
        File::open(self.path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
        self.file = file;
        self.len = 8;
        self.first_lsn = None;
        self.next_lsn = next_lsn;
        Ok(Some(dest))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn next_lsn(&self) -> u64 {
        self.next_lsn
    }

    pub fn append(&mut self, mut record: WalRecord) -> Result<u64> {
        let lsn = self.next_lsn;
        match &mut record {
            WalRecord::Insert { lsn: l, .. }
            | WalRecord::Delete { lsn: l, .. }
            | WalRecord::Checkpoint { lsn: l, .. }
            | WalRecord::Begin { lsn: l, .. }
            | WalRecord::Commit { lsn: l, .. }
            | WalRecord::Abort { lsn: l, .. }
            | WalRecord::Expire { lsn: l, .. }
            | WalRecord::Time { lsn: l, .. } => *l = lsn,
        }
        let frame = record.encode_frame_with(self.cipher.as_deref());
        self.file.seek(SeekFrom::End(0))?;
        let previous_len = self.file.stream_position()?;
        if let Err(error) = self.file.write_all(&frame) {
            let rollback = self.file.set_len(previous_len);
            let _ = self.file.seek(SeekFrom::End(0));
            if rollback.is_err() {
                return Err(Error::Other(format!(
                    "falha ao reverter append parcial do WAL: {error}"
                )));
            }
            return Err(error.into());
        }
        self.next_lsn = lsn + 1;
        self.len += frame.len() as u64;
        self.first_lsn.get_or_insert(lsn);
        Ok(lsn)
    }

    pub fn sync(&mut self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }

    /// Reescreve o WAL mantendo só header (após checkpoint bem-sucedido).
    pub fn truncate_after_checkpoint(&mut self, next_lsn: u64) -> Result<()> {
        // Preserve the validated header: a crash during truncation must not
        // leave a partially-rewritten header.
        self.file.set_len(8)?;
        self.file.seek(SeekFrom::Start(8))?;
        self.file.sync_all()?;
        self.next_lsn = next_lsn;
        self.len = 8;
        self.first_lsn = None;
        Ok(())
    }

    /// Lê todos os registros válidos. Para na cauda truncada ou com CRC ruim (escrita
    /// interrompida); CRC ruim seguido de dados não nulos é corrupção e dá `CorruptWal`.
    pub fn read_all(path: impl AsRef<Path>) -> Result<(u64, Vec<WalRecord>)> {
        Self::read_all_with(path, None)
    }

    pub fn read_all_with(
        path: impl AsRef<Path>,
        cipher: Option<&Cipher>,
    ) -> Result<(u64, Vec<WalRecord>)> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok((1, Vec::new()));
        }
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        if file_len == 0 {
            return Ok((1, Vec::new()));
        }
        if file_len < 8 {
            return Err(Error::CorruptWal(0));
        }
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if magic != WAL_MAGIC {
            return Err(Error::CorruptWal(0));
        }
        let mut ver = [0u8; 4];
        file.read_exact(&mut ver)?;
        if u32::from_le_bytes(ver) != WAL_VERSION {
            return Err(Error::CorruptWal(0));
        }

        let mut records = Vec::new();
        let mut max_lsn = 0u64;
        let mut offset = 8u64;

        while offset + 8 <= file_len {
            file.seek(SeekFrom::Start(offset))?;
            let mut hdr = [0u8; 8];
            if file.read_exact(&mut hdr).is_err() {
                break;
            }
            let payload_len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as u64;
            let crc_expected = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
            let frame_end = offset + 8 + payload_len;
            if !(9..=MAX_FRAME_BODY).contains(&payload_len) || frame_end > file_len {
                // Truncamento mid-write (crash kill -9) — para com segurança.
                break;
            }
            let mut body = vec![0u8; payload_len as usize];
            if file.read_exact(&mut body).is_err() {
                break;
            }
            if crc32(&body) != crc_expected {
                // Cauda de escrita interrompida: o frame ruim é o último, ou depois dele
                // só há zeros (arquivo estendido sem os dados chegarem ao disco numa
                // queda de energia): ignora. Com dados depois dele é corrupção no meio
                // do log: erro, em vez de descartar transações já confirmadas.
                if frame_end < file_len && !only_zeros_from(&mut file, frame_end)? {
                    return Err(Error::CorruptWal(offset));
                }
                break;
            }
            let decoded = match cipher {
                Some(c) if body.len() >= 9 => {
                    let lsn = u64::from_le_bytes(body[0..8].try_into().expect("8"));
                    c.open_wal(lsn, &body[9..]).and_then(|plain| {
                        let mut full = body[..9].to_vec();
                        full.extend_from_slice(&plain);
                        WalRecord::decode_body(&full)
                    })
                }
                _ => WalRecord::decode_body(&body),
            };
            match decoded {
                Ok(rec) => {
                    if rec.lsn() <= max_lsn || rec.lsn() == u64::MAX {
                        break;
                    }
                    max_lsn = rec.lsn();
                    records.push(rec);
                    offset = frame_end;
                }
                Err(_) => break,
            }
        }

        let next_lsn = if max_lsn == 0 { 1 } else { max_lsn + 1 };
        Ok((next_lsn, records))
    }
}

/// `true` se o arquivo só tem zeros de `from` até o fim.
fn only_zeros_from(file: &mut File, from: u64) -> Result<bool> {
    file.seek(SeekFrom::Start(from))?;
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(true);
        }
        if buf[..n].iter().any(|&b| b != 0) {
            return Ok(false);
        }
    }
}

/// Simula crash truncando o arquivo WAL no meio do último frame (teste).
pub fn truncate_file_at(path: impl AsRef<Path>, new_len: u64) -> Result<()> {
    let file = OpenOptions::new().write(true).open(path)?;
    file.set_len(new_len)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn crc32_matches_reference_vector() {
        assert_eq!(super::crc32(b"123456789"), 0xCBF4_3926);
    }
}
