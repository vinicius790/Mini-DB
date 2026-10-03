//! TLS 1.3 (RFC 8446) do lado do servidor, sem dependências: suítes
//! TLS_AES_128_GCM_SHA256 e TLS_CHACHA20_POLY1305_SHA256 (vale a preferida do
//! cliente), troca de chaves X25519 e assinatura Ed25519, ECDSA (P-256/P-384)
//! ou RSA-PSS, conforme a chave do certificado.
//!
//! PKI: certificado autoassinado gerado na primeira execução (`tls.key`,
//! `tls.crt`), cadeia própria emitida por uma CA (`minidb cert ca|issue`,
//! módulo `x509`; `tls.crt` pode ter folha + intermediárias) e verificação de
//! certificado de cliente (mTLS) contra as CAs confiáveis (`tls_ca`).
//! Usado pelo protocolo PostgreSQL (`sslmode=require|verify-full`) e pelo HTTP.
//!
//! Escopo: 1-RTT sem retomada, sem HelloRetryRequest (os clientes mandam
//! x25519 por padrão), sem 0-RTT. Clientes sem nenhum esquema de assinatura
//! compatível com a chave, ou TLS ≤ 1.2, recebem `handshake_failure`.

use crate::crypto::{
    aead_open, aead_seal, aes128_gcm_open, aes128_gcm_seal, hkdf_expand, hkdf_extract, hmac_sha256,
    random_bytes, sha256,
};
use crate::curve25519::{x25519, x25519_base};
use crate::error::{Error, Result};
use crate::pubkey::{KeyAlgo, PrivateKey, PublicKey, TLS_VERIFIABLE};
use crate::x509::{self, Cert, Kind};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;

const REC_HANDSHAKE: u8 = 22;
const REC_APP: u8 = 23;
const REC_ALERT: u8 = 21;
const REC_CCS: u8 = 20;
const MAX_RECORD: usize = 16384;

/// Política para certificado de cliente.
#[derive(Clone, Debug, Default)]
pub enum ClientAuth {
    /// Não pede certificado.
    #[default]
    Off,
    /// Pede; aceita sem certificado, mas um apresentado precisa ser válido.
    Optional(Vec<Cert>),
    /// Exige certificado válido emitido por uma das CAs.
    Required(Vec<Cert>),
}

impl ClientAuth {
    /// Modo `off|optional|required` + PEM das CAs confiáveis.
    pub fn from_config(mode: &str, ca_pem: Option<&str>) -> Result<ClientAuth> {
        let roots = |pem: Option<&str>| {
            pem.ok_or_else(|| {
                Error::Other("tls_client_auth exige tls_ca (arquivo PEM das CAs)".into())
            })
            .and_then(x509::load_roots)
        };
        match mode {
            "off" | "false" | "no" | "" => Ok(ClientAuth::Off),
            "optional" => Ok(ClientAuth::Optional(roots(ca_pem)?)),
            "required" | "require" | "true" | "yes" => Ok(ClientAuth::Required(roots(ca_pem)?)),
            other => Err(Error::Other(format!(
                "tls_client_auth inválido: {other:?} (use off, optional ou required)"
            ))),
        }
    }
}

/// Certificado de cliente verificado (mTLS).
#[derive(Clone, Debug)]
pub struct Peer {
    pub cn: Option<String>,
    pub subject: String,
    pub issuer: String,
}

/// Identidade do servidor: chave (Ed25519/ECDSA/RSA) + certificado DER (+ intermediárias).
pub struct Identity {
    key: PrivateKey,
    pub cert_der: Vec<u8>,
    /// Certificados após a folha (intermediárias), enviados na ordem.
    pub chain: Vec<Vec<u8>>,
    pub client_auth: ClientAuth,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identity({})", self.key.public().description())
    }
}

impl Identity {
    /// Carrega `tls.key`/`tls.crt` de `dir` ou gera um par autoassinado.
    pub fn load_or_create(dir: &Path, host: &str) -> Result<Arc<Identity>> {
        Self::create_or_load(dir, host).map(Arc::new)
    }

    /// Como `load_or_create`, sem o `Arc` (para ajustar a política de cliente).
    pub fn create_or_load(dir: &Path, host: &str) -> Result<Identity> {
        let key_path = dir.join("tls.key");
        let crt_path = dir.join("tls.crt");
        if key_path.exists() && crt_path.exists() {
            return Self::load(&key_path, &crt_path);
        }
        let key = PrivateKey::generate(KeyAlgo::Ed25519);
        let n = x509::name(host, None);
        let hosts = vec![host.to_string(), "localhost".into(), "127.0.0.1".into()];
        let cert_der = x509::build(&key, &n, &n, &key.public(), Kind::Server, &hosts, 3650);
        fs::create_dir_all(dir)?;
        x509::write_private(&key_path, &key.to_pem()?)?;
        fs::write(&crt_path, x509::pem("CERTIFICATE", &cert_der))?;
        Ok(Identity {
            key,
            cert_der,
            chain: Vec::new(),
            client_auth: ClientAuth::Off,
        })
    }

    /// Carrega chave privada e cadeia (folha primeiro) de arquivos PEM/DER.
    pub fn load(key_path: &Path, crt_path: &Path) -> Result<Identity> {
        let key_text = fs::read_to_string(key_path)
            .map_err(|e| Error::Other(format!("{}: {e}", key_path.display())))?;
        let key = PrivateKey::from_pem(&key_text)?;
        let raw =
            fs::read(crt_path).map_err(|e| Error::Other(format!("{}: {e}", crt_path.display())))?;
        let mut certs = match std::str::from_utf8(&raw) {
            Ok(text) if text.contains("-----BEGIN") => x509::pem_all(text, "CERTIFICATE")?,
            _ => vec![raw],
        };
        if certs.is_empty() {
            return Err(Error::Other(format!(
                "{}: nenhum certificado",
                crt_path.display()
            )));
        }
        let leaf = Cert::parse(&certs[0])?;
        if leaf.public != key.public() {
            return Err(Error::Other(format!(
                "{} não corresponde à chave {}",
                crt_path.display(),
                key_path.display()
            )));
        }
        let cert_der = certs.remove(0);
        Ok(Identity {
            key,
            cert_der,
            chain: certs,
            client_auth: ClientAuth::Off,
        })
    }

    pub fn with_client_auth(mut self, auth: ClientAuth) -> Identity {
        self.client_auth = auth;
        self
    }

    pub fn from_key(key: impl Into<PrivateKey>, host: &str) -> Identity {
        let key = key.into();
        let n = x509::name(host, None);
        let hosts = vec![host.to_string(), "localhost".into(), "127.0.0.1".into()];
        let cert_der = x509::build(&key, &n, &n, &key.public(), Kind::Server, &hosts, 3650);
        Identity {
            key,
            cert_der,
            chain: Vec::new(),
            client_auth: ClientAuth::Off,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.public()
    }
}

// ---------------------------------------------------------------------------
// Chaves do handshake
// ---------------------------------------------------------------------------

fn hkdf_expand_label(secret: &[u8; 32], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    let full = format!("tls13 {label}");
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, len)
}

fn derive_secret(secret: &[u8; 32], label: &str, transcript_hash: &[u8; 32]) -> [u8; 32] {
    hkdf_expand_label(secret, label, transcript_hash, 32)
        .try_into()
        .expect("32")
}

/// Suítes TLS 1.3 aceitas (RFC 8446 §9.1); o hash é SHA-256 nas duas, então a
/// agenda de chaves é a mesma e só o AEAD do registro muda.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Suite {
    /// TLS_AES_128_GCM_SHA256 (0x1301), a obrigatória do RFC 8446.
    Aes128Gcm,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303).
    ChaCha20Poly1305,
}

impl Suite {
    fn from_id(id: [u8; 2]) -> Option<Suite> {
        match id {
            [0x13, 0x01] => Some(Suite::Aes128Gcm),
            [0x13, 0x03] => Some(Suite::ChaCha20Poly1305),
            _ => None,
        }
    }

    fn id(self) -> [u8; 2] {
        match self {
            Suite::Aes128Gcm => [0x13, 0x01],
            Suite::ChaCha20Poly1305 => [0x13, 0x03],
        }
    }

    fn key_len(self) -> usize {
        match self {
            Suite::Aes128Gcm => 16,
            Suite::ChaCha20Poly1305 => 32,
        }
    }
}

struct Keys {
    suite: Suite,
    /// Só os primeiros `suite.key_len()` bytes valem.
    key: [u8; 32],
    iv: [u8; 12],
    seq: u64,
}

impl Keys {
    fn from_secret(secret: &[u8; 32], suite: Suite) -> Keys {
        let mut key = [0u8; 32];
        let derived = hkdf_expand_label(secret, "key", &[], suite.key_len());
        key[..derived.len()].copy_from_slice(&derived);
        Keys {
            suite,
            key,
            iv: hkdf_expand_label(secret, "iv", &[], 12)
                .try_into()
                .expect("12"),
            seq: 0,
        }
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        self.seq += 1;
        n
    }

    /// Cifra com o AEAD da suíte (texto cifrado ‖ etiqueta de 16 bytes).
    fn seal(&mut self, aad: &[u8], plain: &[u8]) -> Vec<u8> {
        let nonce = self.nonce();
        match self.suite {
            Suite::Aes128Gcm => {
                let key: [u8; 16] = self.key[..16].try_into().expect("16");
                aes128_gcm_seal(&key, &nonce, aad, plain)
            }
            Suite::ChaCha20Poly1305 => aead_seal(&self.key, &nonce, aad, plain),
        }
    }

    /// Abre e autentica; `None` se a etiqueta não confere.
    fn open(&mut self, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.nonce();
        match self.suite {
            Suite::Aes128Gcm => {
                let key: [u8; 16] = self.key[..16].try_into().expect("16");
                aes128_gcm_open(&key, &nonce, aad, sealed)
            }
            Suite::ChaCha20Poly1305 => aead_open(&self.key, &nonce, aad, sealed),
        }
    }
}

/// Conexão TLS estabelecida: `Read`/`Write` sobre o socket.
pub struct TlsStream<S: Read + Write> {
    inner: S,
    read_keys: Keys,
    write_keys: Keys,
    plain: Vec<u8>,
    plain_pos: usize,
    closed: bool,
    peer: Option<Peer>,
}

fn write_record(inner: &mut impl Write, ty: u8, body: &[u8]) -> io::Result<()> {
    let mut rec = vec![ty, 3, 3];
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(body);
    inner.write_all(&rec)
}

fn read_record(inner: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    inner.read_exact(&mut hdr)?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > MAX_RECORD + 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "registro TLS grande demais",
        ));
    }
    let mut body = vec![0u8; len];
    inner.read_exact(&mut body)?;
    Ok((hdr[0], body))
}

fn seal_record(keys: &mut Keys, ty: u8, plain: &[u8]) -> Vec<u8> {
    let mut inner = plain.to_vec();
    inner.push(ty);
    let len = inner.len() + 16;
    let aad = [REC_APP, 3, 3, (len >> 8) as u8, len as u8];
    keys.seal(&aad, &inner)
}

fn open_record(keys: &mut Keys, body: &[u8]) -> io::Result<(u8, Vec<u8>)> {
    let aad = [REC_APP, 3, 3, (body.len() >> 8) as u8, body.len() as u8];
    let Some(mut plain) = keys.open(&aad, body) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "registro TLS não autentica",
        ));
    };
    while plain.last() == Some(&0) {
        plain.pop();
    }
    let ty = plain
        .pop()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "registro TLS vazio"))?;
    Ok((ty, plain))
}

impl<S: Read + Write> TlsStream<S> {
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Certificado de cliente verificado, se o cliente apresentou um.
    pub fn peer(&self) -> Option<&Peer> {
        self.peer.as_ref()
    }

    fn send_encrypted(&mut self, ty: u8, data: &[u8]) -> io::Result<()> {
        for chunk in data
            .chunks(MAX_RECORD - 1)
            .chain(std::iter::once(&[][..]).take(data.is_empty() as usize))
        {
            let sealed = seal_record(&mut self.write_keys, ty, chunk);
            write_record(&mut self.inner, REC_APP, &sealed)?;
        }
        Ok(())
    }

    fn fill(&mut self) -> io::Result<()> {
        loop {
            let (rty, body) = read_record(&mut self.inner)?;
            match rty {
                REC_CCS => continue,
                REC_APP => {
                    let (ty, plain) = open_record(&mut self.read_keys, &body)?;
                    match ty {
                        REC_APP => {
                            self.plain = plain;
                            self.plain_pos = 0;
                            return Ok(());
                        }
                        REC_ALERT => {
                            self.closed = true;
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "TLS fechado",
                            ));
                        }
                        REC_HANDSHAKE => {
                            // KeyUpdate (24) ou NewSessionTicket do cliente: ignora
                            // (o servidor não atualiza chaves; conexões são curtas).
                            continue;
                        }
                        _ => continue,
                    }
                }
                REC_ALERT => {
                    self.closed = true;
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "alerta TLS"));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "registro TLS inesperado",
                    ))
                }
            }
        }
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed {
            return Ok(0);
        }
        while self.plain_pos >= self.plain.len() {
            if let Err(e) = self.fill() {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    return Ok(0);
                }
                return Err(e);
            }
        }
        let n = (self.plain.len() - self.plain_pos).min(buf.len());
        buf[..n].copy_from_slice(&self.plain[self.plain_pos..self.plain_pos + n]);
        self.plain_pos += n;
        Ok(n)
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send_encrypted(REC_APP, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

struct ClientHello {
    session_id: Vec<u8>,
    key_share: Option<[u8; 32]>,
    supports_13: bool,
    /// Primeira suíte da lista do cliente que o servidor também suporta.
    suite: Option<Suite>,
    sigalgs: Vec<u16>,
}

fn take(b: &[u8], pos: &mut usize, n: usize) -> io::Result<Vec<u8>> {
    let end = *pos + n;
    let out = b
        .get(*pos..end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ClientHello truncado"))?
        .to_vec();
    *pos = end;
    Ok(out)
}

fn u16_at(b: &[u8], pos: &mut usize) -> io::Result<u16> {
    let v = take(b, pos, 2)?;
    Ok(u16::from_be_bytes([v[0], v[1]]))
}

fn parse_client_hello(body: &[u8]) -> io::Result<ClientHello> {
    let mut pos = 0;
    let _version = u16_at(body, &mut pos)?;
    take(body, &mut pos, 32)?; // random do cliente (só entra na transcrição)
    let sid_len = take(body, &mut pos, 1)?[0] as usize;
    let session_id = take(body, &mut pos, sid_len)?;
    let cs_len = u16_at(body, &mut pos)? as usize;
    let suites = take(body, &mut pos, cs_len)?;
    let suite = suites
        .chunks_exact(2)
        .find_map(|c| Suite::from_id([c[0], c[1]]));
    let comp_len = take(body, &mut pos, 1)?[0] as usize;
    take(body, &mut pos, comp_len)?;
    let mut hello = ClientHello {
        session_id,
        key_share: None,
        supports_13: false,
        suite,
        sigalgs: Vec::new(),
    };
    if pos >= body.len() {
        return Ok(hello);
    }
    let ext_len = u16_at(body, &mut pos)? as usize;
    let exts = take(body, &mut pos, ext_len)?;
    let mut p = 0;
    while p + 4 <= exts.len() {
        let ty = u16_at(&exts, &mut p)?;
        let len = u16_at(&exts, &mut p)? as usize;
        let data = take(&exts, &mut p, len)?;
        match ty {
            43 if !data.is_empty() => {
                // supported_versions: u8 len + lista u16
                let n = data[0] as usize;
                hello.supports_13 = data
                    .get(1..1 + n)
                    .is_some_and(|l| l.chunks(2).any(|v| v == [3, 4]));
            }
            51 => {
                // key_share: u16 len, entradas (group u16, len u16, key)
                let mut q = 2;
                while q + 4 <= data.len() {
                    let group = u16_at(&data, &mut q)?;
                    let klen = u16_at(&data, &mut q)? as usize;
                    let key = take(&data, &mut q, klen)?;
                    if group == 0x001d && key.len() == 32 {
                        hello.key_share = Some(key.try_into().expect("32"));
                    }
                }
            }
            13 => {
                // signature_algorithms: u16 len + lista u16
                hello.sigalgs = data
                    .get(2..)
                    .unwrap_or_default()
                    .chunks_exact(2)
                    .map(|v| u16::from_be_bytes([v[0], v[1]]))
                    .collect();
            }
            _ => {}
        }
    }
    Ok(hello)
}

fn handshake_msg(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut m = vec![
        ty,
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ];
    m.extend_from_slice(body);
    m
}

fn alert(inner: &mut impl Write, code: u8) {
    let _ = write_record(inner, REC_ALERT, &[2, code]);
    let _ = inner.flush();
}

/// Alerta fatal cifrado: depois do ServerHello o cliente só aceita alertas
/// protegidos pelas chaves correntes do servidor (RFC 8446 §5.2, §6).
fn alert_sealed(inner: &mut impl Write, keys: &mut Keys, code: u8) {
    let sealed = seal_record(keys, REC_ALERT, &[2, code]);
    let _ = write_record(inner, REC_APP, &sealed);
    let _ = inner.flush();
}

/// Próxima mensagem de handshake (com cabeçalho) vinda de registros cifrados.
fn read_handshake<S: Read + Write>(
    inner: &mut S,
    keys: &mut Keys,
    alert_keys: &mut Keys,
    pending: &mut Vec<u8>,
) -> io::Result<Vec<u8>> {
    loop {
        if pending.len() >= 4 {
            let len =
                ((pending[1] as usize) << 16) | ((pending[2] as usize) << 8) | pending[3] as usize;
            if pending.len() >= 4 + len {
                return Ok(pending.drain(..4 + len).collect());
            }
        }
        let (ty, body) = read_record(inner)?;
        match ty {
            REC_CCS => continue,
            REC_ALERT => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "alerta TLS",
                ))
            }
            REC_APP => {
                let (inner_ty, plain) = open_record(keys, &body)?;
                if inner_ty == REC_ALERT {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "alerta TLS",
                    ));
                }
                if inner_ty != REC_HANDSHAKE {
                    alert_sealed(inner, alert_keys, 10);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "esperava handshake",
                    ));
                }
                pending.extend_from_slice(&plain);
            }
            _ => {
                alert_sealed(inner, alert_keys, 10);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "registro inesperado no handshake",
                ));
            }
        }
    }
}

/// Certificados de uma mensagem `Certificate` (corpo sem cabeçalho).
fn parse_certificate_list(body: &[u8]) -> Option<Vec<Vec<u8>>> {
    let ctx = *body.first()? as usize;
    let b = body.get(1 + ctx..)?;
    let total = ((*b.first()? as usize) << 16) | ((*b.get(1)? as usize) << 8) | *b.get(2)? as usize;
    let mut list = b.get(3..3 + total)?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let n = ((*list.first()? as usize) << 16)
            | ((*list.get(1)? as usize) << 8)
            | *list.get(2)? as usize;
        out.push(list.get(3..3 + n)?.to_vec());
        let ext = ((*list.get(3 + n)? as usize) << 8) | *list.get(4 + n)? as usize;
        list = list.get(5 + n + ext..)?;
    }
    Some(out)
}

/// Executa o handshake do servidor sobre `inner`; devolve o canal cifrado.
pub fn accept<S: Read + Write>(mut inner: S, identity: &Identity) -> io::Result<TlsStream<S>> {
    let fail = |inner: &mut S, code: u8, msg: &str| -> io::Error {
        alert(inner, code);
        io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
    };
    let sealed_fail = |inner: &mut S, keys: &mut Keys, code: u8, msg: &str| -> io::Error {
        alert_sealed(inner, keys, code);
        io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
    };
    // 1. ClientHello (pode vir em vários registros de handshake).
    let mut hs_buf = Vec::new();
    loop {
        let (ty, body) = read_record(&mut inner)?;
        if ty != REC_HANDSHAKE {
            return Err(fail(&mut inner, 10, "esperava ClientHello"));
        }
        hs_buf.extend_from_slice(&body);
        if hs_buf.len() >= 4 {
            let len =
                ((hs_buf[1] as usize) << 16) | ((hs_buf[2] as usize) << 8) | hs_buf[3] as usize;
            if hs_buf.len() >= 4 + len {
                break;
            }
        }
    }
    if hs_buf[0] != 1 {
        return Err(fail(&mut inner, 10, "esperava ClientHello"));
    }
    let ch_len = ((hs_buf[1] as usize) << 16) | ((hs_buf[2] as usize) << 8) | hs_buf[3] as usize;
    let client_hello = &hs_buf[..4 + ch_len];
    let hello = parse_client_hello(&client_hello[4..])?;
    if !hello.supports_13 {
        return Err(fail(&mut inner, 70, "cliente sem TLS 1.3"));
    }
    let Some(suite) = hello.suite else {
        return Err(fail(
            &mut inner,
            40,
            "cliente sem AES-128-GCM nem ChaCha20-Poly1305",
        ));
    };
    let Some(scheme) = identity
        .key
        .tls_schemes()
        .into_iter()
        .find(|c| hello.sigalgs.contains(c))
    else {
        return Err(fail(
            &mut inner,
            40,
            "cliente não aceita o tipo de assinatura da chave do servidor",
        ));
    };
    let Some(client_share) = hello.key_share else {
        return Err(fail(&mut inner, 40, "cliente sem key_share x25519"));
    };
    let mut transcript = client_hello.to_vec();

    // 2. ServerHello.
    let eph = random_bytes::<32>();
    let server_share = x25519_base(&eph);
    let shared = x25519(&eph, &client_share);
    let mut sh = vec![3, 3];
    sh.extend_from_slice(&random_bytes::<32>());
    sh.push(hello.session_id.len() as u8);
    sh.extend_from_slice(&hello.session_id);
    sh.extend_from_slice(&suite.id());
    sh.push(0); // compressão nula
    let mut exts = Vec::new();
    exts.extend_from_slice(&[0, 43, 0, 2, 3, 4]); // supported_versions = 1.3
    exts.extend_from_slice(&[0, 51, 0, 36, 0, 0x1d, 0, 32]);
    exts.extend_from_slice(&server_share);
    sh.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    sh.extend_from_slice(&exts);
    let server_hello = handshake_msg(2, &sh);
    transcript.extend_from_slice(&server_hello);
    write_record(&mut inner, REC_HANDSHAKE, &server_hello)?;
    write_record(&mut inner, REC_CCS, &[1])?; // compatibilidade com middleboxes

    // 3. Segredos do handshake.
    let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let empty_hash = sha256(&[]);
    let derived = derive_secret(&early, "derived", &empty_hash);
    let handshake_secret = hkdf_extract(&derived, &shared);
    let th = sha256(&transcript);
    let c_hs = derive_secret(&handshake_secret, "c hs traffic", &th);
    let s_hs = derive_secret(&handshake_secret, "s hs traffic", &th);
    let mut hs_write = Keys::from_secret(&s_hs, suite);
    let mut hs_read = Keys::from_secret(&c_hs, suite);

    // 4. EncryptedExtensions, [CertificateRequest], Certificate, CertificateVerify, Finished.
    let mut flight = handshake_msg(8, &[0, 0]);
    let want_client = !matches!(identity.client_auth, ClientAuth::Off);
    if want_client {
        // contexto vazio + extensão signature_algorithms com o que sabemos verificar
        let list: Vec<u8> = TLS_VERIFIABLE
            .iter()
            .flat_map(|c| c.to_be_bytes())
            .collect();
        let mut req = vec![0u8];
        let ext_len = list.len() + 2 + 4;
        req.extend_from_slice(&(ext_len as u16).to_be_bytes());
        req.extend_from_slice(&[0, 13]);
        req.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
        req.extend_from_slice(&(list.len() as u16).to_be_bytes());
        req.extend_from_slice(&list);
        flight.extend_from_slice(&handshake_msg(13, &req));
    }
    let mut cert = vec![0u8]; // request context vazio
    let mut entries = Vec::new();
    for der in std::iter::once(&identity.cert_der).chain(identity.chain.iter()) {
        let n = der.len();
        entries.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
        entries.extend_from_slice(der);
        entries.extend_from_slice(&[0, 0]); // extensões da entrada
    }
    let list_len = entries.len();
    cert.extend_from_slice(&[
        (list_len >> 16) as u8,
        (list_len >> 8) as u8,
        list_len as u8,
    ]);
    cert.extend_from_slice(&entries);
    flight.extend_from_slice(&handshake_msg(11, &cert));
    transcript.extend_from_slice(&flight);
    let mut to_sign = vec![0x20u8; 64];
    to_sign.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    to_sign.push(0);
    to_sign.extend_from_slice(&sha256(&transcript));
    let Some(sig) = identity.key.sign_tls(scheme, &to_sign) else {
        return Err(sealed_fail(
            &mut inner,
            &mut hs_write,
            80,
            "falha ao assinar CertificateVerify",
        ));
    };
    let mut cv = scheme.to_be_bytes().to_vec();
    cv.extend_from_slice(&(sig.len() as u16).to_be_bytes());
    cv.extend_from_slice(&sig);
    let cv_msg = handshake_msg(15, &cv);
    transcript.extend_from_slice(&cv_msg);
    flight.extend_from_slice(&cv_msg);
    let finished_key: [u8; 32] = hkdf_expand_label(&s_hs, "finished", &[], 32)
        .try_into()
        .expect("32");
    let verify = hmac_sha256(&finished_key, &[&sha256(&transcript)]);
    let fin_msg = handshake_msg(20, &verify);
    transcript.extend_from_slice(&fin_msg);
    flight.extend_from_slice(&fin_msg);
    for chunk in flight.chunks(MAX_RECORD - 1) {
        let sealed = seal_record(&mut hs_write, REC_HANDSHAKE, chunk);
        write_record(&mut inner, REC_APP, &sealed)?;
    }
    inner.flush()?;

    // 5. Segredos de aplicação (antes do Finished do cliente, como manda a RFC).
    let derived2 = derive_secret(&handshake_secret, "derived", &empty_hash);
    let master = hkdf_extract(&derived2, &[0u8; 32]);
    let th_server_fin = sha256(&transcript);
    let c_app = derive_secret(&master, "c ap traffic", &th_server_fin);
    let s_app = derive_secret(&master, "s ap traffic", &th_server_fin);

    // 6. Certificado do cliente (mTLS) e Finished. Daqui em diante o servidor já
    //    escreve com as chaves de aplicação (inclusive alertas).
    let mut app_write = Keys::from_secret(&s_app, suite);
    let client_finished_key: [u8; 32] = hkdf_expand_label(&c_hs, "finished", &[], 32)
        .try_into()
        .expect("32");
    let mut pending: Vec<u8> = Vec::new();
    let mut peer = None;
    // Recusas do certificado do cliente só são enviadas depois de ler o voo
    // inteiro (Certificate, CertificateVerify, Finished): fechar com dados não
    // lidos faz o TCP mandar RST e o cliente perderia o alerta.
    let mut rejection: Option<(u8, String)> = None;
    if want_client {
        let msg = read_handshake(&mut inner, &mut hs_read, &mut app_write, &mut pending)?;
        if msg[0] != 11 {
            return Err(sealed_fail(
                &mut inner,
                &mut app_write,
                10,
                "esperava Certificate do cliente",
            ));
        }
        transcript.extend_from_slice(&msg);
        let Some(chain) = parse_certificate_list(&msg[4..]) else {
            return Err(sealed_fail(
                &mut inner,
                &mut app_write,
                50,
                "Certificate do cliente malformado",
            ));
        };
        if chain.is_empty() {
            if matches!(identity.client_auth, ClientAuth::Required(_)) {
                rejection = Some((116, "certificado de cliente obrigatório".into()));
            }
        } else {
            let signed_hash = sha256(&transcript);
            let cv = read_handshake(&mut inner, &mut hs_read, &mut app_write, &mut pending)?;
            if cv[0] != 15 {
                return Err(sealed_fail(
                    &mut inner,
                    &mut app_write,
                    10,
                    "esperava CertificateVerify do cliente",
                ));
            }
            transcript.extend_from_slice(&cv);
            let (ClientAuth::Optional(roots) | ClientAuth::Required(roots)) = &identity.client_auth
            else {
                unreachable!("want_client")
            };
            match x509::verify_chain(&chain, roots, crate::rel::func::now_secs()) {
                Err(e) => {
                    let msg = e.to_string();
                    // unknown_ca, certificate_expired ou bad_certificate
                    let code = if msg.contains("não confiável") {
                        48
                    } else if msg.contains("validade") {
                        45
                    } else {
                        42
                    };
                    rejection = Some((code, msg));
                }
                // Certificado emitido só para outro uso (por exemplo `serverAuth`)
                // não autentica cliente: unsupported_certificate.
                Ok(leaf) if leaf.eku_client == Some(false) => {
                    rejection = Some((43, "certificado sem uso clientAuth (EKU)".to_string()));
                }
                Ok(leaf) => {
                    let parsed = (cv.len() >= 8)
                        .then(|| {
                            let code = u16::from_be_bytes([cv[4], cv[5]]);
                            let n = u16::from_be_bytes([cv[6], cv[7]]) as usize;
                            (cv.len() == 8 + n
                                && TLS_VERIFIABLE.contains(&code)
                                && leaf.public.allows_tls(code))
                            .then(|| (code, &cv[8..]))
                        })
                        .flatten();
                    let mut signed = vec![0x20u8; 64];
                    signed.extend_from_slice(b"TLS 1.3, client CertificateVerify");
                    signed.push(0);
                    signed.extend_from_slice(&signed_hash);
                    match parsed {
                        None => {
                            rejection = Some((47, "CertificateVerify do cliente inválido".into()))
                        }
                        Some((code, sig)) if !leaf.public.verify_tls(code, &signed, sig) => {
                            rejection = Some((51, "assinatura do cliente inválida".into()))
                        }
                        Some(_) => {
                            peer = Some(Peer {
                                cn: leaf.cn.clone(),
                                subject: leaf.subject_dn.clone(),
                                issuer: leaf.issuer_dn.clone(),
                            })
                        }
                    }
                }
            }
        }
    }
    let expected = hmac_sha256(&client_finished_key, &[&sha256(&transcript)]);
    let fin = read_handshake(&mut inner, &mut hs_read, &mut app_write, &mut pending)?;
    if let Some((code, msg)) = rejection {
        return Err(sealed_fail(&mut inner, &mut app_write, code, &msg));
    }
    if fin[0] != 20 || !crate::crypto::constant_time_eq(&fin[4..], &expected) {
        return Err(sealed_fail(
            &mut inner,
            &mut app_write,
            51,
            "Finished do cliente inválido",
        ));
    }
    Ok(TlsStream {
        inner,
        read_keys: Keys::from_secret(&c_app, suite),
        write_keys: app_write,
        plain: Vec::new(),
        plain_pos: 0,
        closed: false,
        peer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_expand_label_matches_rfc8448() {
        // RFC 8448 §3: early secret e derived secret com transcript vazio.
        let early = hkdf_extract(&[0u8; 32], &[0u8; 32]);
        assert_eq!(
            crate::crypto::to_hex(&early),
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
        );
        let derived = derive_secret(&early, "derived", &sha256(&[]));
        assert_eq!(
            crate::crypto::to_hex(&derived),
            "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
        );
    }

    #[test]
    fn record_keys_roundtrip_in_both_suites() {
        for suite in [Suite::Aes128Gcm, Suite::ChaCha20Poly1305] {
            assert_eq!(Suite::from_id(suite.id()), Some(suite));
            let secret = [5u8; 32];
            let mut w = Keys::from_secret(&secret, suite);
            let mut r = Keys::from_secret(&secret, suite);
            for n in 0..3u8 {
                let sealed = w.seal(b"aad", &[n; 40]);
                assert_eq!(r.open(b"aad", &sealed), Some(vec![n; 40]));
            }
            let sealed = w.seal(b"aad", b"x");
            assert!(r.open(b"outro", &sealed).is_none());
        }
        assert_eq!(Suite::from_id([0x13, 0x02]), None);
    }

    #[test]
    fn identity_files_roundtrip_with_chain() {
        let dir = std::env::temp_dir().join(format!(
            "minidb-tlsid-{}",
            crate::crypto::to_hex(&random_bytes::<6>())
        ));
        let _ = fs::remove_dir_all(&dir);
        x509::create_ca(&dir, "CA de teste").unwrap();
        let (k, c) = x509::issue_with(&dir, Kind::Server, "db.local", 30, KeyAlgo::P256).unwrap();
        let id = Identity::load(&k, &c).unwrap();
        assert!(id.chain.is_empty());
        // chave de outro certificado é recusada
        let (_, c2) = x509::issue(&dir, Kind::Client, "zed", 30).unwrap();
        assert!(Identity::load(&k, &c2).is_err());
        // folha + CA no mesmo arquivo: a CA segue como intermediária
        let both = format!(
            "{}{}",
            fs::read_to_string(&c).unwrap(),
            fs::read_to_string(dir.join("ca.crt")).unwrap()
        );
        fs::write(dir.join("chain.crt"), both).unwrap();
        assert_eq!(
            Identity::load(&k, &dir.join("chain.crt"))
                .unwrap()
                .chain
                .len(),
            1
        );
        // arquivo de chave inválido dá erro
        fs::write(
            dir.join("bad.key"),
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        assert!(Identity::load(&dir.join("bad.key"), &c).is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
