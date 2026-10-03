//! X.509 mínimo para a PKI própria do Mini-DB: leitura DER, construção de
//! certificados Ed25519 (CA, servidor, cliente), PEM e validação de cadeia
//! (assinaturas, nomes, validade, `basicConstraints`). Chaves e assinaturas
//! Ed25519, RSA (PKCS#1 v1.5) e ECDSA P-256/P-384 (módulo `pubkey`).

use crate::error::{Error, Result};
use crate::pubkey::{KeyAlgo, PrivateKey, PublicKey, SigScheme};

const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_BASIC: &[u8] = &[0x55, 0x1d, 0x13];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
/// extendedKeyUsage (2.5.29.37) e os usos que valem para certificado de cliente.
const OID_EKU: &[u8] = &[0x55, 0x1d, 0x25];
const OID_EKU_ANY: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
const OID_EKU_CLIENT: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const MAX_CHAIN: usize = 8;

// ---------------------------------------------------------------------------
// Construção DER
// ---------------------------------------------------------------------------

fn der_len(n: usize) -> Vec<u8> {
    if n < 128 {
        vec![n as u8]
    } else if n < 256 {
        vec![0x81, n as u8]
    } else if n < 65_536 {
        vec![0x82, (n >> 8) as u8, n as u8]
    } else {
        vec![0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]
    }
}

pub fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(body.len()));
    out.extend_from_slice(body);
    out
}

pub fn der_seq(items: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &items.concat())
}

pub fn der_set(items: &[Vec<u8>]) -> Vec<u8> {
    der(0x31, &items.concat())
}

pub fn der_int(n: i64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let mut start = 0;
    while start < 7 && bytes[start] == 0 && bytes[start + 1] & 0x80 == 0 {
        start += 1;
    }
    der(0x02, &bytes[start..])
}

pub fn der_octet(b: &[u8]) -> Vec<u8> {
    der(0x04, b)
}

pub fn der_bitstring(b: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8];
    body.extend_from_slice(b);
    der(0x03, &body)
}

pub fn der_oid(parts: &[u32]) -> Vec<u8> {
    let mut body = vec![(parts[0] * 40 + parts[1]) as u8];
    for &p in &parts[2..] {
        let mut chunk = vec![(p & 0x7f) as u8];
        let mut v = p >> 7;
        while v > 0 {
            chunk.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        chunk.reverse();
        body.extend(chunk);
    }
    der(0x06, &body)
}

fn der_utf8(s: &str) -> Vec<u8> {
    der(0x0c, s.as_bytes())
}

fn der_time(secs: i64) -> Vec<u8> {
    let text = crate::rel::func::fmt_datetime(secs, true); // AAAA-MM-DD HH:MM:SS
    let compact: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    der(0x18, format!("{compact}Z").as_bytes()) // GeneralizedTime
}

/// `Name` com CN (e opcionalmente O).
pub fn name(cn: &str, org: Option<&str>) -> Vec<u8> {
    let mut rdns = Vec::new();
    if let Some(o) = org {
        rdns.push(der_set(&[der_seq(&[der_oid(&[2, 5, 4, 10]), der_utf8(o)])]));
    }
    rdns.push(der_set(&[der_seq(&[der_oid(&[2, 5, 4, 3]), der_utf8(cn)])]));
    der_seq(&rdns)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ca,
    Server,
    Client,
}

fn key_id(public: &PublicKey) -> Vec<u8> {
    crate::crypto::sha256(&public.to_spki())[..20].to_vec()
}

/// Certificado X.509 v3 assinado por `signer` (Ed25519, RSA ou ECDSA). Para
/// certificado autoassinado passe `issuer_name == subject_name` e `signer` =
/// a própria chave.
pub fn build(
    signer: &PrivateKey,
    issuer_name: &[u8],
    subject_name: &[u8],
    subject_pub: &PublicKey,
    kind: Kind,
    hosts: &[String],
    days: i64,
) -> Vec<u8> {
    let now = crate::rel::func::now_secs();
    let scheme = signer.x509_scheme();
    let algo = scheme.algorithm_identifier();
    let spki = subject_pub.to_spki();
    let mut exts = vec![der_seq(&[
        der_oid(&[2, 5, 29, 19]),
        der(0x01, &[0xff]), // crítica
        der_octet(&der_seq(&if kind == Kind::Ca {
            vec![der(0x01, &[0xff])]
        } else {
            vec![]
        })),
    ])];
    exts.push(der_seq(&[
        der_oid(&[2, 5, 29, 15]),
        der(0x01, &[0xff]),
        der_octet(&match kind {
            Kind::Ca => der(0x03, &[1, 0x06]), // keyCertSign | cRLSign
            _ => der(0x03, &[7, 0x80]),        // digitalSignature
        }),
    ]));
    match kind {
        Kind::Server => exts.push(der_seq(&[
            der_oid(&[2, 5, 29, 37]),
            der_octet(&der_seq(&[der_oid(&[1, 3, 6, 1, 5, 5, 7, 3, 1])])),
        ])),
        Kind::Client => exts.push(der_seq(&[
            der_oid(&[2, 5, 29, 37]),
            der_octet(&der_seq(&[der_oid(&[1, 3, 6, 1, 5, 5, 7, 3, 2])])),
        ])),
        Kind::Ca => {}
    }
    if kind == Kind::Server {
        let mut names = Vec::new();
        for h in hosts {
            match h.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(ip)) => names.push(der(0x87, &ip.octets())),
                Ok(std::net::IpAddr::V6(ip)) => names.push(der(0x87, &ip.octets())),
                Err(_) => names.push(der(0x82, h.as_bytes())),
            }
        }
        exts.push(der_seq(&[
            der_oid(&[2, 5, 29, 17]),
            der_octet(&der_seq(&names)),
        ]));
    }
    exts.push(der_seq(&[
        der_oid(&[2, 5, 29, 14]),
        der_octet(&der_octet(&key_id(subject_pub))),
    ]));
    exts.push(der_seq(&[
        der_oid(&[2, 5, 29, 35]),
        der_octet(&der_seq(&[der(0x80, &key_id(&signer.public()))])),
    ]));
    let serial = u64::from_le_bytes(crate::crypto::random_bytes::<8>()) >> 1;
    let tbs = der_seq(&[
        der(0xa0, &der_int(2)),
        der_int(serial as i64 | 1),
        algo.clone(),
        issuer_name.to_vec(),
        der_seq(&[der_time(now - 86_400), der_time(now + days * 86_400)]),
        subject_name.to_vec(),
        spki,
        der(0xa3, &der_seq(&exts)),
    ]);
    let sig = signer.sign(scheme, &tbs).expect("esquema da própria chave");
    der_seq(&[tbs, algo, der_bitstring(&sig)])
}

fn wrap64(s: &str) -> String {
    s.as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

/// OID do Ed25519 (RFC 8410), mantido para compatibilidade com a 1.2.
pub const OID_ED25519: [u32; 4] = [1, 3, 101, 112];

/// PKCS#8 Ed25519 (RFC 8410) a partir da semente (compatibilidade com a 1.2;
/// use `PrivateKey::to_pem` para qualquer tipo de chave).
pub fn ed25519_key_pem(seed: &[u8; 32]) -> String {
    PrivateKey::Ed25519(crate::curve25519::Ed25519Key::from_seed(*seed))
        .to_pem()
        .expect("Ed25519 sempre serializa")
}

/// Semente de uma chave PKCS#8 Ed25519 (compatibilidade com a 1.2; use
/// `PrivateKey::from_pem` para ler RSA/ECDSA também).
pub fn parse_ed25519_key_pem(text: &str) -> Result<[u8; 32]> {
    match PrivateKey::from_pem(text)? {
        PrivateKey::Ed25519(k) => Ok(*k.seed()),
        other => Err(Error::Other(format!(
            "chave {} não é Ed25519",
            other.public().description()
        ))),
    }
}

pub fn pem(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        wrap64(&crate::crypto::base64_encode(der))
    )
}

/// Todos os blocos PEM `label` de `text`, em ordem.
pub fn pem_all(text: &str, label: &str) -> Result<Vec<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(p) = rest.find(&begin) {
        let body_start = p + begin.len();
        let stop = rest[body_start..]
            .find(&end)
            .ok_or_else(|| Error::Other(format!("PEM sem {end}")))?;
        out.push(
            crate::crypto::base64_decode(&rest[body_start..body_start + stop])
                .ok_or_else(|| Error::Other("PEM inválido".into()))?,
        );
        rest = &rest[body_start + stop + end.len()..];
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Leitura DER / certificados
// ---------------------------------------------------------------------------

/// Lê um TLV: (tag, conteúdo, bytes restantes).
pub(crate) fn read_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)? as usize;
    let (len, hdr) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 3 {
            return None;
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | *b.get(2 + k)? as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    Some((tag, b.get(hdr..end)?, b.get(end..)?))
}

/// Como `read`, mas devolve também os bytes brutos (com cabeçalho).
/// (tag, conteúdo, bytes brutos com cabeçalho, restante)
type RawTlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn read_raw(b: &[u8]) -> Option<RawTlv<'_>> {
    let (tag, body, rest) = read_tlv(b)?;
    Some((tag, body, &b[..b.len() - rest.len()], rest))
}

fn civil_days(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_time(tag: u8, b: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(b).ok()?;
    let (year, rest) = match tag {
        0x17 => {
            let yy: i64 = s.get(..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, s.get(2..)?)
        }
        0x18 => (s.get(..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let f = |a: usize| -> Option<i64> { rest.get(a..a + 2)?.parse().ok() };
    let (mo, d, h, mi, se) = (f(0)?, f(2)?, f(4)?, f(6)?, f(8).unwrap_or(0));
    Some(civil_days(year, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

fn name_string(name_body: &[u8]) -> (String, Option<String>) {
    let mut parts = Vec::new();
    let mut cn = None;
    let mut rdns = name_body;
    while let Some((_, set, rest)) = read_tlv(rdns) {
        rdns = rest;
        let mut attrs = set;
        while let Some((_, seq, more)) = read_tlv(attrs) {
            attrs = more;
            let Some((_, oid, val_rest)) = read_tlv(seq) else {
                continue;
            };
            let Some((_, val, _)) = read_tlv(val_rest) else {
                continue;
            };
            let text = String::from_utf8_lossy(val).into_owned();
            let label = match oid {
                o if o == OID_CN => {
                    cn = Some(text.clone());
                    "CN"
                }
                [0x55, 0x04, 0x0a] => "O",
                [0x55, 0x04, 0x0b] => "OU",
                [0x55, 0x04, 0x06] => "C",
                [0x55, 0x04, 0x07] => "L",
                [0x55, 0x04, 0x08] => "ST",
                _ => continue,
            };
            parts.push(format!("{label}={text}"));
        }
    }
    (parts.join(","), cn)
}

#[derive(Clone, Debug)]
pub struct Cert {
    pub der: Vec<u8>,
    tbs: Vec<u8>,
    scheme: SigScheme,
    sig: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub cn: Option<String>,
    pub public: PublicKey,
    pub not_before: i64,
    pub not_after: i64,
    pub is_ca: bool,
    pub sans: Vec<String>,
    /// extendedKeyUsage: `None` = sem a extensão (qualquer uso); `Some(true)` =
    /// inclui `clientAuth` (ou `anyExtendedKeyUsage`); `Some(false)` = só outros usos.
    pub eku_client: Option<bool>,
}

fn bad(msg: &str) -> Error {
    Error::Other(format!("certificado inválido: {msg}"))
}

impl Cert {
    pub fn parse(der_bytes: &[u8]) -> Result<Cert> {
        let (tag, body, _) = read_tlv(der_bytes).ok_or_else(|| bad("DER"))?;
        if tag != 0x30 {
            return Err(bad("esperava SEQUENCE"));
        }
        let (_, tbs_body, tbs_raw, rest) = read_raw(body).ok_or_else(|| bad("tbs"))?;
        let (_, sig_alg, rest) = read_tlv(rest).ok_or_else(|| bad("algoritmo"))?;
        let (_, sig_bits, _) = read_tlv(rest).ok_or_else(|| bad("assinatura"))?;
        let (_, sig_oid, _) = read_tlv(sig_alg).ok_or_else(|| bad("algoritmo"))?;
        let scheme = SigScheme::from_oid(sig_oid)?;
        let sig = sig_bits.get(1..).ok_or_else(|| bad("assinatura"))?.to_vec();
        let mut r = tbs_body;
        if r.first() == Some(&0xa0) {
            r = read_tlv(r).ok_or_else(|| bad("versão"))?.2;
        }
        r = read_tlv(r).ok_or_else(|| bad("serial"))?.2;
        r = read_tlv(r).ok_or_else(|| bad("algoritmo interno"))?.2;
        let (_, issuer_body, issuer_raw, r) = read_raw(r).ok_or_else(|| bad("emissor"))?;
        let (_, validity, r) = read_tlv(r).ok_or_else(|| bad("validade"))?;
        let (_, subject_body, subject_raw, r) = read_raw(r).ok_or_else(|| bad("sujeito"))?;
        let (_, _, spki_raw, r) = read_raw(r).ok_or_else(|| bad("chave"))?;
        let (t1, nb, v2) = read_tlv(validity).ok_or_else(|| bad("início"))?;
        let (t2, na, _) = read_tlv(v2).ok_or_else(|| bad("fim"))?;
        let public = PublicKey::from_spki(spki_raw)?;
        let mut is_ca = false;
        let mut sans = Vec::new();
        let mut eku_client = None;
        let mut tail = r;
        while let Some((tag, content, more)) = read_tlv(tail) {
            tail = more;
            if tag != 0xa3 {
                continue;
            }
            let (_, exts, _) = read_tlv(content).ok_or_else(|| bad("extensões"))?;
            let mut list = exts;
            while let Some((_, ext, more)) = read_tlv(list) {
                list = more;
                let Some((_, oid, after)) = read_tlv(ext) else {
                    continue;
                };
                // `critical` BOOLEAN opcional antes do OCTET STRING
                let after = match read_tlv(after) {
                    Some((0x01, _, rest)) => rest,
                    _ => after,
                };
                let Some((_, value, _)) = read_tlv(after) else {
                    continue;
                };
                if oid == OID_BASIC {
                    if let Some((_, seq, _)) = read_tlv(value) {
                        is_ca = matches!(read_tlv(seq), Some((0x01, [0xff], _)));
                    }
                } else if oid == OID_SAN {
                    let mut names = read_tlv(value).map_or(&[][..], |(_, s, _)| s);
                    while let Some((tag, n, more)) = read_tlv(names) {
                        names = more;
                        match (tag, n.len()) {
                            (0x82, _) => sans.push(String::from_utf8_lossy(n).into_owned()),
                            (0x87, 4) => sans.push(format!("{}.{}.{}.{}", n[0], n[1], n[2], n[3])),
                            _ => {}
                        }
                    }
                } else if oid == OID_EKU {
                    let mut purposes = read_tlv(value).map_or(&[][..], |(_, s, _)| s);
                    let mut client = false;
                    while let Some((_, purpose, more)) = read_tlv(purposes) {
                        purposes = more;
                        client |= purpose == OID_EKU_CLIENT || purpose == OID_EKU_ANY;
                    }
                    eku_client = Some(client);
                }
            }
        }
        let (subject_dn, cn) = name_string(subject_body);
        let (issuer_dn, _) = name_string(issuer_body);
        Ok(Cert {
            der: der_bytes.to_vec(),
            tbs: tbs_raw.to_vec(),
            scheme,
            sig,
            issuer: issuer_raw.to_vec(),
            subject: subject_raw.to_vec(),
            subject_dn,
            issuer_dn,
            cn,
            public,
            not_before: parse_time(t1, nb).ok_or_else(|| bad("data inicial"))?,
            not_after: parse_time(t2, na).ok_or_else(|| bad("data final"))?,
            is_ca,
            sans,
            eku_client,
        })
    }

    fn signed_by(&self, issuer: &Cert) -> bool {
        self.issuer == issuer.subject && issuer.public.verify(self.scheme, &self.tbs, &self.sig)
    }

    fn valid_at(&self, now: i64) -> bool {
        self.not_before <= now && now <= self.not_after
    }

    /// Emitido por si mesmo (raiz).
    pub fn is_self_signed(&self) -> bool {
        self.signed_by(self)
    }
}

/// Valida `chain` (folha primeiro) até uma das `roots` confiáveis: assinaturas,
/// encadeamento de nomes, validade e `CA:TRUE` nos emissores. Devolve a folha.
pub fn verify_chain(chain: &[Vec<u8>], roots: &[Cert], now: i64) -> Result<Cert> {
    if chain.is_empty() || chain.len() > MAX_CHAIN {
        return Err(Error::Other(
            "cadeia de certificados vazia ou longa demais".into(),
        ));
    }
    let certs = chain
        .iter()
        .map(|d| Cert::parse(d))
        .collect::<Result<Vec<_>>>()?;
    for c in &certs {
        if !c.valid_at(now) {
            return Err(Error::Other(format!(
                "certificado fora da validade: {}",
                c.subject_dn
            )));
        }
    }
    for pair in certs.windows(2) {
        if !pair[1].is_ca || !pair[0].signed_by(&pair[1]) {
            return Err(Error::Other(format!(
                "cadeia inválida: {} não foi emitido por {}",
                pair[0].subject_dn, pair[1].subject_dn
            )));
        }
    }
    let last = certs.last().expect("não vazia");
    let trusted = roots
        .iter()
        .any(|r| r.valid_at(now) && (r.der == last.der || (r.is_ca && last.signed_by(r))));
    if !trusted {
        return Err(Error::Other(format!(
            "certificado não confiável (emissor {} fora das CAs configuradas)",
            last.issuer_dn
        )));
    }
    Ok(certs.into_iter().next().expect("não vazia"))
}

/// Raízes confiáveis a partir de um arquivo PEM (uma ou mais CAs).
pub fn load_roots(pem_text: &str) -> Result<Vec<Cert>> {
    let roots = pem_all(pem_text, "CERTIFICATE")?
        .iter()
        .map(|d| Cert::parse(d))
        .collect::<Result<Vec<_>>>()?;
    if roots.is_empty() {
        return Err(Error::Other("arquivo de CA sem certificados".into()));
    }
    Ok(roots)
}

// ---------------------------------------------------------------------------
// Ferramenta de PKI (`minidb cert ...`)
// ---------------------------------------------------------------------------

/// Cria `ca.key`/`ca.crt` em `dir` (CA de 10 anos). Não sobrescreve.
pub fn create_ca(dir: &std::path::Path, cn: &str) -> Result<()> {
    create_ca_with(dir, cn, KeyAlgo::Ed25519)
}

/// Como `create_ca`, escolhendo o tipo de chave (Ed25519, ECDSA ou RSA).
pub fn create_ca_with(dir: &std::path::Path, cn: &str, algo: KeyAlgo) -> Result<()> {
    let (key_path, crt_path) = (dir.join("ca.key"), dir.join("ca.crt"));
    if key_path.exists() || crt_path.exists() {
        return Err(Error::Other(format!(
            "{} já existe; remova-o antes de criar outra CA",
            key_path.display()
        )));
    }
    std::fs::create_dir_all(dir)?;
    let key = PrivateKey::generate(algo);
    let n = name(cn, Some("Mini-DB"));
    let cert = build(&key, &n, &n, &key.public(), Kind::Ca, &[], 3650);
    write_private(&key_path, &key.to_pem()?)?;
    std::fs::write(&crt_path, pem("CERTIFICATE", &cert))?;
    Ok(())
}

/// Grava chave privada já com modo 0600 (sem janela em que ela fique legível).
pub(crate) fn write_private(path: &std::path::Path, text: &str) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    // Arquivo que já existia mantém o modo antigo: aperta antes de gravar o segredo.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(text.as_bytes())?;
    Ok(())
}

/// Emite certificado assinado pela CA em `dir`: servidor (`nome` = host, com
/// SAN) ou cliente (`nome` = usuário do banco, vira o CN). Grava
/// `<arquivo>.key`/`<arquivo>.crt`; devolve os caminhos.
pub fn issue(
    dir: &std::path::Path,
    kind: Kind,
    subject: &str,
    days: i64,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    issue_with(dir, kind, subject, days, KeyAlgo::Ed25519)
}

/// Como `issue`, escolhendo o tipo de chave da folha.
pub fn issue_with(
    dir: &std::path::Path,
    kind: Kind,
    subject: &str,
    days: i64,
    algo: KeyAlgo,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    if kind == Kind::Ca {
        return Err(Error::Other("use create_ca para CAs".into()));
    }
    let ca_key_text = std::fs::read_to_string(dir.join("ca.key")).map_err(|_| {
        Error::Other(format!(
            "sem {}; rode `minidb cert ca` antes",
            dir.join("ca.key").display()
        ))
    })?;
    let ca_key = PrivateKey::from_pem(&ca_key_text)?;
    let ca_der = pem_all(&std::fs::read_to_string(dir.join("ca.crt"))?, "CERTIFICATE")?
        .into_iter()
        .next()
        .ok_or_else(|| Error::Other("ca.crt vazio".into()))?;
    let ca = Cert::parse(&ca_der)?;
    if ca.public != ca_key.public() {
        return Err(Error::Other("ca.key não corresponde a ca.crt".into()));
    }
    let key = PrivateKey::generate(algo);
    let hosts = if kind == Kind::Server {
        let mut h = vec![subject.to_string(), "localhost".into(), "127.0.0.1".into()];
        h.dedup();
        h
    } else {
        Vec::new()
    };
    let cert = build(
        &ca_key,
        &ca.subject,
        &name(subject, None),
        &key.public(),
        kind,
        &hosts,
        days,
    );
    let stem = match kind {
        Kind::Server => "server".to_string(),
        _ => format!("client-{subject}"),
    };
    let (kp, cp) = (
        dir.join(format!("{stem}.key")),
        dir.join(format!("{stem}.crt")),
    );
    write_private(&kp, &key.to_pem()?)?;
    std::fs::write(&cp, pem("CERTIFICATE", &cert))?;
    Ok((kp, cp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "minidb-x509-{tag}-{}",
            crate::crypto::to_hex(&crate::crypto::random_bytes::<6>())
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn ca_issues_and_chain_verifies() {
        let dir = tmp("ca");
        create_ca(&dir, "Teste CA").unwrap();
        assert!(create_ca(&dir, "Outra").is_err(), "não sobrescreve");
        let (_, srv) = issue(&dir, Kind::Server, "db.exemplo", 30).unwrap();
        let (_, cli) = issue(&dir, Kind::Client, "alice", 30).unwrap();
        let roots = load_roots(&std::fs::read_to_string(dir.join("ca.crt")).unwrap()).unwrap();
        assert!(roots[0].is_ca && roots[0].is_self_signed());
        let now = crate::rel::func::now_secs();
        let leaf = |p: &std::path::PathBuf| {
            pem_all(&std::fs::read_to_string(p).unwrap(), "CERTIFICATE").unwrap()
        };
        let c = verify_chain(&leaf(&cli), &roots, now).unwrap();
        assert_eq!(c.cn.as_deref(), Some("alice"));
        assert!(!c.is_ca);
        let s = verify_chain(&leaf(&srv), &roots, now).unwrap();
        assert!(
            s.sans.contains(&"db.exemplo".to_string()) && s.sans.contains(&"127.0.0.1".to_string())
        );
        // fora da validade
        assert!(verify_chain(&leaf(&cli), &roots, now + 40 * 86_400).is_err());
        // CA desconhecida
        let other = tmp("other");
        create_ca(&other, "Outra CA").unwrap();
        let other_roots =
            load_roots(&std::fs::read_to_string(other.join("ca.crt")).unwrap()).unwrap();
        assert!(verify_chain(&leaf(&cli), &other_roots, now).is_err());
        // adulterado
        let mut tampered = leaf(&cli);
        let n = tampered[0].len();
        tampered[0][n - 70] ^= 1;
        assert!(verify_chain(&tampered, &roots, now).is_err());
        // a chave emitida confere com o certificado
        let key =
            PrivateKey::from_pem(&std::fs::read_to_string(dir.join("client-alice.key")).unwrap())
                .unwrap();
        assert_eq!(key.public(), c.public);
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(other);
    }

    #[test]
    fn intermediate_chain_and_non_ca_issuer() {
        let ca = PrivateKey::generate(KeyAlgo::Ed25519);
        let inter = PrivateKey::generate(KeyAlgo::Ed25519);
        let leaf = PrivateKey::generate(KeyAlgo::Ed25519);
        let (n_ca, n_in, n_leaf) = (
            name("Raiz", None),
            name("Intermediária", None),
            name("bob", None),
        );
        let root_der = build(&ca, &n_ca, &n_ca, &ca.public(), Kind::Ca, &[], 100);
        let inter_der = build(&ca, &n_ca, &n_in, &inter.public(), Kind::Ca, &[], 100);
        let leaf_der = build(
            &inter,
            &n_in,
            &n_leaf,
            &leaf.public(),
            Kind::Client,
            &[],
            100,
        );
        let roots = vec![Cert::parse(&root_der).unwrap()];
        let now = crate::rel::func::now_secs();
        let ok = verify_chain(&[leaf_der.clone(), inter_der.clone()], &roots, now).unwrap();
        assert_eq!(ok.cn.as_deref(), Some("bob"));
        // sem a intermediária a cadeia não fecha
        assert!(verify_chain(std::slice::from_ref(&leaf_der), &roots, now).is_err());
        // folha não pode atuar como CA
        let evil = PrivateKey::generate(KeyAlgo::Ed25519);
        let evil_der = build(
            &leaf,
            &n_leaf,
            &name("mallory", None),
            &evil.public(),
            Kind::Client,
            &[],
            100,
        );
        assert!(verify_chain(&[evil_der, leaf_der], &roots, now).is_err());
    }
}
