//! Chaves públicas e privadas para TLS/X.509: Ed25519, RSA (PKCS#1 v1.5 e
//! PSS) e ECDSA P-256/P-384. Leitura de PEM (PKCS#8, PKCS#1 `RSA PRIVATE KEY`,
//! SEC1 `EC PRIVATE KEY`), gravação PKCS#8, SPKI, geração, assinatura e verificação.

use crate::bignum::Uint;
use crate::crypto::Hash;
use crate::curve25519::{ed25519_verify, Ed25519Key};
use crate::ecc::{curve, CurveId};
use crate::error::{Error, Result};
use crate::rsa::{RsaPrivate, RsaPublic};
use crate::x509::{der, der_bitstring, der_octet, der_seq, pem_all, read_tlv};

const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_RSA_SHA: [&[u8]; 3] = [
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c],
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d],
];
const OID_ECDSA_SHA: [&[u8]; 3] = [
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04],
];
const HASHES: [Hash; 3] = [Hash::Sha256, Hash::Sha384, Hash::Sha512];

fn err(msg: &str) -> Error {
    Error::Other(msg.to_string())
}

/// Esquema de assinatura (independe de como é transportado: X.509 ou TLS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigScheme {
    Ed25519,
    Ecdsa(Hash),
    RsaPkcs1(Hash),
    RsaPss(Hash),
}

impl SigScheme {
    /// `AlgorithmIdentifier` X.509 (PSS não é usado em certificados aqui).
    pub fn algorithm_identifier(self) -> Vec<u8> {
        let idx = |h: Hash| HASHES.iter().position(|x| *x == h).unwrap_or(0);
        match self {
            SigScheme::Ed25519 => der_seq(&[der(0x06, OID_ED25519)]),
            SigScheme::Ecdsa(h) => der_seq(&[der(0x06, OID_ECDSA_SHA[idx(h)])]),
            SigScheme::RsaPkcs1(h) | SigScheme::RsaPss(h) => {
                der_seq(&[der(0x06, OID_RSA_SHA[idx(h)]), der(0x05, &[])])
            }
        }
    }

    /// Esquema de um OID de assinatura X.509; erro claro para o que não é suportado.
    pub fn from_oid(oid: &[u8]) -> Result<SigScheme> {
        if oid == OID_ED25519 {
            return Ok(SigScheme::Ed25519);
        }
        for (i, h) in HASHES.iter().enumerate() {
            if oid == OID_RSA_SHA[i] {
                return Ok(SigScheme::RsaPkcs1(*h));
            }
            if oid == OID_ECDSA_SHA[i] {
                return Ok(SigScheme::Ecdsa(*h));
            }
        }
        Err(Error::Other(
            "algoritmo de assinatura do certificado não suportado (aceitos: Ed25519, RSA PKCS#1 v1.5 e ECDSA com SHA-256/384/512; SHA-1 e RSASSA-PSS em certificados não)".into(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519([u8; 32]),
    Rsa(RsaPublic),
    Ec { curve: CurveId, x: Uint, y: Uint },
}

// Códigos `SignatureScheme` do TLS 1.3.
pub const TLS_ECDSA_P256_SHA256: u16 = 0x0403;
pub const TLS_ECDSA_P384_SHA384: u16 = 0x0503;
pub const TLS_RSA_PSS_SHA256: u16 = 0x0804;
pub const TLS_RSA_PSS_SHA384: u16 = 0x0805;
pub const TLS_RSA_PSS_SHA512: u16 = 0x0806;
pub const TLS_ED25519: u16 = 0x0807;
/// Esquemas que o servidor sabe verificar em certificados de cliente.
pub const TLS_VERIFIABLE: [u16; 6] = [
    TLS_ED25519,
    TLS_ECDSA_P256_SHA256,
    TLS_ECDSA_P384_SHA384,
    TLS_RSA_PSS_SHA256,
    TLS_RSA_PSS_SHA384,
    TLS_RSA_PSS_SHA512,
];

fn tls_scheme(code: u16) -> Option<SigScheme> {
    Some(match code {
        TLS_ED25519 => SigScheme::Ed25519,
        TLS_ECDSA_P256_SHA256 => SigScheme::Ecdsa(Hash::Sha256),
        TLS_ECDSA_P384_SHA384 => SigScheme::Ecdsa(Hash::Sha384),
        TLS_RSA_PSS_SHA256 => SigScheme::RsaPss(Hash::Sha256),
        TLS_RSA_PSS_SHA384 => SigScheme::RsaPss(Hash::Sha384),
        TLS_RSA_PSS_SHA512 => SigScheme::RsaPss(Hash::Sha512),
        _ => return None,
    })
}

fn der_uint(n: &Uint) -> Vec<u8> {
    let mut bytes = n.to_be(n.byte_len().max(1));
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    der(0x02, &bytes)
}

fn ecdsa_to_der(r: &Uint, s: &Uint) -> Vec<u8> {
    der_seq(&[der_uint(r), der_uint(s)])
}

fn ecdsa_from_der(sig: &[u8]) -> Option<(Uint, Uint)> {
    let (tag, body, rest) = read_tlv(sig)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (t1, r, more) = read_tlv(body)?;
    let (t2, s, tail) = read_tlv(more)?;
    (t1 == 0x02 && t2 == 0x02 && tail.is_empty()).then(|| (Uint::from_be(r), Uint::from_be(s)))
}

impl PublicKey {
    pub fn from_spki(spki: &[u8]) -> Result<PublicKey> {
        let bad = || err("chave pública (SPKI) inválida");
        let (tag, body, _) = read_tlv(spki).ok_or_else(bad)?;
        if tag != 0x30 {
            return Err(bad());
        }
        let (_, algo, rest) = read_tlv(body).ok_or_else(bad)?;
        let (_, bits, _) = read_tlv(rest).ok_or_else(bad)?;
        let (_, oid, params) = read_tlv(algo).ok_or_else(bad)?;
        let key = bits.get(1..).ok_or_else(bad)?;
        if oid == OID_ED25519 {
            return Ok(PublicKey::Ed25519(key.try_into().map_err(|_| bad())?));
        }
        if oid == OID_RSA {
            let (_, seq, _) = read_tlv(key).ok_or_else(bad)?;
            let (_, n, more) = read_tlv(seq).ok_or_else(bad)?;
            let (_, e, _) = read_tlv(more).ok_or_else(bad)?;
            let public = RsaPublic {
                n: Uint::from_be(n),
                e: Uint::from_be(e),
            };
            if !(1024..=8192).contains(&public.n.bits())
                || !public.n.is_odd()
                || !public.e.is_odd()
                || !(2..=33).contains(&public.e.bits())
            {
                return Err(err(
                    "chave RSA fora do aceito (1024–8192 bits, n ímpar, 3 ≤ e < 2^33 ímpar)",
                ));
            }
            return Ok(PublicKey::Rsa(public));
        }
        if oid == OID_EC {
            let (_, curve_oid, _) = read_tlv(params).ok_or_else(bad)?;
            let id = curve_id(curve_oid)?;
            let c = curve(id);
            if key.len() != 1 + 2 * c.size || key[0] != 4 {
                return Err(err("ponto EC não está no formato não comprimido"));
            }
            let (x, y) = (
                Uint::from_be(&key[1..1 + c.size]),
                Uint::from_be(&key[1 + c.size..]),
            );
            if !c.on_curve(&x, &y) {
                return Err(err("ponto EC fora da curva"));
            }
            return Ok(PublicKey::Ec { curve: id, x, y });
        }
        Err(err(
            "tipo de chave pública não suportado (aceitos: Ed25519, RSA, ECDSA P-256/P-384)",
        ))
    }

    pub fn to_spki(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(k) => {
                der_seq(&[der_seq(&[der(0x06, OID_ED25519)]), der_bitstring(k)])
            }
            PublicKey::Rsa(k) => der_seq(&[
                der_seq(&[der(0x06, OID_RSA), der(0x05, &[])]),
                der_bitstring(&der_seq(&[der_uint(&k.n), der_uint(&k.e)])),
            ]),
            PublicKey::Ec { curve: id, x, y } => {
                let size = curve(*id).size;
                let mut point = vec![4u8];
                point.extend(x.to_be(size));
                point.extend(y.to_be(size));
                der_seq(&[
                    der_seq(&[der(0x06, OID_EC), der(0x06, curve_oid(*id))]),
                    der_bitstring(&point),
                ])
            }
        }
    }

    pub fn verify(&self, scheme: SigScheme, msg: &[u8], sig: &[u8]) -> bool {
        match (self, scheme) {
            (PublicKey::Ed25519(k), SigScheme::Ed25519) => sig
                .try_into()
                .is_ok_and(|s: &[u8; 64]| ed25519_verify(k, msg, s)),
            (PublicKey::Ec { curve: id, x, y }, SigScheme::Ecdsa(h)) => {
                let Some((r, s)) = ecdsa_from_der(sig) else {
                    return false;
                };
                curve(*id).ecdsa_verify(x, y, &h.digest(msg), &r, &s)
            }
            (PublicKey::Rsa(k), SigScheme::RsaPkcs1(h)) => k.verify_pkcs1(h, msg, sig),
            (PublicKey::Rsa(k), SigScheme::RsaPss(h)) => k.verify_pss(h, msg, sig),
            _ => false,
        }
    }

    /// A chave serve para o esquema TLS `code`?
    pub fn allows_tls(&self, code: u16) -> bool {
        match self {
            PublicKey::Ed25519(_) => code == TLS_ED25519,
            PublicKey::Ec {
                curve: CurveId::P256,
                ..
            } => code == TLS_ECDSA_P256_SHA256,
            PublicKey::Ec {
                curve: CurveId::P384,
                ..
            } => code == TLS_ECDSA_P384_SHA384,
            PublicKey::Rsa(_) => {
                matches!(
                    code,
                    TLS_RSA_PSS_SHA256 | TLS_RSA_PSS_SHA384 | TLS_RSA_PSS_SHA512
                )
            }
        }
    }

    pub fn verify_tls(&self, code: u16, msg: &[u8], sig: &[u8]) -> bool {
        self.allows_tls(code)
            && tls_scheme(code).is_some_and(|scheme| self.verify(scheme, msg, sig))
    }

    pub fn description(&self) -> String {
        match self {
            PublicKey::Ed25519(_) => "Ed25519".into(),
            PublicKey::Rsa(k) => format!("RSA {}", k.modulus_bits()),
            PublicKey::Ec {
                curve: CurveId::P256,
                ..
            } => "ECDSA P-256".into(),
            PublicKey::Ec {
                curve: CurveId::P384,
                ..
            } => "ECDSA P-384".into(),
        }
    }
}

fn curve_id(oid: &[u8]) -> Result<CurveId> {
    if oid == OID_P256 {
        Ok(CurveId::P256)
    } else if oid == OID_P384 {
        Ok(CurveId::P384)
    } else {
        Err(err("curva EC não suportada (aceitas: P-256 e P-384)"))
    }
}

fn curve_oid(id: CurveId) -> &'static [u8] {
    match id {
        CurveId::P256 => OID_P256,
        CurveId::P384 => OID_P384,
    }
}

/// Algoritmo para gerar chaves com `minidb cert`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgo {
    Ed25519,
    P256,
    P384,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl KeyAlgo {
    pub fn parse(s: &str) -> Option<KeyAlgo> {
        match s.to_ascii_lowercase().as_str() {
            "ed25519" => Some(KeyAlgo::Ed25519),
            "p256" | "p-256" | "prime256v1" | "ecdsa" => Some(KeyAlgo::P256),
            "p384" | "p-384" | "secp384r1" => Some(KeyAlgo::P384),
            "rsa" | "rsa2048" | "rsa-2048" => Some(KeyAlgo::Rsa2048),
            "rsa3072" | "rsa-3072" => Some(KeyAlgo::Rsa3072),
            "rsa4096" | "rsa-4096" => Some(KeyAlgo::Rsa4096),
            _ => None,
        }
    }
}

pub enum PrivateKey {
    Ed25519(Ed25519Key),
    Rsa(Box<RsaPrivate>),
    Ec {
        curve: CurveId,
        d: Uint,
        public: (Uint, Uint),
    },
}

impl From<Ed25519Key> for PrivateKey {
    fn from(k: Ed25519Key) -> PrivateKey {
        PrivateKey::Ed25519(k)
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey({})", self.public().description())
    }
}

impl PrivateKey {
    pub fn generate(algo: KeyAlgo) -> PrivateKey {
        match algo {
            KeyAlgo::Ed25519 => PrivateKey::Ed25519(Ed25519Key::generate()),
            KeyAlgo::P256 => Self::generate_ec(CurveId::P256),
            KeyAlgo::P384 => Self::generate_ec(CurveId::P384),
            KeyAlgo::Rsa2048 => PrivateKey::Rsa(Box::new(RsaPrivate::generate(2048))),
            KeyAlgo::Rsa3072 => PrivateKey::Rsa(Box::new(RsaPrivate::generate(3072))),
            KeyAlgo::Rsa4096 => PrivateKey::Rsa(Box::new(RsaPrivate::generate(4096))),
        }
    }

    fn generate_ec(id: CurveId) -> PrivateKey {
        let c = curve(id);
        let d = c.random_scalar();
        let public = c.public_from_private(&d);
        PrivateKey::Ec {
            curve: id,
            d,
            public,
        }
    }

    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(k) => PublicKey::Ed25519(k.public),
            PrivateKey::Rsa(k) => PublicKey::Rsa(k.public.clone()),
            PrivateKey::Ec { curve, public, .. } => PublicKey::Ec {
                curve: *curve,
                x: public.0.clone(),
                y: public.1.clone(),
            },
        }
    }

    /// Esquema usado ao assinar certificados X.509 com esta chave.
    pub fn x509_scheme(&self) -> SigScheme {
        match self {
            PrivateKey::Ed25519(_) => SigScheme::Ed25519,
            PrivateKey::Rsa(_) => SigScheme::RsaPkcs1(Hash::Sha256),
            PrivateKey::Ec {
                curve: CurveId::P256,
                ..
            } => SigScheme::Ecdsa(Hash::Sha256),
            PrivateKey::Ec {
                curve: CurveId::P384,
                ..
            } => SigScheme::Ecdsa(Hash::Sha384),
        }
    }

    pub fn sign(&self, scheme: SigScheme, msg: &[u8]) -> Option<Vec<u8>> {
        match (self, scheme) {
            (PrivateKey::Ed25519(k), SigScheme::Ed25519) => Some(k.sign(msg).to_vec()),
            (PrivateKey::Ec { curve: id, d, .. }, SigScheme::Ecdsa(h)) => {
                let (r, s) = curve(*id).ecdsa_sign(d, &h.digest(msg));
                Some(ecdsa_to_der(&r, &s))
            }
            (PrivateKey::Rsa(k), SigScheme::RsaPkcs1(h)) => k.sign_pkcs1(h, msg),
            (PrivateKey::Rsa(k), SigScheme::RsaPss(h)) => k.sign_pss(h, msg),
            _ => None,
        }
    }

    /// Esquemas TLS 1.3 que esta chave assina, em ordem de preferência.
    pub fn tls_schemes(&self) -> Vec<u16> {
        match self {
            PrivateKey::Ed25519(_) => vec![TLS_ED25519],
            PrivateKey::Ec {
                curve: CurveId::P256,
                ..
            } => vec![TLS_ECDSA_P256_SHA256],
            PrivateKey::Ec {
                curve: CurveId::P384,
                ..
            } => vec![TLS_ECDSA_P384_SHA384],
            PrivateKey::Rsa(k) => [
                (TLS_RSA_PSS_SHA256, Hash::Sha256),
                (TLS_RSA_PSS_SHA384, Hash::Sha384),
                (TLS_RSA_PSS_SHA512, Hash::Sha512),
            ]
            .into_iter()
            .filter(|(_, h)| k.public.fits_pss(*h))
            .map(|(code, _)| code)
            .collect(),
        }
    }

    pub fn sign_tls(&self, code: u16, msg: &[u8]) -> Option<Vec<u8>> {
        if !self.tls_schemes().contains(&code) {
            return None;
        }
        self.sign(tls_scheme(code)?, msg)
    }

    /// PKCS#8 em PEM (Ed25519, EC e RSA).
    pub fn to_pem(&self) -> Result<String> {
        let inner = match self {
            PrivateKey::Ed25519(k) => der_seq(&[
                der(0x02, &[0]),
                der_seq(&[der(0x06, OID_ED25519)]),
                der_octet(&der_octet(k.seed())),
            ]),
            PrivateKey::Ec { curve: id, d, .. } => {
                let size = curve(*id).size;
                let sec1 = der_seq(&[der(0x02, &[1]), der_octet(&d.to_be(size))]);
                der_seq(&[
                    der(0x02, &[0]),
                    der_seq(&[der(0x06, OID_EC), der(0x06, curve_oid(*id))]),
                    der_octet(&sec1),
                ])
            }
            PrivateKey::Rsa(k) => {
                let pkcs1 = der_seq(&[
                    der(0x02, &[0]),
                    der_uint(&k.public.n),
                    der_uint(&k.public.e),
                    der_uint(&k.d),
                    der_uint(&k.p),
                    der_uint(&k.q),
                    der_uint(&k.dp),
                    der_uint(&k.dq),
                    der_uint(&k.qinv),
                ]);
                der_seq(&[
                    der(0x02, &[0]),
                    der_seq(&[der(0x06, OID_RSA), der(0x05, &[])]),
                    der_octet(&pkcs1),
                ])
            }
        };
        Ok(crate::x509::pem("PRIVATE KEY", &inner))
    }

    /// Lê PEM: `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY` (PKCS#1) ou `EC PRIVATE KEY` (SEC1).
    pub fn from_pem(text: &str) -> Result<PrivateKey> {
        if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
            || text.contains("Proc-Type: 4,ENCRYPTED")
        {
            return Err(err(
                "chave privada protegida por senha não é suportada; remova a senha com `openssl pkey -in chave.pem -out chave-sem-senha.pem`",
            ));
        }
        if let Some(der) = pem_all(text, "PRIVATE KEY")?.into_iter().next() {
            return parse_pkcs8(&der);
        }
        if let Some(der) = pem_all(text, "RSA PRIVATE KEY")?.into_iter().next() {
            return parse_rsa(&der);
        }
        if let Some(der) = pem_all(text, "EC PRIVATE KEY")?.into_iter().next() {
            return parse_sec1(&der, None);
        }
        Err(err(
            "PEM sem chave privada (PRIVATE KEY, RSA PRIVATE KEY ou EC PRIVATE KEY)",
        ))
    }
}

fn parse_pkcs8(der: &[u8]) -> Result<PrivateKey> {
    let bad = || err("chave PKCS#8 inválida");
    let (_, seq, _) = read_tlv(der).ok_or_else(bad)?;
    let (_, _version, rest) = read_tlv(seq).ok_or_else(bad)?;
    let (_, algo, rest) = read_tlv(rest).ok_or_else(bad)?;
    let (_, key, _) = read_tlv(rest).ok_or_else(bad)?;
    let (_, oid, params) = read_tlv(algo).ok_or_else(bad)?;
    if oid == OID_ED25519 {
        let (_, seed, _) = read_tlv(key).ok_or_else(bad)?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| bad())?;
        return Ok(PrivateKey::Ed25519(Ed25519Key::from_seed(seed)));
    }
    if oid == OID_RSA {
        return parse_rsa(key);
    }
    if oid == OID_EC {
        let (_, curve_oid, _) = read_tlv(params).ok_or_else(bad)?;
        return parse_sec1(key, Some(curve_id(curve_oid)?));
    }
    Err(err(
        "tipo de chave privada não suportado (aceitos: Ed25519, RSA, ECDSA P-256/P-384)",
    ))
}

fn parse_rsa(der: &[u8]) -> Result<PrivateKey> {
    let bad = || err("chave RSA inválida");
    let (_, mut rest, _) = read_tlv(der).ok_or_else(bad)?;
    let mut ints = Vec::new();
    for _ in 0..9 {
        let (tag, v, more) = read_tlv(rest).ok_or_else(bad)?;
        if tag != 0x02 {
            return Err(bad());
        }
        ints.push(Uint::from_be(v));
        rest = more;
    }
    let [_version, n, e, d, p, q, dp, dq, qinv]: [Uint; 9] = ints.try_into().map_err(|_| bad())?;
    let bad_key = || err("chave RSA inconsistente ou fora do aceito (1024–8192 bits)");
    if !(1024..=8192).contains(&n.bits()) || e.bits() > 33 {
        return Err(bad_key());
    }
    let key = RsaPrivate::new(n, e, d, p, q, dp, dq, qinv).ok_or_else(bad_key)?;
    Ok(PrivateKey::Rsa(Box::new(key)))
}

fn parse_sec1(der: &[u8], known: Option<CurveId>) -> Result<PrivateKey> {
    let bad = || err("chave EC inválida");
    let (_, seq, _) = read_tlv(der).ok_or_else(bad)?;
    let (_, _version, rest) = read_tlv(seq).ok_or_else(bad)?;
    let (_, d, mut rest) = read_tlv(rest).ok_or_else(bad)?;
    let mut id = known;
    while let Some((tag, content, more)) = read_tlv(rest) {
        if tag == 0xa0 {
            let (_, oid, _) = read_tlv(content).ok_or_else(bad)?;
            id = Some(curve_id(oid)?);
        }
        rest = more;
    }
    let id = id.ok_or_else(|| err("chave EC sem curva nomeada"))?;
    let c = curve(id);
    let d = Uint::from_be(d);
    if d.is_zero() || d.cmp_to(c.order()) != std::cmp::Ordering::Less {
        return Err(err("escalar EC fora de [1, n-1]"));
    }
    let public = c.public_from_private(&d);
    Ok(PrivateKey::Ec {
        curve: id,
        d,
        public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ec_keys_roundtrip_pem_and_sign() {
        for algo in [KeyAlgo::P256, KeyAlgo::P384, KeyAlgo::Ed25519] {
            let key = PrivateKey::generate(algo);
            let again = PrivateKey::from_pem(&key.to_pem().unwrap()).unwrap();
            assert_eq!(key.public(), again.public());
            let spki = key.public().to_spki();
            assert_eq!(PublicKey::from_spki(&spki).unwrap(), key.public());
            let scheme = key.x509_scheme();
            let sig = key.sign(scheme, b"msg").unwrap();
            assert!(key.public().verify(scheme, b"msg", &sig));
            assert!(!key.public().verify(scheme, b"outra", &sig));
            let code = key.tls_schemes()[0];
            let sig = key.sign_tls(code, b"x").unwrap();
            assert!(key.public().verify_tls(code, b"x", &sig));
        }
    }

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/pki/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn hex_fixture(name: &str) -> Vec<u8> {
        crate::crypto::from_hex(fixture(name).trim()).unwrap()
    }

    fn public_of(cert: &str) -> PublicKey {
        crate::x509::Cert::parse(&pem_all(&fixture(cert), "CERTIFICATE").unwrap()[0])
            .unwrap()
            .public
    }

    #[test]
    fn openssl_keys_load_in_every_format_and_match_certificates() {
        for (key, cert, desc) in [
            ("rsa-server.key", "rsa-server.crt", "RSA 2048"),
            ("rsa-server.p8.key", "rsa-server.crt", "RSA 2048"),
            ("rsa-server.pkcs1.key", "rsa-server.crt", "RSA 2048"),
            ("ec-server.key", "ec-server.crt", "ECDSA P-256"),
            ("ec-server.p8.key", "ec-server.crt", "ECDSA P-256"),
            ("ec-client.key", "ec-client.crt", "ECDSA P-384"),
        ] {
            let k = PrivateKey::from_pem(&fixture(key)).unwrap_or_else(|e| panic!("{key}: {e}"));
            assert_eq!(k.public(), public_of(cert), "{key}");
            assert_eq!(k.public().description(), desc);
        }
    }

    #[test]
    fn verifies_signatures_made_by_openssl() {
        let msg = b"mensagem de teste";
        let rsa = public_of("rsa-server.crt");
        assert!(rsa.verify(
            SigScheme::RsaPkcs1(Hash::Sha256),
            msg,
            &hex_fixture("sig1.hex")
        ));
        assert!(!rsa.verify(
            SigScheme::RsaPkcs1(Hash::Sha256),
            b"outra",
            &hex_fixture("sig1.hex")
        ));
        assert!(rsa.verify(
            SigScheme::RsaPss(Hash::Sha256),
            msg,
            &hex_fixture("sig2.hex")
        ));
        assert!(rsa.verify(
            SigScheme::RsaPss(Hash::Sha384),
            msg,
            &hex_fixture("sig5.hex")
        ));
        assert!(!rsa.verify(
            SigScheme::RsaPss(Hash::Sha256),
            msg,
            &hex_fixture("sig1.hex")
        ));
        assert!(public_of("ec-server.crt").verify(
            SigScheme::Ecdsa(Hash::Sha256),
            msg,
            &hex_fixture("sig3.hex")
        ));
        assert!(public_of("ec-client.crt").verify(
            SigScheme::Ecdsa(Hash::Sha384),
            msg,
            &hex_fixture("sig4.hex")
        ));
        assert!(!public_of("ec-client.crt").verify(
            SigScheme::Ecdsa(Hash::Sha384),
            b"x",
            &hex_fixture("sig4.hex")
        ));
    }

    #[test]
    fn rsa_signing_matches_openssl_and_pem_roundtrips() {
        let k = PrivateKey::from_pem(&fixture("rsa-server.key")).unwrap();
        // PKCS#1 v1.5 é determinística: CRT + blinding tem de reproduzir o OpenSSL
        let sig = k
            .sign(SigScheme::RsaPkcs1(Hash::Sha256), b"mensagem de teste")
            .unwrap();
        assert_eq!(sig, hex_fixture("sig1.hex"));
        let again = PrivateKey::from_pem(&k.to_pem().unwrap()).unwrap();
        assert_eq!(again.public(), k.public());
        assert_eq!(
            again.sign(SigScheme::RsaPkcs1(Hash::Sha256), b"mensagem de teste"),
            Some(sig)
        );
        // compatibilidade com a 1.2
        let ed = PrivateKey::generate(KeyAlgo::Ed25519);
        let PrivateKey::Ed25519(inner) = &ed else {
            unreachable!()
        };
        let old = crate::x509::ed25519_key_pem(inner.seed());
        assert_eq!(old, ed.to_pem().unwrap());
        assert_eq!(
            &crate::x509::parse_ed25519_key_pem(&old).unwrap(),
            inner.seed()
        );
        assert!(crate::x509::parse_ed25519_key_pem(&fixture("ec-server.key")).is_err());
    }

    #[test]
    fn our_rsa_and_ecdsa_signatures_verify_with_our_verifier() {
        let msg = b"handshake";
        for key in ["rsa-server.key", "ec-server.key", "ec-client.key"] {
            let k = PrivateKey::from_pem(&fixture(key)).unwrap();
            for code in k.tls_schemes() {
                let sig = k.sign_tls(code, msg).unwrap();
                assert!(k.public().verify_tls(code, msg, &sig), "{key} {code:#x}");
                assert!(!k.public().verify_tls(code, b"outra", &sig));
            }
            let x = k.x509_scheme();
            assert!(
                k.public().verify(x, msg, &k.sign(x, msg).unwrap()),
                "{key} x509"
            );
        }
    }

    #[test]
    fn unsupported_inputs_give_clear_errors() {
        let e = PrivateKey::from_pem(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("senha"), "{e}");
        assert!(
            SigScheme::from_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05])
                .unwrap_err()
                .to_string()
                .contains("SHA-1")
        );
    }
}
