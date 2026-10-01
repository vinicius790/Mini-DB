//! RSA (RFC 8017): verificação PKCS#1 v1.5 e PSS, assinatura PSS/PKCS#1 v1.5
//! e geração de chaves. Sobre `bignum`, sem dependências.
//!
//! Assinatura com CRT, **blinding** da mensagem (valor aleatório novo a cada
//! assinatura, removido em cada primo), exponenciação de tempo constante
//! (`Mont::pow_ct`) e conferência `s^e = m` antes de devolver (contra falhas).

use crate::bignum::{Mont, Uint};
use crate::crypto::{random_bytes, Hash};
use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublic {
    pub n: Uint,
    pub e: Uint,
}

#[derive(Clone)]
pub struct RsaPrivate {
    pub public: RsaPublic,
    pub d: Uint,
    pub p: Uint,
    pub q: Uint,
    pub dp: Uint,
    pub dq: Uint,
    pub qinv: Uint,
    mp: Mont,
    mq: Mont,
    mn: Mont,
}

impl std::fmt::Debug for RsaPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RsaPrivate({} bits)", self.public.modulus_bits())
    }
}

/// Primos pequenos para descartar candidatos antes do Miller–Rabin.
fn small_primes() -> Vec<u64> {
    let limit = 4096usize;
    let mut sieve = vec![true; limit];
    let mut out = Vec::new();
    for i in 2..limit {
        if sieve[i] {
            out.push(i as u64);
            (i * i..limit).step_by(i).for_each(|j| sieve[j] = false);
        }
    }
    out
}

fn pow_u64(b: u64, mut e: u64, m: u64) -> u64 {
    let mut r = 1u128;
    let mut b2 = (b % m) as u128;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b2 % m as u128;
        }
        b2 = b2 * b2 % m as u128;
        e >>= 1;
    }
    r as u64
}

/// Miller–Rabin com `rounds` bases aleatórias.
fn probably_prime(n: &Uint, rounds: usize) -> bool {
    let one = Uint::from_u64(1);
    let n1 = n.sub(&one);
    let mut d = n1.clone();
    let mut s = 0;
    while !d.is_odd() {
        d = d.div_small(2).0;
        s += 1;
    }
    let m = Mont::new(n);
    let (one_m, minus_one) = (m.one(), m.to(&n1));
    'bases: for _ in 0..rounds {
        let a = loop {
            let bytes = random_bytes::<1024>();
            let a = Uint::from_be(&bytes[..n.byte_len() - 1]);
            if a.bits() > 1 {
                break a;
            }
        };
        let mut x = m.pow(&m.to(&a), &d);
        if x == one_m || x == minus_one {
            continue;
        }
        for _ in 1..s {
            x = m.mul(&x, &x);
            if x == minus_one {
                continue 'bases;
            }
            if x == one_m {
                return false;
            }
        }
        return false;
    }
    true
}

/// Primo aleatório de exatamente `bits` bits (dois bits de cima ligados, para
/// que p·q tenha 2·bits bits) com `p − 1` coprimo a `e`.
fn random_prime(bits: usize, e: u64) -> Uint {
    let primes = small_primes();
    loop {
        let mut bytes = random_bytes::<512>()[..bits / 8].to_vec();
        bytes[0] |= 0xc0;
        *bytes.last_mut().expect("bytes") |= 1;
        let p = Uint::from_be(&bytes);
        if primes.iter().any(|&sp| p.div_small(sp).1 == 0) {
            continue;
        }
        if p.div_small(e).1 == 1 {
            continue; // e | p − 1
        }
        if probably_prime(&p, 32) {
            return p;
        }
    }
}

/// `x` com `e·x ≡ 1 (mod m)` para `e` primo pequeno: x = (1 + k·m)/e.
fn inverse_of_small_prime(e: u64, m: &Uint) -> Option<Uint> {
    let r = m.div_small(e).1;
    if r == 0 {
        return None;
    }
    let k = (e - pow_u64(r, e - 2, e)) % e;
    let (x, rest) = m
        .mul(&Uint::from_u64(k))
        .add(&Uint::from_u64(1))
        .div_small(e);
    (rest == 0).then_some(x)
}

fn digest_info_prefix(h: Hash) -> &'static [u8] {
    match h {
        Hash::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        Hash::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        Hash::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
    }
}

/// MGF1 (RFC 8017 B.2.1).
fn mgf1(h: Hash, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + h.len());
    let mut counter = 0u32;
    while out.len() < len {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&h.digest(&input));
        counter += 1;
    }
    out.truncate(len);
    out
}

impl RsaPublic {
    pub fn modulus_bits(&self) -> usize {
        self.n.bits()
    }

    /// PSS com sal do tamanho do resumo cabe nesta chave?
    pub fn fits_pss(&self, h: Hash) -> bool {
        (self.modulus_bits() - 1).div_ceil(8) >= 2 * h.len() + 2
    }

    fn size(&self) -> usize {
        self.n.byte_len()
    }

    /// RSAVP1: s^e mod n.
    fn apply(&self, sig: &[u8]) -> Option<Vec<u8>> {
        if sig.len() != self.size() {
            return None;
        }
        let s = Uint::from_be(sig);
        if s.cmp_to(&self.n) != Ordering::Less || !self.n.is_odd() {
            return None;
        }
        let m = Mont::new(&self.n).mod_pow(&s, &self.e);
        Some(m.to_be(self.size()))
    }

    pub fn verify_pkcs1(&self, h: Hash, msg: &[u8], sig: &[u8]) -> bool {
        let Some(em) = self.apply(sig) else {
            return false;
        };
        let k = self.size();
        let prefix = digest_info_prefix(h);
        let digest = h.digest(msg);
        let t_len = prefix.len() + digest.len();
        if k < t_len + 11 {
            return false;
        }
        let mut expected = vec![0x00, 0x01];
        expected.extend(std::iter::repeat_n(0xff, k - t_len - 3));
        expected.push(0x00);
        expected.extend_from_slice(prefix);
        expected.extend_from_slice(&digest);
        crate::crypto::constant_time_eq(&em, &expected)
    }

    /// RSASSA-PSS com MGF1 do mesmo resumo e sal do tamanho do resumo (TLS 1.3).
    pub fn verify_pss(&self, h: Hash, msg: &[u8], sig: &[u8]) -> bool {
        let Some(em_full) = self.apply(sig) else {
            return false;
        };
        let em_bits = self.modulus_bits() - 1;
        let em_len = em_bits.div_ceil(8);
        // em = últimos em_len bytes (quando em_bits é múltiplo de 8 há um 0x00 à frente)
        let em = &em_full[em_full.len() - em_len..];
        let hl = h.len();
        let sl = hl;
        if em_len < hl + sl + 2 || em[em_len - 1] != 0xbc {
            return false;
        }
        let (masked, rest) = em.split_at(em_len - hl - 1);
        let hash = &rest[..hl];
        let top_clear = 8 * em_len - em_bits;
        if top_clear > 0 && masked[0] >> (8 - top_clear) != 0 {
            return false;
        }
        let mask = mgf1(h, hash, masked.len());
        let mut db: Vec<u8> = masked.iter().zip(&mask).map(|(a, b)| a ^ b).collect();
        if top_clear > 0 {
            db[0] &= 0xff >> top_clear;
        }
        let ps_len = em_len - hl - sl - 2;
        if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
            return false;
        }
        let salt = &db[db.len() - sl..];
        let mut m_prime = vec![0u8; 8];
        m_prime.extend_from_slice(&h.digest(msg));
        m_prime.extend_from_slice(salt);
        crate::crypto::constant_time_eq(&h.digest(&m_prime), hash)
    }
}

impl RsaPrivate {
    /// Monta e valida a chave (n = p·q, CRT coerente).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        n: Uint,
        e: Uint,
        d: Uint,
        p: Uint,
        q: Uint,
        dp: Uint,
        dq: Uint,
        qinv: Uint,
    ) -> Option<RsaPrivate> {
        let ok = p.mul(&q) == n
            && p.is_odd()
            && q.is_odd()
            && p.bits() >= 128
            && q.bits() >= 128
            && n.is_odd()
            && e.is_odd()
            && e.bits() >= 2;
        if !ok {
            return None;
        }
        let (mp, mq, mn) = (Mont::new(&p), Mont::new(&q), Mont::new(&n));
        // q·qinv ≡ 1 (mod p)
        if mp.mod_mul(&q, &qinv) != Uint::from_u64(1) {
            return None;
        }
        Some(RsaPrivate {
            public: RsaPublic { n, e },
            d,
            p,
            q,
            dp,
            dq,
            qinv,
            mp,
            mq,
            mn,
        })
    }

    /// Gera chave de `bits` bits (múltiplo de 16) com e = 65537.
    pub fn generate(bits: usize) -> RsaPrivate {
        assert!(
            bits.is_multiple_of(16) && bits >= 1024,
            "tamanho RSA inválido"
        );
        const E: u64 = 65537;
        loop {
            let (mut p, mut q) = (random_prime(bits / 2, E), random_prime(bits / 2, E));
            match p.cmp_to(&q) {
                Ordering::Equal => continue,
                Ordering::Less => std::mem::swap(&mut p, &mut q),
                Ordering::Greater => {}
            }
            let n = p.mul(&q);
            if n.bits() != bits {
                continue;
            }
            let one = Uint::from_u64(1);
            let (p1, q1) = (p.sub(&one), q.sub(&one));
            let (Some(d), Some(dp), Some(dq)) = (
                inverse_of_small_prime(E, &p1.mul(&q1)),
                inverse_of_small_prime(E, &p1),
                inverse_of_small_prime(E, &q1),
            ) else {
                continue;
            };
            let qinv = Mont::new(&p).inv_prime(&q);
            if let Some(k) = RsaPrivate::new(n, Uint::from_u64(E), d, p, q, dp, dq, qinv) {
                return k;
            }
        }
    }

    /// m^d mod n: CRT com blinding (r aleatório; m·r^e em cada primo, depois
    /// multiplica por r⁻¹ = r^(p−2)), expoentes secretos em `pow_ct` e
    /// conferência `s^e == m` (contra falhas de cálculo).
    fn apply(&self, m: &Uint) -> Option<Uint> {
        let e = &self.public.e;
        let two = Uint::from_u64(2);
        for _ in 0..4 {
            let r = Uint::from_be(&random_bytes::<1024>()[..self.public.size()]);
            let mut parts = Vec::with_capacity(2);
            for (mont, prime, dx) in [(&self.mp, &self.p, &self.dp), (&self.mq, &self.q, &self.dq)]
            {
                let bits = prime.bits();
                let rm = mont.to_limbs(&r.limbs_padded(self.mn.limbs()));
                let blinded = mont.mul(&mont.to(m), &mont.pow(&rm, e));
                let sb = mont.pow_ct(&blinded, dx, bits);
                let rinv = mont.pow_ct(&rm, &prime.sub(&two), bits);
                parts.push((Mont::is_zero_vec(&rm), mont.mul(&sb, &rinv)));
            }
            if parts.iter().any(|(zero, _)| *zero) {
                continue; // r múltiplo de p ou q: probabilidade desprezível
            }
            let s2 = self.mq.from(&parts[1].1);
            let s2p = self.mp.to_limbs(&s2.limbs_padded(self.mn.limbs()));
            let diff = self.mp.sub(&parts[0].1, &s2p);
            let h = self.mp.from(&self.mp.mul(&diff, &self.mp.to(&self.qinv)));
            let s = s2.add(&h.mul(&self.q));
            let check = self.mn.mod_pow(&s, e);
            return (check == *m).then_some(s);
        }
        None
    }

    fn sign_em(&self, em: &[u8]) -> Option<Vec<u8>> {
        let s = self.apply(&Uint::from_be(em))?;
        Some(s.to_be(self.public.size()))
    }

    pub fn sign_pkcs1(&self, h: Hash, msg: &[u8]) -> Option<Vec<u8>> {
        let k = self.public.size();
        let prefix = digest_info_prefix(h);
        let digest = h.digest(msg);
        let t_len = prefix.len() + digest.len();
        if k < t_len + 11 {
            return None;
        }
        let mut em = vec![0x00, 0x01];
        em.extend(std::iter::repeat_n(0xff, k - t_len - 3));
        em.push(0x00);
        em.extend_from_slice(prefix);
        em.extend_from_slice(&digest);
        self.sign_em(&em)
    }

    pub fn sign_pss(&self, h: Hash, msg: &[u8]) -> Option<Vec<u8>> {
        let em_bits = self.public.modulus_bits() - 1;
        let em_len = em_bits.div_ceil(8);
        let (hl, sl) = (h.len(), h.len());
        if em_len < hl + sl + 2 {
            return None;
        }
        let salt = random_bytes::<64>()[..sl].to_vec();
        let mut m_prime = vec![0u8; 8];
        m_prime.extend_from_slice(&h.digest(msg));
        m_prime.extend_from_slice(&salt);
        let hash = h.digest(&m_prime);
        let mut db = vec![0u8; em_len - hl - sl - 2];
        db.push(0x01);
        db.extend_from_slice(&salt);
        let mask = mgf1(h, &hash, db.len());
        let mut masked: Vec<u8> = db.iter().zip(&mask).map(|(a, b)| a ^ b).collect();
        let top_clear = 8 * em_len - em_bits;
        if top_clear > 0 {
            masked[0] &= 0xff >> top_clear;
        }
        let mut em = masked;
        em.extend_from_slice(&hash);
        em.push(0xbc);
        self.sign_em(&em)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_signs_and_verifies_both_paddings() {
        let key = RsaPrivate::generate(1024);
        assert_eq!(key.public.modulus_bits(), 1024);
        assert_eq!(key.public.e, Uint::from_u64(65537));
        // d·e ≡ 1 (mod p−1) e (mod q−1): m^(de) = m
        let m = Uint::from_u64(0x1234_5678_9abc);
        let s = Mont::new(&key.public.n).mod_pow(&m, &key.d);
        assert_eq!(Mont::new(&key.public.n).mod_pow(&s, &key.public.e), m);
        // PSS com sal = resumo: SHA-512 não cabe em 1024 bits (em_len < 2·64 + 2)
        assert!(key.sign_pss(Hash::Sha512, b"msg").is_none());
        for h in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
            if h == Hash::Sha512 {
                continue;
            }
            let sig = key.sign_pss(h, b"msg").unwrap();
            assert!(key.public.verify_pss(h, b"msg", &sig));
            assert!(!key.public.verify_pss(h, b"outra", &sig));
        }
        for h in [Hash::Sha256, Hash::Sha384, Hash::Sha512] {
            let sig = key.sign_pkcs1(h, b"msg").unwrap();
            assert!(key.public.verify_pkcs1(h, b"msg", &sig));
            // PKCS#1 v1.5 é determinística: o blinding não muda o resultado
            assert_eq!(sig, key.sign_pkcs1(h, b"msg").unwrap());
        }
        assert!(probably_prime(&key.p, 8) && probably_prime(&key.q, 8));
        assert!(!probably_prime(&key.public.n, 8));
    }

    #[test]
    fn mgf1_has_requested_length() {
        assert_eq!(mgf1(Hash::Sha256, b"seed", 70).len(), 70);
        assert_ne!(mgf1(Hash::Sha256, b"a", 32), mgf1(Hash::Sha256, b"b", 32));
    }
}
