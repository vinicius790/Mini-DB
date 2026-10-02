//! Primitivas criptográficas sem dependências: SHA-256 (FIPS 180-4),
//! HMAC-SHA256 (RFC 2104), ChaCha20 (RFC 8439), AES-128-GCM (SP 800-38D),
//! comparação em tempo constante e bytes aleatórios do sistema.
//!
//! Usadas para autenticar e cifrar o canal de replicação com chave
//! pré-compartilhada e para o hash do índice por valor. Todas têm testes com
//! os vetores oficiais das especificações.

use std::io::Read;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 incremental.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            buf_len: 0,
            total: 0,
        }
    }

    fn compress(&mut self, block: &[u8]) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            self.compress(block);
        }
        let rest = blocks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len += rest.len();
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

/// HMAC-SHA256 sobre a concatenação de `parts`.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(&block.map(|b| b ^ 0x36));
    for part in parts {
        inner.update(part);
    }
    let mut outer = Sha256::new();
    outer.update(&block.map(|b| b ^ 0x5c));
    outer.update(&inner.finish());
    outer.finish()
}

/// PBKDF2-HMAC-SHA256 com saída de 32 bytes (SCRAM, chave de criptografia).
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut u = hmac_sha256(password, &[salt, &1u32.to_be_bytes()]);
    let mut out = u;
    for _ in 1..iterations.max(1) {
        u = hmac_sha256(password, &[&u]);
        for (o, x) in out.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.iter().fold(0u32, |acc, b| (acc << 8) | *b as u32) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Igualdade que não vaza, pelo tempo, em que byte as entradas diferem.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    for i in 0..8 {
        init[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("4"));
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().expect("4"));
    }
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

/// Cifra/decifra `data` no lugar com ChaCha20 (a operação é a mesma).
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let stream = chacha20_block(key, counter.wrapping_add(i as u32), nonce);
        for (b, k) in chunk.iter_mut().zip(stream) {
            *b ^= k;
        }
    }
}

/// Bytes aleatórios do sistema: `BCryptGenRandom` no Windows, `/dev/urandom`
/// nos demais; só se ambos falharem, o gerador com semente aleatória do próprio
/// processo (`RandomState`).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                algorithm: *mut core::ffi::c_void,
                buffer: *mut u8,
                count: u32,
                flags: u32,
            ) -> i32;
        }
        // 2 = BCRYPT_USE_SYSTEM_PREFERRED_RNG (CSPRNG do sistema, sem handle).
        // SAFETY: `out` é um buffer válido de `N` bytes durante a chamada.
        let status =
            unsafe { BCryptGenRandom(std::ptr::null_mut(), out.as_mut_ptr(), N as u32, 2) };
        if status >= 0 {
            return out;
        }
    }
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut out))
        .is_ok()
    {
        return out;
    }
    use std::hash::{BuildHasher, Hasher};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let mut seed = Sha256::new();
    for i in 0..4u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(i);
        h.write_u128(nanos);
        seed.update(&h.finish().to_le_bytes());
    }
    seed.update(&std::process::id().to_le_bytes());
    let mut state = seed.finish();
    for chunk in out.chunks_mut(32) {
        state = sha256(&state);
        chunk.copy_from_slice(&state[..chunk.len()]);
    }
    out
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_fips_vectors() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            to_hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let mut h = Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            to_hex(&h.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn hmac_matches_rfc4231() {
        assert_eq!(
            to_hex(&hmac_sha256(&[0x0b; 20], &[b"Hi There"])),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            to_hex(&hmac_sha256(
                b"Jefe",
                &[b"what do ya want ", b"for nothing?"]
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            to_hex(&hmac_sha256(
                &[0xaa; 131],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn chacha20_matches_rfc8439() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut text = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        chacha20_xor(&key, &nonce, 1, &mut text);
        assert_eq!(
            to_hex(&text),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d"
        );
        chacha20_xor(&key, &nonce, 1, &mut text);
        assert!(text.starts_with(b"Ladies and Gentlemen"));
        assert!(constant_time_eq(b"abc", b"abc") && !constant_time_eq(b"abc", b"abd"));
        assert_ne!(random_bytes::<16>(), random_bytes::<16>());
        assert_eq!(from_hex(&to_hex(&[0, 255, 16])).unwrap(), vec![0, 255, 16]);
    }
}

// ---------------------------------------------------------------------------
// Poly1305, ChaCha20-Poly1305 (RFC 8439) e HKDF (RFC 5869)
// ---------------------------------------------------------------------------

/// Etiqueta Poly1305 de `msg` com a chave de 32 bytes (r ‖ s).
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // Limbos de 26 bits (poly1305-donna-32).
    let le32 = |b: &[u8]| u32::from_le_bytes(b.try_into().expect("4"));
    let r0 = le32(&key[0..4]) & 0x3ffffff;
    let r1 = (le32(&key[3..7]) >> 2) & 0x3ffff03;
    let r2 = (le32(&key[6..10]) >> 4) & 0x3ffc0ff;
    let r3 = (le32(&key[9..13]) >> 6) & 0x3f03fff;
    let r4 = (le32(&key[12..16]) >> 8) & 0x00fffff;
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);
    let mut pos = 0;
    while pos < msg.len() {
        let mut block = [0u8; 17];
        let n = (msg.len() - pos).min(16);
        block[..n].copy_from_slice(&msg[pos..pos + n]);
        block[n] = 1;
        let hibit = if n == 16 { 1u32 << 24 } else { 0 };
        let t0 = le32(&block[0..4]);
        let t1 = le32(&block[4..8]);
        let t2 = le32(&block[8..12]);
        let t3 = le32(&block[12..16]);
        h0 += t0 & 0x3ffffff;
        h1 += ((((t1 as u64) << 32) | t0 as u64) >> 26) as u32 & 0x3ffffff;
        h2 += ((((t2 as u64) << 32) | t1 as u64) >> 20) as u32 & 0x3ffffff;
        h3 += ((((t3 as u64) << 32) | t2 as u64) >> 14) as u32 & 0x3ffffff;
        h4 += (t3 >> 8) | hibit | if n == 16 { 0 } else { (block[16] as u32) << 24 };
        let m = |a: u32, b: u32| a as u64 * b as u64;
        let d0 = m(h0, r0) + m(h1, s4) + m(h2, s3) + m(h3, s2) + m(h4, s1);
        let mut d1 = m(h0, r1) + m(h1, r0) + m(h2, s4) + m(h3, s3) + m(h4, s2);
        let mut d2 = m(h0, r2) + m(h1, r1) + m(h2, r0) + m(h3, s4) + m(h4, s3);
        let mut d3 = m(h0, r3) + m(h1, r2) + m(h2, r1) + m(h3, r0) + m(h4, s4);
        let mut d4 = m(h0, r4) + m(h1, r3) + m(h2, r2) + m(h3, r1) + m(h4, r0);
        let mut c = (d0 >> 26) as u32;
        h0 = d0 as u32 & 0x3ffffff;
        d1 += c as u64;
        c = (d1 >> 26) as u32;
        h1 = d1 as u32 & 0x3ffffff;
        d2 += c as u64;
        c = (d2 >> 26) as u32;
        h2 = d2 as u32 & 0x3ffffff;
        d3 += c as u64;
        c = (d3 >> 26) as u32;
        h3 = d3 as u32 & 0x3ffffff;
        d4 += c as u64;
        c = (d4 >> 26) as u32;
        h4 = d4 as u32 & 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;
        pos += n;
    }
    let mut c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;
    // h + -p
    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
    let mask = (g4 >> 31).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    let g4 = g4 & mask;
    let mask = !mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;
    let hh0 = (h0 | (h1 << 26)) as u64;
    let hh1 = ((h1 >> 6) | (h2 << 20)) as u64;
    let hh2 = ((h2 >> 12) | (h3 << 14)) as u64;
    let hh3 = ((h3 >> 18) | (h4 << 8)) as u64;
    let mut f = hh0 + le32(&key[16..20]) as u64;
    let o0 = f as u32;
    f = hh1 + le32(&key[20..24]) as u64 + (f >> 32);
    let o1 = f as u32;
    f = hh2 + le32(&key[24..28]) as u64 + (f >> 32);
    let o2 = f as u32;
    f = hh3 + le32(&key[28..32]) as u64 + (f >> 32);
    let o3 = f as u32;
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&o0.to_le_bytes());
    out[4..8].copy_from_slice(&o1.to_le_bytes());
    out[8..12].copy_from_slice(&o2.to_le_bytes());
    out[12..16].copy_from_slice(&o3.to_le_bytes());
    out
}

fn aead_tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut otk = [0u8; 32];
    chacha20_xor(key, nonce, 0, &mut otk); // bloco 0 zerado → chave one-time
    let mut mac = Vec::with_capacity(aad.len() + ct.len() + 32);
    mac.extend_from_slice(aad);
    mac.resize(mac.len().div_ceil(16) * 16, 0);
    mac.extend_from_slice(ct);
    mac.resize(mac.len().div_ceil(16) * 16, 0);
    mac.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    poly1305(&otk, &mac)
}

/// Etiqueta (16 bytes) do AEAD sobre um texto cifrado já produzido com
/// `chacha20_xor(.., contador 1, ..)`. Para quem guarda a etiqueta à parte,
/// truncada (páginas de `data.mdb`).
pub fn aead_tag_of(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    aead_tag(key, nonce, aad, ct)
}

/// AEAD ChaCha20-Poly1305: devolve texto cifrado ‖ etiqueta (16 bytes).
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut out = plain.to_vec();
    chacha20_xor(key, nonce, 1, &mut out);
    let tag = aead_tag(key, nonce, aad, &out);
    out.extend_from_slice(&tag);
    out
}

/// Abre um texto cifrado com etiqueta; `None` se a etiqueta não confere.
pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 16 {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    if !constant_time_eq(&aead_tag(key, nonce, aad, ct), tag) {
        return None;
    }
    let mut out = ct.to_vec();
    chacha20_xor(key, nonce, 1, &mut out);
    Some(out)
}

// ---------------------------------------------------------------------------
// AES-128 (FIPS 197) e AES-128-GCM (NIST SP 800-38D)
// ---------------------------------------------------------------------------

/// Multiplica por x em GF(2^8) (polinômio x^8 + x^4 + x^3 + x + 1), sem desvios.
const fn xtime(x: u8) -> u8 {
    (x << 1) ^ (0x1b & (x >> 7).wrapping_neg())
}

/// S-box do AES calculada em tempo de compilação: inverso multiplicativo
/// (por log/exp do gerador 3) seguido da transformação afim da FIPS 197 §5.1.1.
const fn make_sbox() -> [u8; 256] {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x = 1u8;
    let mut i = 0;
    while i < 255 {
        exp[i] = x;
        log[x as usize] = i as u8;
        x ^= xtime(x); // multiplica por 3
        i += 1;
    }
    let mut sbox = [0u8; 256];
    let mut v = 0;
    while v < 256 {
        let inv = if v == 0 {
            0
        } else {
            exp[(255 - log[v] as usize) % 255]
        };
        let mut s = inv;
        let mut r = 1;
        while r <= 4 {
            s ^= inv.rotate_left(r);
            r += 1;
        }
        sbox[v] = s ^ 0x63;
        v += 1;
    }
    sbox
}

// ponytail: a consulta `SBOX[byte]` indexa a memória por um valor secreto, então
// o AES por tabela pode vazar a chave por temporização de cache em quem
// compartilha o processador; é só 256 bytes (cabem em poucas linhas de cache),
// mas não é tempo constante estrito. Subir o limite exigiria AES-NI
// (`std::arch`, via `unsafe`) ou uma S-box bit-sliced.
static SBOX: [u8; 256] = make_sbox();

/// AES-128 só para encriptar (o GCM usa a cifra apenas nesse sentido).
struct Aes128 {
    round_keys: [[u8; 16]; 11],
}

fn xor_block(s: &mut [u8; 16], k: &[u8; 16]) {
    for (a, b) in s.iter_mut().zip(k) {
        *a ^= b;
    }
}

/// SubBytes seguido de ShiftRows (o estado é em colunas: índice = 4·coluna + linha).
fn sub_shift(s: &mut [u8; 16]) {
    let t = *s;
    *s = std::array::from_fn(|i| SBOX[t[4 * ((i / 4 + i % 4) % 4) + i % 4] as usize]);
}

fn mix_columns(s: &mut [u8; 16]) {
    for col in s.chunks_exact_mut(4) {
        let a = [col[0], col[1], col[2], col[3]];
        let all = a[0] ^ a[1] ^ a[2] ^ a[3];
        for (i, b) in col.iter_mut().enumerate() {
            *b = a[i] ^ all ^ xtime(a[i] ^ a[(i + 1) % 4]);
        }
    }
}

impl Aes128 {
    fn new(key: &[u8; 16]) -> Aes128 {
        let mut w = [[0u8; 4]; 44];
        for (word, k) in w.iter_mut().zip(key.chunks_exact(4)) {
            word.copy_from_slice(k);
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = w[i - 1];
            if i & 3 == 0 {
                t = [
                    SBOX[t[1] as usize] ^ rcon,
                    SBOX[t[2] as usize],
                    SBOX[t[3] as usize],
                    SBOX[t[0] as usize],
                ];
                rcon = xtime(rcon);
            }
            let prev = w[i - 4];
            w[i] = std::array::from_fn(|j| prev[j] ^ t[j]);
        }
        let mut round_keys = [[0u8; 16]; 11];
        for (rk, words) in round_keys.iter_mut().zip(w.chunks_exact(4)) {
            for (dst, word) in rk.chunks_exact_mut(4).zip(words) {
                dst.copy_from_slice(word);
            }
        }
        Aes128 { round_keys }
    }

    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        xor_block(&mut s, &self.round_keys[0]);
        for rk in &self.round_keys[1..10] {
            sub_shift(&mut s);
            mix_columns(&mut s);
            xor_block(&mut s, rk);
        }
        sub_shift(&mut s);
        xor_block(&mut s, &self.round_keys[10]);
        s
    }
}

/// Polinômio de redução do GHASH (x^128 + x^7 + x^2 + x + 1) no bit mais alto.
const GCM_R: u128 = 0xe1 << 120;

/// Multiplicação em GF(2^128) do GCM (SP 800-38D §6.3), bit a bit e com
/// máscaras em vez de desvios: tempo e acessos independentes dos operandos.
fn gf_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        z ^= v & ((x >> (127 - i)) & 1).wrapping_neg();
        v = (v >> 1) ^ (GCM_R & (v & 1).wrapping_neg());
    }
    z
}

fn ghash_update(y: &mut u128, h: u128, data: &[u8]) {
    for chunk in data.chunks(16) {
        let mut b = [0u8; 16];
        b[..chunk.len()].copy_from_slice(chunk);
        *y = gf_mul(*y ^ u128::from_be_bytes(b), h);
    }
}

/// Cifra/decifra `data` com AES-CTR, começando em inc32(J0) (SP 800-38D §6.5).
fn gcm_ctr(aes: &Aes128, j0: &[u8; 16], data: &mut [u8]) {
    let mut ctr = *j0;
    for chunk in data.chunks_mut(16) {
        let n = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]).wrapping_add(1);
        ctr[12..].copy_from_slice(&n.to_be_bytes());
        let stream = aes.encrypt_block(&ctr);
        for (b, k) in chunk.iter_mut().zip(stream) {
            *b ^= k;
        }
    }
}

/// Cifra, subchave H do GHASH e bloco J0 (IV de 12 bytes ‖ contador 1).
fn gcm_init(key: &[u8; 16], nonce: &[u8; 12]) -> (Aes128, u128, [u8; 16]) {
    let aes = Aes128::new(key);
    let h = u128::from_be_bytes(aes.encrypt_block(&[0u8; 16]));
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    (aes, h, j0)
}

fn gcm_tag(aes: &Aes128, h: u128, j0: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut y = 0u128;
    ghash_update(&mut y, h, aad);
    ghash_update(&mut y, h, ct);
    let lengths = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
    y = gf_mul(y ^ lengths, h);
    (y ^ u128::from_be_bytes(aes.encrypt_block(j0))).to_be_bytes()
}

/// AEAD AES-128-GCM com nonce de 12 bytes: devolve texto cifrado ‖ etiqueta (16 bytes).
pub fn aes128_gcm_seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let (aes, h, j0) = gcm_init(key, nonce);
    let mut out = plain.to_vec();
    gcm_ctr(&aes, &j0, &mut out);
    let tag = gcm_tag(&aes, h, &j0, aad, &out);
    out.extend_from_slice(&tag);
    out
}

/// Abre um texto cifrado com etiqueta; `None` se a etiqueta não confere (a
/// comparação é em tempo constante e o texto só é decifrado depois dela).
pub fn aes128_gcm_open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    sealed: &[u8],
) -> Option<Vec<u8>> {
    if sealed.len() < 16 {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let (aes, h, j0) = gcm_init(key, nonce);
    if !constant_time_eq(&gcm_tag(&aes, h, &j0, aad, ct), tag) {
        return None;
    }
    let mut out = ct.to_vec();
    gcm_ctr(&aes, &j0, &mut out);
    Some(out)
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, &[ikm])
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let t = hmac_sha256(prk, &[&prev, info, &[counter]]);
        out.extend_from_slice(&t);
        prev = t.to_vec();
        counter += 1;
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod aead_tests {
    use super::*;

    #[test]
    fn rfc8439_vectors() {
        // Poly1305 §2.5.2
        let key: [u8; 32] =
            from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .unwrap()
                .try_into()
                .unwrap();
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(to_hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
        // AEAD §2.8.2
        let k: [u8; 32] =
            from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = from_hex("070000004041424344454647")
            .unwrap()
            .try_into()
            .unwrap();
        let aad = from_hex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plain = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = aead_seal(&k, &nonce, &aad, plain);
        assert_eq!(
            to_hex(&sealed[sealed.len() - 16..]),
            "1ae10b594f09e26a7e902ecbd0600691"
        );
        assert_eq!(to_hex(&sealed[..8]), "d31a8d34648e60db");
        assert_eq!(aead_open(&k, &nonce, &aad, &sealed).unwrap(), plain);
        let mut bad = sealed.clone();
        bad[3] ^= 1;
        assert!(aead_open(&k, &nonce, &aad, &bad).is_none());
        // HKDF RFC 5869 caso 1
        let prk = hkdf_extract(
            &from_hex("000102030405060708090a0b0c").unwrap(),
            &[0x0b; 22],
        );
        assert_eq!(
            to_hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let okm = hkdf_expand(&prk, &from_hex("f0f1f2f3f4f5f6f7f8f9").unwrap(), 42);
        assert_eq!(
            to_hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}

#[cfg(test)]
mod aes_gcm_tests {
    use super::*;

    const P3: [&str; 4] = [
        "d9313225f88406e5a55909c5aff5269a",
        "86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525",
        "b16aedf5aa0de657ba637b391aafd255",
    ];
    const C3: [&str; 4] = [
        "42831ec2217774244b7221b784d0d49c",
        "e3aa212f2c02a4e035c17e2329aca12e",
        "21d514b25466931c7d8f6a5aac84aa05",
        "1ba30b396a0aac973d58e091473f5985",
    ];
    const ZERO_KEY: &str = "00000000000000000000000000000000";
    const ZERO_IV: &str = "000000000000000000000000";
    const KEY_TC3: &str = "feffe9928665731c6d6a8f9467308308";
    const IV_TC3: &str = "cafebabefacedbaddecaf888";

    fn hx(s: &str) -> Vec<u8> {
        from_hex(s).unwrap()
    }

    /// Sela e abre com um vetor conhecido; qualquer bit alterado deve falhar.
    fn check(key: &str, iv: &str, aad: &str, plain: &str, cipher: &str, tag: &str) {
        let key: [u8; 16] = hx(key).try_into().unwrap();
        let iv: [u8; 12] = hx(iv).try_into().unwrap();
        let (aad, plain) = (hx(aad), hx(plain));
        let sealed = aes128_gcm_seal(&key, &iv, &aad, &plain);
        let (ct, t) = sealed.split_at(plain.len());
        assert_eq!(to_hex(ct), cipher);
        assert_eq!(to_hex(t), tag);
        assert_eq!(aes128_gcm_open(&key, &iv, &aad, &sealed), Some(plain));
        let flip = |i: usize| {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            bad
        };
        for i in 0..sealed.len() {
            assert!(aes128_gcm_open(&key, &iv, &aad, &flip(i)).is_none());
        }
        if !aad.is_empty() {
            let mut bad = aad.clone();
            bad[0] ^= 1;
            assert!(aes128_gcm_open(&key, &iv, &bad, &sealed).is_none());
        }
    }

    #[test]
    fn aes128_matches_fips197() {
        let key: [u8; 16] = hx("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let block: [u8; 16] = hx("00112233445566778899aabbccddeeff").try_into().unwrap();
        let out = Aes128::new(&key).encrypt_block(&block);
        assert_eq!(to_hex(&out), "69c4e0d86a7b0430d8cdb78070b4c55a");
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x53], 0xed);
    }

    #[test]
    fn gcm_matches_nist_test_cases() {
        // Test Case 1: sem texto e sem AAD.
        check(
            ZERO_KEY,
            ZERO_IV,
            "",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        );
        // Test Case 2: um bloco de zeros.
        check(
            ZERO_KEY,
            ZERO_IV,
            "",
            "00000000000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        );
        // Test Case 3: quatro blocos, sem AAD.
        let (p3, c3) = (P3.concat(), C3.concat());
        check(
            KEY_TC3,
            IV_TC3,
            "",
            &p3,
            &c3,
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        );
        // Test Case 4: 60 bytes (último bloco parcial) com AAD.
        check(
            KEY_TC3,
            IV_TC3,
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            &p3[..120],
            &c3[..120],
            "5bc94fbc3221a5db94fae95ae7121a47",
        );
    }

    #[test]
    fn gcm_roundtrips_every_length_and_rejects_short_input() {
        let key = [7u8; 16];
        let nonce = [9u8; 12];
        for n in 0..70usize {
            let plain: Vec<u8> = (0..n).map(|i| (i * 31) as u8).collect();
            let aad: Vec<u8> = (0..n % 21).map(|i| i as u8).collect();
            let sealed = aes128_gcm_seal(&key, &nonce, &aad, &plain);
            assert_eq!(sealed.len(), n + 16);
            assert_eq!(aes128_gcm_open(&key, &nonce, &aad, &sealed), Some(plain));
        }
        assert!(aes128_gcm_open(&key, &nonce, b"", &[0u8; 15]).is_none());
    }
}

/// Funções de resumo usadas em assinaturas RSA/ECDSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    pub fn is_empty(self) -> bool {
        false
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => sha256(data).to_vec(),
            Hash::Sha384 => crate::curve25519::sha384(data).to_vec(),
            Hash::Sha512 => crate::curve25519::sha512(data).to_vec(),
        }
    }
}
