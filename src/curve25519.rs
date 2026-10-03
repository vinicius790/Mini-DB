#![allow(
    clippy::needless_range_loop,
    clippy::should_implement_trait,
    clippy::many_single_char_names
)]
//! Curva 25519: X25519 (troca de chaves, RFC 7748), Ed25519 (assinaturas,
//! RFC 8032) e SHA-512. Aritmética em GF(2^255 − 19) com 5 limbos de 51 bits
//! (u128 nos produtos); sem tabelas dependentes de segredo nos caminhos
//! críticos de escalar (escada de Montgomery e duplicação-e-soma em tempo
//! constante por swap condicional).

// ---------------------------------------------------------------------------
// SHA-512
// ---------------------------------------------------------------------------

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

pub fn sha512(data: &[u8]) -> [u8; 64] {
    sha512_core(
        [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ],
        data,
    )
}

/// SHA-384: SHA-512 com outros valores iniciais, truncado a 48 bytes.
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let full = sha512_core(
        [
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4,
        ],
        data,
    );
    full[..48].try_into().expect("48")
}

fn sha512_core(mut h: [u64; 8], data: &[u8]) -> [u8; 64] {
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u128) * 8;
    msg.push(0x80);
    while msg.len() % 128 != 112 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks(128) {
        let mut w = [0u64; 80];
        for (i, c) in block.chunks(8).enumerate() {
            w[i] = u64::from_be_bytes(c.try_into().expect("8"));
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..80 {
            let s1 = v[4].rotate_right(14) ^ v[4].rotate_right(18) ^ v[4].rotate_right(41);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(28) ^ v[0].rotate_right(34) ^ v[0].rotate_right(39);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out = [0u8; 64];
    for (i, x) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&x.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Corpo GF(2^255 - 19)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Fe([u64; 5]);

const MASK51: u64 = (1 << 51) - 1;

impl Fe {
    pub const ZERO: Fe = Fe([0; 5]);
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    pub fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().expect("8"));
        Fe([
            load(0) & MASK51,
            (load(6) >> 3) & MASK51,
            (load(12) >> 6) & MASK51,
            (load(19) >> 1) & MASK51,
            (load(24) >> 12) & MASK51,
        ])
    }

    /// Bytes canônicos (reduzidos mod p).
    pub fn to_bytes(self) -> [u8; 32] {
        let mut l = self.reduce().0;
        // Redução final: soma 19 e testa o carry para decidir se >= p.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        let mut c = l[0] >> 51;
        l[0] &= MASK51;
        for i in 1..5 {
            l[i] += c;
            c = l[i] >> 51;
            l[i] &= MASK51;
        }
        let mut out = [0u8; 32];
        let v: u128 = l[0] as u128 | (l[1] as u128) << 51 | (l[2] as u128) << 102;
        out[..16].copy_from_slice(&v.to_le_bytes());
        let hi: u128 = ((l[2] as u128) >> 26) | (l[3] as u128) << 25 | (l[4] as u128) << 76;
        out[16..].copy_from_slice(&hi.to_le_bytes());
        out
    }

    fn reduce(self) -> Fe {
        let mut l = self.0;
        let mut c = l[0] >> 51;
        l[0] &= MASK51;
        for i in 1..5 {
            l[i] += c;
            c = l[i] >> 51;
            l[i] &= MASK51;
        }
        l[0] += c * 19;
        c = l[0] >> 51;
        l[0] &= MASK51;
        l[1] += c;
        Fe(l)
    }

    pub fn add(self, o: Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + o.0[i];
        }
        Fe(r).reduce()
    }

    pub fn sub(self, o: Fe) -> Fe {
        // self + 2p - o (evita underflow; 2p em limbos de 51 bits).
        let mut r = [0u64; 5];
        r[0] = self.0[0] + 0xFFFFFFFFFFFDA - o.0[0];
        for i in 1..5 {
            r[i] = self.0[i] + 0xFFFFFFFFFFFFE - o.0[i];
        }
        Fe(r).reduce()
    }

    pub fn mul(self, o: Fe) -> Fe {
        let a = self.0;
        let b = o.0;
        let m = |x: u64, y: u64| x as u128 * y as u128;
        let b19: [u64; 5] = [b[0], b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];
        let r0 =
            m(a[0], b[0]) + m(a[1], b19[4]) + m(a[2], b19[3]) + m(a[3], b19[2]) + m(a[4], b19[1]);
        let r1 =
            m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b19[4]) + m(a[3], b19[3]) + m(a[4], b19[2]);
        let r2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b19[4]) + m(a[4], b19[3]);
        let r3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b19[4]);
        let r4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
        Self::carry([r0, r1, r2, r3, r4])
    }

    fn carry(r: [u128; 5]) -> Fe {
        let mut l = [0u64; 5];
        let mut c: u128 = 0;
        for i in 0..5 {
            let v = r[i] + c;
            l[i] = (v as u64) & MASK51;
            c = v >> 51;
        }
        l[0] += (c as u64) * 19;
        let c2 = l[0] >> 51;
        l[0] &= MASK51;
        l[1] += c2;
        Fe(l)
    }

    pub fn square(self) -> Fe {
        self.mul(self)
    }

    pub fn mul_small(self, k: u64) -> Fe {
        let mut r = [0u128; 5];
        for i in 0..5 {
            r[i] = self.0[i] as u128 * k as u128;
        }
        Self::carry(r)
    }

    pub fn invert(self) -> Fe {
        // a^(p-2), p-2 = 2^255 - 21
        let mut r = Fe::ONE;
        let mut base = self;
        let exp: [u8; 32] = {
            let mut e = [0xFFu8; 32];
            e[0] = 0xEB;
            e[31] = 0x7F;
            e
        };
        for i in 0..255 {
            if (exp[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.mul(base);
            }
            base = base.square();
        }
        r
    }

    pub fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    pub fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// Raiz quadrada de `u/v` (RFC 8032 §5.1.3); `None` se não existe.
    pub fn sqrt_ratio(u: Fe, v: Fe) -> Option<Fe> {
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        // x = (u*v^3) * (u*v^7)^((p-5)/8)
        let mut pow = u.mul(v7);
        // (p-5)/8 = 2^252 - 3
        let base = pow;
        let mut r = Fe::ONE;
        let exp: [u8; 32] = {
            let mut e = [0xFFu8; 32];
            e[0] = 0xFD;
            e[31] = 0x0F;
            e
        };
        pow = base;
        for i in 0..252 {
            if (exp[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.mul(pow);
            }
            pow = pow.square();
        }
        let mut x = u.mul(v3).mul(r);
        let check = v.mul(x.square());
        if check.to_bytes() == u.to_bytes() {
            return Some(x);
        }
        if check.to_bytes() == u.neg().to_bytes() {
            x = x.mul(SQRT_M1);
            return Some(x);
        }
        None
    }
}

/// sqrt(-1) mod p.
const SQRT_M1: Fe = Fe([
    0x00061b274a0ea0b0,
    0x0000d5a5fc8f189d,
    0x0007ef5e9cbd0c60,
    0x00078595a6804c9e,
    0x0002b8324804fc1d,
]);

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

fn clamp(k: &[u8; 32]) -> [u8; 32] {
    let mut s = *k;
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    s
}

/// Multiplicação escalar na curva de Montgomery (escada, tempo constante).
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let k = clamp(scalar);
    let mut u_bytes = *point;
    u_bytes[31] &= 127;
    let x1 = Fe::from_bytes(&u_bytes);
    let (mut x2, mut z2) = (Fe::ONE, Fe::ZERO);
    let (mut x3, mut z3) = (x1, Fe::ONE);
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= kt;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = kt;
        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.mul_small(121_665)));
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    x2.mul(z2.invert()).to_bytes()
}

pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(scalar, &base)
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

/// Ponto em coordenadas estendidas (X, Y, Z, T) com x = X/Z, y = Y/Z, T = XY/Z.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

// d = -121665/121666
const D: Fe = Fe([
    0x00034dca135978a3,
    0x0001a8283b156ebd,
    0x0005e7a26001c029,
    0x000739c663a03cbb,
    0x00052036cee2b6ff,
]);

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    fn base() -> Point {
        let y = Fe::from_bytes(&[
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ]);
        let x = Fe::from_bytes(&[
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7,
            0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd,
            0xd3, 0x36, 0x69, 0x21,
        ]);
        Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        }
    }

    /// Soma unificada (fórmulas completas para curvas de Edwards torcidas, a = -1).
    fn add(&self, o: &Point) -> Point {
        let a = self.y.sub(self.x).mul(o.y.sub(o.x));
        let b = self.y.add(self.x).mul(o.y.add(o.x));
        let c = self.t.mul(o.t).mul(D).mul_small(2);
        let d = self.z.mul(o.z).mul_small(2);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    fn double(&self) -> Point {
        self.add(self)
    }

    fn cswap(a: &mut Point, b: &mut Point, swap: u64) {
        Fe::cswap(&mut a.x, &mut b.x, swap);
        Fe::cswap(&mut a.y, &mut b.y, swap);
        Fe::cswap(&mut a.z, &mut b.z, swap);
        Fe::cswap(&mut a.t, &mut b.t, swap);
    }

    /// k·P por duplicação-e-soma com swap condicional (tempo constante).
    fn mul(&self, k: &[u8; 32]) -> Point {
        let mut r0 = Point::IDENTITY;
        let mut r1 = *self;
        for i in (0..256).rev() {
            let bit = ((k[i / 8] >> (i % 8)) & 1) as u64;
            Point::cswap(&mut r0, &mut r1, bit);
            r1 = r0.add(&r1);
            r0 = r0.double();
            Point::cswap(&mut r0, &mut r1, bit);
        }
        r0
    }

    fn compress(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(zi);
        let y = self.y.mul(zi);
        let mut out = y.to_bytes();
        out[31] |= (x.is_negative() as u8) << 7;
        out
    }

    fn decompress(b: &[u8; 32]) -> Option<Point> {
        let mut yb = *b;
        let sign = yb[31] >> 7;
        yb[31] &= 0x7f;
        let y = Fe::from_bytes(&yb);
        let y2 = y.square();
        let u = y2.sub(Fe::ONE);
        let v = D.mul(y2).add(Fe::ONE);
        let mut x = Fe::sqrt_ratio(u, v)?;
        if x.is_negative() as u8 != sign {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }
}

/// Ordem do grupo, L = 2^252 + 27742317777372353535851937790883648493.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Inteiro de até 512 bits em limbos u64 little-endian.
fn to_limbs(b: &[u8]) -> [u64; 8] {
    let mut l = [0u64; 8];
    for (i, chunk) in b.chunks(8).enumerate().take(8) {
        let mut w = [0u8; 8];
        w[..chunk.len()].copy_from_slice(chunk);
        l[i] = u64::from_le_bytes(w);
    }
    l
}

fn limbs_ge(a: &[u64; 8], b: &[u64; 8]) -> bool {
    for i in (0..8).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// `a -= b`; devolve 1 se houve empréstimo (a < b), sem desvios.
fn limbs_sub(a: &mut [u64; 8], b: &[u64; 8]) -> u64 {
    let mut borrow = 0u64;
    for i in 0..8 {
        let (r1, o1) = a[i].overflowing_sub(b[i]);
        let (r2, o2) = r1.overflowing_sub(borrow);
        a[i] = r2;
        borrow = (o1 | o2) as u64;
    }
    borrow
}

fn limbs_shl1(a: &mut [u64; 8]) {
    let mut carry = 0u64;
    for x in a.iter_mut() {
        let next = *x >> 63;
        *x = (*x << 1) | carry;
        carry = next;
    }
}

/// x mod L (x de até 512 bits), por divisão longa binária.
fn mod_l(x: &[u8]) -> [u8; 32] {
    let n = to_limbs(x);
    let l = to_limbs(&L);
    let mut r = [0u64; 8];
    for bit in (0..512).rev() {
        limbs_shl1(&mut r);
        r[0] |= (n[bit / 64] >> (bit % 64)) & 1;
        // Subtração condicional por máscara: o segredo não decide nenhum desvio.
        let mut t = r;
        let borrow = limbs_sub(&mut t, &l);
        let keep_t = 0u64.wrapping_sub(borrow ^ 1);
        for i in 0..8 {
            r[i] = (t[i] & keep_t) | (r[i] & !keep_t);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&r[i].to_le_bytes());
    }
    out
}

/// (a·b + c) mod L, com a, b, c de 32 bytes.
fn muladd_l(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let (al, bl, cl) = (to_limbs(a), to_limbs(b), to_limbs(c));
    // Produto em colunas com propagação de carry a cada linha (sem estouro de u128).
    let mut prod = [0u64; 9];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let v = prod[i + j] as u128 + al[i] as u128 * bl[j] as u128 + carry;
            prod[i + j] = v as u64;
            carry = v >> 64;
        }
        // `prod[i + 4]` ainda é zero nesta linha: o carry cabe nele sem laço.
        prod[i + 4] = carry as u64;
    }
    let mut carry: u128 = 0;
    for i in 0..9 {
        let v = prod[i] as u128 + if i < 4 { cl[i] as u128 } else { 0 } + carry;
        prod[i] = v as u64;
        carry = v >> 64;
    }
    let mut bytes = [0u8; 72];
    for i in 0..9 {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&prod[i].to_le_bytes());
    }
    mod_l(&bytes[..64])
}

pub struct Ed25519Key {
    seed: [u8; 32],
    pub public: [u8; 32],
}

impl Ed25519Key {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let h = sha512(&seed);
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        let s = clamp(&s);
        let public = Point::base().mul(&s).compress();
        Self { seed, public }
    }

    pub fn generate() -> Self {
        Self::from_seed(crate::crypto::random_bytes::<32>())
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let h = sha512(&self.seed);
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        let s = clamp(&s);
        let prefix = &h[32..];
        let mut r_in = prefix.to_vec();
        r_in.extend_from_slice(msg);
        let r = mod_l(&sha512(&r_in));
        let rb = Point::base().mul(&r).compress();
        let mut k_in = rb.to_vec();
        k_in.extend_from_slice(&self.public);
        k_in.extend_from_slice(msg);
        let k = mod_l(&sha512(&k_in));
        let sig_s = muladd_l(&k, &s, &r);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&rb);
        sig[32..].copy_from_slice(&sig_s);
        sig
    }
}

/// Verificação (testes e clientes): S·B == R + k·A.
pub fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Some(a) = Point::decompress(public) else {
        return false;
    };
    let mut rb = [0u8; 32];
    rb.copy_from_slice(&sig[..32]);
    let Some(r) = Point::decompress(&rb) else {
        return false;
    };
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    if limbs_ge(&to_limbs(&s), &to_limbs(&L)) {
        return false;
    }
    let mut k_in = rb.to_vec();
    k_in.extend_from_slice(public);
    k_in.extend_from_slice(msg);
    let k = mod_l(&sha512(&k_in));
    let left = Point::base().mul(&s).compress();
    let right = r.add(&a.mul(&k)).compress();
    left == right
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{from_hex, to_hex};

    #[test]
    fn sha384_vectors() {
        assert_eq!(
            to_hex(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn sha512_vectors() {
        assert_eq!(
            to_hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            to_hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn x25519_rfc7748_vectors() {
        let a: [u8; 32] =
            from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let b: [u8; 32] =
            from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .unwrap()
                .try_into()
                .unwrap();
        let a_pub = x25519_base(&a);
        let b_pub = x25519_base(&b);
        assert_eq!(
            to_hex(&a_pub),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            to_hex(&b_pub),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );
        let shared = x25519(&a, &b_pub);
        assert_eq!(
            to_hex(&shared),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
        assert_eq!(shared, x25519(&b, &a_pub));
    }

    #[test]
    fn ed25519_rfc8032_vectors() {
        let seed: [u8; 32] =
            from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let key = Ed25519Key::from_seed(seed);
        assert_eq!(
            to_hex(&key.public),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = key.sign(b"");
        assert_eq!(to_hex(&sig), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        assert!(ed25519_verify(&key.public, b"", &sig));
        let seed2: [u8; 32] =
            from_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .unwrap()
                .try_into()
                .unwrap();
        let key2 = Ed25519Key::from_seed(seed2);
        assert_eq!(
            to_hex(&key2.public),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );
        let sig2 = key2.sign(&[0x72]);
        assert_eq!(to_hex(&sig2), "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        assert!(ed25519_verify(&key2.public, &[0x72], &sig2));
        assert!(!ed25519_verify(&key2.public, &[0x73], &sig2));
        let long = from_hex("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0").unwrap();
        let seed3: [u8; 32] =
            from_hex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5")
                .unwrap()
                .try_into()
                .unwrap();
        let key3 = Ed25519Key::from_seed(seed3);
        assert_eq!(
            to_hex(&key3.public),
            "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
        );
        assert_eq!(to_hex(&key3.sign(&long)), "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");
    }
}
