//! Inteiros grandes sem sinal e aritmética de Montgomery (base de RSA e das
//! curvas NIST P-256/P-384). Sem dependências.
//!
//! `Uint` (tamanho variável) só manipula valores públicos ou operações feitas
//! uma vez (leitura de chaves, geração de primos). Tudo que toca segredo em
//! cada assinatura passa por `Mont`, cujas operações têm tempo constante:
//! multiplicação, soma e subtração sem desvios dependentes dos dados, redução
//! por Horner com número fixo de limbs e exponenciação em janela fixa com
//! seleção de tabela por máscara (`pow_ct`).

use std::cmp::Ordering;

/// Inteiro sem sinal, limbs de 64 bits em ordem little-endian, sem zeros à esquerda.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Uint(Vec<u64>);

impl Uint {
    pub fn zero() -> Self {
        Uint(Vec::new())
    }

    pub fn from_u64(v: u64) -> Self {
        Uint(vec![v]).trim()
    }

    fn trim(mut self) -> Self {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
        self
    }

    pub fn from_be(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(bytes.len() / 8 + 1);
        for chunk in bytes.rchunks(8) {
            let mut v = 0u64;
            for &b in chunk {
                v = (v << 8) | b as u64;
            }
            limbs.push(v);
        }
        Uint(limbs).trim()
    }

    /// Big-endian com exatamente `len` bytes (trunca se não couber).
    pub fn to_be(&self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for i in 0..len {
            let limb = self.0.get(i / 8).copied().unwrap_or(0);
            out[len - 1 - i] = (limb >> ((i % 8) * 8)) as u8;
        }
        out
    }

    pub fn from_hex(hex: &str) -> Self {
        let bytes = crate::crypto::from_hex(hex).expect("hex válido");
        Self::from_be(&bytes)
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_odd(&self) -> bool {
        self.0.first().is_some_and(|l| l & 1 == 1)
    }

    pub fn bits(&self) -> usize {
        match self.0.last() {
            None => 0,
            Some(top) => self.0.len() * 64 - top.leading_zeros() as usize,
        }
    }

    pub fn bit(&self, i: usize) -> bool {
        self.0.get(i / 64).is_some_and(|l| (l >> (i % 64)) & 1 == 1)
    }

    pub fn byte_len(&self) -> usize {
        self.bits().div_ceil(8)
    }

    pub fn cmp_to(&self, o: &Uint) -> Ordering {
        self.0
            .len()
            .cmp(&o.0.len())
            .then_with(|| self.0.iter().rev().cmp(o.0.iter().rev()))
    }

    pub fn add(&self, o: &Uint) -> Uint {
        let n = self.0.len().max(o.0.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry = 0u128;
        for i in 0..n {
            let v =
                *self.0.get(i).unwrap_or(&0) as u128 + *o.0.get(i).unwrap_or(&0) as u128 + carry;
            out.push(v as u64);
            carry = v >> 64;
        }
        if carry > 0 {
            out.push(carry as u64);
        }
        Uint(out).trim()
    }

    /// `self - o`; exige `self >= o`.
    pub fn sub(&self, o: &Uint) -> Uint {
        debug_assert!(self.cmp_to(o) != Ordering::Less);
        let mut out = Vec::with_capacity(self.0.len());
        let mut borrow = 0i128;
        for i in 0..self.0.len() {
            let mut v = self.0[i] as i128 - *o.0.get(i).unwrap_or(&0) as i128 - borrow;
            if v < 0 {
                v += 1i128 << 64;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(v as u64);
        }
        Uint(out).trim()
    }

    pub fn mul(&self, o: &Uint) -> Uint {
        if self.is_zero() || o.is_zero() {
            return Uint::zero();
        }
        let mut out = vec![0u64; self.0.len() + o.0.len()];
        for (i, &a) in self.0.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in o.0.iter().enumerate() {
                let v = out[i + j] as u128 + a as u128 * b as u128 + carry;
                out[i + j] = v as u64;
                carry = v >> 64;
            }
            out[i + o.0.len()] = carry as u64;
        }
        Uint(out).trim()
    }

    fn shl1_or(&self, bit: bool) -> Uint {
        let mut out = Vec::with_capacity(self.0.len() + 1);
        let mut carry = bit as u64;
        for &l in &self.0 {
            out.push((l << 1) | carry);
            carry = l >> 63;
        }
        if carry > 0 {
            out.push(carry);
        }
        Uint(out).trim()
    }

    /// Limbs little-endian com pelo menos `n` posições (zeros à esquerda).
    pub fn limbs_padded(&self, n: usize) -> Vec<u64> {
        let mut v = self.0.clone();
        v.resize(v.len().max(n), 0);
        v
    }

    /// `(self / d, self mod d)` para divisor pequeno.
    pub fn div_small(&self, d: u64) -> (Uint, u64) {
        assert!(d != 0, "divisão por zero");
        let mut q = vec![0u64; self.0.len()];
        let mut r = 0u128;
        for i in (0..self.0.len()).rev() {
            let cur = (r << 64) | self.0[i] as u128;
            q[i] = (cur / d as u128) as u64;
            r = cur % d as u128;
        }
        (Uint(q).trim(), r as u64)
    }

    /// Resto da divisão (bit a bit: lento, mas só roda sobre valores pequenos).
    pub fn rem(&self, m: &Uint) -> Uint {
        assert!(!m.is_zero(), "módulo zero");
        if self.cmp_to(m) == Ordering::Less {
            return self.clone();
        }
        let mut r = Uint::zero();
        for i in (0..self.bits()).rev() {
            r = r.shl1_or(self.bit(i));
            if r.cmp_to(m) != Ordering::Less {
                r = r.sub(m);
            }
        }
        r
    }

    /// `(a + b) mod m` com `a, b < m`.
    pub fn add_mod(&self, o: &Uint, m: &Uint) -> Uint {
        let s = self.add(o);
        if s.cmp_to(m) == Ordering::Less {
            s
        } else {
            s.sub(m)
        }
    }

    /// `(a - b) mod m` com `a, b < m`.
    pub fn sub_mod(&self, o: &Uint, m: &Uint) -> Uint {
        if self.cmp_to(o) == Ordering::Less {
            self.add(m).sub(o)
        } else {
            self.sub(o)
        }
    }
}

/// Contexto de Montgomery para módulo ímpar com pelo menos dois limbs.
#[derive(Clone)]
pub struct Mont {
    pub modulus: Uint,
    n: Vec<u64>,
    n0: u64,
    r2: Vec<u64>,
    /// 2^64 em forma de Montgomery (passo da redução por Horner).
    base: Vec<u64>,
    k: usize,
}

impl std::fmt::Debug for Mont {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mont({} bits)", self.modulus.bits())
    }
}

/// Máscara de todos os bits 1 se `a == b`, senão 0 (sem desvio).
fn ct_eq_mask(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    ((x | x.wrapping_neg()) >> 63).wrapping_sub(1)
}

/// `a - b` em `a` (mesmo tamanho); devolve o empréstimo final (0 ou 1).
fn sub_in_place(a: &mut [u64], b: &[u64]) -> u64 {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (v, b1) = a[i].overflowing_sub(b[i]);
        let (v, b2) = v.overflowing_sub(borrow);
        a[i] = v;
        borrow = (b1 | b2) as u64;
    }
    borrow
}

impl Mont {
    pub fn new(m: &Uint) -> Mont {
        assert!(m.is_odd(), "Montgomery exige módulo ímpar");
        let k = m.0.len();
        assert!(
            k >= 2,
            "módulo de Montgomery precisa de pelo menos 128 bits"
        );
        let n = m.0.clone();
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        let mut mont = Mont {
            modulus: m.clone(),
            n,
            n0: inv.wrapping_neg(),
            r2: Vec::new(),
            base: Vec::new(),
            k,
        };
        // R² mod n: parte de 1 e dobra 128·k vezes com a soma modular (sem desvios).
        let mut r = vec![0u64; k];
        r[0] = 1;
        for _ in 0..(128 * k) {
            r = mont.add(&r, &r);
        }
        mont.r2 = r;
        let mut b = vec![0u64; k];
        b[1] = 1;
        mont.base = mont.mul(&b, &mont.r2);
        mont
    }

    pub fn limbs(&self) -> usize {
        self.k
    }

    /// `t - n` se `t >= n` (t com `k` limbs + `top`), sem desvio.
    fn reduce_once(&self, mut t: Vec<u64>, top: u64) -> Vec<u64> {
        let mut u = t.clone();
        let borrow = sub_in_place(&mut u, &self.n);
        // usa `u` quando não houve empréstimo líquido: top − borrow ≥ 0
        let keep_t = ct_eq_mask(top, 0) & ct_eq_mask(borrow, 1);
        for i in 0..self.k {
            t[i] = (t[i] & keep_t) | (u[i] & !keep_t);
        }
        t
    }

    /// Multiplicação de Montgomery `a·b·R⁻¹ mod n` (tempo constante).
    pub fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let k = self.k;
        let mut t = vec![0u64; k + 2];
        for &bi in b.iter().take(k) {
            let mut carry = 0u128;
            for j in 0..k {
                let v = t[j] as u128 + a[j] as u128 * bi as u128 + carry;
                t[j] = v as u64;
                carry = v >> 64;
            }
            let v = t[k] as u128 + carry;
            t[k] = v as u64;
            t[k + 1] = (v >> 64) as u64;
            let m = t[0].wrapping_mul(self.n0);
            let v = t[0] as u128 + m as u128 * self.n[0] as u128;
            let mut carry = v >> 64;
            for j in 1..k {
                let v = t[j] as u128 + m as u128 * self.n[j] as u128 + carry;
                t[j - 1] = v as u64;
                carry = v >> 64;
            }
            let v = t[k] as u128 + carry;
            t[k - 1] = v as u64;
            t[k] = t[k + 1] + (v >> 64) as u64;
        }
        let top = t[k];
        t.truncate(k);
        self.reduce_once(t, top)
    }

    /// Para a forma de Montgomery; aceita qualquer tamanho (redução por Horner
    /// sobre `max(limbs, k)` limbs, então o tempo não depende do valor).
    pub fn to(&self, a: &Uint) -> Vec<u64> {
        self.to_limbs(&a.limbs_padded(self.k))
    }

    /// Como `to`, a partir de limbs little-endian de tamanho fixo.
    pub fn to_limbs(&self, limbs: &[u64]) -> Vec<u64> {
        let mut acc = self.zero_vec();
        let mut digit = self.zero_vec();
        for &l in limbs.iter().rev() {
            acc = self.mul(&acc, &self.base);
            digit[0] = l;
            acc = self.add(&acc, &self.mul(&digit, &self.r2));
        }
        acc
    }

    pub fn from(&self, a: &[u64]) -> Uint {
        let mut one = vec![0u64; self.k];
        one[0] = 1;
        Uint(self.mul(a, &one)).trim()
    }

    pub fn one(&self) -> Vec<u64> {
        let mut one = vec![0u64; self.k];
        one[0] = 1;
        self.mul(&one, &self.r2)
    }

    pub fn zero_vec(&self) -> Vec<u64> {
        vec![0; self.k]
    }

    pub fn is_zero_vec(a: &[u64]) -> bool {
        a.iter().fold(0, |acc, &l| acc | l) == 0
    }

    pub fn add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut out = vec![0u64; self.k];
        let mut carry = 0u128;
        for i in 0..self.k {
            let v = a[i] as u128 + b[i] as u128 + carry;
            out[i] = v as u64;
            carry = v >> 64;
        }
        self.reduce_once(out, carry as u64)
    }

    pub fn sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut out = a.to_vec();
        let borrow = sub_in_place(&mut out, b);
        // se houve empréstimo, soma n (máscara em vez de desvio)
        let mask = borrow.wrapping_neg();
        let mut carry = 0u128;
        for (o, &n) in out.iter_mut().zip(&self.n) {
            let v = *o as u128 + (n & mask) as u128 + carry;
            *o = v as u64;
            carry = v >> 64;
        }
        out
    }

    /// `base^exp` com expoente **público** (verificação, e = 65537, p − 2 de
    /// curvas): percorre só os bits de `exp`.
    pub fn pow(&self, base: &[u64], exp: &Uint) -> Vec<u64> {
        let mut result = self.one();
        for i in (0..exp.bits()).rev() {
            result = self.mul(&result, &result);
            if exp.bit(i) {
                result = self.mul(&result, base);
            }
        }
        result
    }

    /// `base^exp` com expoente **secreto** de até `bits` bits: janela fixa de
    /// 4 bits, mesma sequência de operações para qualquer expoente e leitura da
    /// tabela por máscara (sem acesso indexado pelo segredo).
    pub fn pow_ct(&self, base: &[u64], exp: &Uint, bits: usize) -> Vec<u64> {
        let windows = bits.div_ceil(4).max(1);
        let limbs = exp.limbs_padded((windows * 4).div_ceil(64));
        let mut table = Vec::with_capacity(16);
        table.push(self.one());
        for i in 1..16 {
            let next = self.mul(&table[i - 1], base);
            table.push(next);
        }
        let mut acc = self.one();
        let mut pick = self.zero_vec();
        for w in (0..windows).rev() {
            for _ in 0..4 {
                acc = self.mul(&acc, &acc);
            }
            let bit = w * 4;
            let nibble = (limbs[bit / 64] >> (bit % 64)) & 0xf;
            pick.iter_mut().for_each(|l| *l = 0);
            for (j, entry) in table.iter().enumerate() {
                let mask = ct_eq_mask(j as u64, nibble);
                for (p, e) in pick.iter_mut().zip(entry) {
                    *p |= e & mask;
                }
            }
            acc = self.mul(&acc, &pick);
        }
        acc
    }

    /// `a·b mod n` com valores comuns.
    pub fn mod_mul(&self, a: &Uint, b: &Uint) -> Uint {
        let (am, bm) = (self.to(a), self.to(b));
        self.from(&self.mul(&am, &bm))
    }

    /// `base^exp mod n` com expoente público.
    pub fn mod_pow(&self, base: &Uint, exp: &Uint) -> Uint {
        self.from(&self.pow(&self.to(base), exp))
    }

    /// Inverso modular por Fermat (módulo primo **público**; em forma comum).
    pub fn inv_prime(&self, a: &Uint) -> Uint {
        let exp = self.modulus.sub(&Uint::from_u64(2));
        self.mod_pow(a, &exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_roundtrip_and_modular() {
        let a = Uint::from_hex("ffffffffffffffffffffffffffffffff");
        let b = Uint::from_hex("0123456789abcdef0123456789abcdef01");
        assert_eq!(a.add(&b).sub(&b), a);
        assert_eq!(Uint::from_be(&a.to_be(20)), a);
        let m = Uint::from_hex("fffffffffffffffffffffffffffffffeffffffffffffffff"); // ímpar
        let r = a.mul(&b).rem(&m);
        assert_eq!(
            r,
            Uint::from_hex("23456789abcdef0100000000000000010000000000000000")
        );
        let mont = Mont::new(&m);
        assert_eq!(mont.mod_mul(&a, &b), r);
        // Fermat pequeno com primo conhecido (2^127 - 1)
        let p = Uint::from_hex("7fffffffffffffffffffffffffffffff");
        let mp = Mont::new(&p);
        let x = Uint::from_u64(123_456_789);
        assert_eq!(
            mp.mod_pow(&x, &p.sub(&Uint::from_u64(1))),
            Uint::from_u64(1)
        );
        assert_eq!(mp.mod_mul(&x, &mp.inv_prime(&x)), Uint::from_u64(1));
        assert_eq!(
            mp.mod_pow(&Uint::from_u64(3), &Uint::from_u64(200)),
            Uint::from_hex("08221debd28e3482d638cb0c2ea5d889")
        );
        // pow_ct = pow; to() aceita valores maiores que o módulo
        for e in [0u64, 1, 2, 15, 16, 200, 0xdead_beef_1234] {
            let e = Uint::from_u64(e);
            let b = mp.to(&x);
            assert_eq!(mp.from(&mp.pow_ct(&b, &e, 64)), mp.from(&mp.pow(&b, &e)));
        }
        let big = a.mul(&b).mul(&b);
        assert_eq!(mont.from(&mont.to(&big)), big.rem(&m));
        let (q, r) = big.div_small(65537);
        assert_eq!(q.mul(&Uint::from_u64(65537)).add(&Uint::from_u64(r)), big);
        // sub/add modulares com e sem volta
        let (one, two) = (mont.to(&Uint::from_u64(1)), mont.to(&Uint::from_u64(2)));
        assert_eq!(mont.from(&mont.sub(&one, &two)), m.sub(&Uint::from_u64(1)));
        assert_eq!(
            mont.from(&mont.add(&mont.sub(&one, &two), &two)),
            Uint::from_u64(1)
        );
    }
}
