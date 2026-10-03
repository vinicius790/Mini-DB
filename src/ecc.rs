//! Curvas NIST P-256 e P-384 e ECDSA (FIPS 186-4), sobre `bignum`.
//!
//! Coordenadas projetivas com as fórmulas **completas** de Renes–Costello–
//! Batina (2016, alg. 4, a = −3): a mesma sequência de operações serve para
//! soma, dobra e ponto no infinito, sem desvios. A multiplicação escalar usa
//! janela fixa de 4 bits sobre todos os bits da ordem, com leitura da tabela
//! por máscara; as operações com o escalar secreto (d, k) ficam em `Mont`
//! (tempo constante). A chave efêmera `k` do ECDSA é uniforme em [1, n−1],
//! tirada do gerador do sistema por rejeição.

use crate::bignum::{Mont, Uint};
use std::cmp::Ordering;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurveId {
    P256,
    P384,
}

pub struct Curve {
    pub id: CurveId,
    /// Bytes de uma coordenada/escalar.
    pub size: usize,
    p: Mont,
    n: Mont,
    b: Vec<u64>,
    g: (Uint, Uint),
}

fn build(id: CurveId) -> Curve {
    let (size, p, b, n, gx, gy) = match id {
        CurveId::P256 => (
            32,
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        ),
        CurveId::P384 => (
            48,
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        ),
    };
    let pm = Mont::new(&Uint::from_hex(p));
    let b = pm.to(&Uint::from_hex(b));
    Curve {
        id,
        size,
        b,
        n: Mont::new(&Uint::from_hex(n)),
        p: pm,
        g: (Uint::from_hex(gx), Uint::from_hex(gy)),
    }
}

pub fn curve(id: CurveId) -> &'static Curve {
    static P256: OnceLock<Curve> = OnceLock::new();
    static P384: OnceLock<Curve> = OnceLock::new();
    match id {
        CurveId::P256 => P256.get_or_init(|| build(id)),
        CurveId::P384 => P384.get_or_init(|| build(id)),
    }
}

/// Ponto em coordenadas projetivas (X:Y:Z) em forma de Montgomery; `Z = 0`
/// é o infinito (0:1:0).
#[derive(Clone)]
struct Proj {
    x: Vec<u64>,
    y: Vec<u64>,
    z: Vec<u64>,
}

impl Curve {
    pub fn order(&self) -> &Uint {
        &self.n.modulus
    }

    fn infinity(&self) -> Proj {
        Proj {
            x: self.p.zero_vec(),
            y: self.p.one(),
            z: self.p.zero_vec(),
        }
    }

    fn lift(&self, x: &Uint, y: &Uint) -> Proj {
        Proj {
            x: self.p.to(x),
            y: self.p.to(y),
            z: self.p.one(),
        }
    }

    fn is_inf(p: &Proj) -> bool {
        Mont::is_zero_vec(&p.z)
    }

    /// Soma completa (RCB16, alg. 4): vale também para P = Q e para o infinito.
    fn add(&self, p1: &Proj, p2: &Proj) -> Proj {
        let f = &self.p;
        let b = &self.b;
        let t0 = f.mul(&p1.x, &p2.x);
        let t1 = f.mul(&p1.y, &p2.y);
        let t2 = f.mul(&p1.z, &p2.z);
        let t3 = f.mul(&f.add(&p1.x, &p1.y), &f.add(&p2.x, &p2.y));
        let t3 = f.sub(&t3, &f.add(&t0, &t1));
        let t4 = f.mul(&f.add(&p1.y, &p1.z), &f.add(&p2.y, &p2.z));
        let t4 = f.sub(&t4, &f.add(&t1, &t2));
        let x3 = f.mul(&f.add(&p1.x, &p1.z), &f.add(&p2.x, &p2.z));
        let y3 = f.sub(&x3, &f.add(&t0, &t2));
        let z3 = f.mul(b, &t2);
        let x3 = f.sub(&y3, &z3);
        let z3 = f.add(&x3, &x3);
        let x3 = f.add(&x3, &z3);
        let z3 = f.sub(&t1, &x3);
        let x3 = f.add(&t1, &x3);
        let y3 = f.mul(b, &y3);
        let t1 = f.add(&t2, &t2);
        let t2 = f.add(&t1, &t2);
        let y3 = f.sub(&f.sub(&y3, &t2), &t0);
        let t1 = f.add(&y3, &y3);
        let y3 = f.add(&t1, &y3);
        let t1 = f.add(&t0, &t0);
        let t0 = f.sub(&f.add(&t1, &t0), &t2);
        let t1 = f.mul(&t4, &y3);
        let t2 = f.mul(&t0, &y3);
        let y3 = f.add(&f.mul(&x3, &z3), &t2);
        let x3 = f.sub(&f.mul(&t3, &x3), &t1);
        let z3 = f.add(&f.mul(&t4, &z3), &f.mul(&t3, &t0));
        Proj {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `k·P` em tempo constante: janela fixa de 4 bits sobre `size` bytes do
    /// escalar e seleção da tabela por máscara.
    fn mul(&self, k: &Uint, p: &Proj) -> Proj {
        let bytes = k.to_be(self.size);
        let mut table = Vec::with_capacity(16);
        table.push(self.infinity());
        for i in 1..16 {
            let next = self.add(&table[i - 1], p);
            table.push(next);
        }
        let mut acc = self.infinity();
        let mut pick = self.infinity();
        for byte in bytes {
            for nibble in [byte >> 4, byte & 0xf] {
                for _ in 0..4 {
                    acc = self.add(&acc, &acc);
                }
                for c in [&mut pick.x, &mut pick.y, &mut pick.z] {
                    c.iter_mut().for_each(|l| *l = 0);
                }
                for (j, entry) in table.iter().enumerate() {
                    let x = (j as u64) ^ nibble as u64;
                    let mask = ((x | x.wrapping_neg()) >> 63).wrapping_sub(1);
                    for (dst, src) in [
                        (&mut pick.x, &entry.x),
                        (&mut pick.y, &entry.y),
                        (&mut pick.z, &entry.z),
                    ] {
                        for (d, s) in dst.iter_mut().zip(src) {
                            *d |= s & mask;
                        }
                    }
                }
                acc = self.add(&acc, &pick);
            }
        }
        acc
    }

    fn affine(&self, p: &Proj) -> Option<(Uint, Uint)> {
        if Self::is_inf(p) {
            return None;
        }
        let f = &self.p;
        // p é público: expoente p − 2 pode ser percorrido normalmente
        let zinv = f.pow(&p.z, &f.modulus.sub(&Uint::from_u64(2)));
        Some((f.from(&f.mul(&p.x, &zinv)), f.from(&f.mul(&p.y, &zinv))))
    }

    /// `(x, y)` está na curva: y² = x³ − 3x + b.
    pub fn on_curve(&self, x: &Uint, y: &Uint) -> bool {
        let f = &self.p;
        if x.cmp_to(&f.modulus) != Ordering::Less || y.cmp_to(&f.modulus) != Ordering::Less {
            return false;
        }
        let (xm, ym) = (f.to(x), f.to(y));
        let x2 = f.mul(&xm, &xm);
        let x3 = f.mul(&x2, &xm);
        let three_x = f.add(&f.add(&xm, &xm), &xm);
        let rhs = f.add(&f.sub(&x3, &three_x), &self.b);
        f.mul(&ym, &ym) == rhs
    }

    /// Chave pública `d·G`.
    pub fn public_from_private(&self, d: &Uint) -> (Uint, Uint) {
        let g = self.lift(&self.g.0, &self.g.1);
        self.affine(&self.mul(d, &g)).expect("d em [1, n-1]")
    }

    /// Escalar uniforme em [1, n−1] (rejeição; nada é reduzido módulo n).
    pub fn random_scalar(&self) -> Uint {
        loop {
            let bytes: [u8; 48] = crate::crypto::random_bytes();
            let k = Uint::from_be(&bytes[..self.size]);
            if !k.is_zero() && k.cmp_to(self.order()) == Ordering::Less {
                return k;
            }
        }
    }

    /// Inteiro do resumo (bits mais à esquerda, no máximo `size` bytes) módulo n.
    fn digest_int(&self, digest: &[u8]) -> Uint {
        Uint::from_be(&digest[..digest.len().min(self.size)]).rem(self.order())
    }

    /// Verifica ECDSA `(r, s)` sobre `digest` com a chave pública `(qx, qy)`.
    pub fn ecdsa_verify(&self, qx: &Uint, qy: &Uint, digest: &[u8], r: &Uint, s: &Uint) -> bool {
        let n = self.order();
        if r.is_zero()
            || s.is_zero()
            || r.cmp_to(n) != Ordering::Less
            || s.cmp_to(n) != Ordering::Less
        {
            return false;
        }
        if !self.on_curve(qx, qy) {
            return false;
        }
        let e = self.digest_int(digest);
        let w = self.n.inv_prime(s);
        let u1 = self.n.mod_mul(&e, &w);
        let u2 = self.n.mod_mul(r, &w);
        let g = self.lift(&self.g.0, &self.g.1);
        let q = self.lift(qx, qy);
        let sum = self.add(&self.mul(&u1, &g), &self.mul(&u2, &q));
        match self.affine(&sum) {
            Some((x, _)) => x.rem(n) == *r,
            None => false,
        }
    }

    /// Assina `digest` com a chave privada `d`; devolve `(r, s)`. `k`, `k⁻¹` e
    /// `r·d` só passam por operações de tempo constante.
    pub fn ecdsa_sign(&self, d: &Uint, digest: &[u8]) -> (Uint, Uint) {
        let (fnn, n) = (&self.n, self.order());
        let e = fnn.to(&self.digest_int(digest));
        let dm = fnn.to_limbs(&d.limbs_padded(fnn.limbs()));
        let g = self.lift(&self.g.0, &self.g.1);
        let n_minus_2 = n.sub(&Uint::from_u64(2));
        loop {
            let k = self.random_scalar();
            let Some((x, _)) = self.affine(&self.mul(&k, &g)) else {
                continue;
            };
            let r = x.rem(n);
            if r.is_zero() {
                continue;
            }
            let km = fnn.to_limbs(&k.limbs_padded(fnn.limbs()));
            let kinv = fnn.pow(&km, &n_minus_2); // expoente público (n − 2)
            let rd = fnn.mul(&fnn.to(&r), &dm);
            let s = fnn.from(&fnn.mul(&kinv, &fnn.add(&e, &rd)));
            if !s.is_zero() {
                return (r, s);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_are_on_curve_and_have_the_right_order() {
        for id in [CurveId::P256, CurveId::P384] {
            let c = curve(id);
            assert!(c.on_curve(&c.g.0, &c.g.1), "{id:?}: G na curva");
            // n·G = infinito; (n−1)·G = −G (mesmo x, y' = p − y)
            let g = c.lift(&c.g.0, &c.g.1);
            assert!(Curve::is_inf(&c.mul(c.order(), &g)), "{id:?}: n·G");
            let (x, y) = c
                .affine(&c.mul(&c.order().sub(&Uint::from_u64(1)), &g))
                .unwrap();
            assert_eq!(x, c.g.0);
            assert_eq!(y, c.p.modulus.sub(&c.g.1));
        }
    }

    #[test]
    fn sign_then_verify_and_reject_tampering() {
        for id in [CurveId::P256, CurveId::P384] {
            let c = curve(id);
            let d = c.random_scalar();
            let (qx, qy) = c.public_from_private(&d);
            assert!(c.on_curve(&qx, &qy));
            let digest = crate::crypto::sha256(b"mensagem");
            let (r, s) = c.ecdsa_sign(&d, &digest);
            assert!(c.ecdsa_verify(&qx, &qy, &digest, &r, &s), "{id:?}");
            let other = crate::crypto::sha256(b"outra");
            assert!(!c.ecdsa_verify(&qx, &qy, &other, &r, &s));
            assert!(!c.ecdsa_verify(
                &qx,
                &qy,
                &digest,
                &r,
                &s.add_mod(&Uint::from_u64(1), c.order())
            ));
        }
    }
}
