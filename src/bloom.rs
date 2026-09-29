//! Bloom filter clássico (k hashes via double-hashing) para GET negativo rápido.
//! Não substitui a B+ Tree: só evita I/O quando a chave com certeza não existe.

const NBYTES: usize = 4096;
const K: u32 = 4;

#[derive(Clone)]
pub struct Bloom {
    bits: [u8; NBYTES],
    inserts: u64,
}

impl Default for Bloom {
    fn default() -> Self {
        Self::new()
    }
}

impl Bloom {
    pub fn new() -> Self {
        Self {
            bits: [0; NBYTES],
            inserts: 0,
        }
    }

    fn mix(key: &[u8]) -> (u64, u64) {
        let mut h1 = 0xcbf29ce484222325u64;
        let mut h2 = 0x100000001b3u64;
        for &b in key {
            h1 ^= b as u64;
            h1 = h1.wrapping_mul(0x100000001b3);
            h2 ^= (b as u64).wrapping_shl(1);
            h2 = h2.wrapping_mul(0xc2b2ae3d27d4eb4f);
        }
        (h1, h2 | 1)
    }

    pub fn insert(&mut self, key: &[u8]) {
        let (h1, h2) = Self::mix(key);
        let nbits = (NBYTES * 8) as u64;
        for i in 0..K {
            let bit = h1.wrapping_add((i as u64).wrapping_mul(h2)) % nbits;
            let byte = (bit / 8) as usize;
            let mask = 1u8 << (bit % 8);
            self.bits[byte] |= mask;
        }
        self.inserts += 1;
    }

    pub fn may_contain(&self, key: &[u8]) -> bool {
        if self.inserts == 0 {
            return true; // filtro vazio = sem informação
        }
        let (h1, h2) = Self::mix(key);
        let nbits = (NBYTES * 8) as u64;
        for i in 0..K {
            let bit = h1.wrapping_add((i as u64).wrapping_mul(h2)) % nbits;
            let byte = (bit / 8) as usize;
            let mask = 1u8 << (bit % 8);
            if self.bits[byte] & mask == 0 {
                return false;
            }
        }
        true
    }

    pub fn inserts(&self) -> u64 {
        self.inserts
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negatives_are_reliable() {
        let mut b = Bloom::new();
        b.insert(b"alpha");
        b.insert(b"beta");
        assert!(b.may_contain(b"alpha"));
        assert!(b.may_contain(b"beta"));
        // falso negativo é bug; falso positivo é aceitável
        // uma chave bem diferente deve falhar na maioria das vezes
        let miss = b.may_contain(b"zzzz-not-present-xxxx");
        let _ = miss;
    }
}
