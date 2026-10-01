//! Bloom filter escalável (k hashes via double-hashing) para GET negativo rápido.
//! Não substitui a B+ Tree: só evita I/O quando a chave com certeza não existe.
//!
//! Um filtro de tamanho fixo satura: com 4 KiB, algumas dezenas de milhares de
//! chaves já fazem quase toda consulta responder "talvez". Aqui ele cresce em
//! camadas: quando a camada atual atinge a capacidade, abre-se outra com o
//! dobro do tamanho, e a consulta olha todas. Nunca há falso negativo.

const FIRST_BYTES: usize = 4096;
const K: u32 = 4;
/// Bits por chave em cada camada (≈1 % de falso positivo por camada com `K = 4`).
const BITS_PER_KEY: u64 = 10;
/// Teto de uma camada (64 MiB); depois disso a última camada só enche.
const MAX_LAYER_BYTES: usize = 64 << 20;

#[derive(Clone)]
struct Layer {
    bits: Vec<u8>,
    keys: u64,
}

impl Layer {
    fn new(nbytes: usize) -> Self {
        Self {
            bits: vec![0; nbytes],
            keys: 0,
        }
    }

    fn capacity(&self) -> u64 {
        self.bits.len() as u64 * 8 / BITS_PER_KEY
    }

    /// Posição (byte, máscara) do `i`-ésimo hash.
    fn slot(&self, h1: u64, h2: u64, i: u32) -> (usize, u8) {
        let nbits = self.bits.len() as u64 * 8;
        let bit = h1.wrapping_add((i as u64).wrapping_mul(h2)) % nbits;
        ((bit / 8) as usize, 1u8 << (bit % 8))
    }

    fn set(&mut self, h1: u64, h2: u64) {
        for i in 0..K {
            let (byte, mask) = self.slot(h1, h2, i);
            self.bits[byte] |= mask;
        }
        self.keys += 1;
    }

    fn has(&self, h1: u64, h2: u64) -> bool {
        (0..K).all(|i| {
            let (byte, mask) = self.slot(h1, h2, i);
            self.bits[byte] & mask != 0
        })
    }
}

#[derive(Clone)]
pub struct Bloom {
    /// Nunca vazio: a primeira camada existe desde `new`.
    layers: Vec<Layer>,
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
            layers: vec![Layer::new(FIRST_BYTES)],
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

    fn probe(&self, h1: u64, h2: u64) -> bool {
        self.layers.iter().any(|layer| layer.has(h1, h2))
    }

    pub fn insert(&mut self, key: &[u8]) {
        let (h1, h2) = Self::mix(key);
        self.inserts += 1;
        // Regravar a mesma chave (ou um falso positivo) não acrescenta informação:
        // o filtro já responde "talvez" para ela. Assim atualizações não o incham.
        if self.probe(h1, h2) {
            return;
        }
        let (full, len) = match self.layers.last() {
            Some(last) => (last.keys >= last.capacity(), last.bits.len()),
            None => (true, FIRST_BYTES / 2),
        };
        if full && len < MAX_LAYER_BYTES {
            self.layers.push(Layer::new(len * 2));
        }
        if let Some(last) = self.layers.last_mut() {
            last.set(h1, h2);
        }
    }

    pub fn may_contain(&self, key: &[u8]) -> bool {
        if self.inserts == 0 {
            return true; // filtro vazio = sem informação
        }
        let (h1, h2) = Self::mix(key);
        self.probe(h1, h2)
    }

    pub fn inserts(&self) -> u64 {
        self.inserts
    }

    /// Bits da primeira camada (compatibilidade; o filtro pode ter várias).
    pub fn as_bytes(&self) -> &[u8] {
        match self.layers.first() {
            Some(layer) => &layer.bits,
            None => &[],
        }
    }

    /// Memória ocupada pelas camadas, em bytes.
    pub fn size_bytes(&self) -> usize {
        self.layers.iter().map(|layer| layer.bits.len()).sum()
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
        // Falso negativo é bug; falso positivo é aceitável, mas raro num filtro vazio.
        assert!(!b.may_contain(b"zzzz-not-present-xxxx"));
    }

    #[test]
    fn grows_instead_of_saturating() {
        let mut b = Bloom::new();
        for i in 0..50_000u32 {
            b.insert(format!("key:{i}").as_bytes());
        }
        // Nenhum falso negativo.
        for i in 0..50_000u32 {
            assert!(b.may_contain(format!("key:{i}").as_bytes()), "faltou {i}");
        }
        // Um filtro fixo de 4 KiB responderia "talvez" para quase tudo aqui.
        let false_positives = (0..10_000u32)
            .filter(|i| b.may_contain(format!("absent:{i}").as_bytes()))
            .count();
        assert!(
            false_positives < 2_000,
            "falsos positivos demais: {false_positives} de 10000"
        );
        assert!(b.size_bytes() > FIRST_BYTES);
    }

    #[test]
    fn rewriting_the_same_key_does_not_grow() {
        let mut b = Bloom::new();
        for _ in 0..100_000 {
            b.insert(b"same-key");
        }
        assert_eq!(b.size_bytes(), FIRST_BYTES);
        assert_eq!(b.inserts(), 100_000);
    }
}
