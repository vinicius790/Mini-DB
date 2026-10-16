//! Otimizador Baseado em Custo (CBO) e Estimador de Cardinalidade HyperLogLog (HLL).
//!
//! Provê estruturas estatísticas probabilísticas de memória constante (1 KiB por coluna)
//! e modelos de custo de I/O e CPU calibrados para escolher os caminhos de acesso
//! mais eficientes no Mini-DB (SeqScan vs IndexScan vs Sort-Merge vs Hash Join).

use crate::error::{Error, Result};

/// Constante alfa para m = 1024 registradores:
/// alpha_m = 0.7213 / (1.0 + 1.079 / 1024) ~= 0.72054
const HLL_ALPHA_1024: f64 = 0.72054238;
pub const HLL_REGISTERS: usize = 1024;
pub const HLL_P: u32 = 10;

/// Estimador HyperLogLog com p = 10 (m = 1024 registradores de 1 byte).
/// Erro padrão esperado: 1.04 / sqrt(1024) = 3.25%.
/// Consumo de memória fixo em exatamente 1024 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hll {
    pub registers: [u8; HLL_REGISTERS],
}

impl Default for Hll {
    fn default() -> Self {
        Self::new()
    }
}

impl Hll {
    pub fn new() -> Self {
        Self {
            registers: [0u8; HLL_REGISTERS],
        }
    }

    /// Função hash de alta difusão (SplitMix64 + FNV-1a) para 64 bits.
    #[inline]
    pub fn hash64(data: &[u8]) -> u64 {
        let mut h = 0xcbf29ce484222325u64;
        for &b in data {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
        h ^ (h >> 33)
    }

    /// Insere uma amostra de bytes no sketch HyperLogLog.
    pub fn insert(&mut self, data: &[u8]) {
        let hash = Self::hash64(data);
        // Primeiro p bits determinam o registrador (0..1023)
        let idx = (hash >> (64 - HLL_P)) as usize;
        // Os (64 - p) bits restantes determinam a contagem de zeros à esquerda + 1
        let remaining = hash << HLL_P;
        let leading = (remaining.leading_zeros() as u8).saturating_add(1);
        if leading > self.registers[idx] {
            self.registers[idx] = leading;
        }
    }

    /// Estima a quantidade de valores distintos (Number of Distinct Values - NDV).
    pub fn count(&self) -> u64 {
        let m = HLL_REGISTERS as f64;
        let mut sum = 0.0;
        let mut zeros = 0usize;

        for &val in &self.registers {
            sum += 2.0f64.powi(-(val as i32));
            if val == 0 {
                zeros += 1;
            }
        }

        let raw_estimate = HLL_ALPHA_1024 * m * m / sum;

        // Correção para pequena cardinalidade: Linear Counting se houver registradores com zero
        if raw_estimate <= 2.5 * m && zeros > 0 {
            let lc = m * (m / zeros as f64).ln();
            lc.round() as u64
        } else if raw_estimate <= (1u64 << 32) as f64 / 30.0 {
            // Faixa intermediária padrão
            raw_estimate.round() as u64
        } else {
            // Correção para cardinalidades massivas (> 2^32)
            let two_to_64 = 18446744073709551616.0f64;
            let est = -two_to_64 * (1.0 - raw_estimate / two_to_64).ln();
            est.round() as u64
        }
    }

    /// Combina dois sketches HyperLogLog (União de conjuntos).
    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.registers.iter_mut().zip(&other.registers) {
            if *b > *a {
                *a = *b;
            }
        }
    }

    /// Serializa para representação binária fixa de 1024 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.registers.to_vec()
    }

    /// Deserializa a partir de 1024 bytes brutos.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HLL_REGISTERS {
            return Err(Error::Other(format!(
                "sketch HLL inválido: tamanho esperado {}, encontrado {}",
                HLL_REGISTERS,
                bytes.len()
            )));
        }
        let mut registers = [0u8; HLL_REGISTERS];
        registers.copy_from_slice(bytes);
        Ok(Self { registers })
    }
}

/// Modelo de custo relativo de execução de planos de consulta.
#[derive(Clone, Copy, Debug)]
pub struct CostModel {
    pub page_seq_cost: f64,
    pub page_rand_cost: f64,
    pub cpu_tuple_cost: f64,
    pub cpu_index_tuple_cost: f64,
    pub cpu_filter_cost: f64,
}

impl Default for CostModel {
    fn default() -> Self {
        Self {
            page_seq_cost: 1.0,
            page_rand_cost: 4.0,
            cpu_tuple_cost: 0.01,
            cpu_index_tuple_cost: 0.005,
            cpu_filter_cost: 0.002,
        }
    }
}

impl CostModel {
    /// Custo de varredura sequencial da tabela.
    pub fn scan_cost(&self, total_pages: usize, rows: usize) -> f64 {
        (total_pages as f64) * self.page_seq_cost + (rows as f64) * self.cpu_filter_cost
    }

    /// Custo de busca através de índice secundário B+ Tree.
    pub fn index_cost(&self, est_matches: usize, _total_pages: usize, idx_fanout: usize) -> f64 {
        let fanout = idx_fanout.max(2) as f64;
        let index_pages = ((est_matches as f64) / fanout).ceil();
        let index_io = index_pages * self.page_rand_cost;
        let table_io = (est_matches as f64) * self.page_rand_cost;
        let cpu = (est_matches as f64) * (self.cpu_index_tuple_cost + self.cpu_tuple_cost);
        index_io + table_io + cpu
    }

    /// Seletividade de predicado de igualdade (`col = val`) baseada no NDV.
    pub fn selectivity_eq(&self, ndv: u64) -> f64 {
        if ndv == 0 {
            1.0
        } else {
            (1.0 / (ndv as f64)).clamp(0.0001, 1.0)
        }
    }

    /// Avalia se o custo do índice é mais vantajoso que o scan sequencial
    /// (Tipping Point do CBO).
    pub fn prefer_index(&self, total_pages: usize, rows: usize, est_matches: usize) -> bool {
        let scan = self.scan_cost(total_pages, rows);
        let index = self.index_cost(est_matches, total_pages, 64);
        index < scan
    }
}

/// Chave reservada do motor para persistência do sketch HLL da coluna da tabela:
/// [0xFF, b'h', tid[4 bytes BE], col_idx[2 bytes BE]]
pub fn hll_key(table_id: u32, col_idx: u16) -> Vec<u8> {
    let mut key = Vec::with_capacity(8);
    key.push(0xFF);
    key.push(b'h');
    key.extend_from_slice(&table_id.to_be_bytes());
    key.extend_from_slice(&col_idx.to_be_bytes());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hll_cardinality_estimation() {
        let mut hll = Hll::new();
        let n = 20_000u64;
        for i in 0..n {
            let key = format!("user_identifier_{}", i);
            hll.insert(key.as_bytes());
        }
        let est = hll.count();
        let diff = (est as f64 - n as f64).abs();
        let rel_err = diff / n as f64;
        assert!(rel_err < 0.10, "erro esperado < 10%, foi {:.2}% (est={est}, real={n})", rel_err * 100.0);
    }

    #[test]
    fn test_hll_merge() {
        let mut hll1 = Hll::new();
        let mut hll2 = Hll::new();
        for i in 0..5_000 {
            hll1.insert(format!("a_{i}").as_bytes());
        }
        for i in 5_000..10_000 {
            hll2.insert(format!("a_{i}").as_bytes());
        }
        hll1.merge(&hll2);
        let est = hll1.count();
        let diff = (est as f64 - 10_000.0).abs();
        assert!(diff / 10_000.0 < 0.10);
    }

    #[test]
    fn test_cost_model_tipping_point() {
        let cbo = CostModel::default();
        let total_pages = 1000;
        let rows = 100_000;

        // Seletivo (100 linhas): índice deve ser muito preferível
        assert!(cbo.prefer_index(total_pages, rows, 100));

        // Não seletivo (50_000 linhas em 1000 páginas): scan sequencial é melhor que 50k random I/Os
        assert!(!cbo.prefer_index(total_pages, rows, 50_000));
    }
}
