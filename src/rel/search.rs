//! Busca avançada: texto completo (BM25), vetores (HNSW) e espaço (Z-order).
//!
//! Tudo é independente do armazenamento: os índices persistem em chaves do
//! prefixo do índice e o executor fornece leitura/escrita via [`NodeStore`].

use crate::error::{Error, Result};
use std::collections::{BTreeMap, HashMap, HashSet};

// ---------------------------------------------------------------------------
// Texto: tokenização, dobra de acentos, stemming leve
// ---------------------------------------------------------------------------

fn fold_char(c: char) -> char {
    match c {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
        'è' | 'é' | 'ê' | 'ë' => 'e',
        'ì' | 'í' | 'î' | 'ï' => 'i',
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' => 'o',
        'ù' | 'ú' | 'û' | 'ü' => 'u',
        'ç' => 'c',
        'ñ' => 'n',
        'ý' | 'ÿ' => 'y',
        other => other,
    }
}

/// Stemming leve (português e inglês): plurais e sufixos frequentes. Não
/// tenta ser um Snowball; o objetivo é casar variações comuns sem colar
/// palavras distintas.
pub fn stem(word: &str) -> String {
    let mut w = word.to_string();
    let n = w.chars().count();
    if n <= 3 {
        return w;
    }
    for (suffix, replacement) in [
        ("coes", "cao"),
        ("oes", "ao"),
        ("aes", "ao"),
        ("mente", ""),
        ("ing", ""),
        ("ness", ""),
        ("ies", "y"),
        ("ed", ""),
        ("es", "e"),
        ("s", ""),
    ] {
        // Plurais em -ão precisam de raiz curta ("ações" -> "ação").
        let min_stem = if replacement == "ao" || replacement == "cao" {
            2
        } else {
            3
        };
        if w.ends_with(suffix) && w.chars().count() - suffix.chars().count() >= min_stem {
            let cut = w.len() - suffix.len();
            w.truncate(cut);
            w.push_str(replacement);
            break;
        }
    }
    w
}

/// Termos normalizados de um texto (minúsculas, sem acentos, com stemming).
pub fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        if c.is_alphanumeric() {
            cur.extend(fold_char(c.to_lowercase().next().unwrap_or(c)).to_lowercase());
        } else if !cur.is_empty() {
            out.push(stem(&std::mem::take(&mut cur)));
        }
    }
    if !cur.is_empty() {
        out.push(stem(&cur));
    }
    out
}

/// Consulta de texto: termos obrigatórios, alternativas (`OR`), exclusões
/// (`-termo`/`NOT termo`), frases (`"a b"`) e prefixos (`termo*`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TextQuery {
    /// Grupos: cada grupo é um OR de alternativas; todos os grupos são exigidos.
    pub groups: Vec<Vec<Term>>,
    pub excluded: Vec<Term>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Term {
    Word(String),
    Prefix(String),
    Phrase(Vec<String>),
}

impl TextQuery {
    pub fn parse(q: &str) -> Self {
        let mut groups: Vec<Vec<Term>> = Vec::new();
        let mut excluded = Vec::new();
        let mut pending_or = false;
        let mut negate = false;
        let mut rest = q.trim();
        while !rest.is_empty() {
            rest = rest.trim_start();
            if rest.is_empty() {
                break;
            }
            let term: Option<Term>;
            if let Some(after) = rest.strip_prefix('"') {
                let end = after.find('"').unwrap_or(after.len());
                let words = tokenize(&after[..end]);
                rest = &after[(end + 1).min(after.len())..];
                term = if words.is_empty() {
                    None
                } else {
                    Some(Term::Phrase(words))
                };
            } else {
                let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
                let raw = &rest[..end];
                rest = &rest[end..];
                let upper = raw.to_ascii_uppercase();
                if upper == "OR" {
                    pending_or = true;
                    continue;
                }
                if upper == "AND" {
                    continue;
                }
                if upper == "NOT" {
                    negate = true;
                    continue;
                }
                let (raw, neg) = match raw.strip_prefix('-') {
                    Some(r) => (r, true),
                    None => (raw, false),
                };
                let prefix = raw.ends_with('*');
                let words = tokenize(raw.trim_end_matches('*'));
                term = match (words.len(), prefix) {
                    (0, _) => None,
                    (1, true) => Some(Term::Prefix(words[0].clone())),
                    (1, false) => Some(Term::Word(words[0].clone())),
                    (_, _) => Some(Term::Phrase(words)),
                };
                if neg {
                    negate = true;
                }
            }
            let Some(term) = term else {
                pending_or = false;
                continue;
            };
            if negate {
                excluded.push(term);
                negate = false;
                pending_or = false;
                continue;
            }
            if pending_or && !groups.is_empty() {
                groups.last_mut().expect("não vazio").push(term);
            } else {
                groups.push(vec![term]);
            }
            pending_or = false;
        }
        Self { groups, excluded }
    }

    /// Termos que precisam existir no índice para um documento casar.
    pub fn all_terms(&self) -> Vec<String> {
        let mut out = Vec::new();
        for g in &self.groups {
            for t in g {
                match t {
                    Term::Word(w) | Term::Prefix(w) => out.push(w.clone()),
                    Term::Phrase(ws) => out.extend(ws.iter().cloned()),
                }
            }
        }
        out
    }
}

/// Postings de um documento para um termo: posições (para frases).
pub fn encode_positions(pos: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pos.len() * 2);
    for p in pos {
        let mut v = *p;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }
    out
}

#[cfg(test)]
pub fn decode_positions(b: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut v: u32 = 0;
    let mut shift = 0;
    for &byte in b {
        v |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            out.push(v);
            v = 0;
            shift = 0;
        } else {
            shift += 7;
        }
    }
    out
}

/// Posições de cada termo num documento (texto já concatenado).
pub fn term_positions(text: &str) -> BTreeMap<String, Vec<u32>> {
    let mut map: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for (i, term) in tokenize(text).into_iter().enumerate() {
        map.entry(term).or_default().push(i as u32);
    }
    map
}

/// BM25 (k1 = 1.2, b = 0.75) de um documento dado df por termo.
pub struct Bm25 {
    pub docs: f64,
    pub avg_len: f64,
}

impl Bm25 {
    pub fn idf(&self, df: f64) -> f64 {
        ((self.docs - df + 0.5) / (df + 0.5) + 1.0).ln()
    }

    pub fn score(&self, tf: f64, df: f64, doc_len: f64) -> f64 {
        if tf <= 0.0 {
            return 0.0;
        }
        let (k1, b) = (1.2, 0.75);
        let norm = k1 * (1.0 - b + b * doc_len / self.avg_len.max(1.0));
        self.idf(df) * tf * (k1 + 1.0) / (tf + norm)
    }
}

/// O documento (posições por termo, lista de termos do índice para prefixos)
/// casa com a consulta? Devolve os termos que contribuem para a pontuação.
pub fn matches(
    q: &TextQuery,
    positions: &BTreeMap<String, Vec<u32>>,
    vocabulary: impl Fn(&str) -> Vec<String>,
) -> Option<Vec<String>> {
    let mut hits = Vec::new();
    let has_word = |w: &str| positions.contains_key(w);
    let phrase_ok = |words: &[String]| -> bool {
        let Some(first) = positions.get(&words[0]) else {
            return false;
        };
        first.iter().any(|&start| {
            words.iter().enumerate().all(|(k, w)| {
                positions
                    .get(w)
                    .is_some_and(|p| p.contains(&(start + k as u32)))
            })
        })
    };
    let term_hits = |t: &Term| -> Vec<String> {
        match t {
            Term::Word(w) => {
                if has_word(w) {
                    vec![w.clone()]
                } else {
                    Vec::new()
                }
            }
            Term::Prefix(p) => vocabulary(p).into_iter().filter(|w| has_word(w)).collect(),
            Term::Phrase(words) => {
                if phrase_ok(words) {
                    words.clone()
                } else {
                    Vec::new()
                }
            }
        }
    };
    // Sem termo positivo nada casa (igual ao caminho com índice).
    if q.groups.is_empty() {
        return None;
    }
    for t in &q.excluded {
        if !term_hits(t).is_empty() {
            return None;
        }
    }
    for group in &q.groups {
        let mut any = false;
        for t in group {
            let h = term_hits(t);
            if !h.is_empty() {
                any = true;
                hits.extend(h);
            }
        }
        if !any {
            return None;
        }
    }
    hits.sort();
    hits.dedup();
    Some(hits)
}

/// Realça os termos da consulta no texto original.
pub fn highlight(text: &str, q: &TextQuery, open: &str, close: &str) -> String {
    let wanted: HashSet<String> = q.all_terms().into_iter().collect();
    let prefixes: Vec<String> = q
        .groups
        .iter()
        .flatten()
        .filter_map(|t| match t {
            Term::Prefix(p) => Some(p.clone()),
            _ => None,
        })
        .collect();
    let mut out = String::new();
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if word.is_empty() {
            return;
        }
        let norm = tokenize(word);
        let hit = norm
            .iter()
            .any(|t| wanted.contains(t) || prefixes.iter().any(|p| t.starts_with(p.as_str())));
        if hit {
            out.push_str(open);
            out.push_str(word);
            out.push_str(close);
        } else {
            out.push_str(word);
        }
        word.clear();
    };
    for c in text.chars() {
        if c.is_alphanumeric() {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Vetores
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Metric {
    Cosine,
    L2,
    Dot,
}

impl Metric {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "cosine" | "cos" => Self::Cosine,
            "l2" | "euclidean" | "euclid" => Self::L2,
            "dot" | "ip" | "inner" => Self::Dot,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Cosine => "cosine",
            Self::L2 => "l2",
            Self::Dot => "dot",
        }
    }

    /// Distância (menor = mais parecido). Para `Dot`, é `-produto`.
    pub fn distance(self, a: &[f32], b: &[f32]) -> f64 {
        let n = a.len().min(b.len());
        match self {
            Self::L2 => (0..n)
                .map(|i| {
                    let d = a[i] as f64 - b[i] as f64;
                    d * d
                })
                .sum::<f64>()
                .sqrt(),
            Self::Dot => -(0..n).map(|i| a[i] as f64 * b[i] as f64).sum::<f64>(),
            Self::Cosine => {
                let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
                for i in 0..n {
                    dot += a[i] as f64 * b[i] as f64;
                    na += (a[i] as f64).powi(2);
                    nb += (b[i] as f64).powi(2);
                }
                if na == 0.0 || nb == 0.0 {
                    1.0
                } else {
                    1.0 - dot / (na.sqrt() * nb.sqrt())
                }
            }
        }
    }
}

/// `[0.1, 0.2, ...]` (JSON) ou `0.1,0.2` para vetor.
pub fn parse_vector(text: &str) -> Result<Vec<f32>> {
    let t = text.trim();
    let inner = t
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(t);
    if inner.trim().is_empty() {
        return Err(Error::Sql("vetor vazio".into()));
    }
    inner
        .split(',')
        .map(|p| {
            p.trim()
                .parse::<f32>()
                .map_err(|_| Error::Sql(format!("vetor inválido: {text}")))
                .and_then(|x| {
                    if x.is_finite() {
                        Ok(x)
                    } else {
                        Err(Error::Sql("vetor com NaN/infinito".into()))
                    }
                })
        })
        .collect()
}

pub fn vector_text(v: &[f32]) -> String {
    let parts: Vec<String> = v.iter().map(|x| format!("{x}")).collect();
    format!("[{}]", parts.join(","))
}

pub fn encode_vector(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

pub fn decode_vector(b: &[u8]) -> Vec<f32> {
    b.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Nó do grafo HNSW: vetor e vizinhos por nível.
#[derive(Clone, Debug, Default)]
pub struct Node {
    pub vector: Vec<f32>,
    pub neighbors: Vec<Vec<Vec<u8>>>,
}

impl Node {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.vector.len() as u32).to_le_bytes());
        out.extend(encode_vector(&self.vector));
        out.push(self.neighbors.len() as u8);
        for level in &self.neighbors {
            out.extend_from_slice(&(level.len() as u16).to_le_bytes());
            for n in level {
                out.extend_from_slice(&(n.len() as u16).to_le_bytes());
                out.extend_from_slice(n);
            }
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let bad = || Error::Other("nó HNSW corrompido".into());
        let mut i = 0;
        let take = |i: &mut usize, n: usize| -> Result<&[u8]> {
            let s = b.get(*i..*i + n).ok_or_else(bad)?;
            *i += n;
            Ok(s)
        };
        let dims = u32::from_le_bytes(take(&mut i, 4)?.try_into().expect("4")) as usize;
        let vector = decode_vector(take(&mut i, dims * 4)?);
        let levels = take(&mut i, 1)?[0] as usize;
        let mut neighbors = Vec::with_capacity(levels);
        for _ in 0..levels {
            let count = u16::from_le_bytes(take(&mut i, 2)?.try_into().expect("2")) as usize;
            let mut level = Vec::with_capacity(count);
            for _ in 0..count {
                let len = u16::from_le_bytes(take(&mut i, 2)?.try_into().expect("2")) as usize;
                level.push(take(&mut i, len)?.to_vec());
            }
            neighbors.push(level);
        }
        Ok(Self { vector, neighbors })
    }
}

/// Acesso aos nós (implementado pelo executor sobre as chaves do índice).
pub trait NodeStore {
    fn get_node(&self, id: &[u8]) -> Result<Option<Node>>;
    fn put_node(&self, id: &[u8], node: &Node) -> Result<()>;
    /// Ponto de entrada e nível máximo.
    fn entry(&self) -> Result<Option<(Vec<u8>, usize)>>;
    fn set_entry(&self, id: &[u8], level: usize) -> Result<()>;
}

#[derive(Clone, Copy, Debug)]
pub struct HnswParams {
    pub m: usize,
    pub ef_construction: usize,
    pub metric: Metric,
}

impl Default for HnswParams {
    fn default() -> Self {
        Self {
            m: 16,
            ef_construction: 100,
            metric: Metric::Cosine,
        }
    }
}

struct Candidate {
    dist: f64,
    id: Vec<u8>,
}

/// Busca gulosa numa camada: devolve até `ef` vizinhos mais próximos.
fn search_layer(
    store: &dyn NodeStore,
    metric: Metric,
    query: &[f32],
    entry: &[u8],
    ef: usize,
    level: usize,
) -> Result<Vec<Candidate>> {
    let Some(entry_node) = store.get_node(entry)? else {
        return Ok(Vec::new());
    };
    let mut visited: HashSet<Vec<u8>> = HashSet::new();
    visited.insert(entry.to_vec());
    let d0 = metric.distance(query, &entry_node.vector);
    // candidatos (a explorar) e resultados, ambos como listas ordenadas simples.
    let mut candidates: Vec<Candidate> = vec![Candidate {
        dist: d0,
        id: entry.to_vec(),
    }];
    let mut results: Vec<Candidate> = vec![Candidate {
        dist: d0,
        id: entry.to_vec(),
    }];
    let mut nodes: HashMap<Vec<u8>, Node> = HashMap::new();
    nodes.insert(entry.to_vec(), entry_node);
    while let Some(pos) = candidates
        .iter()
        .enumerate()
        .min_by(|a, b| a.1.dist.total_cmp(&b.1.dist))
        .map(|(i, _)| i)
    {
        let current = candidates.swap_remove(pos);
        let worst = results
            .iter()
            .map(|c| c.dist)
            .fold(f64::NEG_INFINITY, f64::max);
        if current.dist > worst && results.len() >= ef {
            break;
        }
        let node = match nodes.get(&current.id) {
            Some(n) => n.clone(),
            None => match store.get_node(&current.id)? {
                Some(n) => n,
                None => continue,
            },
        };
        let Some(neigh) = node.neighbors.get(level) else {
            continue;
        };
        for nid in neigh {
            if !visited.insert(nid.clone()) {
                continue;
            }
            let Some(nnode) = store.get_node(nid)? else {
                continue; // apagado: tombstone
            };
            let d = metric.distance(query, &nnode.vector);
            let worst = results
                .iter()
                .map(|c| c.dist)
                .fold(f64::NEG_INFINITY, f64::max);
            if results.len() < ef || d < worst {
                candidates.push(Candidate {
                    dist: d,
                    id: nid.clone(),
                });
                results.push(Candidate {
                    dist: d,
                    id: nid.clone(),
                });
                nodes.insert(nid.clone(), nnode);
                if results.len() > ef {
                    let worst_pos = results
                        .iter()
                        .enumerate()
                        .max_by(|a, b| a.1.dist.total_cmp(&b.1.dist))
                        .map(|(i, _)| i)
                        .expect("não vazio");
                    results.swap_remove(worst_pos);
                }
            }
        }
    }
    results.sort_by(|a, b| a.dist.total_cmp(&b.dist));
    Ok(results)
}

/// Nível aleatório com decaimento exponencial (1/ln(m)).
fn random_level(m: usize, seed: &[u8]) -> usize {
    let h = crate::crypto::sha256(seed);
    let r = u64::from_le_bytes(h[..8].try_into().expect("8")) as f64 / u64::MAX as f64;
    let ml = 1.0 / (m.max(2) as f64).ln();
    ((-(r.max(1e-12)).ln()) * ml).floor() as usize
}

/// Insere `id` com `vector` no grafo.
pub fn hnsw_insert(
    store: &dyn NodeStore,
    params: HnswParams,
    id: &[u8],
    vector: Vec<f32>,
) -> Result<()> {
    let level = random_level(params.m, id).min(16);
    let mut node = Node {
        vector,
        neighbors: vec![Vec::new(); level + 1],
    };
    let Some((mut entry, max_level)) = store.entry()? else {
        store.put_node(id, &node)?;
        store.set_entry(id, level)?;
        return Ok(());
    };
    if store.get_node(&entry)?.is_none() {
        // Entrada apagada: recomeça o grafo por este nó.
        store.put_node(id, &node)?;
        store.set_entry(id, level)?;
        return Ok(());
    }
    // Desce até o nível do novo nó pelo vizinho mais próximo.
    for l in ((level + 1)..=max_level).rev() {
        let found = search_layer(store, params.metric, &node.vector, &entry, 1, l)?;
        if let Some(best) = found.first() {
            entry = best.id.clone();
        }
    }
    for l in (0..=level.min(max_level)).rev() {
        let found = search_layer(
            store,
            params.metric,
            &node.vector,
            &entry,
            params.ef_construction,
            l,
        )?;
        let m_max = if l == 0 { params.m * 2 } else { params.m };
        let chosen: Vec<Vec<u8>> = found.iter().take(params.m).map(|c| c.id.clone()).collect();
        node.neighbors[l] = chosen.clone();
        for nid in &chosen {
            if let Some(mut n) = store.get_node(nid)? {
                while n.neighbors.len() <= l {
                    n.neighbors.push(Vec::new());
                }
                if !n.neighbors[l].iter().any(|x| x == id) {
                    n.neighbors[l].push(id.to_vec());
                    if n.neighbors[l].len() > m_max {
                        // Poda: mantém os mais próximos do próprio nó.
                        let mut scored: Vec<(f64, Vec<u8>)> = Vec::new();
                        for cand in &n.neighbors[l] {
                            if let Some(c) = store.get_node(cand)? {
                                scored.push((
                                    params.metric.distance(&n.vector, &c.vector),
                                    cand.clone(),
                                ));
                            } else if cand == id {
                                scored.push((
                                    params.metric.distance(&n.vector, &node.vector),
                                    cand.clone(),
                                ));
                            }
                        }
                        scored.sort_by(|a, b| a.0.total_cmp(&b.0));
                        n.neighbors[l] = scored.into_iter().take(m_max).map(|(_, c)| c).collect();
                    }
                }
                store.put_node(nid, &n)?;
            }
        }
        if let Some(best) = found.first() {
            entry = best.id.clone();
        }
    }
    store.put_node(id, &node)?;
    if level > max_level {
        store.set_entry(id, level)?;
    }
    Ok(())
}

/// Os `k` vizinhos aproximados mais próximos: `(distância, id)`.
pub fn hnsw_search(
    store: &dyn NodeStore,
    metric: Metric,
    query: &[f32],
    k: usize,
    ef: usize,
) -> Result<Vec<(f64, Vec<u8>)>> {
    let Some((mut entry, max_level)) = store.entry()? else {
        return Ok(Vec::new());
    };
    if store.get_node(&entry)?.is_none() {
        return Ok(Vec::new());
    }
    for l in (1..=max_level).rev() {
        let found = search_layer(store, metric, query, &entry, 1, l)?;
        if let Some(best) = found.first() {
            entry = best.id.clone();
        }
    }
    let found = search_layer(store, metric, query, &entry, ef.max(k), 0)?;
    Ok(found.into_iter().take(k).map(|c| (c.dist, c.id)).collect())
}

// ---------------------------------------------------------------------------
// Espaço: curva Z (Morton) em 2D/3D
// ---------------------------------------------------------------------------

/// Faixa de coordenadas indexável: `[-range, range]` por eixo.
pub const SPATIAL_RANGE: f64 = 1_000_000.0;

fn quantize(v: f64, bits: u32) -> u64 {
    let cells = (1u64 << bits) as f64;
    let t =
        ((v.clamp(-SPATIAL_RANGE, SPATIAL_RANGE) + SPATIAL_RANGE) / (2.0 * SPATIAL_RANGE)) * cells;
    (t.floor() as u64).min((1u64 << bits) - 1)
}

fn spread(v: u64, dims: u32, bits: u32) -> u64 {
    let mut out = 0u64;
    for i in 0..bits {
        if v & (1 << i) != 0 {
            out |= 1 << (i * dims);
        }
    }
    out
}

pub fn bits_for(dims: usize) -> u32 {
    match dims {
        2 => 31,
        _ => 21,
    }
}

/// Código Morton das coordenadas (2 ou 3 dimensões).
pub fn morton(coords: &[f64]) -> u64 {
    let dims = coords.len() as u32;
    let bits = bits_for(coords.len());
    let mut code = 0u64;
    for (i, &c) in coords.iter().enumerate() {
        code |= spread(quantize(c, bits), dims, bits) << i;
    }
    code
}

fn cell_bounds(lo: &[u64], hi: &[u64], dims: usize) -> (u64, u64) {
    let bits = bits_for(dims);
    let dims_u = dims as u32;
    let mut a = 0u64;
    let mut b = 0u64;
    for i in 0..dims {
        a |= spread(lo[i], dims_u, bits) << i;
        b |= spread(hi[i], dims_u, bits) << i;
    }
    (a, b)
}

/// Faixas de códigos Morton que cobrem a caixa `[lo, hi]` (coordenadas
/// quantizadas), com no máximo `max_ranges` faixas (as células restantes são
/// mescladas, produzindo candidatos a mais que o filtro exato descarta).
pub fn z_ranges(lo: &[f64], hi: &[f64], max_ranges: usize) -> Vec<(u64, u64)> {
    let dims = lo.len();
    let bits = bits_for(dims);
    let qlo: Vec<u64> = lo.iter().map(|&v| quantize(v, bits)).collect();
    let qhi: Vec<u64> = hi.iter().map(|&v| quantize(v, bits)).collect();
    // Decomposição recursiva do espaço em quadrantes/octantes.
    let mut out: Vec<(u64, u64)> = Vec::new();
    let mut stack: Vec<(Vec<u64>, Vec<u64>, u32)> =
        vec![(vec![0; dims], vec![(1u64 << bits) - 1; dims], bits)];
    let mut budget = max_ranges.max(1) * 8;
    while let Some((clo, chi, level)) = stack.pop() {
        // Célula fora da caixa?
        if (0..dims).any(|i| chi[i] < qlo[i] || clo[i] > qhi[i]) {
            continue;
        }
        let inside = (0..dims).all(|i| clo[i] >= qlo[i] && chi[i] <= qhi[i]);
        if inside || level == 0 || budget == 0 {
            out.push(cell_bounds(&clo, &chi, dims));
            continue;
        }
        budget -= 1;
        let half = 1u64 << (level - 1);
        let parts = 1usize << dims;
        for p in 0..parts {
            let mut nlo = clo.clone();
            let mut nhi = chi.clone();
            for i in 0..dims {
                let mid = clo[i] + half;
                if p & (1 << i) != 0 {
                    nlo[i] = mid;
                } else {
                    nhi[i] = mid - 1;
                }
            }
            stack.push((nlo, nhi, level - 1));
        }
    }
    out.sort();
    // Mescla faixas contíguas e reduz ao máximo pedido.
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (a, b) in out {
        match merged.last_mut() {
            Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    while merged.len() > max_ranges.max(1) {
        // Junta o par com o menor buraco entre si.
        let mut best = 0;
        let mut gap = u64::MAX;
        for i in 0..merged.len() - 1 {
            let g = merged[i + 1].0 - merged[i].1;
            if g < gap {
                gap = g;
                best = i;
            }
        }
        let next = merged.remove(best + 1);
        merged[best].1 = next.1;
    }
    merged
}

/// Distância euclidiana em N dimensões.
pub fn euclid(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(x, y)| (x - y) * (x - y))
        .sum::<f64>()
        .sqrt()
}

/// Distância em metros entre dois pontos (lat/lon em graus).
pub fn haversine(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6_371_008.8;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = p2 - p1;
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * r * a.sqrt().asin()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn tokenizer_and_query() {
        assert_eq!(
            tokenize("Coração, AÇÕES rápidas!"),
            ["coracao", "acao", "rapida"]
        );
        assert_eq!(tokenize("Running dogs jumped"), ["runn", "dog", "jump"]);
        let q = TextQuery::parse("gato \"casa azul\" OR jardim -cachorro pre*");
        assert_eq!(q.groups.len(), 3);
        assert_eq!(
            q.groups[1],
            vec![
                Term::Phrase(vec!["casa".into(), "azul".into()]),
                Term::Word("jardim".into())
            ]
        );
        assert_eq!(q.excluded, vec![Term::Word("cachorro".into())]);
        assert_eq!(q.groups[2], vec![Term::Prefix("pre".into())]);
        let pos = term_positions("o gato da casa azul mora no jardim");
        assert!(matches(&TextQuery::parse("\"casa azul\""), &pos, |_| vec![]).is_some());
        assert!(matches(&TextQuery::parse("\"azul casa\""), &pos, |_| vec![]).is_none());
        assert!(matches(&TextQuery::parse("gato -jardim"), &pos, |_| vec![]).is_none());
        assert!(matches(&TextQuery::parse("gat*"), &pos, |p| if p == "gat" {
            vec!["gato".into()]
        } else {
            vec![]
        })
        .is_some());
        assert_eq!(
            decode_positions(&encode_positions(&[0, 1, 127, 128, 70000])),
            [0, 1, 127, 128, 70000]
        );
        assert_eq!(
            highlight("O Gato azul", &TextQuery::parse("gato"), "<", ">"),
            "O <Gato> azul"
        );
    }

    #[derive(Default)]
    struct MemStore {
        nodes: RefCell<HashMap<Vec<u8>, Node>>,
        entry: RefCell<Option<(Vec<u8>, usize)>>,
    }

    impl NodeStore for MemStore {
        fn get_node(&self, id: &[u8]) -> Result<Option<Node>> {
            Ok(self.nodes.borrow().get(id).cloned())
        }
        fn put_node(&self, id: &[u8], node: &Node) -> Result<()> {
            self.nodes.borrow_mut().insert(id.to_vec(), node.clone());
            Ok(())
        }
        fn entry(&self) -> Result<Option<(Vec<u8>, usize)>> {
            Ok(self.entry.borrow().clone())
        }
        fn set_entry(&self, id: &[u8], level: usize) -> Result<()> {
            *self.entry.borrow_mut() = Some((id.to_vec(), level));
            Ok(())
        }
    }

    #[test]
    fn hnsw_finds_near_neighbors() {
        let store = MemStore::default();
        let params = HnswParams {
            metric: Metric::L2,
            ..HnswParams::default()
        };
        let mut pts = Vec::new();
        for i in 0..400u32 {
            let h = crate::crypto::sha256(&i.to_le_bytes());
            let v: Vec<f32> = (0..8).map(|d| h[d] as f32 / 255.0).collect();
            hnsw_insert(&store, params, &i.to_le_bytes(), v.clone()).unwrap();
            pts.push((v, i));
        }
        let q: Vec<f32> = vec![0.5; 8];
        let mut exact: Vec<(f64, u32)> = pts
            .iter()
            .map(|(v, i)| (Metric::L2.distance(&q, v), *i))
            .collect();
        exact.sort_by(|a, b| a.0.total_cmp(&b.0));
        let got = hnsw_search(&store, Metric::L2, &q, 10, 64).unwrap();
        let got_ids: HashSet<u32> = got
            .iter()
            .map(|(_, id)| u32::from_le_bytes(id[..4].try_into().unwrap()))
            .collect();
        let exact_ids: HashSet<u32> = exact.iter().take(10).map(|(_, i)| *i).collect();
        let overlap = got_ids.intersection(&exact_ids).count();
        assert!(overlap >= 8, "recall baixo: {overlap}/10");
        assert!(got.windows(2).all(|w| w[0].0 <= w[1].0));
        let n = Node {
            vector: vec![1.0, 2.0],
            neighbors: vec![vec![b"a".to_vec()], vec![]],
        };
        assert_eq!(
            Node::decode(&n.encode()).unwrap().neighbors[0],
            vec![b"a".to_vec()]
        );
        assert_eq!(parse_vector("[1, 2.5,-3]").unwrap(), vec![1.0, 2.5, -3.0]);
        assert!(parse_vector("[1, x]").is_err());
        assert!((Metric::Cosine.distance(&[1.0, 0.0], &[1.0, 0.0])).abs() < 1e-9);
    }

    #[test]
    fn morton_ranges_cover_boxes() {
        let inside = |p: &[f64], lo: &[f64], hi: &[f64]| {
            (0..p.len()).all(|i| p[i] >= lo[i] && p[i] <= hi[i])
        };
        let pts: Vec<Vec<f64>> = (0..2000)
            .map(|i| {
                let h = crate::crypto::sha256(&(i as u32).to_le_bytes());
                vec![h[0] as f64 * 4.0 - 500.0, h[1] as f64 * 4.0 - 500.0]
            })
            .collect();
        let (lo, hi) = (vec![-100.0, -50.0], vec![120.0, 300.0]);
        let ranges = z_ranges(&lo, &hi, 32);
        assert!(ranges.len() <= 32);
        for p in &pts {
            let code = morton(p);
            let covered = ranges.iter().any(|(a, b)| code >= *a && code <= *b);
            if inside(p, &lo, &hi) {
                assert!(covered, "ponto dentro sem cobertura: {p:?}");
            }
        }
        let ranges3 = z_ranges(&[0.0, 0.0, 0.0], &[10.0, 10.0, 10.0], 16);
        let code = morton(&[5.0, 5.0, 5.0]);
        assert!(ranges3.iter().any(|(a, b)| code >= *a && code <= *b));
        assert!((haversine(0.0, 0.0, 0.0, 1.0) - 111_195.0).abs() < 200.0);
    }
}
