//! Compressão LZ77 própria (sem dependências) para valores armazenados.
//!
//! Formato do valor gravado na folha da árvore primária (bancos com
//! `META_FLAG_COMPRESSED_VALUES`):
//!
//! - `[0x00][bytes]` — valor cru (não comprimiu o suficiente);
//! - `[0x01][len:u16 LE][tokens]` — valor comprimido com até 64 KiB lógicos;
//! - `[0x02][len:u32 LE][tokens]` — valor comprimido maior (até o limite de valor).
//!
//! Tokens: `c < 0x80` = literal de `c + 1` bytes; `c >= 0x80` = cópia de
//! `(c & 0x7f) + MIN_MATCH` bytes a partir do offset `u16 LE` (1..=65535).
//! O codificador é determinístico: o mesmo valor produz sempre os mesmos bytes.

use crate::error::{Error, Result};

const TAG_RAW: u8 = 0;
const TAG_LZ: u8 = 1;
const TAG_LZ32: u8 = 2;
const MIN_MATCH: usize = 4;
const MAX_MATCH: usize = 0x7f + MIN_MATCH;
const MAX_LITERAL: usize = 0x80;
const HASH_BITS: u32 = 12;
/// Abaixo disso a compressão não compensa o cabeçalho.
const MIN_INPUT: usize = 32;

fn hash4(b: &[u8]) -> usize {
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    (v.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize
}

fn flush_literals(out: &mut Vec<u8>, lit: &[u8]) {
    for chunk in lit.chunks(MAX_LITERAL) {
        out.push((chunk.len() - 1) as u8);
        out.extend_from_slice(chunk);
    }
}

/// Comprime `input` em tokens LZ (sem cabeçalho).
pub fn compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2 + 8);
    let mut table = vec![usize::MAX; 1 << HASH_BITS];
    let (mut i, mut lit_start) = (0usize, 0usize);
    while i + MIN_MATCH <= input.len() {
        let h = hash4(&input[i..]);
        let cand = table[h];
        table[h] = i;
        if cand != usize::MAX && i - cand <= u16::MAX as usize {
            let max = (input.len() - i).min(MAX_MATCH);
            let len = (0..max)
                .take_while(|&n| input[cand + n] == input[i + n])
                .count();
            if len >= MIN_MATCH {
                flush_literals(&mut out, &input[lit_start..i]);
                out.push(0x80 | (len - MIN_MATCH) as u8);
                out.extend_from_slice(&((i - cand) as u16).to_le_bytes());
                i += len;
                lit_start = i;
                continue;
            }
        }
        i += 1;
    }
    flush_literals(&mut out, &input[lit_start..]);
    out
}

/// Descomprime tokens LZ exigindo exatamente `expected` bytes de saída.
pub fn decompress(tokens: &[u8], expected: usize) -> Result<Vec<u8>> {
    let bad = || Error::Other("valor comprimido corrompido".into());
    if expected > crate::page::MAX_VALUE_LEN {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(expected);
    let mut i = 0;
    while i < tokens.len() {
        let c = tokens[i] as usize;
        i += 1;
        if c < 0x80 {
            let lit = tokens.get(i..i + c + 1).ok_or_else(bad)?;
            out.extend_from_slice(lit);
            i += c + 1;
        } else {
            let off = tokens.get(i..i + 2).ok_or_else(bad)?;
            let off = u16::from_le_bytes([off[0], off[1]]) as usize;
            i += 2;
            if off == 0 || off > out.len() {
                return Err(bad());
            }
            let start = out.len() - off;
            // Cópia byte a byte: o trecho pode sobrepor a própria saída (RLE).
            for n in 0..(c & 0x7f) + MIN_MATCH {
                out.push(out[start + n]);
            }
        }
        if out.len() > expected {
            return Err(bad());
        }
    }
    if out.len() != expected {
        return Err(bad());
    }
    Ok(out)
}

/// Codifica um valor lógico para gravação (comprime só quando reduz).
pub fn encode_value(value: &[u8]) -> Vec<u8> {
    if value.len() >= MIN_INPUT {
        let tokens = compress(value);
        let small = value.len() <= u16::MAX as usize;
        let header = if small { 3 } else { 5 };
        if tokens.len() + header < value.len() + 1 {
            let mut out = Vec::with_capacity(tokens.len() + header);
            if small {
                out.push(TAG_LZ);
                out.extend_from_slice(&(value.len() as u16).to_le_bytes());
            } else {
                out.push(TAG_LZ32);
                out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            }
            out.extend_from_slice(&tokens);
            return out;
        }
    }
    let mut out = Vec::with_capacity(value.len() + 1);
    out.push(TAG_RAW);
    out.extend_from_slice(value);
    out
}

/// Decodifica um valor gravado por [`encode_value`].
pub fn decode_value(stored: &[u8]) -> Result<Vec<u8>> {
    match stored.split_first() {
        Some((&TAG_RAW, raw)) => Ok(raw.to_vec()),
        Some((&TAG_LZ, rest)) if rest.len() >= 2 => {
            decompress(&rest[2..], u16::from_le_bytes([rest[0], rest[1]]) as usize)
        }
        Some((&TAG_LZ32, rest)) if rest.len() >= 4 => decompress(
            &rest[4..],
            u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize,
        ),
        _ => Err(Error::Other("tag de valor armazenado inválida".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_ratio() {
        let text = b"minidb minidb minidb: chave-valor, chave-valor, chave-valor!".repeat(12);
        let enc = encode_value(&text);
        assert!(
            enc.len() < text.len() / 3,
            "{} -> {}",
            text.len(),
            enc.len()
        );
        assert_eq!(decode_value(&enc).unwrap(), text);
        for v in [&b""[..], b"a", b"curto", &[7u8; 1024][..]] {
            assert_eq!(decode_value(&encode_value(v)).unwrap(), v);
        }
        // Acima de 64 KiB o cabeçalho usa u32.
        let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let enc = encode_value(&big);
        assert_eq!(enc[0], TAG_LZ32);
        assert_eq!(decode_value(&enc).unwrap(), big);
    }

    #[test]
    fn incompressible_stays_raw_and_random_roundtrips() {
        let mut s = 0x1234_5678u32;
        let mut noise = || {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s as u8
        };
        let random: Vec<u8> = (0..1024).map(|_| noise()).collect();
        assert_eq!(encode_value(&random)[0], TAG_RAW);
        for len in 0..300 {
            let v: Vec<u8> = (0..len).map(|_| noise() % 4).collect();
            assert_eq!(decode_value(&encode_value(&v)).unwrap(), v, "len={len}");
        }
    }

    #[test]
    fn corrupt_input_is_an_error_not_a_panic() {
        for bad in [
            &[9u8][..],
            &[1, 5, 0, 0x80, 1, 0],
            &[1, 2, 0, 5, b'a'],
            &[1],
        ] {
            assert!(decode_value(bad).is_err());
        }
    }
}
