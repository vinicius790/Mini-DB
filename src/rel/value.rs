//! Valores tipados, codificação de linhas e chaves que preservam a ordem.

use crate::error::{Error, Result};
use crate::json::Json;
use std::cmp::Ordering;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Int,
    Real,
    Text,
    Bool,
}

impl Type {
    pub fn parse(word: &str) -> Option<Self> {
        Some(match word.to_ascii_uppercase().as_str() {
            "INT" | "INTEGER" | "BIGINT" | "SMALLINT" => Self::Int,
            "REAL" | "FLOAT" | "DOUBLE" | "NUMERIC" | "DECIMAL" => Self::Real,
            "TEXT" | "VARCHAR" | "CHAR" | "STRING" => Self::Text,
            "BOOL" | "BOOLEAN" => Self::Bool,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Int => "INTEGER",
            Self::Real => "REAL",
            Self::Text => "TEXT",
            Self::Bool => "BOOLEAN",
        }
    }
}

/// Valor SQL. `Real` nunca é NaN (rejeitado na conversão).
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Bool(bool),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("NULL"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Real(x) => write!(f, "{x:?}"),
            Self::Text(s) => f.write_str(s),
            Self::Bool(b) => f.write_str(if *b { "true" } else { "false" }),
        }
    }
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "NULL",
            Self::Int(_) => "INTEGER",
            Self::Real(_) => "REAL",
            Self::Text(_) => "TEXT",
            Self::Bool(_) => "BOOLEAN",
        }
    }

    /// Verdade SQL: `None` = desconhecido (NULL).
    pub fn truth(&self) -> Option<bool> {
        match self {
            Self::Null => None,
            Self::Bool(b) => Some(*b),
            Self::Int(n) => Some(*n != 0),
            Self::Real(x) => Some(*x != 0.0),
            Self::Text(s) => Some(!s.is_empty()),
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Int(n) => Some(*n as f64),
            Self::Real(x) => Some(*x),
            _ => None,
        }
    }

    /// Converte para o tipo da coluna (INTEGER→REAL, REAL inteiro→INTEGER).
    pub fn coerce(self, ty: Type) -> Result<Self> {
        Ok(match (self, ty) {
            (Self::Null, _) => Self::Null,
            (v @ Self::Int(_), Type::Int) => v,
            (Self::Int(n), Type::Real) => Self::Real(n as f64),
            (Self::Real(x), Type::Real) if !x.is_nan() => Self::Real(x),
            (Self::Real(x), Type::Int) if x.fract() == 0.0 && x.abs() < 9.2e18 => {
                Self::Int(x as i64)
            }
            (v @ Self::Text(_), Type::Text) => v,
            (v @ Self::Bool(_), Type::Bool) => v,
            (Self::Int(n @ (0 | 1)), Type::Bool) => Self::Bool(n == 1),
            (v, ty) => {
                return Err(Error::Constraint(format!(
                    "valor {v} ({}) incompatível com {}",
                    v.type_name(),
                    ty.name()
                )))
            }
        })
    }

    /// Comparação SQL: `None` se algum lado é NULL ou os tipos não comparam.
    pub fn sql_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Null, _) | (_, Self::Null) => None,
            (Self::Int(a), Self::Int(b)) => Some(a.cmp(b)),
            (Self::Text(a), Self::Text(b)) => Some(a.cmp(b)),
            (Self::Bool(a), Self::Bool(b)) => Some(a.cmp(b)),
            (a, b) => a.as_f64()?.partial_cmp(&b.as_f64()?),
        }
    }

    /// Ordem total para ORDER BY/GROUP BY: NULL < BOOLEAN < números < TEXT.
    pub fn total_cmp(&self, other: &Self) -> Ordering {
        fn rank(v: &Value) -> u8 {
            match v {
                Value::Null => 0,
                Value::Bool(_) => 1,
                Value::Int(_) | Value::Real(_) => 2,
                Value::Text(_) => 3,
            }
        }
        rank(self)
            .cmp(&rank(other))
            .then_with(|| self.sql_cmp(other).unwrap_or(Ordering::Equal))
    }

    pub fn to_json(&self) -> Json {
        match self {
            Self::Null => Json::Null,
            Self::Int(n) => Json::Number(*n),
            Self::Real(x) => Json::Float(*x),
            Self::Text(s) => Json::String(s.clone()),
            Self::Bool(b) => Json::Bool(*b),
        }
    }
}

/// Codificação de chave: ordem dos bytes = ordem dos valores, auto-delimitada.
pub fn encode_key(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.push(1),
        Value::Bool(b) => out.extend_from_slice(&[2, *b as u8]),
        Value::Int(n) => {
            out.push(3);
            out.extend_from_slice(&((*n as u64) ^ (1 << 63)).to_be_bytes());
        }
        Value::Real(x) => {
            let x = if *x == 0.0 { 0.0 } else { *x }; // -0.0 == 0.0
            let bits = x.to_bits();
            let ordered = if bits >> 63 == 0 {
                bits ^ (1 << 63)
            } else {
                !bits
            };
            out.push(4);
            out.extend_from_slice(&ordered.to_be_bytes());
        }
        Value::Text(s) => {
            out.push(5);
            for &b in s.as_bytes() {
                out.push(b);
                if b == 0 {
                    out.push(0xFF);
                }
            }
            out.extend_from_slice(&[0, 0]);
        }
    }
}

pub fn key_of(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_key(v, &mut out);
    out
}

pub fn encode_row(values: &[Value]) -> Vec<u8> {
    let mut out = (values.len() as u16).to_le_bytes().to_vec();
    for v in values {
        match v {
            Value::Null => out.push(0),
            Value::Bool(b) => out.extend_from_slice(&[1, *b as u8]),
            Value::Int(n) => {
                out.push(2);
                out.extend_from_slice(&n.to_le_bytes());
            }
            Value::Real(x) => {
                out.push(3);
                out.extend_from_slice(&x.to_le_bytes());
            }
            Value::Text(s) => {
                out.push(4);
                out.extend_from_slice(&(s.len() as u16).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
    out
}

pub fn decode_row(b: &[u8]) -> Result<Vec<Value>> {
    let bad = || Error::Other("linha SQL corrompida".into());
    let take = |i: &mut usize, n: usize| -> Result<&[u8]> {
        let s = b.get(*i..*i + n).ok_or_else(bad)?;
        *i += n;
        Ok(s)
    };
    let mut i = 0;
    let n = take(&mut i, 2)?;
    let n = u16::from_le_bytes([n[0], n[1]]) as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let tag = take(&mut i, 1)?[0];
        out.push(match tag {
            0 => Value::Null,
            1 => Value::Bool(take(&mut i, 1)?[0] != 0),
            2 => Value::Int(i64::from_le_bytes(take(&mut i, 8)?.try_into().expect("8"))),
            3 => Value::Real(f64::from_le_bytes(take(&mut i, 8)?.try_into().expect("8"))),
            4 => {
                let len = take(&mut i, 2)?;
                let len = u16::from_le_bytes([len[0], len[1]]) as usize;
                Value::Text(String::from_utf8(take(&mut i, len)?.to_vec()).map_err(|_| bad())?)
            }
            _ => return Err(bad()),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_order_matches_value_order() {
        let ints = [i64::MIN, -5, -1, 0, 1, 7, i64::MAX].map(Value::Int);
        let reals = [-1e300, -2.5, -0.0, 0.5, 3.0, 1e300].map(Value::Real);
        let texts = ["", "\0", "\0a", "a", "a\0", "ab", "b"].map(|s| Value::Text(s.into()));
        for group in [&ints[..], &reals[..], &texts[..]] {
            for w in group.windows(2) {
                assert!(key_of(&w[0]) <= key_of(&w[1]), "{:?} vs {:?}", w[0], w[1]);
            }
        }
        let row = vec![
            Value::Null,
            Value::Int(-3),
            Value::Real(1.5),
            Value::Text("olá".into()),
            Value::Bool(true),
        ];
        assert_eq!(decode_row(&encode_row(&row)).unwrap(), row);
        assert!(decode_row(&[5, 0, 9]).is_err());
    }
}
