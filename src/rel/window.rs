//! Funções de janela (`... OVER (PARTITION BY ... ORDER BY ... frame)`).
//!
//! O executor avalia por linha os argumentos, a chave de partição e os valores
//! do `ORDER BY`; aqui as linhas são agrupadas, ordenadas dentro de cada
//! partição e cada função recebe a moldura da linha corrente. Agregados com
//! moldura que começa no início da partição são acumulados incrementalmente;
//! os demais recalculam sobre a moldura.

use super::exec::{cmp_order, AggState};
use super::parser::{Bound, Frame, WinFn, WindowSpec};
use super::value::Value;
use crate::error::{Error, Result};
use std::collections::BTreeMap;

/// Entrada de uma função de janela: um elemento por linha do resultado.
pub(super) struct WindowInput<'a> {
    pub func: WinFn,
    pub spec: &'a WindowSpec,
    /// `args[linha][k]`: argumentos avaliados.
    pub args: Vec<Vec<Value>>,
    /// Chave de partição codificada por linha.
    pub partition: Vec<Vec<u8>>,
    /// Valores do `ORDER BY` por linha.
    pub order: Vec<Vec<Value>>,
}

/// Valor da função para cada linha, na ordem original das linhas.
pub(super) fn evaluate(input: &WindowInput<'_>) -> Result<Vec<Value>> {
    let n = input.args.len();
    let mut out = vec![Value::Null; n];
    let mut groups: BTreeMap<&[u8], Vec<usize>> = BTreeMap::new();
    for (i, key) in input.partition.iter().enumerate() {
        groups.entry(key.as_slice()).or_default().push(i);
    }
    let items = &input.spec.order_by;
    for (_, mut sorted) in groups {
        sorted.sort_by(|&a, &b| cmp_order(&input.order[a], &input.order[b], items));
        let m = sorted.len();
        // Pares (linhas com o mesmo ORDER BY): início e fim de cada grupo.
        let mut peer_start = vec![0usize; m];
        let mut peer_end = vec![0usize; m];
        let mut dense = vec![0usize; m];
        let mut i = 0;
        let mut rank = 0;
        while i < m {
            let mut j = i;
            while j + 1 < m
                && (items.is_empty()
                    || cmp_order(&input.order[sorted[j + 1]], &input.order[sorted[i]], items)
                        == std::cmp::Ordering::Equal)
            {
                j += 1;
            }
            rank += 1;
            for k in i..=j {
                peer_start[k] = i;
                peer_end[k] = j;
                dense[k] = rank;
            }
            i = j + 1;
        }
        let peers = Peers {
            start: &peer_start,
            end: &peer_end,
        };
        let mut running: Option<(AggState, usize)> = None;
        for pos in 0..m {
            let row = sorted[pos];
            let arg = |k: usize| input.args[row].get(k).cloned().unwrap_or(Value::Null);
            let value = match input.func {
                WinFn::RowNumber => Value::Int(pos as i64 + 1),
                WinFn::Rank => Value::Int(peer_start[pos] as i64 + 1),
                WinFn::DenseRank => Value::Int(dense[pos] as i64),
                WinFn::PercentRank => Value::Real(if m == 1 {
                    0.0
                } else {
                    peer_start[pos] as f64 / (m - 1) as f64
                }),
                WinFn::CumeDist => Value::Real((peer_end[pos] + 1) as f64 / m as f64),
                WinFn::Ntile => {
                    let k = match arg(0) {
                        Value::Int(k) if k > 0 => k as usize,
                        other => {
                            return Err(Error::Sql(format!(
                                "ntile() espera inteiro positivo, recebeu {other}"
                            )))
                        }
                    };
                    let per = m / k;
                    let extra = m % k;
                    let big = extra * (per + 1);
                    Value::Int(if pos < big {
                        (pos / (per + 1)) as i64 + 1
                    } else {
                        (extra + (pos - big) / per.max(1)) as i64 + 1
                    })
                }
                WinFn::Lag | WinFn::Lead => {
                    let off = match input.args[row].get(1) {
                        None => 1,
                        Some(Value::Int(o)) if *o >= 0 => *o as usize,
                        Some(other) => {
                            return Err(Error::Sql(format!(
                                "deslocamento de lag/lead inválido: {other}"
                            )))
                        }
                    };
                    let target = if input.func == WinFn::Lag {
                        pos.checked_sub(off)
                    } else {
                        Some(pos + off).filter(|&t| t < m)
                    };
                    match target {
                        Some(t) => input.args[sorted[t]][0].clone(),
                        None => input.args[row].get(2).cloned().unwrap_or(Value::Null),
                    }
                }
                WinFn::FirstValue | WinFn::LastValue | WinFn::NthValue | WinFn::Agg(_) => {
                    let Some((lo, hi)) = frame(input, &sorted, pos, &peers)? else {
                        // Moldura vazia.
                        out[row] = match input.func {
                            WinFn::Agg(f) => AggState::new(f).finish(),
                            _ => Value::Null,
                        };
                        continue;
                    };
                    match input.func {
                        WinFn::FirstValue => input.args[sorted[lo]][0].clone(),
                        WinFn::LastValue => input.args[sorted[hi]][0].clone(),
                        WinFn::NthValue => match arg(1) {
                            Value::Int(k) if k >= 1 => {
                                let at = lo + k as usize - 1;
                                if at <= hi {
                                    input.args[sorted[at]][0].clone()
                                } else {
                                    Value::Null
                                }
                            }
                            other => {
                                return Err(Error::Sql(format!(
                                    "nth_value() espera n >= 1, recebeu {other}"
                                )))
                            }
                        },
                        WinFn::Agg(f) => {
                            let feed = |state: &mut AggState, j: usize| -> Result<()> {
                                let r = sorted[j];
                                if input.args[r].len() > 1 {
                                    state.set_extra(&input.args[r][1]);
                                }
                                let v = input.args[r].first().cloned().unwrap_or(Value::Int(1));
                                state.feed(v)
                            };
                            if lo == 0 {
                                // Moldura cresce a partir do início: acumula.
                                let (state, fed) =
                                    running.get_or_insert_with(|| (AggState::new(f), 0));
                                if *fed > hi + 1 {
                                    *state = AggState::new(f);
                                    *fed = 0;
                                }
                                while *fed <= hi {
                                    feed(state, *fed)?;
                                    *fed += 1;
                                }
                                state.clone().finish()
                            } else {
                                let mut state = AggState::new(f);
                                for j in lo..=hi {
                                    feed(&mut state, j)?;
                                }
                                state.finish()
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            };
            out[row] = value;
        }
    }
    Ok(out)
}

struct Peers<'a> {
    start: &'a [usize],
    end: &'a [usize],
}

/// Moldura `[lo, hi]` (posições na partição ordenada) da linha `pos`;
/// `None` = vazia.
fn frame(
    input: &WindowInput<'_>,
    sorted: &[usize],
    pos: usize,
    peers: &Peers<'_>,
) -> Result<Option<(usize, usize)>> {
    let m = sorted.len();
    let spec = input.spec;
    let Some(Frame { rows, start, end }) = spec.frame else {
        return Ok(Some(if spec.order_by.is_empty() {
            (0, m - 1)
        } else {
            (0, peers.end[pos])
        }));
    };
    let clamp = |x: i64| x.clamp(0, m as i64 - 1) as usize;
    let (lo, hi): (i64, i64) = if rows {
        let k64 = |k: u64| i64::try_from(k).unwrap_or(i64::MAX);
        let lo = match start {
            Bound::UnboundedPreceding => 0,
            Bound::Preceding(k) => (pos as i64).saturating_sub(k64(k)),
            Bound::CurrentRow => pos as i64,
            Bound::Following(k) => (pos as i64).saturating_add(k64(k)),
            Bound::UnboundedFollowing => unreachable!("rejeitado no parser"),
        };
        let hi = match end {
            Bound::UnboundedFollowing => m as i64 - 1,
            Bound::Following(k) => (pos as i64).saturating_add(k64(k)),
            Bound::CurrentRow => pos as i64,
            Bound::Preceding(k) => (pos as i64).saturating_sub(k64(k)),
            Bound::UnboundedPreceding => unreachable!("rejeitado no parser"),
        };
        (lo, hi)
    } else {
        let numeric = |b: Bound| matches!(b, Bound::Preceding(_) | Bound::Following(_));
        if numeric(start) || numeric(end) {
            if spec.order_by.len() != 1 {
                return Err(Error::Sql(
                    "RANGE com deslocamento exige exatamente uma expressão no ORDER BY".into(),
                ));
            }
            let sign = if spec.order_by[0].desc { -1.0 } else { 1.0 };
            let key = |p: usize| -> Result<Option<f64>> {
                match &input.order[sorted[p]][0] {
                    Value::Null => Ok(None),
                    v => v.as_f64().map(|x| Some(x * sign)).ok_or_else(|| {
                        Error::Sql("RANGE com deslocamento exige ORDER BY numérico".into())
                    }),
                }
            };
            let Some(x) = key(pos)? else {
                // Linha com chave NULL: a moldura são só os pares.
                return Ok(Some((peers.start[pos], peers.end[pos])));
            };
            let offset = |b: Bound| -> Option<f64> {
                match b {
                    Bound::Preceding(k) => Some(-(k as f64)),
                    Bound::Following(k) => Some(k as f64),
                    _ => None,
                }
            };
            let mut lo = match start {
                Bound::UnboundedPreceding => 0,
                Bound::CurrentRow => peers.start[pos],
                b => {
                    let target = x + offset(b).expect("numérico");
                    let mut found = m;
                    for j in 0..m {
                        if key(j)?.is_some_and(|y| y >= target) {
                            found = j;
                            break;
                        }
                    }
                    found
                }
            };
            let hi = match end {
                Bound::UnboundedFollowing => m as i64 - 1,
                Bound::CurrentRow => peers.end[pos] as i64,
                b => {
                    let target = x + offset(b).expect("numérico");
                    let mut found = -1i64;
                    for j in 0..m {
                        if key(j)?.is_some_and(|y| y <= target) {
                            found = j as i64;
                        }
                    }
                    found
                }
            };
            if lo > m {
                lo = m;
            }
            (lo as i64, hi)
        } else {
            let lo = match start {
                Bound::UnboundedPreceding => 0,
                _ => peers.start[pos] as i64,
            };
            let hi = match end {
                Bound::UnboundedFollowing => m as i64 - 1,
                _ => peers.end[pos] as i64,
            };
            (lo, hi)
        }
    };
    if hi < 0 || lo >= m as i64 || lo > hi {
        return Ok(None);
    }
    Ok(Some((clamp(lo), clamp(hi))))
}
