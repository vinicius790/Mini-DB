//! Catálogo, planejador e executor do SQL relacional.

use super::parser::{AggFn, BinOp, ColumnDef, Expr, Join, Select, SelectItem, Stmt};
use super::value::{decode_row, encode_row, key_of, Type, Value};
use super::Source;
use crate::db::{prefix_successor, Db, ExecResult, Op, RESERVED_PREFIX};
use crate::error::{Error, Result};
use crate::json::Json;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Catálogo
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct IndexDef {
    name: String,
    column: usize,
    unique: bool,
    id: u32,
}

#[derive(Clone, Debug)]
struct Table {
    name: String,
    id: u32,
    columns: Vec<ColumnDef>,
    /// `None` = rowid oculto e autoincrementado.
    pk: Option<usize>,
    indexes: Vec<IndexDef>,
    next_index_id: u32,
}

fn key(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![RESERVED_PREFIX];
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

fn catalog_key(name: &str) -> Vec<u8> {
    key(&[b"c", name.as_bytes()])
}

const TABLE_SEQ: &[u8] = &[RESERVED_PREFIX, b'q'];

impl Table {
    fn row_prefix(&self) -> Vec<u8> {
        key(&[b"t", &self.id.to_be_bytes()])
    }

    fn row_key(&self, pk: &[u8]) -> Vec<u8> {
        let mut k = self.row_prefix();
        k.extend_from_slice(pk);
        k
    }

    fn rowid_key(&self) -> Vec<u8> {
        key(&[b"s", &self.id.to_be_bytes()])
    }

    fn index_prefix(&self, idx: &IndexDef) -> Vec<u8> {
        key(&[b"x", &self.id.to_be_bytes(), &idx.id.to_be_bytes()])
    }

    fn index_key(&self, idx: &IndexDef, value: &Value, pk: &[u8]) -> Vec<u8> {
        let mut k = self.index_prefix(idx);
        k.extend(key_of(value));
        k.extend_from_slice(pk);
        k
    }

    fn column(&self, name: &str) -> Result<usize> {
        self.columns
            .iter()
            .position(|c| c.name == name)
            .ok_or_else(|| Error::Sql(format!("coluna desconhecida {}.{name}", self.name)))
    }

    /// Decodifica e completa colunas adicionadas depois da linha ser gravada.
    fn decode(&self, raw: &[u8]) -> Result<Vec<Value>> {
        let mut row = decode_row(raw)?;
        for col in &self.columns[row.len().min(self.columns.len())..] {
            row.push(col.default.clone().unwrap_or(Value::Null));
        }
        Ok(row)
    }

    fn to_json(&self) -> Json {
        let cols = self
            .columns
            .iter()
            .map(|c| {
                let mut j = Json::obj()
                    .put("name", Json::String(c.name.clone()))
                    .put("type", Json::String(c.ty.name().into()))
                    .put("not_null", Json::Bool(c.not_null));
                if let Some(d) = &c.default {
                    j = j.put("default", d.to_json());
                }
                j
            })
            .collect();
        let idx = self
            .indexes
            .iter()
            .map(|i| {
                Json::obj()
                    .put("name", Json::String(i.name.clone()))
                    .put("column", Json::Number(i.column as i64))
                    .put("unique", Json::Bool(i.unique))
                    .put("id", Json::Number(i.id as i64))
            })
            .collect();
        Json::obj()
            .put("name", Json::String(self.name.clone()))
            .put("id", Json::Number(self.id as i64))
            .put("pk", self.pk.map_or(Json::Null, |p| Json::Number(p as i64)))
            .put("columns", Json::Array(cols))
            .put("indexes", Json::Array(idx))
            .put("next_index_id", Json::Number(self.next_index_id as i64))
    }

    fn from_json(j: &Json) -> Result<Self> {
        let bad = || Error::Other("catálogo SQL corrompido".into());
        let num = |j: Option<&Json>| match j {
            Some(Json::Number(n)) => Ok(*n),
            _ => Err(bad()),
        };
        let arr = |j: Option<&Json>| match j {
            Some(Json::Array(a)) => Ok(a.clone()),
            _ => Err(bad()),
        };
        let flag = |j: Option<&Json>| matches!(j, Some(Json::Bool(true)));
        let columns = arr(j.get("columns"))?
            .iter()
            .map(|c| {
                Ok(ColumnDef {
                    name: c.get("name").and_then(Json::as_str).ok_or_else(bad)?.into(),
                    ty: c
                        .get("type")
                        .and_then(Json::as_str)
                        .and_then(Type::parse)
                        .ok_or_else(bad)?,
                    primary: false,
                    not_null: flag(c.get("not_null")),
                    unique: false,
                    default: c.get("default").map(json_value),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let indexes = arr(j.get("indexes"))?
            .iter()
            .map(|i| {
                Ok(IndexDef {
                    name: i.get("name").and_then(Json::as_str).ok_or_else(bad)?.into(),
                    column: num(i.get("column"))? as usize,
                    unique: flag(i.get("unique")),
                    id: num(i.get("id"))? as u32,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let pk = match j.get("pk") {
            Some(Json::Number(n)) => Some(*n as usize),
            _ => None,
        };
        Ok(Self {
            name: j.get("name").and_then(Json::as_str).ok_or_else(bad)?.into(),
            id: num(j.get("id"))? as u32,
            columns,
            pk,
            indexes,
            next_index_id: num(j.get("next_index_id"))? as u32,
        })
    }
}

fn json_value(j: &Json) -> Value {
    match j {
        Json::Number(n) => Value::Int(*n),
        Json::Float(x) => Value::Real(*x),
        Json::String(s) => Value::Text(s.clone()),
        Json::Bool(b) => Value::Bool(*b),
        _ => Value::Null,
    }
}

fn load_table(src: &mut dyn Source, name: &str) -> Result<Table> {
    let raw = src
        .get(&catalog_key(name))?
        .ok_or_else(|| Error::UnknownTable(name.to_string()))?;
    let text = String::from_utf8(raw).map_err(|_| Error::Other("catálogo não UTF-8".into()))?;
    Table::from_json(&Json::parse(&text)?)
}

fn list_tables(src: &mut dyn Source) -> Result<Vec<Table>> {
    let start = key(&[b"c"]);
    let end = key(&[b"d"]);
    let mut raw = Vec::new();
    src.scan(&start, Some(&end), &mut |_, v| {
        raw.push(v);
        Ok(true)
    })?;
    raw.iter()
        .map(|v| Table::from_json(&Json::parse(&String::from_utf8_lossy(v))?))
        .collect()
}

// ---------------------------------------------------------------------------
// Escritas pendentes de um comando (atômicas via um único lote no WAL)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Pending {
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Pending {
    fn put(&mut self, k: Vec<u8>, v: Vec<u8>) {
        self.writes.insert(k, Some(v));
    }

    fn del(&mut self, k: Vec<u8>) {
        self.writes.insert(k, None);
    }

    fn get(&self, src: &mut dyn Source, k: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.writes.get(k) {
            Some(v) => Ok(v.clone()),
            None => src.get(k),
        }
    }

    /// Chaves visíveis em `[start, end)` (banco + pendentes).
    fn keys(&self, src: &mut dyn Source, start: &[u8], end: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut keys = BTreeSet::new();
        src.scan(start, Some(end), &mut |k, _| {
            keys.insert(k);
            Ok(true)
        })?;
        for (k, v) in self.writes.range(start.to_vec()..end.to_vec()) {
            match v {
                Some(_) => keys.insert(k.clone()),
                None => keys.remove(k),
            };
        }
        Ok(keys.into_iter().collect())
    }

    fn commit(self, db: &mut Db) -> Result<()> {
        let ops = self
            .writes
            .into_iter()
            .map(|(key, v)| match v {
                Some(value) => Op::Put { key, value },
                None => Op::Delete { key },
            })
            .collect();
        db.write_internal(ops)
    }
}

// ---------------------------------------------------------------------------
// Avaliação de expressões
// ---------------------------------------------------------------------------

/// Colunas visíveis: (alias da tabela, nome da coluna) na ordem da linha.
#[derive(Clone, Default)]
struct Scope {
    cols: Vec<(String, String)>,
}

impl Scope {
    fn add(&mut self, alias: &str, table: &Table) {
        for c in &table.columns {
            self.cols.push((alias.to_string(), c.name.clone()));
        }
    }

    fn resolve(&self, table: Option<&str>, name: &str) -> Result<usize> {
        let mut hits = self
            .cols
            .iter()
            .enumerate()
            .filter(|(_, (t, c))| c == name && table.is_none_or(|x| x == t));
        match (hits.next(), hits.next()) {
            (Some((i, _)), None) => Ok(i),
            (Some(_), Some(_)) => Err(Error::Sql(format!("coluna ambígua {name}"))),
            _ => Err(Error::Sql(format!(
                "coluna desconhecida {}{name}",
                table.map(|t| format!("{t}.")).unwrap_or_default()
            ))),
        }
    }
}

/// Valores de agregados já calculados para o grupo corrente.
type AggValues<'a> = Option<(&'a [Expr], &'a [Value])>;

fn like(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    // DP clássico O(n·m): dp[j] = p[..i] casa com t[..j].
    let mut dp = vec![false; t.len() + 1];
    dp[0] = true;
    for &pc in &p {
        let mut next = vec![false; t.len() + 1];
        if pc == '%' {
            let mut any = false;
            for j in 0..=t.len() {
                any |= dp[j];
                next[j] = any;
            }
        } else {
            for j in 1..=t.len() {
                next[j] = dp[j - 1] && (pc == '_' || pc == t[j - 1]);
            }
        }
        dp = next;
    }
    dp[t.len()]
}

fn arith(a: Value, op: BinOp, b: Value) -> Result<Value> {
    if a.is_null() || b.is_null() {
        return Ok(Value::Null);
    }
    if op == BinOp::Concat {
        return Ok(Value::Text(format!("{a}{b}")));
    }
    let overflow = || Error::Sql("estouro aritmético".into());
    if let (Value::Int(x), Value::Int(y)) = (&a, &b) {
        let (x, y) = (*x, *y);
        return Ok(match op {
            BinOp::Add => Value::Int(x.checked_add(y).ok_or_else(overflow)?),
            BinOp::Sub => Value::Int(x.checked_sub(y).ok_or_else(overflow)?),
            BinOp::Mul => Value::Int(x.checked_mul(y).ok_or_else(overflow)?),
            BinOp::Div if y == 0 => Value::Null,
            BinOp::Div => Value::Int(x.checked_div(y).ok_or_else(overflow)?),
            BinOp::Mod if y == 0 => Value::Null,
            _ => Value::Int(x.checked_rem(y).ok_or_else(overflow)?),
        });
    }
    let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) else {
        return Err(Error::Sql(format!(
            "operação aritmética entre {} e {}",
            a.type_name(),
            b.type_name()
        )));
    };
    Ok(match op {
        BinOp::Add => Value::Real(x + y),
        BinOp::Sub => Value::Real(x - y),
        BinOp::Mul => Value::Real(x * y),
        BinOp::Div if y == 0.0 => Value::Null,
        BinOp::Div => Value::Real(x / y),
        BinOp::Mod if y == 0.0 => Value::Null,
        _ => Value::Real(x % y),
    })
}

fn truth(v: Option<bool>) -> Value {
    v.map_or(Value::Null, Value::Bool)
}

fn eval(e: &Expr, row: &[Value], scope: &Scope, aggs: AggValues<'_>) -> Result<Value> {
    let ev = |x: &Expr| eval(x, row, scope, aggs);
    Ok(match e {
        Expr::Lit(v) => v.clone(),
        Expr::Col(t, name) => row[scope.resolve(t.as_deref(), name)?].clone(),
        Expr::Neg(x) => match ev(x)? {
            Value::Int(n) => Value::Int(
                n.checked_neg()
                    .ok_or_else(|| Error::Sql("estouro".into()))?,
            ),
            Value::Real(x) => Value::Real(-x),
            Value::Null => Value::Null,
            other => return Err(Error::Sql(format!("negação de {}", other.type_name()))),
        },
        Expr::Not(x) => truth(ev(x)?.truth().map(|b| !b)),
        Expr::Bin(a, BinOp::And, b) => {
            let (a, b) = (ev(a)?.truth(), ev(b)?.truth());
            truth(match (a, b) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            })
        }
        Expr::Bin(a, BinOp::Or, b) => {
            let (a, b) = (ev(a)?.truth(), ev(b)?.truth());
            truth(match (a, b) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            })
        }
        Expr::Bin(a, op, b) => {
            let (a, b) = (ev(a)?, ev(b)?);
            let cmp = |f: fn(Ordering) -> bool| truth(a.sql_cmp(&b).map(f));
            match op {
                BinOp::Eq => cmp(|o| o == Ordering::Equal),
                BinOp::Ne => cmp(|o| o != Ordering::Equal),
                BinOp::Lt => cmp(|o| o == Ordering::Less),
                BinOp::Le => cmp(|o| o != Ordering::Greater),
                BinOp::Gt => cmp(|o| o == Ordering::Greater),
                BinOp::Ge => cmp(|o| o != Ordering::Less),
                _ => arith(a, *op, b)?,
            }
        }
        Expr::IsNull(x, neg) => Value::Bool(ev(x)?.is_null() != *neg),
        Expr::Like(x, p, neg) => match (ev(x)?, ev(p)?) {
            (Value::Null, _) | (_, Value::Null) => Value::Null,
            (x, p) => Value::Bool(like(&x.to_string(), &p.to_string()) != *neg),
        },
        Expr::In(x, list, neg) => {
            let x = ev(x)?;
            if x.is_null() {
                return Ok(Value::Null);
            }
            let mut saw_null = false;
            for item in list {
                match x.sql_cmp(&ev(item)?) {
                    Some(Ordering::Equal) => return Ok(Value::Bool(!neg)),
                    None => saw_null = true,
                    _ => {}
                }
            }
            if saw_null {
                Value::Null
            } else {
                Value::Bool(*neg)
            }
        }
        Expr::Between(x, lo, hi, neg) => {
            let x = ev(x)?;
            let ge = x.sql_cmp(&ev(lo)?).map(|o| o != Ordering::Less);
            let le = x.sql_cmp(&ev(hi)?).map(|o| o != Ordering::Greater);
            truth(match (ge, le) {
                (Some(a), Some(b)) => Some((a && b) != *neg),
                _ => None,
            })
        }
        Expr::Func(name, args) => {
            let vals = args.iter().map(ev).collect::<Result<Vec<_>>>()?;
            scalar(name, vals)?
        }
        Expr::Agg(..) => match aggs
            .and_then(|(exprs, vals)| exprs.iter().position(|x| x == e).map(|i| &vals[i]))
        {
            Some(v) => v.clone(),
            None => return Err(Error::Sql("agregado fora de SELECT/HAVING/ORDER BY".into())),
        },
    })
}

fn scalar(name: &str, mut v: Vec<Value>) -> Result<Value> {
    let arity = |n: usize| {
        if v.len() == n {
            Ok(())
        } else {
            Err(Error::Sql(format!("{name}() espera {n} argumento(s)")))
        }
    };
    Ok(match name {
        "coalesce" | "ifnull" => v.into_iter().find(|x| !x.is_null()).unwrap_or(Value::Null),
        "lower" | "upper" | "length" | "abs" | "typeof" | "trim" => {
            arity(1)?;
            let x = v.pop().expect("aridade");
            match (name, x) {
                ("typeof", x) => Value::Text(x.type_name().to_lowercase()),
                (_, Value::Null) => Value::Null,
                ("lower", x) => Value::Text(x.to_string().to_lowercase()),
                ("upper", x) => Value::Text(x.to_string().to_uppercase()),
                ("trim", x) => Value::Text(x.to_string().trim().to_string()),
                ("length", x) => Value::Int(x.to_string().chars().count() as i64),
                ("abs", Value::Int(n)) => Value::Int(
                    n.checked_abs()
                        .ok_or_else(|| Error::Sql("estouro".into()))?,
                ),
                ("abs", Value::Real(x)) => Value::Real(x.abs()),
                (_, x) => return Err(Error::Sql(format!("{name}() não aceita {}", x.type_name()))),
            }
        }
        "round" => {
            let digits = match v.get(1) {
                Some(Value::Int(d)) => *d as i32,
                None => 0,
                _ => return Err(Error::Sql("round(x, casas)".into())),
            };
            match v.first().and_then(Value::as_f64) {
                Some(x) => {
                    let m = 10f64.powi(digits);
                    Value::Real((x * m).round() / m)
                }
                None => Value::Null,
            }
        }
        "substr" | "substring" => {
            let s: Vec<char> = match v.first() {
                Some(Value::Null) | None => return Ok(Value::Null),
                Some(x) => x.to_string().chars().collect(),
            };
            let start = match v.get(1) {
                Some(Value::Int(n)) => (*n).max(1) as usize - 1,
                _ => return Err(Error::Sql("substr(texto, início[, tamanho])".into())),
            };
            let len = match v.get(2) {
                Some(Value::Int(n)) => (*n).max(0) as usize,
                None => usize::MAX,
                _ => return Err(Error::Sql("substr(texto, início[, tamanho])".into())),
            };
            Value::Text(s.iter().skip(start).take(len).collect())
        }
        _ => return Err(Error::Sql(format!("função desconhecida {name}()"))),
    })
}

fn is_true(e: Option<&Expr>, row: &[Value], scope: &Scope, aggs: AggValues<'_>) -> Result<bool> {
    match e {
        None => Ok(true),
        Some(e) => Ok(eval(e, row, scope, aggs)?.truth() == Some(true)),
    }
}

fn conjuncts(e: &Expr, out: &mut Vec<Expr>) {
    match e {
        Expr::Bin(a, BinOp::And, b) => {
            conjuncts(a, out);
            conjuncts(b, out);
        }
        other => out.push(other.clone()),
    }
}

fn contains_agg(e: &Expr) -> bool {
    let mut found = Vec::new();
    collect_aggs(e, &mut found);
    !found.is_empty()
}

fn collect_aggs(e: &Expr, out: &mut Vec<Expr>) {
    match e {
        Expr::Agg(..) => {
            if !out.contains(e) {
                out.push(e.clone());
            }
        }
        Expr::Neg(x) | Expr::Not(x) | Expr::IsNull(x, _) => collect_aggs(x, out),
        Expr::Bin(a, _, b) | Expr::Like(a, b, _) => {
            collect_aggs(a, out);
            collect_aggs(b, out);
        }
        Expr::Between(a, b, c, _) => {
            for x in [a, b, c] {
                collect_aggs(x, out);
            }
        }
        Expr::In(x, list, _) => {
            collect_aggs(x, out);
            list.iter().for_each(|i| collect_aggs(i, out));
        }
        Expr::Func(_, args) => args.iter().for_each(|a| collect_aggs(a, out)),
        Expr::Lit(_) | Expr::Col(..) => {}
    }
}

fn columns_of(e: &Expr, out: &mut Vec<(Option<String>, String)>) {
    match e {
        Expr::Col(t, c) => out.push((t.clone(), c.clone())),
        Expr::Neg(x) | Expr::Not(x) | Expr::IsNull(x, _) => columns_of(x, out),
        Expr::Bin(a, _, b) | Expr::Like(a, b, _) => {
            columns_of(a, out);
            columns_of(b, out);
        }
        Expr::Between(a, b, c, _) => {
            for x in [a, b, c] {
                columns_of(x, out);
            }
        }
        Expr::In(x, list, _) => {
            columns_of(x, out);
            list.iter().for_each(|i| columns_of(i, out));
        }
        Expr::Func(_, args) => args.iter().for_each(|a| columns_of(a, out)),
        Expr::Agg(_, arg, _) => {
            if let Some(a) = arg {
                columns_of(a, out);
            }
        }
        Expr::Lit(_) => {}
    }
}

fn expr_name(e: &Expr) -> String {
    match e {
        Expr::Col(_, c) => c.clone(),
        Expr::Agg(f, arg, _) => {
            let f = format!("{f:?}").to_lowercase();
            match arg {
                None => format!("{f}(*)"),
                Some(a) => format!("{f}({})", expr_name(a)),
            }
        }
        Expr::Func(name, _) => format!("{name}(...)"),
        Expr::Lit(v) => v.to_string(),
        _ => "?column?".into(),
    }
}

// ---------------------------------------------------------------------------
// Planejamento de acesso a uma tabela
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Access {
    Full,
    Point(Value),
    Range(Option<Value>, Option<Value>),
    Index(usize, Value),
}

impl Access {
    fn describe(&self, t: &Table) -> String {
        let pk =
            t.pk.map_or("rowid".to_string(), |p| t.columns[p].name.clone());
        match self {
            Self::Full => format!("SCAN {}", t.name),
            Self::Point(v) => format!("SEARCH {} USING PRIMARY KEY ({pk}={v})", t.name),
            Self::Range(lo, hi) => format!(
                "SEARCH {} USING PRIMARY KEY RANGE ({} <= {pk} <= {})",
                t.name,
                lo.as_ref().map_or("-inf".into(), Value::to_string),
                hi.as_ref().map_or("+inf".into(), Value::to_string)
            ),
            Self::Index(i, v) => {
                let idx = &t.indexes[*i];
                format!(
                    "SEARCH {} USING {}INDEX {} ({}={v})",
                    t.name,
                    if idx.unique { "UNIQUE " } else { "" },
                    idx.name,
                    t.columns[idx.column].name
                )
            }
        }
    }
}

/// Escolhe o caminho de acesso a partir de `coluna op literal` no WHERE.
/// O filtro completo é reaplicado depois, então o plano só precisa ser um
/// superconjunto correto das linhas.
fn plan(t: &Table, alias: &str, filter: Option<&Expr>, scope: &Scope, offset: usize) -> Access {
    let Some(filter) = filter else {
        return Access::Full;
    };
    let mut parts = Vec::new();
    conjuncts(filter, &mut parts);
    let column_of = |e: &Expr| match e {
        Expr::Col(q, name) if q.as_deref().is_none_or(|q| q == alias) => {
            let i = scope.resolve(q.as_deref(), name).ok()?;
            (i >= offset && i < offset + t.columns.len() && scope.cols[i].0 == alias)
                .then_some(i - offset)
        }
        _ => None,
    };
    let lit = |e: &Expr, col: usize| match e {
        Expr::Lit(v) if !v.is_null() => v.clone().coerce(t.columns[col].ty).ok(),
        Expr::Neg(x) => match &**x {
            Expr::Lit(Value::Int(n)) => Value::Int(-n).coerce(t.columns[col].ty).ok(),
            Expr::Lit(Value::Real(x)) => Value::Real(-x).coerce(t.columns[col].ty).ok(),
            _ => None,
        },
        _ => None,
    };
    let (mut lo, mut hi, mut index): (Option<Value>, Option<Value>, Option<(usize, Value)>) =
        (None, None, None);
    for part in &parts {
        let (col, op, v) = match part {
            Expr::Bin(a, op, b) => match (column_of(a), column_of(b)) {
                (Some(c), _) => match lit(b, c) {
                    Some(v) => (c, *op, v),
                    None => continue,
                },
                (_, Some(c)) => match lit(a, c) {
                    Some(v) => {
                        let flipped = match op {
                            BinOp::Lt => BinOp::Gt,
                            BinOp::Le => BinOp::Ge,
                            BinOp::Gt => BinOp::Lt,
                            BinOp::Ge => BinOp::Le,
                            o => *o,
                        };
                        (c, flipped, v)
                    }
                    None => continue,
                },
                _ => continue,
            },
            Expr::Between(x, a, b, false) => {
                if let Some(c) = column_of(x) {
                    if Some(c) == t.pk {
                        if let (Some(a), Some(b)) = (lit(a, c), lit(b, c)) {
                            lo = Some(a);
                            hi = Some(b);
                        }
                    }
                }
                continue;
            }
            _ => continue,
        };
        if Some(col) == t.pk {
            match op {
                BinOp::Eq => return Access::Point(v),
                BinOp::Gt | BinOp::Ge => lo = Some(v),
                BinOp::Lt | BinOp::Le => hi = Some(v),
                _ => {}
            }
        } else if op == BinOp::Eq {
            if let Some(i) = t.indexes.iter().position(|ix| ix.column == col) {
                let better = index
                    .as_ref()
                    .is_none_or(|(j, _)| t.indexes[i].unique && !t.indexes[*j].unique);
                if better {
                    index = Some((i, v));
                }
            }
        }
    }
    match index {
        Some((i, v)) if t.indexes[i].unique || (lo.is_none() && hi.is_none()) => {
            Access::Index(i, v)
        }
        _ if lo.is_some() || hi.is_some() => Access::Range(lo, hi),
        Some((i, v)) => Access::Index(i, v),
        None => Access::Full,
    }
}

/// Visita as linhas candidatas do plano: `(pk codificada, linha)`.
fn fetch(
    src: &mut dyn Source,
    t: &Table,
    access: &Access,
    visit: &mut dyn FnMut(Vec<u8>, Vec<Value>) -> Result<bool>,
) -> Result<()> {
    let prefix = t.row_prefix();
    let pk_of = |k: &[u8]| k[prefix.len()..].to_vec();
    match access {
        Access::Point(v) => {
            let pk = key_of(v);
            if let Some(raw) = src.get(&t.row_key(&pk))? {
                visit(pk, t.decode(&raw)?)?;
            }
            Ok(())
        }
        Access::Index(i, v) => {
            let mut p = t.index_prefix(&t.indexes[*i]);
            p.extend(key_of(v));
            let end = prefix_successor(&p).expect("prefixo não é só 0xFF");
            let mut pks = Vec::new();
            src.scan(&p, Some(&end), &mut |_, pk| {
                pks.push(pk);
                Ok(true)
            })?;
            for pk in pks {
                if let Some(raw) = src.get(&t.row_key(&pk))? {
                    if !visit(pk, t.decode(&raw)?)? {
                        break;
                    }
                }
            }
            Ok(())
        }
        Access::Full | Access::Range(..) => {
            let (start, end) = match access {
                Access::Range(lo, hi) => (
                    lo.as_ref()
                        .map_or(prefix.clone(), |v| t.row_key(&key_of(v))),
                    // Codificação auto-delimitada: nada fica entre enc(hi) e enc(hi)+FF.
                    hi.as_ref().map_or_else(
                        || prefix_successor(&prefix).expect("prefixo"),
                        |v| {
                            let mut k = t.row_key(&key_of(v));
                            k.push(0xFF);
                            k
                        },
                    ),
                ),
                _ => (prefix.clone(), prefix_successor(&prefix).expect("prefixo")),
            };
            let mut failure = None;
            src.scan(&start, Some(&end), &mut |k, raw| match t.decode(&raw) {
                Ok(row) => visit(pk_of(&k), row),
                Err(e) => {
                    failure = Some(e);
                    Ok(false)
                }
            })?;
            failure.map_or(Ok(()), Err)
        }
    }
}

// ---------------------------------------------------------------------------
// Execução
// ---------------------------------------------------------------------------

pub(super) fn run(db: &mut Db, stmt: Stmt) -> Result<ExecResult> {
    if let Some(result) = read_only(db, stmt.clone()) {
        return result;
    }
    if db.is_read_only() {
        return Err(Error::ReadOnly);
    }
    let mut pending = Pending::default();
    let msg = match stmt {
        Stmt::CreateTable {
            name,
            columns,
            if_not_exists,
        } => create_table(db, &mut pending, name, columns, if_not_exists)?,
        Stmt::DropTable { name, if_exists } => match load_table(db, &name) {
            Err(Error::UnknownTable(_)) if if_exists => {
                return Ok(ExecResult::Ok("DROP TABLE 0".into()))
            }
            t => {
                let t = t?;
                let mut ends = vec![(
                    t.row_prefix(),
                    prefix_successor(&t.row_prefix()).expect("p"),
                )];
                ends.extend(t.indexes.iter().map(|i| {
                    let p = t.index_prefix(i);
                    let e = prefix_successor(&p).expect("p");
                    (p, e)
                }));
                for (s, e) in ends {
                    for k in pending.keys(db, &s, &e)? {
                        pending.del(k);
                    }
                }
                pending.del(t.rowid_key());
                pending.del(catalog_key(&t.name));
                format!("DROP TABLE {}", t.name)
            }
        },
        Stmt::CreateIndex {
            name,
            table,
            column,
            unique,
            if_not_exists,
        } => {
            if let Some(owner) = list_tables(db)?
                .into_iter()
                .find(|t| t.indexes.iter().any(|i| i.name == name))
            {
                if if_not_exists {
                    return Ok(ExecResult::Ok(format!(
                        "CREATE INDEX {name} (já existe em {})",
                        owner.name
                    )));
                }
                return Err(Error::Sql(format!("índice {name} já existe")));
            }
            let mut t = load_table(db, &table)?;
            let col = t.column(&column)?;
            let idx = IndexDef {
                name: name.clone(),
                column: col,
                unique,
                id: t.next_index_id,
            };
            t.next_index_id += 1;
            let mut rows = Vec::new();
            fetch(db, &t, &Access::Full, &mut |pk, row| {
                rows.push((pk, row));
                Ok(true)
            })?;
            let mut seen = BTreeSet::new();
            for (pk, row) in &rows {
                let v = &row[col];
                if unique && !v.is_null() && !seen.insert(key_of(v)) {
                    return Err(Error::Constraint(format!(
                        "valor duplicado {v} impede UNIQUE {name}"
                    )));
                }
                pending.put(t.index_key(&idx, v, pk), pk.clone());
            }
            t.indexes.push(idx);
            pending.put(catalog_key(&t.name), t.to_json().stringify().into_bytes());
            format!("CREATE INDEX {name} rows={}", rows.len())
        }
        Stmt::DropIndex { name, if_exists } => {
            match list_tables(db)?
                .into_iter()
                .find(|t| t.indexes.iter().any(|i| i.name == name))
            {
                None if if_exists => "DROP INDEX 0".into(),
                None => return Err(Error::UnknownIndex(name)),
                Some(mut t) => {
                    let pos = t
                        .indexes
                        .iter()
                        .position(|i| i.name == name)
                        .expect("achado");
                    let idx = t.indexes.remove(pos);
                    let p = t.index_prefix(&idx);
                    for k in pending.keys(db, &p, &prefix_successor(&p).expect("p"))? {
                        pending.del(k);
                    }
                    pending.put(catalog_key(&t.name), t.to_json().stringify().into_bytes());
                    format!("DROP INDEX {name}")
                }
            }
        }
        Stmt::AddColumn { table, column } => {
            let mut t = load_table(db, &table)?;
            if column.primary || column.unique {
                return Err(Error::Sql(
                    "ADD COLUMN não aceita PRIMARY KEY/UNIQUE".into(),
                ));
            }
            if column.not_null && column.default.is_none() {
                return Err(Error::Sql("ADD COLUMN NOT NULL exige DEFAULT".into()));
            }
            if t.column(&column.name).is_ok() {
                return Err(Error::Sql(format!("coluna {} já existe", column.name)));
            }
            let mut column = column;
            column.default = column.default.map(|d| d.coerce(column.ty)).transpose()?;
            t.columns.push(column);
            pending.put(catalog_key(&t.name), t.to_json().stringify().into_bytes());
            format!("ALTER TABLE {} ADD COLUMN", t.name)
        }
        Stmt::Insert {
            table,
            columns,
            rows,
        } => insert(db, &mut pending, &table, columns, rows)?,
        Stmt::Update {
            table,
            sets,
            filter,
        } => {
            let t = load_table(db, &table)?;
            let targets = matching(db, &t, filter.as_ref())?;
            let sets = sets
                .into_iter()
                .map(|(c, e)| Ok((t.column(&c)?, e)))
                .collect::<Result<Vec<_>>>()?;
            let scope = single_scope(&t);
            let n = targets.len();
            // Primeiro remove todas as versões antigas: trocas de PK/UNIQUE entre
            // linhas do mesmo UPDATE não geram falso conflito.
            let mut new_rows = Vec::with_capacity(n);
            for (pk, old) in &targets {
                let mut row = old.clone();
                for (c, e) in &sets {
                    row[*c] = eval(e, old, &scope, None)?;
                }
                remove_row(&t, &mut pending, pk, old);
                new_rows.push(row);
            }
            for row in new_rows {
                write_row(db, &t, &mut pending, row, false)?;
            }
            format!("UPDATE {n}")
        }
        Stmt::Delete { table, filter } => {
            let t = load_table(db, &table)?;
            let targets = matching(db, &t, filter.as_ref())?;
            for (pk, row) in &targets {
                remove_row(&t, &mut pending, pk, row);
            }
            format!("DELETE {}", targets.len())
        }
        Stmt::Select(_) | Stmt::ShowTables | Stmt::Describe(_) | Stmt::Explain(_) => {
            unreachable!("leitura")
        }
    };
    pending.commit(db)?;
    Ok(ExecResult::Ok(msg))
}

/// Comandos de leitura (também usados por snapshots). `None` = é escrita.
pub(super) fn read_only(src: &mut dyn Source, stmt: Stmt) -> Option<Result<ExecResult>> {
    Some(match stmt {
        Stmt::Select(s) => select(src, &s),
        Stmt::ShowTables => list_tables(src).map(|ts| ExecResult::Table {
            columns: vec!["name".into(), "columns".into(), "indexes".into()],
            rows: ts
                .into_iter()
                .map(|t| {
                    vec![
                        Value::Text(t.name),
                        Value::Int(t.columns.len() as i64),
                        Value::Int(t.indexes.len() as i64),
                    ]
                })
                .collect(),
        }),
        Stmt::Describe(name) => load_table(src, &name).map(|t| ExecResult::Table {
            columns: ["column", "type", "pk", "not_null", "default", "index"]
                .map(String::from)
                .to_vec(),
            rows: t
                .columns
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let idx: Vec<_> = t
                        .indexes
                        .iter()
                        .filter(|x| x.column == i)
                        .map(|x| x.name.clone())
                        .collect();
                    vec![
                        Value::Text(c.name.clone()),
                        Value::Text(c.ty.name().into()),
                        Value::Bool(t.pk == Some(i)),
                        Value::Bool(c.not_null || t.pk == Some(i)),
                        c.default.clone().unwrap_or(Value::Null),
                        if idx.is_empty() {
                            Value::Null
                        } else {
                            Value::Text(idx.join(","))
                        },
                    ]
                })
                .collect(),
        }),
        Stmt::Explain(inner) => explain(src, &inner).map(ExecResult::Ok),
        _ => return None,
    })
}

fn single_scope(t: &Table) -> Scope {
    let mut s = Scope::default();
    s.add(&t.name, t);
    s
}

fn matching(
    src: &mut dyn Source,
    t: &Table,
    filter: Option<&Expr>,
) -> Result<Vec<(Vec<u8>, Vec<Value>)>> {
    let scope = single_scope(t);
    let access = plan(t, &t.name, filter, &scope, 0);
    let mut out = Vec::new();
    let mut failure = None;
    fetch(
        src,
        t,
        &access,
        &mut |pk, row| match is_true(filter, &row, &scope, None) {
            Ok(true) => {
                out.push((pk, row));
                Ok(true)
            }
            Ok(false) => Ok(true),
            Err(e) => {
                failure = Some(e);
                Ok(false)
            }
        },
    )?;
    failure.map_or(Ok(out), Err)
}

fn remove_row(t: &Table, pending: &mut Pending, pk: &[u8], row: &[Value]) {
    pending.del(t.row_key(pk));
    for idx in &t.indexes {
        pending.del(t.index_key(idx, &row[idx.column], pk));
    }
}

/// Valida tipos/restrições e grava linha + entradas de índice.
fn write_row(
    db: &mut Db,
    t: &Table,
    pending: &mut Pending,
    mut row: Vec<Value>,
    autoinc: bool,
) -> Result<()> {
    for (i, col) in t.columns.iter().enumerate() {
        row[i] = std::mem::replace(&mut row[i], Value::Null).coerce(col.ty)?;
    }
    let seq_key = t.rowid_key();
    let next = pending
        .get(db, &seq_key)?
        .and_then(|v| v.try_into().ok())
        .map(i64::from_le_bytes)
        .unwrap_or(1);
    let pk_value = match t.pk {
        None => Value::Int(next),
        Some(p) if row[p].is_null() && autoinc && t.columns[p].ty == Type::Int => {
            row[p] = Value::Int(next);
            row[p].clone()
        }
        Some(p) if row[p].is_null() => {
            return Err(Error::Constraint(format!(
                "PRIMARY KEY {} não pode ser NULL",
                t.columns[p].name
            )))
        }
        Some(p) => row[p].clone(),
    };
    if let Value::Int(n) = pk_value {
        if n >= next {
            pending.put(seq_key, n.saturating_add(1).to_le_bytes().to_vec());
        }
    }
    for (i, col) in t.columns.iter().enumerate() {
        if col.not_null && row[i].is_null() {
            return Err(Error::Constraint(format!(
                "{}.{} é NOT NULL",
                t.name, col.name
            )));
        }
    }
    let pk = key_of(&pk_value);
    let row_key = t.row_key(&pk);
    if pending.get(db, &row_key)?.is_some() {
        return Err(Error::Constraint(format!(
            "chave primária duplicada {pk_value} em {}",
            t.name
        )));
    }
    for idx in &t.indexes {
        let v = &row[idx.column];
        if idx.unique && !v.is_null() {
            let mut p = t.index_prefix(idx);
            p.extend(key_of(v));
            if !pending
                .keys(db, &p, &prefix_successor(&p).expect("p"))?
                .is_empty()
            {
                return Err(Error::Constraint(format!(
                    "valor duplicado {v} em {}.{} (UNIQUE {})",
                    t.name, t.columns[idx.column].name, idx.name
                )));
            }
        }
        let entry = t.index_key(idx, v, &pk);
        if entry.len() > crate::MAX_KEY_LEN {
            return Err(Error::Constraint(format!(
                "valor longo demais para o índice {} ({} bytes na chave; máx {})",
                idx.name,
                entry.len(),
                crate::MAX_KEY_LEN
            )));
        }
        pending.put(entry, pk.clone());
    }
    let encoded = encode_row(&row);
    if encoded.len() > crate::MAX_VALUE_LEN {
        return Err(Error::Constraint(format!(
            "linha de {} bytes excede o máximo de {} bytes",
            encoded.len(),
            crate::MAX_VALUE_LEN
        )));
    }
    pending.put(row_key, encoded);
    Ok(())
}

fn create_table(
    db: &mut Db,
    pending: &mut Pending,
    name: String,
    columns: Vec<ColumnDef>,
    if_not_exists: bool,
) -> Result<String> {
    if matches!(name.as_str(), "kv" | "t") {
        return Err(Error::Sql(
            "kv e t são reservados à tabela chave-valor".into(),
        ));
    }
    match load_table(db, &name) {
        Ok(_) if if_not_exists => return Ok(format!("CREATE TABLE {name} (já existe)")),
        Ok(_) => return Err(Error::Sql(format!("tabela {name} já existe"))),
        Err(Error::UnknownTable(_)) => {}
        Err(e) => return Err(e),
    }
    let mut names = BTreeSet::new();
    for c in &columns {
        if !names.insert(c.name.as_str()) {
            return Err(Error::Sql(format!("coluna {} repetida", c.name)));
        }
    }
    let pks: Vec<usize> = columns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.primary)
        .map(|(i, _)| i)
        .collect();
    if pks.len() > 1 {
        return Err(Error::Sql(
            "só uma coluna pode ser PRIMARY KEY (chave composta não suportada)".into(),
        ));
    }
    let id = db
        .get_raw(TABLE_SEQ)?
        .and_then(|v| v.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(1);
    let mut columns = columns;
    for c in &mut columns {
        c.default = c.default.take().map(|d| d.coerce(c.ty)).transpose()?;
    }
    let mut t = Table {
        name: name.clone(),
        id,
        pk: pks.first().copied(),
        indexes: Vec::new(),
        next_index_id: 1,
        columns,
    };
    for i in 0..t.columns.len() {
        if t.columns[i].unique && t.pk != Some(i) {
            t.indexes.push(IndexDef {
                name: format!("{name}_{}_key", t.columns[i].name),
                column: i,
                unique: true,
                id: t.next_index_id,
            });
            t.next_index_id += 1;
        }
    }
    pending.put(TABLE_SEQ.to_vec(), (id + 1).to_le_bytes().to_vec());
    pending.put(catalog_key(&name), t.to_json().stringify().into_bytes());
    Ok(format!("CREATE TABLE {name}"))
}

fn insert(
    db: &mut Db,
    pending: &mut Pending,
    table: &str,
    columns: Option<Vec<String>>,
    rows: Vec<Vec<Expr>>,
) -> Result<String> {
    let t = load_table(db, table)?;
    let targets: Vec<usize> = match &columns {
        Some(cols) => cols.iter().map(|c| t.column(c)).collect::<Result<_>>()?,
        None => (0..t.columns.len()).collect(),
    };
    let empty = Scope::default();
    let n = rows.len();
    for exprs in rows {
        if exprs.len() != targets.len() {
            return Err(Error::Sql(format!(
                "{} valores para {} colunas",
                exprs.len(),
                targets.len()
            )));
        }
        let mut row: Vec<Value> = t
            .columns
            .iter()
            .map(|c| c.default.clone().unwrap_or(Value::Null))
            .collect();
        for (i, e) in targets.iter().zip(&exprs) {
            row[*i] = eval(e, &[], &empty, None)?;
        }
        write_row(db, &t, pending, row, true)?;
    }
    Ok(format!("INSERT {n}"))
}

// ---------------------------------------------------------------------------
// SELECT
// ---------------------------------------------------------------------------

struct Joined {
    table: Table,
    join: Join,
    /// Coluna da tabela interna e expressão externa para busca por chave.
    lookup: Option<(usize, Expr)>,
}

fn join_lookup(t: &Table, alias: &str, on: &Expr, outer: &Scope) -> Option<(usize, Expr)> {
    let mut parts = Vec::new();
    conjuncts(on, &mut parts);
    let mut best: Option<(usize, Expr, u8)> = None;
    for p in parts {
        let Expr::Bin(a, BinOp::Eq, b) = p else {
            continue;
        };
        for (inner, other) in [(&a, &b), (&b, &a)] {
            let Expr::Col(q, name) = &**inner else {
                continue;
            };
            if q.as_deref().is_some_and(|q| q != alias)
                || (q.is_none() && outer.resolve(None, name).is_ok())
            {
                continue;
            }
            let Ok(col) = t.column(name) else { continue };
            let mut refs = Vec::new();
            columns_of(other, &mut refs);
            if refs
                .iter()
                .any(|(q, c)| outer.resolve(q.as_deref(), c).is_err())
            {
                continue;
            }
            let rank = if Some(col) == t.pk {
                3
            } else if t.indexes.iter().any(|i| i.column == col && i.unique) {
                2
            } else if t.indexes.iter().any(|i| i.column == col) {
                1
            } else {
                0
            };
            if rank > 0 && best.as_ref().is_none_or(|b| rank > b.2) {
                best = Some((col, (**other).clone(), rank));
            }
        }
    }
    best.map(|(c, e, _)| (c, e))
}

fn setup(src: &mut dyn Source, s: &Select) -> Result<(Table, Vec<Joined>, Scope)> {
    let base = load_table(src, &s.from)?;
    let mut scope = Scope::default();
    scope.add(&s.alias, &base);
    let mut joins = Vec::new();
    for j in &s.joins {
        if j.alias == s.alias || s.joins.iter().filter(|x| x.alias == j.alias).count() > 1 {
            return Err(Error::Sql(format!("alias {} repetido; use AS", j.alias)));
        }
        let table = load_table(src, &j.table)?;
        let lookup = join_lookup(&table, &j.alias, &j.on, &scope);
        scope.add(&j.alias, &table);
        joins.push(Joined {
            table,
            join: j.clone(),
            lookup,
        });
    }
    Ok((base, joins, scope))
}

fn explain(src: &mut dyn Source, stmt: &Stmt) -> Result<String> {
    Ok(match stmt {
        Stmt::Select(s) => {
            let (base, joins, scope) = setup(src, s)?;
            let filter = if joins.is_empty() {
                s.filter.as_ref()
            } else {
                None
            };
            let mut lines = vec![
                plan(&base, &s.alias, filter.or(s.filter.as_ref()), &scope, 0).describe(&base),
            ];
            for j in &joins {
                let kind = if j.join.left { "LEFT JOIN" } else { "JOIN" };
                lines.push(match &j.lookup {
                    Some((c, _)) => format!(
                        "{kind} {} USING LOOKUP ON {} (index nested loop)",
                        j.table.name, j.table.columns[*c].name
                    ),
                    None => format!("{kind} {} USING SCAN (nested loop)", j.table.name),
                });
            }
            let mut aggs = Vec::new();
            for item in &s.items {
                if let SelectItem::Expr(e, _) = item {
                    collect_aggs(e, &mut aggs);
                }
            }
            if !s.group_by.is_empty() || !aggs.is_empty() {
                lines.push(format!(
                    "AGGREGATE groups_by={} aggregates={}",
                    s.group_by.len(),
                    aggs.len()
                ));
            }
            if !s.order_by.is_empty() {
                lines.push("SORT".into());
            }
            if s.limit.is_some() {
                lines.push(format!(
                    "LIMIT {} OFFSET {}",
                    s.limit.unwrap_or(0),
                    s.offset
                ));
            }
            lines.join("\n")
        }
        Stmt::Update { table, filter, .. } | Stmt::Delete { table, filter } => {
            let t = load_table(src, table)?;
            plan(&t, &t.name, filter.as_ref(), &single_scope(&t), 0).describe(&t)
        }
        other => format!("{other:?}"),
    })
}

#[derive(Clone)]
enum AggState {
    Count(i64),
    Sum(Option<Value>),
    Avg(f64, i64),
    Min(Option<Value>),
    Max(Option<Value>),
}

impl AggState {
    fn new(f: AggFn) -> Self {
        match f {
            AggFn::Count => Self::Count(0),
            AggFn::Sum => Self::Sum(None),
            AggFn::Avg => Self::Avg(0.0, 0),
            AggFn::Min => Self::Min(None),
            AggFn::Max => Self::Max(None),
        }
    }

    fn feed(&mut self, v: Value) -> Result<()> {
        if v.is_null() {
            return Ok(());
        }
        match self {
            Self::Count(n) => *n += 1,
            Self::Sum(acc) => {
                if v.as_f64().is_none() {
                    return Err(Error::Sql(format!("SUM de {}", v.type_name())));
                }
                *acc = Some(match acc.take() {
                    None => v,
                    Some(a) => arith(a, BinOp::Add, v)?,
                });
            }
            Self::Avg(sum, n) => {
                *sum += v
                    .as_f64()
                    .ok_or_else(|| Error::Sql(format!("AVG de {}", v.type_name())))?;
                *n += 1;
            }
            Self::Min(m) => {
                if m.as_ref().is_none_or(|m| v.total_cmp(m) == Ordering::Less) {
                    *m = Some(v);
                }
            }
            Self::Max(m) => {
                if m.as_ref()
                    .is_none_or(|m| v.total_cmp(m) == Ordering::Greater)
                {
                    *m = Some(v);
                }
            }
        }
        Ok(())
    }

    fn finish(self) -> Value {
        match self {
            Self::Count(n) => Value::Int(n),
            Self::Avg(_, 0) => Value::Null,
            Self::Avg(s, n) => Value::Real(s / n as f64),
            Self::Sum(v) | Self::Min(v) | Self::Max(v) => v.unwrap_or(Value::Null),
        }
    }
}

struct Group {
    first: Option<Vec<Value>>,
    states: Vec<AggState>,
    distinct: Vec<BTreeSet<Vec<u8>>>,
}

fn select(src: &mut dyn Source, s: &Select) -> Result<ExecResult> {
    let (base, joins, scope) = setup(src, s)?;
    let mut aggs = Vec::new();
    for item in &s.items {
        if let SelectItem::Expr(e, _) = item {
            collect_aggs(e, &mut aggs);
        }
    }
    if let Some(h) = &s.having {
        collect_aggs(h, &mut aggs);
    }
    for (e, _) in &s.order_by {
        collect_aggs(e, &mut aggs);
    }
    if s.filter.as_ref().is_some_and(contains_agg) {
        return Err(Error::Sql("agregado no WHERE; use HAVING".into()));
    }
    let grouped = !s.group_by.is_empty() || !aggs.is_empty();
    if s.having.is_some() && !grouped {
        return Err(Error::Sql("HAVING exige GROUP BY ou agregado".into()));
    }

    // 1. Linhas-fonte (tabela base + joins + WHERE).
    let simple = joins.is_empty() && !grouped && s.order_by.is_empty() && !s.distinct;
    let stop_after = s.limit.filter(|_| simple).map(|l| (l + s.offset) as usize);
    let base_scope = {
        let mut b = Scope::default();
        b.add(&s.alias, &base);
        b
    };
    let access = plan(&base, &s.alias, s.filter.as_ref(), &base_scope, 0);
    let mut rows: Vec<Vec<Value>> = Vec::new();
    let mut failure = None;
    let base_filter = if joins.is_empty() {
        s.filter.as_ref()
    } else {
        None
    };
    fetch(src, &base, &access, &mut |_, row| {
        match is_true(base_filter, &row, &base_scope, None) {
            Ok(true) => rows.push(row),
            Ok(false) => {}
            Err(e) => {
                failure = Some(e);
                return Ok(false);
            }
        }
        Ok(stop_after.is_none_or(|n| rows.len() < n))
    })?;
    if let Some(e) = failure {
        return Err(e);
    }
    let mut width = base.columns.len();
    for j in &joins {
        let partial = Scope {
            cols: scope.cols[..width].to_vec(),
        };
        let inner_width = j.table.columns.len();
        let materialized = if j.lookup.is_none() {
            let mut all = Vec::new();
            fetch(src, &j.table, &Access::Full, &mut |_, r| {
                all.push(r);
                Ok(true)
            })?;
            Some(all)
        } else {
            None
        };
        let mut combined_scope = partial.clone();
        combined_scope.add(&j.join.alias, &j.table);
        let mut next = Vec::new();
        for outer in rows {
            let candidates = match (&j.lookup, &materialized) {
                (_, Some(all)) => all.clone(),
                (Some((col, e)), None) => {
                    let v = eval(e, &outer, &partial, None)?;
                    let mut found = Vec::new();
                    if let Ok(v) = v.coerce(j.table.columns[*col].ty) {
                        if !v.is_null() {
                            let access = if Some(*col) == j.table.pk {
                                Access::Point(v)
                            } else {
                                let i = j
                                    .table
                                    .indexes
                                    .iter()
                                    .position(|i| i.column == *col)
                                    .expect("índice");
                                Access::Index(i, v)
                            };
                            fetch(src, &j.table, &access, &mut |_, r| {
                                found.push(r);
                                Ok(true)
                            })?;
                        }
                    }
                    found
                }
                (None, None) => unreachable!(),
            };
            let mut matched = false;
            for inner in candidates {
                let mut row = outer.clone();
                row.extend(inner);
                if is_true(Some(&j.join.on), &row, &combined_scope, None)? {
                    matched = true;
                    next.push(row);
                }
            }
            if !matched && j.join.left {
                let mut row = outer;
                row.extend(std::iter::repeat_n(Value::Null, inner_width));
                next.push(row);
            }
        }
        rows = next;
        width += inner_width;
    }
    if !joins.is_empty() {
        let mut kept = Vec::with_capacity(rows.len());
        for row in rows {
            if is_true(s.filter.as_ref(), &row, &scope, None)? {
                kept.push(row);
            }
        }
        rows = kept;
    }

    // 2. Nomes das colunas de saída.
    let mut columns = Vec::new();
    for item in &s.items {
        match item {
            SelectItem::Star(None) => columns.extend(scope.cols.iter().map(|(_, c)| c.clone())),
            SelectItem::Star(Some(t)) => {
                let before = columns.len();
                columns.extend(
                    scope
                        .cols
                        .iter()
                        .filter(|(a, _)| a == t)
                        .map(|(_, c)| c.clone()),
                );
                if columns.len() == before {
                    return Err(Error::Sql(format!("tabela {t} não está no FROM")));
                }
            }
            SelectItem::Expr(e, alias) => {
                columns.push(alias.clone().unwrap_or_else(|| expr_name(e)))
            }
        }
    }
    let project = |row: &[Value], aggs_ctx: AggValues<'_>| -> Result<Vec<Value>> {
        let mut out = Vec::new();
        for item in &s.items {
            match item {
                SelectItem::Star(None) => out.extend_from_slice(row),
                SelectItem::Star(Some(t)) => out.extend(
                    scope
                        .cols
                        .iter()
                        .zip(row)
                        .filter(|((a, _), _)| a == t)
                        .map(|(_, v)| v.clone()),
                ),
                SelectItem::Expr(e, _) => out.push(eval(e, row, &scope, aggs_ctx)?),
            }
        }
        Ok(out)
    };
    // Chave de ordenação: posição (ORDER BY 2), alias da saída ou expressão.
    let sort_key = |row: &[Value], out: &[Value], aggs_ctx: AggValues<'_>| -> Result<Vec<Value>> {
        s.order_by
            .iter()
            .map(|(e, _)| match e {
                Expr::Lit(Value::Int(k)) if *k >= 1 && (*k as usize) <= out.len() => {
                    Ok(out[*k as usize - 1].clone())
                }
                Expr::Lit(Value::Int(k)) => Err(Error::Sql(format!("ORDER BY {k} fora da lista"))),
                Expr::Col(None, name) if scope.resolve(None, name).is_err() => columns
                    .iter()
                    .position(|c| c == name)
                    .map(|i| out[i].clone())
                    .ok_or_else(|| Error::Sql(format!("coluna desconhecida {name}"))),
                e => eval(e, row, &scope, aggs_ctx),
            })
            .collect()
    };

    // 3. Projeção (com ou sem agregação).
    let mut output: Vec<(Vec<Value>, Vec<Value>)> = Vec::new();
    if grouped {
        let mut groups: BTreeMap<Vec<u8>, Group> = BTreeMap::new();
        let new_group = || Group {
            first: None,
            states: aggs
                .iter()
                .map(|a| match a {
                    Expr::Agg(f, _, _) => AggState::new(*f),
                    _ => unreachable!(),
                })
                .collect(),
            distinct: vec![BTreeSet::new(); aggs.len()],
        };
        if s.group_by.is_empty() {
            groups.insert(Vec::new(), new_group());
        }
        for row in &rows {
            let mut gk = Vec::new();
            for g in &s.group_by {
                gk.extend(key_of(&eval(g, row, &scope, None)?));
            }
            let group = groups.entry(gk).or_insert_with(new_group);
            if group.first.is_none() {
                group.first = Some(row.clone());
            }
            for (i, a) in aggs.iter().enumerate() {
                let Expr::Agg(_, arg, distinct) = a else {
                    unreachable!()
                };
                let v = match arg {
                    None => Value::Int(1),
                    Some(e) => eval(e, row, &scope, None)?,
                };
                if *distinct && !v.is_null() && !group.distinct[i].insert(key_of(&v)) {
                    continue;
                }
                group.states[i].feed(v)?;
            }
        }
        let nulls = vec![Value::Null; scope.cols.len()];
        for (_, g) in groups {
            let vals: Vec<Value> = g.states.into_iter().map(AggState::finish).collect();
            let ctx = Some((&aggs[..], &vals[..]));
            let row = g.first.as_deref().unwrap_or(&nulls);
            if !is_true(s.having.as_ref(), row, &scope, ctx)? {
                continue;
            }
            let out = project(row, ctx)?;
            output.push((sort_key(row, &out, ctx)?, out));
        }
    } else {
        for row in &rows {
            let out = project(row, None)?;
            output.push((sort_key(row, &out, None)?, out));
        }
    }

    // 4. DISTINCT, ORDER BY, OFFSET/LIMIT.
    if s.distinct {
        let mut seen = BTreeSet::new();
        output.retain(|(_, out)| seen.insert(out.iter().flat_map(key_of).collect::<Vec<u8>>()));
    }
    if !s.order_by.is_empty() {
        output.sort_by(|(a, _), (b, _)| {
            for ((x, y), (_, desc)) in a.iter().zip(b).zip(&s.order_by) {
                let o = x.total_cmp(y);
                if o != Ordering::Equal {
                    return if *desc { o.reverse() } else { o };
                }
            }
            Ordering::Equal
        });
    }
    let rows = output
        .into_iter()
        .skip(s.offset as usize)
        .take(s.limit.map_or(usize::MAX, |l| l as usize))
        .map(|(_, out)| out)
        .collect();
    Ok(ExecResult::Table { columns, rows })
}

#[cfg(test)]
mod tests {
    use super::like;

    #[test]
    fn like_matches_sql_semantics() {
        for (t, p, want) in [
            ("abc", "a%", true),
            ("abc", "%c", true),
            ("abc", "a_c", true),
            ("abc", "A%", true),
            ("abc", "%b", false),
            ("", "%", true),
            ("ação", "a__o", true),
        ] {
            assert_eq!(like(t, p), want, "{t} LIKE {p}");
        }
    }
}
