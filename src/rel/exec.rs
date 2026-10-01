//! Catálogo, planejador e executor de consultas do SQL relacional.
//!
//! O executor materializa relações intermediárias (resultado de joins, grupos,
//! ordenação), mas lê as tabelas por scans e buscas pontuais na B+ Tree
//! escolhidos pelo planejador: chave primária (ponto, lista `IN`, prefixo de
//! chave composta, faixa), índices secundários (prefixo das colunas) ou scan.
//! Joins usam busca por chave/índice, hash join em igualdades ou nested loop.
//! Subconsultas e CTEs não correlacionadas rodam uma vez e ficam em cache;
//! correlacionadas rodam por linha enxergando as colunas da consulta externa.
//! CTEs recursivas iteram até não produzir linhas novas; views são expandidas
//! como subconsultas; funções de janela rodam sobre o resultado agrupado.

use super::func;
use super::parser::{
    AggFn, BinOp, Check, ColumnDef, Expr, FkAction, FromItem, IndexKind, JoinKind, OrderItem,
    Query, Select, SelectItem, SetExpr, SetOp, Source as FromSource, Stmt, TriggerDef,
    TriggerEvent, TriggerTiming, WinFn,
};
use super::search::{self, HnswParams, Metric, NodeStore, TextQuery};
use super::value::{decode_row, key_of, Type, Value};
use super::window::{self, WindowInput};
use super::Source;
use crate::db::{prefix_successor, ExecResult, Op, RESERVED_PREFIX};
use crate::error::{Error, Result};
use crate::events::Change;
use crate::json::Json;
use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

/// Maior chave primária codificada (a linha e as entradas de índice precisam
/// caber no limite de chave da árvore).
pub const MAX_PK_BYTES: usize = 768;
/// Bytes do valor indexado guardados na entrada; valores mais longos são
/// truncados e a busca confere a linha (o índice continua exato).
pub const INDEX_VALUE_BYTES: usize = 256;
/// Iterações máximas de uma CTE recursiva.
pub const MAX_RECURSION: usize = 100_000;

// ---------------------------------------------------------------------------
// Catálogo
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub(super) struct IndexDef {
    pub name: String,
    pub columns: Vec<usize>,
    pub unique: bool,
    pub id: u32,
    /// Criado automaticamente (UNIQUE de coluna/tabela ou chave estrangeira).
    pub auto: bool,
    pub kind: IndexKind,
    /// `WITH (chave = valor)`: `metric`, `m`, `ef_construction`...
    pub options: Vec<(String, String)>,
}

impl IndexDef {
    pub fn btree(name: String, columns: Vec<usize>, unique: bool, id: u32, auto: bool) -> Self {
        Self {
            name,
            columns,
            unique,
            id,
            auto,
            kind: IndexKind::BTree,
            options: Vec::new(),
        }
    }

    pub fn is_btree(&self) -> bool {
        self.kind == IndexKind::BTree
    }

    pub fn option(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn metric(&self) -> Metric {
        self.option("metric")
            .and_then(Metric::parse)
            .unwrap_or(Metric::Cosine)
    }

    pub fn hnsw(&self) -> HnswParams {
        HnswParams {
            m: self
                .option("m")
                .and_then(|v| v.parse().ok())
                .unwrap_or(16)
                .clamp(4, 64),
            ef_construction: self
                .option("ef_construction")
                .and_then(|v| v.parse().ok())
                .unwrap_or(100)
                .clamp(16, 1000),
            metric: self.metric(),
        }
    }
}

/// Sub-chaves dos índices especiais (depois do prefixo do índice).
pub(super) const FTS_POSTING: u8 = b'p';
pub(super) const FTS_DOC: u8 = b'd';
pub(super) const FTS_STATS: u8 = b's';
pub(super) const VEC_NODE: u8 = b'n';
pub(super) const VEC_ENTRY: u8 = b'e';

/// Chave estrangeira gravada no catálogo da tabela filha.
#[derive(Clone, Debug)]
pub(super) struct Fk {
    pub name: String,
    pub columns: Vec<usize>,
    pub parent: String,
    /// Nomes das colunas na tabela pai (vazio = chave primária dela).
    pub parent_columns: Vec<String>,
    pub on_delete: FkAction,
    pub on_update: FkAction,
}

/// Tabela comum ou view materializada (linhas guardadas como tabela).
#[derive(Clone, Debug, PartialEq)]
pub(super) enum TableKind {
    Table,
    Materialized { sql: String, auto: bool },
}

#[derive(Clone, Debug)]
pub(super) struct Table {
    pub name: String,
    pub id: u32,
    pub columns: Vec<ColumnDef>,
    /// Colunas da chave primária; vazio = rowid oculto e autoincrementado.
    pub pk: Vec<usize>,
    pub indexes: Vec<IndexDef>,
    pub checks: Vec<Check>,
    pub fks: Vec<Fk>,
    pub triggers: Vec<TriggerDef>,
    pub kind: TableKind,
    pub next_index_id: u32,
}

/// Estatísticas de uma coluna (`ANALYZE`).
#[derive(Clone, Debug, Default)]
pub(super) struct ColStats {
    pub distinct: u64,
    pub nulls: u64,
    pub min: Option<Value>,
    pub max: Option<Value>,
}

/// Estatísticas de uma tabela para o planejador.
#[derive(Clone, Debug, Default)]
pub(super) struct Stats {
    pub rows: u64,
    pub columns: Vec<ColStats>,
    pub analyzed_at: String,
}

pub(super) fn stats_key(name: &str) -> Vec<u8> {
    key(&[b"a", name.as_bytes()])
}

impl Stats {
    pub fn to_json(&self) -> Json {
        Json::obj()
            .put("rows", Json::Number(self.rows as i64))
            .put("analyzed_at", Json::String(self.analyzed_at.clone()))
            .put(
                "columns",
                Json::Array(
                    self.columns
                        .iter()
                        .map(|c| {
                            Json::obj()
                                .put("distinct", Json::Number(c.distinct as i64))
                                .put("nulls", Json::Number(c.nulls as i64))
                                .put("min", c.min.as_ref().map_or(Json::Null, Value::to_json))
                                .put("max", c.max.as_ref().map_or(Json::Null, Value::to_json))
                        })
                        .collect(),
                ),
            )
    }

    pub fn from_json(j: &Json) -> Result<Self> {
        let bad = || Error::Other("estatísticas corrompidas".into());
        let num = |j: Option<&Json>| match j {
            Some(Json::Number(n)) => Ok(*n as u64),
            _ => Err(bad()),
        };
        let columns = match j.get("columns") {
            Some(Json::Array(a)) => a
                .iter()
                .map(|c| {
                    Ok(ColStats {
                        distinct: num(c.get("distinct"))?,
                        nulls: num(c.get("nulls"))?,
                        min: c.get("min").map(json_value).filter(|v| !v.is_null()),
                        max: c.get("max").map(json_value).filter(|v| !v.is_null()),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            _ => Vec::new(),
        };
        Ok(Self {
            rows: num(j.get("rows"))?,
            columns,
            analyzed_at: j
                .get("analyzed_at")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }

    /// Fração das linhas que passam em `lo <= col <= hi` (interpolação pelo
    /// mínimo/máximo; 1/3 quando não dá para estimar).
    pub fn range_fraction(&self, col: usize, lo: Option<&Value>, hi: Option<&Value>) -> f64 {
        let Some(c) = self.columns.get(col) else {
            return 1.0 / 3.0;
        };
        let (Some(min), Some(max)) = (
            c.min.as_ref().and_then(Value::as_f64),
            c.max.as_ref().and_then(Value::as_f64),
        ) else {
            return 1.0 / 3.0;
        };
        if max <= min {
            return 1.0;
        }
        let lo = lo.and_then(Value::as_f64).unwrap_or(min).clamp(min, max);
        let hi = hi.and_then(Value::as_f64).unwrap_or(max).clamp(min, max);
        ((hi - lo) / (max - min)).clamp(0.001, 1.0)
    }
}

pub(super) fn load_stats(src: &dyn Source, name: &str) -> Result<Option<Stats>> {
    match src.get(&stats_key(name))? {
        None => Ok(None),
        Some(raw) => {
            let text = String::from_utf8(raw)
                .map_err(|_| Error::Other("estatísticas não UTF-8".into()))?;
            Stats::from_json(&Json::parse(&text)?).map(Some)
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct View {
    pub name: String,
    pub columns: Vec<String>,
    pub sql: String,
}

pub(super) fn key(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![RESERVED_PREFIX];
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

pub(super) fn catalog_key(name: &str) -> Vec<u8> {
    key(&[b"c", name.as_bytes()])
}

pub(super) fn view_key(name: &str) -> Vec<u8> {
    key(&[b"v", name.as_bytes()])
}

pub(super) const TABLE_SEQ: &[u8] = &[RESERVED_PREFIX, b'q'];

pub(super) fn encode_tuple(values: &[&Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in values {
        super::value::encode_key(v, &mut out);
    }
    out
}

fn quote_ident(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && s.chars().next().is_some_and(|c| !c.is_ascii_digit())
    {
        s.to_string()
    } else {
        format!("\"{}\"", s.replace('"', "\"\""))
    }
}

pub(super) fn sql_literal(v: &Value) -> String {
    match v {
        Value::Text(s) => format!("'{}'", s.replace('\'', "''")),
        other => other.to_string(),
    }
}

impl Table {
    pub fn row_prefix(&self) -> Vec<u8> {
        key(&[b"t", &self.id.to_be_bytes()])
    }

    pub fn row_key(&self, pk: &[u8]) -> Vec<u8> {
        let mut k = self.row_prefix();
        k.extend_from_slice(pk);
        k
    }

    pub fn rowid_key(&self) -> Vec<u8> {
        key(&[b"s", &self.id.to_be_bytes()])
    }

    pub fn index_prefix(&self, idx: &IndexDef) -> Vec<u8> {
        key(&[b"x", &self.id.to_be_bytes(), &idx.id.to_be_bytes()])
    }

    /// Prefixo de busca no índice para os valores das primeiras colunas.
    pub fn index_lookup(&self, idx: &IndexDef, values: &[&Value]) -> Vec<u8> {
        let mut k = self.index_prefix(idx);
        let enc = encode_tuple(values);
        k.extend_from_slice(&enc[..enc.len().min(INDEX_VALUE_BYTES)]);
        k
    }

    pub fn index_key(&self, idx: &IndexDef, row: &[Value], pk: &[u8]) -> Vec<u8> {
        let vals: Vec<&Value> = idx.columns.iter().map(|&c| &row[c]).collect();
        let mut k = self.index_lookup(idx, &vals);
        k.extend_from_slice(pk);
        k
    }

    pub fn column(&self, name: &str) -> Result<usize> {
        self.columns
            .iter()
            .position(|c| c.name == name)
            .ok_or_else(|| Error::Sql(format!("coluna desconhecida {}.{name}", self.name)))
    }

    pub fn pk_name(&self) -> String {
        if self.pk.is_empty() {
            return "rowid".into();
        }
        self.pk
            .iter()
            .map(|&c| self.columns[c].name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Índice cujas colunas são exatamente `cols` (em qualquer ordem) e único.
    pub fn unique_index_on(&self, cols: &[usize]) -> Option<usize> {
        self.indexes.iter().position(|i| {
            i.is_btree()
                && i.unique
                && i.columns.len() == cols.len()
                && cols.iter().all(|c| i.columns.contains(c))
        })
    }

    /// Índice que começa pelas colunas `cols` (para buscas de chave estrangeira).
    pub fn index_prefixed_by(&self, cols: &[usize]) -> Option<usize> {
        self.indexes.iter().position(|i| {
            i.is_btree() && i.columns.len() >= cols.len() && i.columns[..cols.len()] == *cols
        })
    }

    /// Texto indexado por um índice full-text (colunas concatenadas).
    pub fn fts_text(&self, idx: &IndexDef, row: &[Value]) -> String {
        idx.columns
            .iter()
            .map(|&c| match &row[c] {
                Value::Null => String::new(),
                v => v.to_string(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Índice full-text exatamente sobre as colunas `cols` (qualquer ordem).
    pub fn fulltext_index_on(&self, cols: &[usize]) -> Option<usize> {
        self.indexes.iter().position(|i| {
            i.kind == IndexKind::FullText
                && i.columns.len() == cols.len()
                && cols.iter().all(|c| i.columns.contains(c))
        })
    }

    pub fn vector_index_on(&self, col: usize) -> Option<usize> {
        self.indexes
            .iter()
            .position(|i| i.kind == IndexKind::Vector && i.columns == [col])
    }

    /// Decodifica e completa colunas adicionadas depois da linha ser gravada.
    pub fn decode(&self, raw: &[u8]) -> Result<Vec<Value>> {
        let mut row = decode_row(raw)?;
        for col in &self.columns[row.len().min(self.columns.len())..] {
            row.push(col.fill.clone().unwrap_or(Value::Null));
        }
        row.truncate(self.columns.len());
        Ok(row)
    }

    pub fn to_json(&self) -> Json {
        let cols = self
            .columns
            .iter()
            .map(|c| {
                let mut j = Json::obj()
                    .put("name", Json::String(c.name.clone()))
                    .put("type", Json::String(c.ty.name().into()))
                    .put("not_null", Json::Bool(c.not_null));
                if c.autoincrement {
                    j = j.put("autoincrement", Json::Bool(true));
                }
                match (&c.default, &c.default_sql) {
                    (Some(_), Some(sql)) => j = j.put("default_sql", Json::String(sql.clone())),
                    (Some(Expr::Lit(v)), None) => j = j.put("default", v.to_json()),
                    (Some(Expr::Neg(inner)), None) => {
                        if let Expr::Lit(v) = &**inner {
                            let neg = match v {
                                Value::Int(n) => Value::Int(-n),
                                Value::Real(x) => Value::Real(-x),
                                other => other.clone(),
                            };
                            j = j.put("default", neg.to_json());
                        }
                    }
                    _ => {}
                }
                if let Some(f) = &c.fill {
                    j = j.put("fill", f.to_json());
                }
                j
            })
            .collect();
        let nums = |v: &[usize]| Json::Array(v.iter().map(|&n| Json::Number(n as i64)).collect());
        let strs = |v: &[String]| Json::Array(v.iter().map(|s| Json::String(s.clone())).collect());
        let idx = self
            .indexes
            .iter()
            .map(|i| {
                let mut j = Json::obj()
                    .put("name", Json::String(i.name.clone()))
                    .put("columns", nums(&i.columns))
                    .put("unique", Json::Bool(i.unique))
                    .put("auto", Json::Bool(i.auto))
                    .put("id", Json::Number(i.id as i64));
                if !i.is_btree() {
                    j = j.put("kind", Json::String(i.kind.name().into()));
                }
                if !i.options.is_empty() {
                    let mut o = Json::obj();
                    for (k, v) in &i.options {
                        o = o.put(k, Json::String(v.clone()));
                    }
                    j = j.put("options", o);
                }
                j
            })
            .collect();
        let checks = self
            .checks
            .iter()
            .map(|c| {
                let mut j = Json::obj().put("sql", Json::String(c.sql.clone()));
                if let Some(n) = &c.name {
                    j = j.put("name", Json::String(n.clone()));
                }
                j
            })
            .collect();
        let fks = self
            .fks
            .iter()
            .map(|f| {
                Json::obj()
                    .put("name", Json::String(f.name.clone()))
                    .put("columns", nums(&f.columns))
                    .put("parent", Json::String(f.parent.clone()))
                    .put("parent_columns", strs(&f.parent_columns))
                    .put("on_delete", Json::String(f.on_delete.sql().to_lowercase()))
                    .put("on_update", Json::String(f.on_update.sql().to_lowercase()))
            })
            .collect();
        let triggers = self
            .triggers
            .iter()
            .map(|t| {
                let mut j = Json::obj()
                    .put("name", Json::String(t.name.clone()))
                    .put(
                        "timing",
                        Json::String(
                            match t.timing {
                                TriggerTiming::Before => "before",
                                TriggerTiming::After => "after",
                            }
                            .into(),
                        ),
                    )
                    .put(
                        "event",
                        Json::String(
                            match &t.event {
                                TriggerEvent::Insert => "insert",
                                TriggerEvent::Update(_) => "update",
                                TriggerEvent::Delete => "delete",
                            }
                            .into(),
                        ),
                    )
                    .put(
                        "body",
                        Json::Array(
                            t.body
                                .iter()
                                .map(|(sql, _)| Json::String(sql.clone()))
                                .collect(),
                        ),
                    );
                if let TriggerEvent::Update(cols) = &t.event {
                    j = j.put("of", strs(cols));
                }
                if let Some((_, sql)) = &t.when {
                    j = j.put("when", Json::String(sql.clone()));
                }
                j
            })
            .collect();
        let mut out = Json::obj()
            .put("name", Json::String(self.name.clone()))
            .put("id", Json::Number(self.id as i64))
            .put("pk", nums(&self.pk))
            .put("columns", Json::Array(cols))
            .put("indexes", Json::Array(idx))
            .put("checks", Json::Array(checks))
            .put("fks", Json::Array(fks))
            .put("triggers", Json::Array(triggers))
            .put("next_index_id", Json::Number(self.next_index_id as i64));
        if let TableKind::Materialized { sql, auto } = &self.kind {
            out = out
                .put("materialized", Json::String(sql.clone()))
                .put("auto_refresh", Json::Bool(*auto));
        }
        out
    }

    pub fn from_json(j: &Json) -> Result<Self> {
        let bad = || Error::Other("catálogo SQL corrompido".into());
        let num = |j: Option<&Json>| match j {
            Some(Json::Number(n)) => Ok(*n),
            _ => Err(bad()),
        };
        let arr = |j: Option<&Json>| match j {
            Some(Json::Array(a)) => Ok(a.clone()),
            None => Ok(Vec::new()),
            _ => Err(bad()),
        };
        // 0.5 gravava um número (ou null); 0.6+ grava uma lista.
        let positions = |j: Option<&Json>| -> Result<Vec<usize>> {
            match j {
                Some(Json::Number(n)) => Ok(vec![*n as usize]),
                Some(Json::Array(a)) => a
                    .iter()
                    .map(|v| match v {
                        Json::Number(n) => Ok(*n as usize),
                        _ => Err(bad()),
                    })
                    .collect(),
                _ => Ok(Vec::new()),
            }
        };
        let names = |j: Option<&Json>| -> Result<Vec<String>> {
            match j {
                Some(Json::Array(a)) => a
                    .iter()
                    .map(|v| v.as_str().map(String::from).ok_or_else(bad))
                    .collect(),
                _ => Ok(Vec::new()),
            }
        };
        let flag = |j: Option<&Json>| matches!(j, Some(Json::Bool(true)));
        let text = |j: Option<&Json>| j.and_then(Json::as_str).map(String::from);
        let columns = arr(j.get("columns"))?
            .iter()
            .map(|c| {
                let ty = c
                    .get("type")
                    .and_then(Json::as_str)
                    .and_then(Type::parse)
                    .ok_or_else(bad)?;
                let mut col = ColumnDef::new(
                    c.get("name").and_then(Json::as_str).ok_or_else(bad)?.into(),
                    ty,
                );
                col.not_null = flag(c.get("not_null"));
                col.autoincrement = flag(c.get("autoincrement"));
                let literal = c.get("default").map(json_value);
                if let Some(sql) = text(c.get("default_sql")) {
                    col.default = Some(super::parser::parse_expr(&sql)?);
                    col.default_sql = Some(sql);
                } else if let Some(v) = &literal {
                    col.default = Some(Expr::Lit(v.clone()));
                }
                col.fill = c.get("fill").map(json_value).or(literal);
                Ok(col)
            })
            .collect::<Result<Vec<_>>>()?;
        let indexes = arr(j.get("indexes"))?
            .iter()
            .map(|i| {
                let options = match i.get("options") {
                    Some(Json::Object(map)) => map
                        .iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                        .collect(),
                    _ => Vec::new(),
                };
                Ok(IndexDef {
                    name: i.get("name").and_then(Json::as_str).ok_or_else(bad)?.into(),
                    columns: positions(i.get("columns").or(i.get("column")))?,
                    unique: flag(i.get("unique")),
                    id: num(i.get("id"))? as u32,
                    auto: flag(i.get("auto")),
                    kind: text(i.get("kind"))
                        .as_deref()
                        .and_then(IndexKind::parse)
                        .unwrap_or(IndexKind::BTree),
                    options,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let checks = arr(j.get("checks"))?
            .iter()
            .map(|c| {
                let sql = text(c.get("sql")).ok_or_else(bad)?;
                Ok(Check {
                    name: text(c.get("name")),
                    expr: super::parser::parse_expr(&sql)?,
                    sql,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let fks = arr(j.get("fks"))?
            .iter()
            .map(|f| {
                let action = |k: &str| {
                    text(f.get(k))
                        .as_deref()
                        .map(FkAction::parse)
                        .unwrap_or(Some(FkAction::NoAction))
                        .ok_or_else(bad)
                };
                Ok(Fk {
                    name: text(f.get("name")).ok_or_else(bad)?,
                    columns: positions(f.get("columns"))?,
                    parent: text(f.get("parent")).ok_or_else(bad)?,
                    parent_columns: names(f.get("parent_columns"))?,
                    on_delete: action("on_delete")?,
                    on_update: action("on_update")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let name: String = j.get("name").and_then(Json::as_str).ok_or_else(bad)?.into();
        let triggers = arr(j.get("triggers"))?
            .iter()
            .map(|t| {
                let event = match text(t.get("event")).as_deref() {
                    Some("insert") => TriggerEvent::Insert,
                    Some("delete") => TriggerEvent::Delete,
                    Some("update") => TriggerEvent::Update(names(t.get("of"))?),
                    _ => return Err(bad()),
                };
                let when = match text(t.get("when")) {
                    Some(sql) => Some((super::parser::parse_expr(&sql)?, sql)),
                    None => None,
                };
                let body = names(t.get("body"))?
                    .into_iter()
                    .map(|sql| {
                        let (stmt, _) = super::parser::parse(&sql)?;
                        Ok((sql, stmt))
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(TriggerDef {
                    name: text(t.get("name")).ok_or_else(bad)?,
                    timing: match text(t.get("timing")).as_deref() {
                        Some("before") => TriggerTiming::Before,
                        _ => TriggerTiming::After,
                    },
                    event,
                    table: name.clone(),
                    when,
                    body,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let kind = match text(j.get("materialized")) {
            Some(sql) => TableKind::Materialized {
                sql,
                auto: flag(j.get("auto_refresh")),
            },
            None => TableKind::Table,
        };
        let t = Self {
            name,
            id: num(j.get("id"))? as u32,
            pk: positions(j.get("pk"))?,
            indexes,
            checks,
            fks,
            triggers,
            kind,
            next_index_id: num(j.get("next_index_id"))? as u32,
            columns,
        };
        let n = t.columns.len();
        if t.pk
            .iter()
            .chain(t.indexes.iter().flat_map(|i| &i.columns))
            .chain(t.fks.iter().flat_map(|f| &f.columns))
            .any(|&c| c >= n)
        {
            return Err(bad());
        }
        Ok(t)
    }

    /// DDL equivalente (`SHOW CREATE TABLE`).
    pub fn ddl(&self) -> String {
        if let TableKind::Materialized { sql, auto } = &self.kind {
            let cols: Vec<String> = self.columns.iter().map(|c| quote_ident(&c.name)).collect();
            let mut out = format!(
                "CREATE MATERIALIZED VIEW {} ({}){} AS {};",
                quote_ident(&self.name),
                cols.join(", "),
                if *auto { " WITH AUTO REFRESH" } else { "" },
                sql
            );
            for t in &self.triggers {
                out.push('\n');
                out.push_str(&t.ddl());
            }
            return out;
        }
        let mut parts = Vec::new();
        for (i, c) in self.columns.iter().enumerate() {
            let mut s = format!("  {} {}", quote_ident(&c.name), c.ty.name());
            if self.pk == [i] {
                s.push_str(" PRIMARY KEY");
            }
            if c.autoincrement {
                s.push_str(" AUTOINCREMENT");
            }
            if c.not_null && !self.pk.contains(&i) {
                s.push_str(" NOT NULL");
            }
            match (&c.default_sql, &c.default) {
                (Some(sql), _) => s.push_str(&format!(" DEFAULT ({sql})")),
                (None, Some(Expr::Lit(v))) => s.push_str(&format!(" DEFAULT {}", sql_literal(v))),
                (None, Some(Expr::Neg(inner))) => {
                    if let Expr::Lit(v) = &**inner {
                        s.push_str(&format!(" DEFAULT -{}", sql_literal(v)));
                    }
                }
                _ => {}
            }
            parts.push(s);
        }
        let names = |cols: &[usize]| {
            cols.iter()
                .map(|&c| quote_ident(&self.columns[c].name))
                .collect::<Vec<_>>()
                .join(", ")
        };
        if self.pk.len() > 1 {
            parts.push(format!("  PRIMARY KEY ({})", names(&self.pk)));
        }
        for idx in self.indexes.iter().filter(|i| i.auto && i.unique) {
            parts.push(format!("  UNIQUE ({})", names(&idx.columns)));
        }
        for c in &self.checks {
            let prefix = c
                .name
                .as_ref()
                .map(|n| format!("CONSTRAINT {} ", quote_ident(n)))
                .unwrap_or_default();
            parts.push(format!("  {prefix}CHECK ({})", c.sql));
        }
        for f in &self.fks {
            let mut s = format!(
                "  CONSTRAINT {} FOREIGN KEY ({}) REFERENCES {}",
                quote_ident(&f.name),
                names(&f.columns),
                quote_ident(&f.parent)
            );
            if !f.parent_columns.is_empty() {
                s.push_str(&format!(
                    " ({})",
                    f.parent_columns
                        .iter()
                        .map(|c| quote_ident(c))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if f.on_delete != FkAction::NoAction {
                s.push_str(&format!(" ON DELETE {}", f.on_delete.sql()));
            }
            if f.on_update != FkAction::NoAction {
                s.push_str(&format!(" ON UPDATE {}", f.on_update.sql()));
            }
            parts.push(s);
        }
        let mut out = format!(
            "CREATE TABLE {} (\n{}\n);",
            quote_ident(&self.name),
            parts.join(",\n")
        );
        for idx in self.indexes.iter().filter(|i| !i.auto) {
            let kind = match idx.kind {
                IndexKind::BTree if idx.unique => "UNIQUE ",
                IndexKind::BTree => "",
                IndexKind::FullText => "FULLTEXT ",
                IndexKind::Vector => "VECTOR ",
                IndexKind::Spatial => "SPATIAL ",
            };
            let with = if idx.options.is_empty() {
                String::new()
            } else {
                format!(
                    " WITH ({})",
                    idx.options
                        .iter()
                        .map(|(k, v)| format!("{k} = '{v}'"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            out.push_str(&format!(
                "\nCREATE {kind}INDEX {} ON {} ({}){with};",
                quote_ident(&idx.name),
                quote_ident(&self.name),
                names(&idx.columns)
            ));
        }
        for t in &self.triggers {
            out.push('\n');
            out.push_str(&t.ddl());
        }
        out
    }
}

pub(super) trait TriggerDdl {
    fn ddl(&self) -> String;
}

impl TriggerDdl for TriggerDef {
    fn ddl(&self) -> String {
        let when = self
            .when
            .as_ref()
            .map(|(_, sql)| format!(" WHEN ({sql})"))
            .unwrap_or_default();
        let body: Vec<String> = self
            .body
            .iter()
            .map(|(sql, _)| format!("  {sql};"))
            .collect();
        format!(
            "CREATE TRIGGER {} {} {} ON {}{when} BEGIN\n{}\nEND;",
            quote_ident(&self.name),
            match self.timing {
                TriggerTiming::Before => "BEFORE",
                TriggerTiming::After => "AFTER",
            },
            self.event.sql(),
            quote_ident(&self.table),
            body.join("\n")
        )
    }
}

impl View {
    pub fn to_json(&self) -> Json {
        Json::obj()
            .put("name", Json::String(self.name.clone()))
            .put(
                "columns",
                Json::Array(
                    self.columns
                        .iter()
                        .map(|c| Json::String(c.clone()))
                        .collect(),
                ),
            )
            .put("sql", Json::String(self.sql.clone()))
    }

    pub fn from_json(j: &Json) -> Result<Self> {
        let bad = || Error::Other("catálogo de views corrompido".into());
        let columns = match j.get("columns") {
            Some(Json::Array(a)) => a
                .iter()
                .map(|v| v.as_str().map(String::from).ok_or_else(bad))
                .collect::<Result<Vec<_>>>()?,
            _ => Vec::new(),
        };
        Ok(Self {
            name: j.get("name").and_then(Json::as_str).ok_or_else(bad)?.into(),
            columns,
            sql: j.get("sql").and_then(Json::as_str).ok_or_else(bad)?.into(),
        })
    }

    pub fn ddl(&self) -> String {
        let cols = if self.columns.is_empty() {
            String::new()
        } else {
            format!(
                " ({})",
                self.columns
                    .iter()
                    .map(|c| quote_ident(c))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        format!(
            "CREATE VIEW {}{cols} AS {};",
            quote_ident(&self.name),
            self.sql
        )
    }
}

pub(super) fn json_value(j: &Json) -> Value {
    match j {
        Json::Number(n) => Value::Int(*n),
        Json::Float(x) => Value::Real(*x),
        Json::String(s) => Value::Text(s.clone()),
        Json::Bool(b) => Value::Bool(*b),
        _ => Value::Null,
    }
}

pub(super) fn load_table(src: &dyn Source, name: &str) -> Result<Table> {
    let raw = src
        .get(&catalog_key(name))?
        .ok_or_else(|| Error::UnknownTable(name.to_string()))?;
    let text = String::from_utf8(raw).map_err(|_| Error::Other("catálogo não UTF-8".into()))?;
    Table::from_json(&Json::parse(&text)?)
}

pub(super) fn load_view(src: &dyn Source, name: &str) -> Result<Option<View>> {
    match src.get(&view_key(name))? {
        None => Ok(None),
        Some(raw) => {
            let text =
                String::from_utf8(raw).map_err(|_| Error::Other("catálogo não UTF-8".into()))?;
            View::from_json(&Json::parse(&text)?).map(Some)
        }
    }
}

fn scan_catalog<T>(
    src: &dyn Source,
    tag: u8,
    parse: impl Fn(&Json) -> Result<T>,
) -> Result<Vec<T>> {
    let start = key(&[&[tag]]);
    let end = key(&[&[tag + 1]]);
    let mut raw = Vec::new();
    src.scan(&start, Some(&end), &mut |_, v| {
        raw.push(v);
        Ok(true)
    })?;
    raw.iter()
        .map(|v| parse(&Json::parse(&String::from_utf8_lossy(v))?))
        .collect()
}

pub(super) fn list_tables(src: &dyn Source) -> Result<Vec<Table>> {
    scan_catalog(src, b'c', Table::from_json)
}

pub(super) fn list_views(src: &dyn Source) -> Result<Vec<View>> {
    scan_catalog(src, b'v', View::from_json)
}

// ---------------------------------------------------------------------------
// Escritas pendentes de um comando (atômicas via um único lote no WAL)
// ---------------------------------------------------------------------------

pub(crate) type Writes = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// Escritas, mudanças e notificações acumuladas por um comando. Interior
/// mutável: corpos de gatilho leem pelo [`PendingSource`] enquanto o comando
/// continua gravando.
#[derive(Default)]
pub(super) struct Pending {
    pub writes: RefCell<Writes>,
    pub changes: RefCell<Vec<Change>>,
    pub notifications: RefCell<Vec<(String, String)>>,
}

impl Pending {
    pub fn put(&self, k: Vec<u8>, v: Vec<u8>) {
        self.writes.borrow_mut().insert(k, Some(v));
    }

    pub fn del(&self, k: Vec<u8>) {
        self.writes.borrow_mut().insert(k, None);
    }

    pub fn get(&self, src: &dyn Source, k: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.writes.borrow().get(k) {
            Some(v) => Ok(v.clone()),
            None => src.get(k),
        }
    }

    /// Entradas visíveis em `[start, end)` (banco + pendentes).
    pub fn entries(
        &self,
        src: &dyn Source,
        start: &[u8],
        end: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = BTreeMap::new();
        src.scan(start, Some(end), &mut |k, v| {
            out.insert(k, v);
            Ok(true)
        })?;
        for (k, v) in self.writes.borrow().range(start.to_vec()..end.to_vec()) {
            match v {
                Some(v) => out.insert(k.clone(), v.clone()),
                None => out.remove(k),
            };
        }
        Ok(out.into_iter().collect())
    }

    /// Fonte de leitura que enxerga as escritas pendentes.
    pub fn source<'a>(&'a self, base: &'a dyn Source) -> PendingSource<'a> {
        PendingSource {
            base,
            writes: &self.writes,
        }
    }

    pub fn change(&self, c: Change) {
        self.changes.borrow_mut().push(c);
    }

    pub fn notify(&self, channel: String, payload: String) {
        self.notifications.borrow_mut().push((channel, payload));
    }

    pub fn into_ops(self) -> Vec<Op> {
        ops_of(self.writes.into_inner())
    }
}

fn ops_of(writes: Writes) -> Vec<Op> {
    writes
        .into_iter()
        .map(|(key, v)| match v {
            Some(value) => Op::Put { key, value },
            None => Op::Delete { key },
        })
        .collect()
}

/// [`Pending`] visto como fonte (escritas pendentes sobre a base).
pub(super) struct PendingSource<'a> {
    base: &'a dyn Source,
    writes: &'a RefCell<Writes>,
}

impl Source for PendingSource<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let w = self.writes.borrow();
        Overlay {
            base: self.base,
            writes: &w,
        }
        .get(key)
    }

    fn scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()> {
        let w = self.writes.borrow();
        Overlay {
            base: self.base,
            writes: &w,
        }
        .scan(start, end, visit)
    }

    fn guard_unchanged(&self, start: &[u8], end: &[u8]) {
        self.base.guard_unchanged(start, end);
    }

    fn guard_present(&self, start: &[u8], end: &[u8]) {
        self.base.guard_present(start, end);
    }
}

/// Fonte que sobrepõe escritas ainda não aplicadas a outra fonte (transações
/// SQL, scripts e o próprio comando em execução).
pub(crate) struct Overlay<'a> {
    pub base: &'a dyn Source,
    pub writes: &'a Writes,
}

impl Source for Overlay<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.writes.get(key) {
            Some(v) => Ok(v.clone()),
            None => self.base.get(key),
        }
    }

    fn scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()> {
        let upper: Vec<u8> = match end {
            Some(e) => e.to_vec(),
            None => Vec::new(),
        };
        let range: Vec<(&Vec<u8>, &Option<Vec<u8>>)> = match end {
            Some(_) => self.writes.range(start.to_vec()..upper.clone()).collect(),
            None => self.writes.range(start.to_vec()..).collect(),
        };
        let mut pending = range.into_iter().peekable();
        let mut stopped = false;
        let mut emit = |k: Vec<u8>, v: Option<Vec<u8>>, stopped: &mut bool| -> Result<()> {
            if let Some(v) = v {
                if !visit(k, v)? {
                    *stopped = true;
                }
            }
            Ok(())
        };
        self.base.scan(start, end, &mut |k, v| {
            while pending.peek().is_some_and(|(pk, _)| **pk < k) {
                let (pk, pv) = pending.next().expect("peek");
                emit(pk.clone(), pv.clone(), &mut stopped)?;
                if stopped {
                    return Ok(false);
                }
            }
            let value = match pending.peek() {
                Some((pk, _)) if **pk == k => pending.next().expect("peek").1.clone(),
                _ => Some(v),
            };
            emit(k, value, &mut stopped)?;
            Ok(!stopped)
        })?;
        if stopped {
            return Ok(());
        }
        for (pk, pv) in pending {
            emit(pk.clone(), pv.clone(), &mut stopped)?;
            if stopped {
                break;
            }
        }
        Ok(())
    }

    fn guard_unchanged(&self, start: &[u8], end: &[u8]) {
        self.base.guard_unchanged(start, end);
    }

    fn guard_present(&self, start: &[u8], end: &[u8]) {
        self.base.guard_present(start, end);
    }
}

// ---------------------------------------------------------------------------
// Escopo e contexto de avaliação
// ---------------------------------------------------------------------------

/// Colunas visíveis: (alias da relação, nome da coluna) na ordem da linha.
/// Colunas ocultas (lado direito de `USING`) só respondem com qualificador.
#[derive(Clone, Default, Debug)]
pub(super) struct Scope {
    pub cols: Vec<(String, String)>,
    pub hidden: Vec<bool>,
}

pub(super) fn unknown_column(table: Option<&str>, name: &str) -> Error {
    Error::Sql(format!(
        "coluna desconhecida {}{name}",
        table.map(|t| format!("{t}.")).unwrap_or_default()
    ))
}

fn is_unknown_column(e: &Error) -> bool {
    matches!(e, Error::Sql(m) if m.starts_with("coluna desconhecida"))
}

impl Scope {
    pub fn add(&mut self, alias: &str, names: &[String]) {
        self.add_using(alias, names, &[]);
    }

    pub fn add_using(&mut self, alias: &str, names: &[String], using: &[String]) {
        for c in names {
            self.cols.push((alias.to_string(), c.clone()));
            self.hidden.push(using.contains(c));
        }
    }

    fn slice(&self, n: usize) -> Scope {
        Scope {
            cols: self.cols[..n].to_vec(),
            hidden: self.hidden[..n].to_vec(),
        }
    }

    /// `Ok(None)` = não está aqui; `Err` = ambígua.
    pub fn lookup(&self, table: Option<&str>, name: &str) -> Result<Option<usize>> {
        let mut hits = self.cols.iter().enumerate().filter(|(i, (t, c))| {
            c == name && table.is_none_or(|x| x == t) && (table.is_some() || !self.hidden[*i])
        });
        match (hits.next(), hits.next()) {
            (Some((i, _)), None) => Ok(Some(i)),
            (Some(_), Some(_)) => Err(Error::Sql(format!("coluna ambígua {name}"))),
            _ => Ok(None),
        }
    }
}

/// Valores de agregados/janelas já calculados para a linha corrente.
type AggValues<'a> = Option<(&'a [Expr], &'a [Value])>;

/// Linha em avaliação e, para subconsultas correlacionadas, a externa.
#[derive(Clone, Copy)]
pub(super) struct Ctx<'a> {
    pub scope: &'a Scope,
    pub row: &'a [Value],
    pub aggs: AggValues<'a>,
    pub outer: Option<&'a Ctx<'a>>,
}

impl<'a> Ctx<'a> {
    pub fn new(scope: &'a Scope, row: &'a [Value], outer: Option<&'a Ctx<'a>>) -> Self {
        Self {
            scope,
            row,
            aggs: None,
            outer,
        }
    }
}

/// Resultado de uma consulta.
#[derive(Clone, Debug, Default)]
pub(super) struct Output {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

impl Output {
    pub fn into_result(self) -> ExecResult {
        ExecResult::Table {
            columns: self.columns,
            rows: self.rows,
        }
    }
}

/// Um elemento de padrão `LIKE`/`GLOB`.
enum Pat {
    Any,
    One,
    Ch(char),
    /// Classe `[a-z0-9]` / `[^x]` (só GLOB).
    Class(Vec<(char, char)>, bool),
}

fn pattern_tokens(pattern: &str, glob: bool) -> Vec<Pat> {
    let fold = |c: char| {
        if glob {
            c
        } else {
            c.to_lowercase().next().unwrap_or(c)
        }
    };
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        match (glob, c) {
            (false, '%') | (true, '*') => out.push(Pat::Any),
            (false, '_') | (true, '?') => out.push(Pat::One),
            (true, '[') => {
                let mut negate = false;
                if matches!(chars.get(i), Some('^' | '!')) {
                    negate = true;
                    i += 1;
                }
                let mut ranges = Vec::new();
                let mut first = true;
                loop {
                    let Some(&x) = chars.get(i) else {
                        // `[` sem fechamento: literal.
                        out.push(Pat::Ch('['));
                        return out;
                    };
                    i += 1;
                    if x == ']' && !first {
                        break;
                    }
                    first = false;
                    if chars.get(i) == Some(&'-') && chars.get(i + 1).is_some_and(|&y| y != ']') {
                        let hi = chars[i + 1];
                        i += 2;
                        ranges.push((x, hi));
                    } else {
                        ranges.push((x, x));
                    }
                }
                out.push(Pat::Class(ranges, negate));
            }
            _ => out.push(Pat::Ch(fold(c))),
        }
    }
    out
}

/// `LIKE` (sem distinção de caixa, `%`/`_`) ou `GLOB` (`*`/`?`/`[...]`, exato).
pub(super) fn like(text: &str, pattern: &str, glob: bool) -> bool {
    let fold = |c: char| {
        if glob {
            c
        } else {
            c.to_lowercase().next().unwrap_or(c)
        }
    };
    let t: Vec<char> = text.chars().map(fold).collect();
    let p = pattern_tokens(pattern, glob);
    // DP clássico O(n·m): dp[j] = p[..i] casa com t[..j].
    let mut dp = vec![false; t.len() + 1];
    dp[0] = true;
    for pc in &p {
        let mut next = vec![false; t.len() + 1];
        match pc {
            Pat::Any => {
                let mut seen = false;
                for j in 0..=t.len() {
                    seen |= dp[j];
                    next[j] = seen;
                }
            }
            _ => {
                for j in 1..=t.len() {
                    let ok = match pc {
                        Pat::One => true,
                        Pat::Ch(c) => *c == t[j - 1],
                        Pat::Class(ranges, negate) => {
                            ranges
                                .iter()
                                .any(|(lo, hi)| (*lo..=*hi).contains(&t[j - 1]))
                                != *negate
                        }
                        Pat::Any => unreachable!(),
                    };
                    next[j] = dp[j - 1] && ok;
                }
            }
        }
        dp = next;
    }
    dp[t.len()]
}

pub(super) fn arith(a: Value, op: BinOp, b: Value) -> Result<Value> {
    if a.is_null() || b.is_null() {
        return Ok(Value::Null);
    }
    if op == BinOp::Concat {
        return Ok(Value::Text(format!("{a}{b}")));
    }
    let overflow = || Error::Sql("estouro aritmético".into());
    let as_int = |v: &Value| match v {
        Value::Int(n) => Some(*n),
        Value::Bool(b) => Some(*b as i64),
        Value::Real(x) if x.fract() == 0.0 && x.abs() < 9.2e18 => Some(*x as i64),
        _ => None,
    };
    if matches!(op, BinOp::BitAnd | BinOp::BitOr | BinOp::Shl | BinOp::Shr) {
        let (Some(x), Some(y)) = (as_int(&a), as_int(&b)) else {
            return Err(Error::Sql("operador bit a bit exige inteiros".into()));
        };
        return Ok(Value::Int(match op {
            BinOp::BitAnd => x & y,
            BinOp::BitOr => x | y,
            BinOp::Shl if y >= 64 || y <= -64 => 0,
            BinOp::Shl if y < 0 => x >> (-y),
            BinOp::Shl => x << y,
            _ if y >= 64 || y <= -64 => 0,
            _ if y < 0 => x << (-y),
            _ => x >> y,
        }));
    }
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

/// Subexpressões diretas (não entra em subconsultas).
pub(crate) fn children(e: &Expr) -> Vec<&Expr> {
    match e {
        Expr::Lit(_) | Expr::Param(_) | Expr::Col(..) | Expr::Exists(..) | Expr::Subquery(_) => {
            Vec::new()
        }
        Expr::Neg(x) | Expr::Not(x) | Expr::BitNot(x) | Expr::IsNull(x, _) | Expr::Cast(x, _) => {
            vec![x]
        }
        Expr::InQuery(x, _, _) | Expr::Quantified(x, _, _, _) => vec![x],
        Expr::Bin(a, _, b) | Expr::Like(a, b, _, _) | Expr::IsDistinct(a, b, _) => vec![a, b],
        Expr::Between(a, b, c, _) => vec![a, b, c],
        Expr::In(x, list, _) => std::iter::once(&**x).chain(list.iter()).collect(),
        Expr::Case {
            operand,
            whens,
            otherwise,
        } => operand
            .iter()
            .map(|o| &**o)
            .chain(whens.iter().flat_map(|(w, t)| [w, t]))
            .chain(otherwise.iter().map(|o| &**o))
            .collect(),
        Expr::Func(_, args) | Expr::Agg(_, args, _) => args.iter().collect(),
        Expr::Match { columns, query } => columns.iter().chain(std::iter::once(&**query)).collect(),
        Expr::Window(_, args, spec) => args
            .iter()
            .chain(spec.partition_by.iter())
            .chain(spec.order_by.iter().map(|o| &o.expr))
            .collect(),
    }
}

/// Agregados da consulta atual (não entra em subconsultas: elas agregam sozinhas).
pub(super) fn collect_aggs(e: &Expr, out: &mut Vec<Expr>) {
    match e {
        Expr::Agg(..) => {
            if !out.contains(e) {
                out.push(e.clone());
            }
        }
        other => children(other)
            .into_iter()
            .for_each(|c| collect_aggs(c, out)),
    }
}

fn collect_windows(e: &Expr, out: &mut Vec<Expr>) {
    match e {
        Expr::Window(..) => {
            if !out.contains(e) {
                out.push(e.clone());
            }
        }
        other => children(other)
            .into_iter()
            .for_each(|c| collect_windows(c, out)),
    }
}

/// Colunas referenciadas diretamente (fora de subconsultas).
pub(super) fn columns_of(e: &Expr, out: &mut Vec<(Option<String>, String)>) {
    if let Expr::Col(t, c) = e {
        out.push((t.clone(), c.clone()));
    }
    children(e).into_iter().for_each(|c| columns_of(c, out));
}

pub(super) fn has_subquery(e: &Expr) -> bool {
    match e {
        Expr::Exists(..) | Expr::Subquery(_) | Expr::InQuery(..) | Expr::Quantified(..) => true,
        other => children(other).into_iter().any(has_subquery),
    }
}

pub(super) fn has_agg_or_window(e: &Expr) -> bool {
    match e {
        Expr::Agg(..) | Expr::Window(..) => true,
        other => children(other).into_iter().any(has_agg_or_window),
    }
}

pub(super) fn expr_name(e: &Expr) -> String {
    match e {
        Expr::Col(_, c) => c.clone(),
        Expr::Agg(f, args, _) => match args.first() {
            None => format!("{}(*)", f.name()),
            Some(a) => format!("{}({})", f.name(), expr_name(a)),
        },
        Expr::Window(f, _, _) => f.name(),
        Expr::Func(name, _) => name.clone(),
        Expr::Lit(v) => v.to_string(),
        Expr::Cast(x, _) => expr_name(x),
        _ => "?column?".into(),
    }
}

pub(super) fn row_key(row: &[Value]) -> Vec<u8> {
    row.iter().flat_map(key_of).collect()
}

/// Ordem de `ORDER BY`: NULL primeiro em ASC e último em DESC, salvo
/// `NULLS FIRST/LAST`.
pub(super) fn cmp_order(a: &[Value], b: &[Value], items: &[OrderItem]) -> Ordering {
    for ((x, y), item) in a.iter().zip(b).zip(items) {
        let o = match (x.is_null(), y.is_null(), item.nulls_first) {
            (true, true, _) => Ordering::Equal,
            (true, false, Some(first)) => {
                if first {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (false, true, Some(first)) => {
                if first {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            _ => {
                let o = x.total_cmp(y);
                if item.desc {
                    o.reverse()
                } else {
                    o
                }
            }
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

// ---------------------------------------------------------------------------
// Planejamento de acesso a uma tabela
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(super) enum Access {
    Full,
    /// Chave primária completa.
    Point(Vec<Value>),
    /// Várias chaves primárias (`pk IN (...)`).
    Points(Vec<Vec<Value>>),
    /// Prefixo da chave primária e faixa opcional na coluna seguinte.
    Range {
        prefix: Vec<Value>,
        lo: Option<Value>,
        hi: Option<Value>,
    },
    /// Valores das primeiras colunas de um índice.
    Index(usize, Vec<Value>),
    /// Índice full-text: candidatos que contêm os termos da consulta.
    FullText(usize, Rc<TextQuery>),
    /// Índice vetorial: os `k` vizinhos aproximados do vetor.
    Vector(usize, Vec<f32>, usize),
    /// Índice espacial: faixas Morton que cobrem a caixa consultada.
    Spatial(usize, Vec<(u64, u64)>),
}

impl Access {
    fn describe_est(&self, t: &Table, est: Option<f64>) -> String {
        let mut line = self.describe(t);
        if let Some(e) = est {
            line.push_str(&format!(" (est. rows≈{})", e.round() as u64));
        }
        line
    }

    fn describe(&self, t: &Table) -> String {
        let pk = t.pk_name();
        let list = |v: &[Value]| {
            v.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        match self {
            Self::Full => format!("SCAN {}", t.name),
            Self::Point(v) => format!("SEARCH {} USING PRIMARY KEY ({pk})=({})", t.name, list(v)),
            Self::Points(v) => format!(
                "SEARCH {} USING PRIMARY KEY ({pk}) IN {} values",
                t.name,
                v.len()
            ),
            Self::Range { prefix, lo, hi } => format!(
                "SEARCH {} USING PRIMARY KEY RANGE ({pk}) prefix=({}) {} .. {}",
                t.name,
                list(prefix),
                lo.as_ref().map_or("-inf".into(), Value::to_string),
                hi.as_ref().map_or("+inf".into(), Value::to_string)
            ),
            Self::Index(i, v) => {
                let idx = &t.indexes[*i];
                let cols: Vec<&str> = idx
                    .columns
                    .iter()
                    .map(|&c| t.columns[c].name.as_str())
                    .collect();
                format!(
                    "SEARCH {} USING {}INDEX {} ({})=({})",
                    t.name,
                    if idx.unique { "UNIQUE " } else { "" },
                    idx.name,
                    cols.join(", "),
                    list(v)
                )
            }
            Self::FullText(i, q) => format!(
                "SEARCH {} USING FULLTEXT INDEX {} terms={}",
                t.name,
                t.indexes[*i].name,
                q.all_terms().len()
            ),
            Self::Vector(i, v, k) => format!(
                "SEARCH {} USING VECTOR INDEX {} ({}) dims={} k={k}",
                t.name,
                t.indexes[*i].name,
                t.indexes[*i].metric().name(),
                v.len()
            ),
            Self::Spatial(i, ranges) => format!(
                "SEARCH {} USING SPATIAL INDEX {} ranges={}",
                t.name,
                t.indexes[*i].name,
                ranges.len()
            ),
        }
    }
}

/// Nós HNSW guardados nas chaves do índice (`prefixo 'n' pk`, entrada em
/// `prefixo 'e'`). Sem `pending` é somente leitura.
pub(super) struct HnswStore<'a> {
    pub src: &'a dyn Source,
    pub pending: Option<&'a Pending>,
    pub prefix: Vec<u8>,
}

impl HnswStore<'_> {
    fn key(&self, tag: u8, id: &[u8]) -> Vec<u8> {
        let mut k = self.prefix.clone();
        k.push(tag);
        k.extend_from_slice(id);
        k
    }

    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.pending {
            Some(p) => p.get(self.src, key),
            None => self.src.get(key),
        }
    }
}

impl NodeStore for HnswStore<'_> {
    fn get_node(&self, id: &[u8]) -> Result<Option<search::Node>> {
        match self.read(&self.key(VEC_NODE, id))? {
            Some(raw) => search::Node::decode(&raw).map(Some),
            None => Ok(None),
        }
    }

    fn put_node(&self, id: &[u8], node: &search::Node) -> Result<()> {
        let p = self
            .pending
            .ok_or_else(|| Error::Other("índice vetorial somente leitura".into()))?;
        p.put(self.key(VEC_NODE, id), node.encode());
        Ok(())
    }

    fn entry(&self) -> Result<Option<(Vec<u8>, usize)>> {
        Ok(self
            .read(&self.key(VEC_ENTRY, &[]))?
            .filter(|v| !v.is_empty())
            .map(|v| (v[1..].to_vec(), v[0] as usize)))
    }

    fn set_entry(&self, id: &[u8], level: usize) -> Result<()> {
        let p = self
            .pending
            .ok_or_else(|| Error::Other("índice vetorial somente leitura".into()))?;
        let mut v = vec![level as u8];
        v.extend_from_slice(id);
        p.put(self.key(VEC_ENTRY, &[]), v);
        Ok(())
    }
}

/// Chaves de postings de um termo: `prefixo 'p' termo 0 pk`.
pub(super) fn posting_prefix(index_prefix: &[u8], term: &str) -> Vec<u8> {
    let mut k = index_prefix.to_vec();
    k.push(FTS_POSTING);
    k.extend_from_slice(term.as_bytes());
    k.push(0);
    k
}

/// Chaves primárias dos documentos que contêm `term` (ou começam por ele):
/// `(termo, pk)`.
pub(super) fn fts_postings(
    src: &dyn Source,
    index_prefix: &[u8],
    term: &str,
    prefix_match: bool,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut start = index_prefix.to_vec();
    start.push(FTS_POSTING);
    start.extend_from_slice(term.as_bytes());
    if !prefix_match {
        start.push(0);
    }
    let end = prefix_successor(&start).expect("prefixo");
    let base = index_prefix.len() + 1;
    let mut out = Vec::new();
    src.scan(&start, Some(&end), &mut |k, _| {
        let rest = &k[base..];
        if let Some(zero) = rest.iter().position(|&b| b == 0) {
            let word = String::from_utf8_lossy(&rest[..zero]).into_owned();
            out.push((word, rest[zero + 1..].to_vec()));
        }
        Ok(true)
    })?;
    Ok(out)
}

/// Estatísticas do índice full-text: (documentos, soma dos comprimentos).
pub(super) fn fts_stats(src: &dyn Source, index_prefix: &[u8]) -> Result<(u64, u64)> {
    let mut k = index_prefix.to_vec();
    k.push(FTS_STATS);
    Ok(match src.get(&k)? {
        Some(v) if v.len() >= 16 => (
            u64::from_le_bytes(v[..8].try_into().expect("8")),
            u64::from_le_bytes(v[8..16].try_into().expect("8")),
        ),
        _ => (0, 0),
    })
}

/// Visita as linhas candidatas do plano em `src`: `(pk codificada, linha)`.
/// Visita as linhas das chaves primárias dadas, na ordem dada.
fn visit_pks(
    src: &dyn Source,
    t: &Table,
    pks: Vec<Vec<u8>>,
    visit: &mut dyn FnMut(Vec<u8>, Vec<Value>) -> Result<bool>,
) -> Result<()> {
    for pk in pks {
        if let Some(raw) = src.get(&t.row_key(&pk))? {
            if !visit(pk, t.decode(&raw)?)? {
                break;
            }
        }
    }
    Ok(())
}

/// Candidatos de um índice full-text: chaves primárias ordenadas (todos os
/// grupos da consulta casam por algum termo) e df por termo encontrado.
/// `(chaves primárias, df por termo)`.
type FtsCandidates = (Vec<Vec<u8>>, HashMap<String, f64>);

pub(super) fn fts_candidates(
    src: &dyn Source,
    t: &Table,
    i: usize,
    q: &TextQuery,
) -> Result<FtsCandidates> {
    let prefix = t.index_prefix(&t.indexes[i]);
    let mut df: HashMap<String, f64> = HashMap::new();
    let word_pks = |w: &str, df: &mut HashMap<String, f64>| -> Result<BTreeSet<Vec<u8>>> {
        let posts = fts_postings(src, &prefix, w, false)?;
        df.insert(w.to_string(), posts.len() as f64);
        Ok(posts.into_iter().map(|(_, pk)| pk).collect())
    };
    let mut result: Option<BTreeSet<Vec<u8>>> = None;
    for group in &q.groups {
        let mut union = BTreeSet::new();
        for term in group {
            match term {
                search::Term::Word(w) => union.extend(word_pks(w, &mut df)?),
                search::Term::Prefix(p) => {
                    for (w, pk) in fts_postings(src, &prefix, p, true)? {
                        *df.entry(w).or_default() += 1.0;
                        union.insert(pk);
                    }
                }
                search::Term::Phrase(words) => {
                    let mut acc: Option<BTreeSet<Vec<u8>>> = None;
                    for w in words {
                        let set = word_pks(w, &mut df)?;
                        acc = Some(match acc {
                            Some(a) => a.intersection(&set).cloned().collect(),
                            None => set,
                        });
                    }
                    union.extend(acc.unwrap_or_default());
                }
            }
        }
        result = Some(match result {
            Some(r) => r.intersection(&union).cloned().collect(),
            None => union,
        });
    }
    Ok((result.unwrap_or_default().into_iter().collect(), df))
}

/// Pontuação BM25 de `MATCH ... AGAINST` (estatísticas do índice quando a
/// consulta usou um; sem índice, só a frequência no documento conta).
#[derive(Default)]
pub(super) struct FtsScorer {
    pub docs: f64,
    pub avg_len: f64,
    pub df: HashMap<String, f64>,
}

impl FtsScorer {
    fn score(&self, tf: f64, term: &str, doc_len: f64) -> f64 {
        if self.docs < 1.0 {
            return search::Bm25 {
                docs: 1.0,
                avg_len: doc_len,
            }
            .score(tf, 0.0, doc_len);
        }
        let bm25 = search::Bm25 {
            docs: self.docs,
            avg_len: self.avg_len,
        };
        bm25.score(tf, self.df.get(term).copied().unwrap_or(1.0), doc_len)
    }
}

#[derive(Default)]
pub(super) struct FtsCache {
    queries: HashMap<String, Rc<TextQuery>>,
    scorers: HashMap<String, Rc<FtsScorer>>,
}

fn scorer_key(q: &TextQuery) -> String {
    q.all_terms().join(" ")
}

pub(super) fn fetch_from(
    src: &dyn Source,
    t: &Table,
    access: &Access,
    visit: &mut dyn FnMut(Vec<u8>, Vec<Value>) -> Result<bool>,
) -> Result<()> {
    let prefix = t.row_prefix();
    let pk_of = |k: &[u8]| k[prefix.len()..].to_vec();
    let point = |vals: &[Value], visit: &mut dyn FnMut(Vec<u8>, Vec<Value>) -> Result<bool>| {
        let pk = encode_tuple(&vals.iter().collect::<Vec<_>>());
        match src.get(&t.row_key(&pk))? {
            Some(raw) => visit(pk, t.decode(&raw)?),
            None => Ok(true),
        }
    };
    match access {
        Access::Point(vals) => {
            point(vals, visit)?;
            Ok(())
        }
        Access::Points(list) => {
            let mut sorted: Vec<&Vec<Value>> = list.iter().collect();
            sorted.sort_by_key(|v| row_key(v));
            sorted.dedup_by_key(|v| row_key(v));
            for vals in sorted {
                if !point(vals, visit)? {
                    break;
                }
            }
            Ok(())
        }
        Access::Index(i, vals) => {
            let p = t.index_lookup(&t.indexes[*i], &vals.iter().collect::<Vec<_>>());
            let end = prefix_successor(&p).expect("prefixo não é só 0xFF");
            let mut pks = Vec::new();
            src.scan(&p, Some(&end), &mut |_, pk| {
                pks.push(pk);
                Ok(true)
            })?;
            visit_pks(src, t, pks, visit)
        }
        Access::FullText(i, q) => {
            let (pks, _) = fts_candidates(src, t, *i, q)?;
            visit_pks(src, t, pks, visit)
        }
        Access::Vector(i, q, k) => {
            let idx = &t.indexes[*i];
            let store = HnswStore {
                src,
                pending: None,
                prefix: t.index_prefix(idx),
            };
            let ef = (*k * 4).max(64);
            let found = search::hnsw_search(&store, idx.metric(), q, *k, ef)?;
            visit_pks(src, t, found.into_iter().map(|(_, pk)| pk).collect(), visit)
        }
        Access::Spatial(i, ranges) => {
            let p = t.index_prefix(&t.indexes[*i]);
            let mut pks = BTreeSet::new();
            for (a, b) in ranges {
                let mut start = p.clone();
                start.extend_from_slice(&a.to_be_bytes());
                let mut end = p.clone();
                end.extend_from_slice(&b.to_be_bytes());
                end.push(0xFF);
                src.scan(&start, Some(&end), &mut |k, _| {
                    pks.insert(k[p.len() + 8..].to_vec());
                    Ok(true)
                })?;
            }
            visit_pks(src, t, pks.into_iter().collect(), visit)
        }
        Access::Full | Access::Range { .. } => {
            let (start, end) = match access {
                Access::Range { prefix: p, lo, hi } => {
                    let mut base = prefix.clone();
                    base.extend(encode_tuple(&p.iter().collect::<Vec<_>>()));
                    let start = match lo {
                        Some(v) => {
                            let mut k = base.clone();
                            k.extend(key_of(v));
                            k
                        }
                        None => base.clone(),
                    };
                    // Codificação auto-delimitada: nada fica entre enc(hi)
                    // e enc(hi)+FF além das chaves que começam com enc(hi).
                    let end = match hi {
                        Some(v) => {
                            let mut k = base.clone();
                            k.extend(key_of(v));
                            k.push(0xFF);
                            k
                        }
                        None => prefix_successor(&base).expect("prefixo"),
                    };
                    (start, end)
                }
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
// Relações do FROM
// ---------------------------------------------------------------------------

pub(super) enum Relation {
    Table(Table),
    /// Linhas materializadas e, opcionalmente, nomes de coluna renomeados.
    Derived(Rc<Output>, Option<Vec<String>>),
}

impl Relation {
    fn names(&self) -> Vec<String> {
        match self {
            Self::Table(t) => t.columns.iter().map(|c| c.name.clone()).collect(),
            Self::Derived(o, None) => o.columns.clone(),
            Self::Derived(_, Some(names)) => names.clone(),
        }
    }

    fn width(&self) -> usize {
        match self {
            Self::Table(t) => t.columns.len(),
            Self::Derived(o, _) => o.columns.len(),
        }
    }
}

/// Estratégia de um join (também usada pelo EXPLAIN).
enum JoinPlan {
    /// Busca por chave/índice da tabela interna, por linha externa.
    Lookup {
        column: usize,
        expr: Expr,
    },
    /// Hash join: `inner_expr = outer_expr`.
    Hash {
        inner: Expr,
        outer: Expr,
    },
    Nested,
}

/// CTE visível: definição (avaliada sob demanda, com cache) ou linhas já
/// materializadas (passo de uma CTE recursiva).
enum CteBinding {
    Def {
        name: String,
        query: Rc<Query>,
        key: usize,
        columns: Vec<String>,
        recursive: bool,
    },
    Rows(String, Rc<Output>),
}

impl CteBinding {
    fn name(&self) -> &str {
        match self {
            Self::Def { name, .. } | Self::Rows(name, _) => name,
        }
    }
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// View carregada: definição do catálogo e consulta já analisada.
type ViewRef = Rc<(View, Rc<Query>)>;

pub(super) struct Exec<'a> {
    pub src: &'a dyn Source,
    pub params: &'a [Value],
    ctes: RefCell<Vec<CteBinding>>,
    /// Resultados de subconsultas/CTEs/views não correlacionadas, por ponteiro da AST.
    cache: RefCell<HashMap<usize, Rc<Output>>>,
    correlated: RefCell<HashSet<usize>>,
    /// ASTs clonadas uma vez por comando (CTEs, views).
    asts: RefCell<HashMap<usize, Rc<Query>>>,
    views: RefCell<HashMap<String, Option<ViewRef>>>,
    tables: RefCell<HashMap<String, Rc<Table>>>,
    children: RefCell<HashMap<String, Rc<Vec<Table>>>>,
    stats: RefCell<HashMap<String, Option<Rc<Stats>>>>,
    /// Views em expansão (detecta referência circular).
    view_depth: Cell<usize>,
    /// Profundidade de gatilhos aninhados (corpo que dispara outro gatilho).
    pub trigger_depth: usize,
    /// `EXPLAIN ANALYZE`: anota linhas lidas e tempos.
    analyze: Cell<bool>,
    notes: RefCell<Vec<String>>,
    fts: RefCell<FtsCache>,
}

impl<'a> Exec<'a> {
    pub(super) fn new(src: &'a dyn Source, params: &'a [Value]) -> Self {
        Self {
            src,
            params,
            ctes: RefCell::default(),
            cache: RefCell::default(),
            correlated: RefCell::default(),
            asts: RefCell::default(),
            views: RefCell::default(),
            tables: RefCell::default(),
            children: RefCell::default(),
            stats: RefCell::default(),
            view_depth: Cell::new(0),
            trigger_depth: 0,
            analyze: Cell::new(false),
            notes: RefCell::default(),
            fts: RefCell::default(),
        }
    }

    /// Consulta full-text analisada (com cache) e o pontuador correspondente.
    fn fts_query(&self, text: &str) -> (Rc<TextQuery>, Rc<FtsScorer>) {
        let mut cache = self.fts.borrow_mut();
        let q = cache
            .queries
            .entry(text.to_string())
            .or_insert_with(|| Rc::new(TextQuery::parse(text)))
            .clone();
        let scorer = cache
            .scorers
            .get(&scorer_key(&q))
            .cloned()
            .unwrap_or_default();
        (q, scorer)
    }

    /// `ORDER BY distância(vetor) LIMIT k` numa tabela com índice vetorial na
    /// coluna e mesma métrica: vizinhos aproximados pelo HNSW.
    fn knn_access(
        &self,
        s: &Select,
        t: &Table,
        alias: &str,
        order_by: &[OrderItem],
        limit: Option<usize>,
        offset: usize,
    ) -> Option<(Access, Option<f64>)> {
        let plain = s.joins.is_empty() && s.group_by.is_empty() && !s.distinct;
        let [o] = order_by else {
            return None;
        };
        if !plain || o.desc {
            return None;
        }
        let (col, metric, q) = self.knn_target(t, alias, &o.expr)?;
        let i = t
            .vector_index_on(col)
            .filter(|&i| t.indexes[i].metric() == metric)?;
        // ponytail: com filtro, 4x candidatos; ainda pode voltar menos que k.
        let k = (limit? + offset).max(1) * if s.filter.is_some() { 4 } else { 1 };
        Some((Access::Vector(i, q, k), Some(k as f64)))
    }

    /// `ORDER BY distância(coluna, vetor)`: coluna, métrica e vetor consultado.
    fn knn_target(&self, t: &Table, alias: &str, e: &Expr) -> Option<(usize, Metric, Vec<f32>)> {
        let Expr::Func(name, args) = e else {
            return None;
        };
        let metric = match (name.as_str(), args.len()) {
            ("vec_l2", 2) => Metric::L2,
            ("vec_cosine", 2) | ("vec_distance", 2) => Metric::Cosine,
            ("vec_dot", 2) => Metric::Dot,
            ("vec_distance", 3) => match &args[2] {
                Expr::Lit(Value::Text(m)) => Metric::parse(m)?,
                _ => return None,
            },
            _ => return None,
        };
        let col = |x: &Expr| match x {
            Expr::Col(q, name) if q.as_deref().is_none_or(|q| q == alias) => t.column(name).ok(),
            _ => None,
        };
        let vector = |x: &Expr| match x {
            Expr::Lit(v) => search::parse_vector(&v.to_string()).ok(),
            Expr::Param(i) => search::parse_vector(&self.params.get(*i)?.to_string()).ok(),
            _ => None,
        };
        match (col(&args[0]), col(&args[1])) {
            (Some(c), _) => Some((c, metric, vector(&args[1])?)),
            (_, Some(c)) => Some((c, metric, vector(&args[0])?)),
            _ => None,
        }
    }

    /// Executor aninhado (corpo de gatilho) lendo por `src`.
    pub(super) fn nested(src: &'a dyn Source, params: &'a [Value], depth: usize) -> Self {
        let mut e = Self::new(src, params);
        e.trigger_depth = depth;
        e
    }

    /// Estatísticas da tabela (cache por comando).
    pub(super) fn stats(&self, name: &str) -> Result<Option<Rc<Stats>>> {
        if let Some(s) = self.stats.borrow().get(name) {
            return Ok(s.clone());
        }
        let loaded = load_stats(self.src, name)?.map(Rc::new);
        self.stats
            .borrow_mut()
            .insert(name.to_string(), loaded.clone());
        Ok(loaded)
    }

    fn note(&self, line: String) {
        if self.analyze.get() {
            self.notes.borrow_mut().push(line);
        }
    }

    /// Tabelas materializadas com atualização automática que leem `table`.
    pub(super) fn auto_views_of(&self, table: &str) -> Result<Vec<Table>> {
        let mut out = Vec::new();
        for t in list_tables(self.src)? {
            if let TableKind::Materialized { sql, auto: true } = &t.kind {
                if let Ok((Stmt::Query(q), _)) = super::parser::parse(sql) {
                    if super::parser::query_mentions(&q, table) && t.name != table {
                        out.push(t);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Tabela do catálogo (cache por comando).
    pub(super) fn table(&self, name: &str) -> Result<Rc<Table>> {
        if let Some(t) = self.tables.borrow().get(name) {
            return Ok(Rc::clone(t));
        }
        let t = Rc::new(load_table(self.src, name)?);
        self.tables
            .borrow_mut()
            .insert(name.to_string(), Rc::clone(&t));
        Ok(t)
    }

    /// Tabelas com chave estrangeira apontando para `parent`.
    pub(super) fn children_of(&self, parent: &str) -> Result<Rc<Vec<Table>>> {
        if let Some(c) = self.children.borrow().get(parent) {
            return Ok(Rc::clone(c));
        }
        let all: Vec<Table> = list_tables(self.src)?
            .into_iter()
            .filter(|t| t.fks.iter().any(|f| f.parent == parent))
            .collect();
        let rc = Rc::new(all);
        self.children
            .borrow_mut()
            .insert(parent.to_string(), Rc::clone(&rc));
        Ok(rc)
    }

    fn view(&self, name: &str) -> Result<Option<ViewRef>> {
        if let Some(v) = self.views.borrow().get(name) {
            return Ok(v.clone());
        }
        let loaded = match load_view(self.src, name)? {
            None => None,
            Some(v) => {
                let (stmt, _) = super::parser::parse(&v.sql)?;
                let Stmt::Query(q) = stmt else {
                    return Err(Error::Sql(format!("view {name} não é uma consulta")));
                };
                Some(Rc::new((v, Rc::from(q))))
            }
        };
        self.views
            .borrow_mut()
            .insert(name.to_string(), loaded.clone());
        Ok(loaded)
    }

    fn column(&self, ctx: &Ctx<'_>, table: Option<&str>, name: &str) -> Result<Value> {
        let mut frame = Some(ctx);
        while let Some(c) = frame {
            if let Some(i) = c.scope.lookup(table, name)? {
                return Ok(c.row[i].clone());
            }
            frame = c.outer;
        }
        Err(unknown_column(table, name))
    }

    pub(super) fn eval(&self, e: &Expr, ctx: &Ctx<'_>) -> Result<Value> {
        let ev = |x: &Expr| self.eval(x, ctx);
        Ok(match e {
            Expr::Lit(v) => v.clone(),
            Expr::Param(i) => self
                .params
                .get(*i)
                .cloned()
                .ok_or_else(|| Error::Sql(format!("parâmetro {} não informado", i + 1)))?,
            Expr::Col(t, name) => self.column(ctx, t.as_deref(), name)?,
            Expr::Neg(x) => match ev(x)? {
                Value::Int(n) => Value::Int(
                    n.checked_neg()
                        .ok_or_else(|| Error::Sql("estouro".into()))?,
                ),
                Value::Real(x) => Value::Real(-x),
                Value::Null => Value::Null,
                other => return Err(Error::Sql(format!("negação de {}", other.type_name()))),
            },
            Expr::BitNot(x) => match ev(x)? {
                Value::Int(n) => Value::Int(!n),
                Value::Null => Value::Null,
                other => return Err(Error::Sql(format!("~ de {}", other.type_name()))),
            },
            Expr::Not(x) => truth(ev(x)?.truth().map(|b| !b)),
            Expr::Bin(a, BinOp::And, b) => {
                let a = ev(a)?.truth();
                if a == Some(false) {
                    return Ok(Value::Bool(false));
                }
                truth(match (a, ev(b)?.truth()) {
                    (_, Some(false)) => Some(false),
                    (Some(true), Some(true)) => Some(true),
                    _ => None,
                })
            }
            Expr::Bin(a, BinOp::Or, b) => {
                let a = ev(a)?.truth();
                if a == Some(true) {
                    return Ok(Value::Bool(true));
                }
                truth(match (a, ev(b)?.truth()) {
                    (_, Some(true)) => Some(true),
                    (Some(false), Some(false)) => Some(false),
                    _ => None,
                })
            }
            Expr::Bin(a, op, b) => {
                let (a, b) = (ev(a)?, ev(b)?);
                match compare(&a, *op, &b) {
                    Some(v) => v,
                    None => arith(a, *op, b)?,
                }
            }
            Expr::IsNull(x, neg) => Value::Bool(ev(x)?.is_null() != *neg),
            Expr::IsDistinct(a, b, neg) => {
                let (a, b) = (ev(a)?, ev(b)?);
                let same = match (a.is_null(), b.is_null()) {
                    (true, true) => true,
                    (false, false) => a.sql_cmp(&b) == Some(Ordering::Equal),
                    _ => false,
                };
                Value::Bool(same == *neg)
            }
            Expr::Like(x, p, neg, glob) => match (ev(x)?, ev(p)?) {
                (Value::Null, _) | (_, Value::Null) => Value::Null,
                (x, p) => Value::Bool(like(&x.to_string(), &p.to_string(), *glob) != *neg),
            },
            Expr::In(x, list, neg) => {
                let x = ev(x)?;
                let values = list.iter().map(ev).collect::<Result<Vec<_>>>()?;
                in_list(&x, values.iter(), *neg)
            }
            Expr::InQuery(x, q, neg) => {
                let x = ev(x)?;
                let out = self.subquery(q, Some(ctx))?;
                if out.columns.len() != 1 {
                    return Err(Error::Sql("IN (SELECT ...) precisa de uma coluna".into()));
                }
                in_list(&x, out.rows.iter().map(|r| &r[0]), *neg)
            }
            Expr::Quantified(x, op, all, q) => {
                let x = ev(x)?;
                let out = self.subquery(q, Some(ctx))?;
                if out.columns.len() != 1 {
                    return Err(Error::Sql(
                        "ANY/ALL (SELECT ...) precisa de uma coluna".into(),
                    ));
                }
                let mut unknown = false;
                for row in &out.rows {
                    match compare(&x, *op, &row[0]).and_then(|v| v.truth()) {
                        Some(true) if !*all => return Ok(Value::Bool(true)),
                        Some(false) if *all => return Ok(Value::Bool(false)),
                        None => unknown = true,
                        _ => {}
                    }
                }
                if unknown {
                    Value::Null
                } else {
                    Value::Bool(*all)
                }
            }
            Expr::Exists(q, neg) => {
                Value::Bool(self.subquery(q, Some(ctx))?.rows.is_empty() == *neg)
            }
            Expr::Subquery(q) => {
                let out = self.subquery(q, Some(ctx))?;
                if out.columns.len() != 1 {
                    return Err(Error::Sql(
                        "subconsulta escalar precisa de uma coluna".into(),
                    ));
                }
                match out.rows.len() {
                    0 => Value::Null,
                    1 => out.rows[0][0].clone(),
                    n => {
                        return Err(Error::Sql(format!(
                            "subconsulta escalar devolveu {n} linhas"
                        )))
                    }
                }
            }
            Expr::Between(x, lo, hi, neg) => {
                let x = ev(x)?;
                let ge = x.sql_cmp(&ev(lo)?).map(|o| o != Ordering::Less);
                let le = x.sql_cmp(&ev(hi)?).map(|o| o != Ordering::Greater);
                truth(match (ge, le) {
                    (Some(false), _) | (_, Some(false)) => Some(*neg),
                    (Some(true), Some(true)) => Some(!neg),
                    _ => None,
                })
            }
            Expr::Case {
                operand,
                whens,
                otherwise,
            } => {
                let subject = operand.as_deref().map(ev).transpose()?;
                for (when, then) in whens {
                    let hit = match &subject {
                        Some(s) => s.sql_cmp(&ev(when)?) == Some(Ordering::Equal),
                        None => ev(when)?.truth() == Some(true),
                    };
                    if hit {
                        return ev(then);
                    }
                }
                match otherwise {
                    Some(o) => ev(o)?,
                    None => Value::Null,
                }
            }
            Expr::Cast(x, ty) => func::cast(ev(x)?, *ty)?,
            Expr::Func(name, args) => {
                let vals = args.iter().map(ev).collect::<Result<Vec<_>>>()?;
                if name.starts_with("pg_get_")
                    || name.ends_with("regclass")
                    || name.starts_with("pg_") && name.ends_with("_size")
                {
                    if let Some(v) = super::pgcatalog::function(self.src, name, &vals)? {
                        return Ok(v);
                    }
                }
                func::call(name, vals)?
            }
            Expr::Match { columns, query } => {
                let mut text = String::new();
                for c in columns {
                    let v = ev(c)?;
                    if !v.is_null() {
                        if !text.is_empty() {
                            text.push(' ');
                        }
                        text.push_str(&v.to_string());
                    }
                }
                let q = ev(query)?;
                if q.is_null() {
                    return Ok(Value::Null);
                }
                let (q, scorer) = self.fts_query(&q.to_string());
                let positions = search::term_positions(&text);
                let vocabulary = |p: &str| {
                    positions
                        .keys()
                        .filter(|w| w.starts_with(p))
                        .cloned()
                        .collect::<Vec<_>>()
                };
                match search::matches(&q, &positions, vocabulary) {
                    None => Value::Real(0.0),
                    Some(hits) => {
                        let len = positions.values().map(Vec::len).sum::<usize>() as f64;
                        let score: f64 = hits
                            .iter()
                            .map(|h| scorer.score(positions[h].len() as f64, h, len))
                            .sum();
                        Value::Real(score.max(1e-9))
                    }
                }
            }
            Expr::Agg(..) | Expr::Window(..) => {
                let mut frame = Some(ctx);
                while let Some(c) = frame {
                    if let Some((exprs, vals)) = c.aggs {
                        if let Some(i) = exprs.iter().position(|x| x == e) {
                            return Ok(vals[i].clone());
                        }
                    }
                    frame = c.outer;
                }
                return Err(Error::Sql(if matches!(e, Expr::Agg(..)) {
                    "agregado fora de SELECT/HAVING/ORDER BY".into()
                } else {
                    "função de janela só em SELECT/ORDER BY".into()
                }));
            }
        })
    }

    pub(super) fn is_true(&self, e: Option<&Expr>, ctx: &Ctx<'_>) -> Result<bool> {
        match e {
            None => Ok(true),
            Some(e) => Ok(self.eval(e, ctx)?.truth() == Some(true)),
        }
    }

    /// Avalia com cache por ponteiro da AST. Tenta primeiro sem a linha
    /// externa: se der certo, não é correlacionada e o resultado fica em cache.
    fn cached(
        &self,
        key: usize,
        outer: Option<&Ctx<'_>>,
        run: &dyn Fn(Option<&Ctx<'_>>) -> Result<Output>,
    ) -> Result<Rc<Output>> {
        if let Some(out) = self.cache.borrow().get(&key) {
            return Ok(Rc::clone(out));
        }
        if !self.correlated.borrow().contains(&key) {
            match run(None) {
                Ok(out) => {
                    let out = Rc::new(out);
                    self.cache.borrow_mut().insert(key, Rc::clone(&out));
                    return Ok(out);
                }
                Err(e) if is_unknown_column(&e) && outer.is_some() => {
                    self.correlated.borrow_mut().insert(key);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Rc::new(run(outer)?))
    }

    fn subquery(&self, q: &Query, outer: Option<&Ctx<'_>>) -> Result<Rc<Output>> {
        self.cached(q as *const Query as usize, outer, &|o| self.query(q, o))
    }

    fn constant(&self, e: Option<&Expr>, what: &str) -> Result<Option<usize>> {
        let Some(e) = e else { return Ok(None) };
        let empty = Scope::default();
        match self.eval(e, &Ctx::new(&empty, &[], None))? {
            Value::Int(n) if n >= 0 => Ok(Some(n as usize)),
            Value::Null => Ok(None),
            other => Err(Error::Sql(format!(
                "{what} precisa ser inteiro não negativo (recebido {other})"
            ))),
        }
    }

    /// Executa uma consulta completa (CTEs, conjunto, ORDER BY, LIMIT).
    pub(super) fn query(&self, q: &Query, outer: Option<&Ctx<'_>>) -> Result<Output> {
        let pushed = q.ctes.len();
        for cte in &q.ctes {
            let key = &cte.query as *const Query as usize;
            let query = Rc::clone(
                self.asts
                    .borrow_mut()
                    .entry(key)
                    .or_insert_with(|| Rc::new(cte.query.clone())),
            );
            self.ctes.borrow_mut().push(CteBinding::Def {
                name: cte.name.clone(),
                query,
                key,
                columns: cte.columns.clone(),
                recursive: cte.recursive,
            });
        }
        let result = (|| {
            let limit = self.constant(q.limit.as_ref(), "LIMIT")?;
            let offset = self.constant(q.offset.as_ref(), "OFFSET")?.unwrap_or(0);
            match &q.body {
                SetExpr::Select(s) => self.select(s, &q.order_by, limit, offset, outer),
                compound => {
                    let mut out = self.set_expr(compound, outer)?;
                    self.order_output(&mut out, &q.order_by)?;
                    out.rows = std::mem::take(&mut out.rows)
                        .into_iter()
                        .skip(offset)
                        .take(limit.unwrap_or(usize::MAX))
                        .collect();
                    Ok(out)
                }
            }
        })();
        let mut ctes = self.ctes.borrow_mut();
        let keep = ctes.len() - pushed;
        ctes.truncate(keep);
        result
    }

    /// CTE recursiva: termo base, depois o passo até não surgir linha nova.
    fn recursive_cte(
        &self,
        name: &str,
        q: &Query,
        columns: &[String],
        outer: Option<&Ctx<'_>>,
    ) -> Result<Output> {
        let SetExpr::SetOp {
            op: SetOp::Union,
            all,
            left,
            right,
        } = &q.body
        else {
            return Err(Error::Sql(format!(
                "CTE recursiva {name} precisa de 'termo base UNION [ALL] passo recursivo'"
            )));
        };
        let base = self.set_expr(left, outer)?;
        let columns: Vec<String> = if columns.is_empty() {
            base.columns.clone()
        } else {
            if columns.len() != base.columns.len() {
                return Err(Error::Sql(format!(
                    "CTE {name} declara {} colunas, consulta tem {}",
                    columns.len(),
                    base.columns.len()
                )));
            }
            columns.to_vec()
        };
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut result: Vec<Vec<Value>> = Vec::new();
        for row in base.rows {
            if *all || seen.insert(row_key(&row)) {
                result.push(row);
            }
        }
        let mut working = result.clone();
        let mut iterations = 0usize;
        while !working.is_empty() {
            iterations += 1;
            if iterations > MAX_RECURSION {
                return Err(Error::Sql(format!(
                    "CTE recursiva {name} passou de {MAX_RECURSION} iterações: limite o passo com WHERE ou LIMIT dentro da CTE"
                )));
            }
            self.ctes.borrow_mut().push(CteBinding::Rows(
                name.to_string(),
                Rc::new(Output {
                    columns: columns.clone(),
                    rows: working,
                }),
            ));
            let step = self.set_expr(right, outer);
            self.ctes.borrow_mut().pop();
            let step = step?;
            if step.columns.len() != columns.len() {
                return Err(Error::Sql(format!(
                    "passo recursivo de {name} devolve {} colunas, base tem {}",
                    step.columns.len(),
                    columns.len()
                )));
            }
            working = Vec::new();
            for row in step.rows {
                if *all || seen.insert(row_key(&row)) {
                    working.push(row.clone());
                    result.push(row);
                }
            }
            if let Some(limit) = self.constant(q.limit.as_ref(), "LIMIT")? {
                let offset = self.constant(q.offset.as_ref(), "OFFSET")?.unwrap_or(0);
                if q.order_by.is_empty() && result.len() >= limit + offset {
                    break;
                }
            }
        }
        let mut out = Output {
            columns,
            rows: result,
        };
        self.order_output(&mut out, &q.order_by)?;
        let limit = self.constant(q.limit.as_ref(), "LIMIT")?;
        let offset = self.constant(q.offset.as_ref(), "OFFSET")?.unwrap_or(0);
        if limit.is_some() || offset > 0 {
            out.rows = std::mem::take(&mut out.rows)
                .into_iter()
                .skip(offset)
                .take(limit.unwrap_or(usize::MAX))
                .collect();
        }
        Ok(out)
    }

    fn values(&self, rows: &[Vec<Expr>], outer: Option<&Ctx<'_>>) -> Result<Output> {
        let empty = Scope::default();
        let ctx = Ctx::new(&empty, &[], outer);
        let width = rows.first().map_or(0, Vec::len);
        let out_rows = rows
            .iter()
            .map(|r| {
                r.iter()
                    .map(|e| self.eval(e, &ctx))
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Output {
            columns: (1..=width).map(|i| format!("column{i}")).collect(),
            rows: out_rows,
        })
    }

    fn set_expr(&self, e: &SetExpr, outer: Option<&Ctx<'_>>) -> Result<Output> {
        match e {
            SetExpr::Select(s) => self.select(s, &[], None, 0, outer),
            SetExpr::Values(rows) => self.values(rows, outer),
            SetExpr::SetOp {
                op,
                all,
                left,
                right,
            } => {
                let l = self.set_expr(left, outer)?;
                let r = self.set_expr(right, outer)?;
                if l.columns.len() != r.columns.len() {
                    return Err(Error::Sql(format!(
                        "{op:?} com {} e {} colunas",
                        l.columns.len(),
                        r.columns.len()
                    )));
                }
                let mut right_counts: HashMap<Vec<u8>, usize> = HashMap::new();
                for row in &r.rows {
                    *right_counts.entry(row_key(row)).or_default() += 1;
                }
                let mut seen = HashSet::new();
                let mut rows = Vec::new();
                let mut distinct_push = |row: Vec<Value>, rows: &mut Vec<Vec<Value>>| {
                    if *all || seen.insert(row_key(&row)) {
                        rows.push(row);
                    }
                };
                match op {
                    SetOp::Union => {
                        for row in l.rows.into_iter().chain(r.rows) {
                            distinct_push(row, &mut rows);
                        }
                    }
                    SetOp::Intersect | SetOp::Except => {
                        for row in l.rows {
                            let key = row_key(&row);
                            let count = right_counts.get_mut(&key);
                            let in_right = count.as_ref().is_some_and(|c| **c > 0);
                            if *all {
                                if let Some(c) = count {
                                    if *c > 0 {
                                        *c -= 1;
                                    }
                                }
                            }
                            if in_right == (*op == SetOp::Intersect) {
                                distinct_push(row, &mut rows);
                            }
                        }
                    }
                }
                Ok(Output {
                    columns: l.columns,
                    rows,
                })
            }
        }
    }

    /// ORDER BY sobre colunas de saída (UNION & cia, CTE recursiva): nome ou posição.
    fn order_output(&self, out: &mut Output, order_by: &[OrderItem]) -> Result<()> {
        if order_by.is_empty() {
            return Ok(());
        }
        let positions = order_by
            .iter()
            .map(|item| match &item.expr {
                Expr::Lit(Value::Int(k)) if *k >= 1 && (*k as usize) <= out.columns.len() => {
                    Ok(*k as usize - 1)
                }
                Expr::Col(None, name) => out
                    .columns
                    .iter()
                    .position(|c| c == name)
                    .ok_or_else(|| unknown_column(None, name)),
                other => Err(Error::Sql(format!(
                    "ORDER BY de UNION/INTERSECT/EXCEPT usa nome ou posição da coluna, não {}",
                    expr_name(other)
                ))),
            })
            .collect::<Result<Vec<_>>>()?;
        out.rows.sort_by(|a, b| {
            let ka: Vec<Value> = positions.iter().map(|&p| a[p].clone()).collect();
            let kb: Vec<Value> = positions.iter().map(|&p| b[p].clone()).collect();
            cmp_order(&ka, &kb, order_by)
        });
        Ok(())
    }

    fn relation(&self, item: &FromItem, outer: Option<&Ctx<'_>>) -> Result<Relation> {
        let renamed = |rel: Relation| -> Result<Relation> {
            if item.columns.is_empty() {
                return Ok(rel);
            }
            if item.columns.len() != rel.width() {
                return Err(Error::Sql(format!(
                    "{} declara {} colunas, relação tem {}",
                    item.alias,
                    item.columns.len(),
                    rel.width()
                )));
            }
            Ok(match rel {
                Relation::Derived(o, _) => Relation::Derived(o, Some(item.columns.clone())),
                Relation::Table(t) => {
                    let mut rows = Vec::new();
                    fetch_from(self.src, &t, &Access::Full, &mut |_, r| {
                        rows.push(r);
                        Ok(true)
                    })?;
                    Relation::Derived(
                        Rc::new(Output {
                            columns: t.columns.iter().map(|c| c.name.clone()).collect(),
                            rows,
                        }),
                        Some(item.columns.clone()),
                    )
                }
            })
        };
        match &item.source {
            FromSource::Table(name) => {
                let cte = self
                    .ctes
                    .borrow()
                    .iter()
                    .rev()
                    .position(|c| c.name() == name);
                if let Some(rev_pos) = cte {
                    let ctes = self.ctes.borrow();
                    let idx = ctes.len() - 1 - rev_pos;
                    let (out, names) = match &ctes[idx] {
                        CteBinding::Rows(_, out) => (Rc::clone(out), None),
                        CteBinding::Def {
                            name,
                            query,
                            key,
                            columns,
                            recursive,
                        } => {
                            let (name, query, key, columns, recursive) = (
                                name.clone(),
                                Rc::clone(query),
                                *key,
                                columns.clone(),
                                *recursive,
                            );
                            drop(ctes);
                            let out = if recursive {
                                self.cached(key, outer, &|o| {
                                    self.recursive_cte(&name, &query, &columns, o)
                                })?
                            } else {
                                self.cached(key, outer, &|o| self.query(&query, o))?
                            };
                            let names = if columns.is_empty() || recursive {
                                None
                            } else {
                                if columns.len() != out.columns.len() {
                                    return Err(Error::Sql(format!(
                                        "CTE {name} declara {} colunas, consulta tem {}",
                                        columns.len(),
                                        out.columns.len()
                                    )));
                                }
                                Some(columns)
                            };
                            (out, names)
                        }
                    };
                    return renamed(Relation::Derived(out, names));
                }
                match load_table(self.src, name) {
                    Ok(t) => renamed(Relation::Table(t)),
                    Err(Error::UnknownTable(_)) => match self.view(name)? {
                        Some(view) => {
                            let (v, q) = &*view;
                            let key = Rc::as_ptr(q) as usize;
                            if self.view_depth.get() >= 32 {
                                return Err(Error::Sql(format!(
                                    "views aninhadas demais ou referência circular em {name}"
                                )));
                            }
                            self.view_depth.set(self.view_depth.get() + 1);
                            let out = self.cached(key, outer, &|o| self.query(q, o));
                            self.view_depth.set(self.view_depth.get() - 1);
                            let out = out?;
                            let names = if v.columns.is_empty() {
                                None
                            } else {
                                if v.columns.len() != out.columns.len() {
                                    return Err(Error::Sql(format!(
                                        "view {name} declara {} colunas, consulta tem {}",
                                        v.columns.len(),
                                        out.columns.len()
                                    )));
                                }
                                Some(v.columns.clone())
                            };
                            renamed(Relation::Derived(out, names))
                        }
                        None => match super::pgcatalog::relation(self.src, name, &|v| {
                            if !v.columns.is_empty() {
                                return v.columns.clone();
                            }
                            self.view(&v.name)
                                .ok()
                                .flatten()
                                .and_then(|vr| self.query(&vr.1, None).ok())
                                .map(|o| o.columns.clone())
                                .unwrap_or_default()
                        })? {
                            Some(out) => renamed(Relation::Derived(Rc::new(out), None)),
                            None => Err(Error::UnknownTable(name.clone())),
                        },
                    },
                    Err(e) => Err(e),
                }
            }
            FromSource::Query(q) => renamed(Relation::Derived(self.subquery(q, outer)?, None)),
            FromSource::Function(name, args, ordinality) => {
                let empty = Scope::default();
                let ctx = Ctx::new(&empty, &[], outer);
                let vals = args
                    .iter()
                    .map(|a| self.eval(a, &ctx))
                    .collect::<Result<Vec<_>>>()?;
                let rows: Vec<Vec<Value>> = match (name.as_str(), vals.as_slice()) {
                    ("generate_series", [Value::Int(a), Value::Int(b)]) => (*a..=*b)
                        .take(1_000_000)
                        .map(|n| vec![Value::Int(n)])
                        .collect(),
                    ("generate_series", [Value::Int(a), Value::Int(b), Value::Int(step)])
                        if *step != 0 =>
                    {
                        let mut out = Vec::new();
                        let mut n = *a;
                        while (*step > 0 && n <= *b) || (*step < 0 && n >= *b) {
                            out.push(vec![Value::Int(n)]);
                            match n.checked_add(*step) {
                                Some(next) => n = next,
                                None => break,
                            }
                            if out.len() >= 1_000_000 {
                                break;
                            }
                        }
                        out
                    }
                    ("generate_series", [Value::Null, ..] | [_, Value::Null, ..]) => Vec::new(),
                    ("unnest" | "json_each" | "json_array_elements", [v]) => match v {
                        Value::Null => Vec::new(),
                        v => {
                            let s = v.to_string();
                            match Json::parse(&s) {
                                Ok(Json::Array(items)) => items
                                    .iter()
                                    .map(|x| {
                                        vec![match x {
                                            Json::String(s) => Value::Text(s.clone()),
                                            Json::Number(n) => Value::Int(*n),
                                            Json::Float(f) => Value::Real(*f),
                                            Json::Bool(b) => Value::Bool(*b),
                                            Json::Null => Value::Null,
                                            other => Value::Text(other.stringify()),
                                        }]
                                    })
                                    .collect(),
                                _ => s
                                    .trim_matches(|c| c == '{' || c == '}')
                                    .split(',')
                                    .filter(|x| !x.trim().is_empty())
                                    .map(|x| {
                                        vec![Value::Text(x.trim().trim_matches('"').to_string())]
                                    })
                                    .collect(),
                            }
                        }
                    },
                    // Sem partições no Mini-DB: árvores vazias (psql `\d` consulta isto).
                    ("pg_partition_ancestors" | "pg_partition_tree", _) => Vec::new(),
                    _ => {
                        return Err(Error::Sql(format!(
                            "função de tabela desconhecida {name}() (generate_series, unnest)"
                        )))
                    }
                };
                let rows = if *ordinality {
                    rows.into_iter()
                        .enumerate()
                        .map(|(n, mut r)| {
                            r.push(Value::Int(n as i64 + 1));
                            r
                        })
                        .collect()
                } else {
                    rows
                };
                let mut columns = match name.as_str() {
                    "pg_partition_tree" => ["relid", "parentrelid", "isleaf", "level"]
                        .map(String::from)
                        .to_vec(),
                    other => vec![if item.columns.is_empty() && item.alias != *name {
                        item.alias.clone()
                    } else if other == "generate_series" {
                        "generate_series".to_string()
                    } else if other == "pg_partition_ancestors" {
                        other.to_string()
                    } else {
                        "unnest".to_string()
                    }],
                };
                if *ordinality {
                    columns.push("ordinality".into());
                }
                renamed(Relation::Derived(Rc::new(Output { columns, rows }), None))
            }
        }
    }

    /// Escolhe o caminho de acesso a partir de `coluna op literal` no WHERE.
    /// O filtro completo é reaplicado depois, então o plano só precisa ser um
    /// superconjunto correto das linhas.
    pub(super) fn plan(
        &self,
        t: &Table,
        alias: &str,
        filter: Option<&Expr>,
        scope: &Scope,
    ) -> Access {
        self.plan_est(t, alias, filter, scope).0
    }

    /// Como [`Exec::plan`], com a estimativa de linhas (quando há estatísticas).
    pub(super) fn plan_est(
        &self,
        t: &Table,
        alias: &str,
        filter: Option<&Expr>,
        scope: &Scope,
    ) -> (Access, Option<f64>) {
        self.plan_ordered(t, alias, filter, scope, &[])
    }

    /// Como [`Exec::plan_est`], preferindo (a custo parecido) um acesso que já
    /// entregue as linhas na ordem das colunas `order`.
    pub(super) fn plan_ordered(
        &self,
        t: &Table,
        alias: &str,
        filter: Option<&Expr>,
        scope: &Scope,
        order: &[usize],
    ) -> (Access, Option<f64>) {
        let stats = self.stats(&t.name).ok().flatten();
        let total = stats.as_ref().map(|s| s.rows as f64);
        let Some(filter) = filter else {
            return (Access::Full, total);
        };
        let mut parts = Vec::new();
        conjuncts(filter, &mut parts);
        let column_of = |e: &Expr| match e {
            Expr::Col(q, name) if q.as_deref().is_none_or(|q| q == alias) => {
                let i = scope.lookup(q.as_deref(), name).ok()??;
                (scope.cols[i].0 == alias).then(|| t.column(name).ok())?
            }
            _ => None,
        };
        let lit = |e: &Expr, col: usize| -> Option<Value> {
            let v = match e {
                Expr::Lit(v) => v.clone(),
                Expr::Param(i) => self.params.get(*i)?.clone(),
                Expr::Neg(x) => match &**x {
                    Expr::Lit(Value::Int(n)) => Value::Int(n.checked_neg()?),
                    Expr::Lit(Value::Real(x)) => Value::Real(-x),
                    _ => return None,
                },
                _ => return None,
            };
            if v.is_null() {
                return None;
            }
            // `coluna_texto = 5` compara como número (`'05' = 5`): índice não serve.
            if t.columns[col].ty == Type::Text && !matches!(v, Value::Text(_)) {
                return None;
            }
            v.coerce(t.columns[col].ty).ok()
        };
        let mut eq: HashMap<usize, Value> = HashMap::new();
        let mut lo: HashMap<usize, Value> = HashMap::new();
        let mut hi: HashMap<usize, Value> = HashMap::new();
        let mut inlist: Option<(usize, Vec<Value>)> = None;
        // Caixas por coluna (índice espacial) e consulta full-text.
        let mut boxes: HashMap<usize, (f64, f64)> = HashMap::new();
        let mut fts: Option<Access> = None;
        let numlit = |e: &Expr| -> Option<f64> {
            match e {
                Expr::Lit(v) => v.as_f64(),
                Expr::Param(i) => self.params.get(*i)?.as_f64(),
                Expr::Neg(x) => match &**x {
                    Expr::Lit(v) => Some(-v.as_f64()?),
                    _ => None,
                },
                _ => None,
            }
        };
        let narrow =
            |boxes: &mut HashMap<usize, (f64, f64)>, c: usize, lo: Option<f64>, hi: Option<f64>| {
                let b = boxes
                    .entry(c)
                    .or_insert((-search::SPATIAL_RANGE, search::SPATIAL_RANGE));
                if let Some(v) = lo {
                    b.0 = b.0.max(v);
                }
                if let Some(v) = hi {
                    b.1 = b.1.min(v);
                }
            };
        for part in &parts {
            match part {
                Expr::Match { columns, query } if fts.is_none() => {
                    let cols: Option<Vec<usize>> = columns.iter().map(column_of).collect();
                    let text = match &**query {
                        Expr::Lit(Value::Text(s)) => Some(s.clone()),
                        Expr::Param(i) => self.params.get(*i).map(ToString::to_string),
                        _ => None,
                    };
                    if let (Some(cols), Some(text)) = (cols, text) {
                        if let Some(i) = t.fulltext_index_on(&cols) {
                            fts = Some(Access::FullText(i, Rc::new(TextQuery::parse(&text))));
                        }
                    }
                }
                Expr::Func(name, args) if name == "st_dwithin" && args.len() == 5 => {
                    if let (Some(x), Some(y), Some(cx), Some(cy), Some(r)) = (
                        column_of(&args[0]),
                        column_of(&args[1]),
                        numlit(&args[2]),
                        numlit(&args[3]),
                        numlit(&args[4]),
                    ) {
                        narrow(&mut boxes, x, Some(cx - r), Some(cx + r));
                        narrow(&mut boxes, y, Some(cy - r), Some(cy + r));
                    }
                }
                Expr::Bin(a, op, b) => {
                    let (col, op, v) = match (column_of(a), column_of(b)) {
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
                    };
                    match op {
                        BinOp::Eq => {
                            narrow(&mut boxes, col, v.as_f64(), v.as_f64());
                            eq.entry(col).or_insert(v);
                        }
                        BinOp::Gt | BinOp::Ge => {
                            narrow(&mut boxes, col, v.as_f64(), None);
                            lo.entry(col).or_insert(v);
                        }
                        BinOp::Lt | BinOp::Le => {
                            narrow(&mut boxes, col, None, v.as_f64());
                            hi.entry(col).or_insert(v);
                        }
                        _ => {}
                    }
                }
                Expr::Between(x, a, b, false) => {
                    if let Some(c) = column_of(x) {
                        if let (Some(a), Some(b)) = (lit(a, c), lit(b, c)) {
                            narrow(&mut boxes, c, a.as_f64(), b.as_f64());
                            lo.entry(c).or_insert(a);
                            hi.entry(c).or_insert(b);
                        }
                    }
                }
                Expr::In(x, list, false) if inlist.is_none() && !list.is_empty() => {
                    if let Some(c) = column_of(x) {
                        let values: Option<Vec<Value>> = list.iter().map(|e| lit(e, c)).collect();
                        if let Some(values) = values {
                            inlist = Some((c, values));
                        }
                    }
                }
                _ => {}
            }
        }
        // Índice espacial: todas as colunas com faixa fechada (caixa).
        let spatial = t
            .indexes
            .iter()
            .enumerate()
            .filter(|(_, idx)| idx.kind == IndexKind::Spatial)
            .find_map(|(i, idx)| {
                let bounds: Option<Vec<(f64, f64)>> =
                    idx.columns.iter().map(|c| boxes.get(c).copied()).collect();
                let bounds = bounds?;
                if bounds
                    .iter()
                    .any(|b| b.0 <= -search::SPATIAL_RANGE && b.1 >= search::SPATIAL_RANGE)
                {
                    return None;
                }
                let lo: Vec<f64> = bounds.iter().map(|b| b.0).collect();
                let hi: Vec<f64> = bounds.iter().map(|b| b.1).collect();
                Some(Access::Spatial(i, search::z_ranges(&lo, &hi, 64)))
            });
        let (access, est) = self.choose(t, stats.as_deref(), &eq, &lo, &hi, inlist, order);
        if matches!(access, Access::Point(_) | Access::Points(_)) {
            return (access, est);
        }
        if let Some(f) = fts {
            return (f, None);
        }
        if let Some(sp) = spatial {
            return (sp, None);
        }
        (access, est)
    }

    /// Escolhe o acesso de menor custo estimado. Com estatísticas, o custo é o
    /// número de linhas que o caminho lê; sem elas, vale a heurística de
    /// "mais colunas de igualdade casadas".
    #[allow(clippy::too_many_arguments)]
    fn choose(
        &self,
        t: &Table,
        stats: Option<&Stats>,
        eq: &HashMap<usize, Value>,
        lo: &HashMap<usize, Value>,
        hi: &HashMap<usize, Value>,
        inlist: Option<(usize, Vec<Value>)>,
        order: &[usize],
    ) -> (Access, Option<f64>) {
        // O acesso entrega as linhas na ordem pedida?
        let provides_order = |access: &Access| -> bool {
            if order.is_empty() {
                return false;
            }
            let cols: Vec<usize> = match access {
                Access::Index(i, vals) => t.indexes[*i].columns[vals.len()..]
                    .iter()
                    .chain(t.pk.iter())
                    .copied()
                    .collect(),
                _ => t.pk.clone(),
            };
            order.len() <= cols.len() && order.iter().zip(&cols).all(|(a, b)| a == b)
        };
        // Chave primária: igualdade em todas as colunas = ponto.
        let pk_prefix: Vec<Value> = t.pk.iter().map_while(|c| eq.get(c).cloned()).collect();
        if !t.pk.is_empty() && pk_prefix.len() == t.pk.len() {
            return (Access::Point(pk_prefix), Some(1.0));
        }
        // Índice único com todas as colunas em igualdade.
        let index_hits = |unique_full: bool| {
            t.indexes
                .iter()
                .enumerate()
                .filter(|(_, idx)| idx.is_btree())
                .map(|(i, idx)| {
                    let vals: Vec<Value> = idx
                        .columns
                        .iter()
                        .map_while(|c| eq.get(c).cloned())
                        .collect();
                    (i, vals)
                })
                .filter(|(i, vals)| {
                    !vals.is_empty()
                        && (!unique_full
                            || (t.indexes[*i].unique && vals.len() == t.indexes[*i].columns.len()))
                })
                .collect::<Vec<_>>()
        };
        if let Some((i, vals)) = index_hits(true).into_iter().max_by_key(|(_, v)| v.len()) {
            return (Access::Index(i, vals), Some(1.0));
        }
        if let (Some((c, values)), [pk]) = (&inlist, t.pk.as_slice()) {
            if c == pk && values.len() <= 1024 {
                let n = values.len();
                return (
                    Access::Points(values.iter().map(|v| vec![v.clone()]).collect()),
                    Some(n as f64),
                );
            }
        }
        let next = t.pk.get(pk_prefix.len());
        let (range_lo, range_hi) = match next {
            Some(c) => (lo.get(c).cloned(), hi.get(c).cloned()),
            None => (None, None),
        };
        let range_usable = !pk_prefix.is_empty() || range_lo.is_some() || range_hi.is_some();
        let indexes = index_hits(false);
        let Some(stats) = stats else {
            // Sem estatísticas: prefixo de PK/faixa ganha de índice mais fraco;
            // entre índices empatados, o que entrega a ordem pedida.
            let top = indexes.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
            let best = indexes
                .iter()
                .filter(|(_, v)| v.len() == top)
                .max_by_key(|(i, v)| provides_order(&Access::Index(*i, v.clone())) as u8)
                .cloned();
            if range_usable {
                let pk_strength =
                    pk_prefix.len() + usize::from(range_lo.is_some() || range_hi.is_some());
                if best
                    .as_ref()
                    .is_none_or(|(_, v)| v.len() < pk_strength.max(1))
                {
                    return (
                        Access::Range {
                            prefix: pk_prefix,
                            lo: range_lo,
                            hi: range_hi,
                        },
                        None,
                    );
                }
            }
            return (
                match best {
                    Some((i, vals)) => Access::Index(i, vals),
                    None => Access::Full,
                },
                None,
            );
        };
        let rows = stats.rows.max(1) as f64;
        // Linhas estimadas com igualdade nas colunas `cols` (independência, com teto).
        let eq_rows = |cols: &[usize]| -> f64 {
            let mut distinct = 1.0f64;
            for c in cols {
                let d = stats.columns.get(*c).map_or(1, |s| s.distinct.max(1)) as f64;
                distinct = (distinct * d).min(rows);
            }
            (rows / distinct).max(1.0)
        };
        let mut best: (Access, f64, f64) = (Access::Full, rows, rows);
        let mut consider = |access: Access, est: f64, cost: f64| {
            if cost < best.2 {
                best = (access, est, cost);
            }
        };
        if range_usable {
            let mut est = eq_rows(&t.pk[..pk_prefix.len()]);
            if let Some(c) = next {
                if range_lo.is_some() || range_hi.is_some() {
                    est *= stats.range_fraction(*c, range_lo.as_ref(), range_hi.as_ref());
                }
            }
            let est = est.max(1.0);
            consider(
                Access::Range {
                    prefix: pk_prefix.clone(),
                    lo: range_lo.clone(),
                    hi: range_hi.clone(),
                },
                est,
                est + 1.0,
            );
        }
        let mut candidates: Vec<(Access, f64, f64)> = Vec::new();
        for (i, vals) in indexes {
            let cols = &t.indexes[i].columns[..vals.len()];
            let est = eq_rows(cols);
            // Entrada de índice + busca da linha: mais caro por linha que o scan.
            let cost = est * 2.0 + 1.0;
            candidates.push((Access::Index(i, vals.clone()), est, cost));
            consider(Access::Index(i, vals), est, cost);
        }
        // Um acesso que evita a ordenação vale até o dobro do custo.
        if !order.is_empty() && !provides_order(&best.0) {
            if let Some(alt) = candidates
                .into_iter()
                .filter(|(a, _, c)| provides_order(a) && *c <= best.2 * 2.0 + 1.0)
                .min_by(|a, b| a.2.total_cmp(&b.2))
            {
                best = alt;
            }
        }
        (best.0, Some(best.1))
    }

    /// Visita as linhas candidatas do plano: `(pk codificada, linha)`.
    pub(super) fn fetch(
        &self,
        t: &Table,
        access: &Access,
        visit: &mut dyn FnMut(Vec<u8>, Vec<Value>) -> Result<bool>,
    ) -> Result<()> {
        if let Access::FullText(i, q) = access {
            let (pks, df) = fts_candidates(self.src, t, *i, q)?;
            let (docs, total) = fts_stats(self.src, &t.index_prefix(&t.indexes[*i]))?;
            let scorer = FtsScorer {
                docs: docs as f64,
                avg_len: if docs == 0 {
                    0.0
                } else {
                    total as f64 / docs as f64
                },
                df,
            };
            self.fts
                .borrow_mut()
                .scorers
                .insert(scorer_key(q), Rc::new(scorer));
            return visit_pks(self.src, t, pks, visit);
        }
        fetch_from(self.src, t, access, visit)
    }

    fn all_rows(&self, t: &Table) -> Result<Vec<Vec<Value>>> {
        let mut rows = Vec::new();
        self.fetch(t, &Access::Full, &mut |_, r| {
            rows.push(r);
            Ok(true)
        })?;
        Ok(rows)
    }

    fn join_plan(
        &self,
        rel: &Relation,
        kind: JoinKind,
        on: Option<&Expr>,
        outer: &Scope,
        inner: &Scope,
    ) -> JoinPlan {
        let Some(on) = on else {
            return JoinPlan::Nested;
        };
        let mut parts = Vec::new();
        conjuncts(on, &mut parts);
        let only = |e: &Expr, scope: &Scope, other: &Scope| {
            if has_subquery(e) {
                return false;
            }
            let mut refs = Vec::new();
            columns_of(e, &mut refs);
            !refs.is_empty()
                && refs.iter().all(|(q, c)| {
                    matches!(scope.lookup(q.as_deref(), c), Ok(Some(_)))
                        && matches!(other.lookup(q.as_deref(), c), Ok(None))
                })
        };
        let mut hash = None;
        for p in &parts {
            let Expr::Bin(a, BinOp::Eq, b) = p else {
                continue;
            };
            for (inner_e, outer_e) in [(a, b), (b, a)] {
                if !only(inner_e, inner, outer) || !only(outer_e, outer, inner) {
                    continue;
                }
                if let (Relation::Table(t), Expr::Col(_, name), JoinKind::Inner | JoinKind::Left) =
                    (rel, &**inner_e, kind)
                {
                    if let Ok(col) = t.column(name) {
                        let leading_index = t
                            .indexes
                            .iter()
                            .any(|i| i.is_btree() && i.columns.first() == Some(&col));
                        if t.pk == [col] || leading_index {
                            return JoinPlan::Lookup {
                                column: col,
                                expr: (**outer_e).clone(),
                            };
                        }
                    }
                }
                hash.get_or_insert(JoinPlan::Hash {
                    inner: (**inner_e).clone(),
                    outer: (**outer_e).clone(),
                });
            }
        }
        hash.unwrap_or(JoinPlan::Nested)
    }

    fn select(
        &self,
        s: &Select,
        order_by: &[OrderItem],
        limit: Option<usize>,
        offset: usize,
        outer: Option<&Ctx<'_>>,
    ) -> Result<Output> {
        let mut aggs = Vec::new();
        let mut windows = Vec::new();
        for item in &s.items {
            if let SelectItem::Expr(e, _) = item {
                collect_aggs(e, &mut aggs);
                collect_windows(e, &mut windows);
            }
        }
        if let Some(h) = &s.having {
            collect_aggs(h, &mut aggs);
            let mut w = Vec::new();
            collect_windows(h, &mut w);
            if !w.is_empty() {
                return Err(Error::Sql("função de janela no HAVING".into()));
            }
        }
        for item in order_by {
            collect_aggs(&item.expr, &mut aggs);
            collect_windows(&item.expr, &mut windows);
        }
        for g in &s.group_by {
            if has_agg_or_window(g) {
                return Err(Error::Sql("agregado/janela no GROUP BY".into()));
            }
        }
        if let Some(f) = &s.filter {
            if has_agg_or_window(f) {
                return Err(Error::Sql(
                    "agregado ou função de janela no WHERE; use HAVING ou uma subconsulta".into(),
                ));
            }
        }
        let grouped = !s.group_by.is_empty() || !aggs.is_empty();
        if s.having.is_some() && !grouped {
            return Err(Error::Sql("HAVING exige GROUP BY ou agregado".into()));
        }

        // 1. Relações e escopo.
        let mut scope = Scope::default();
        let base = match &s.from {
            Some(item) => {
                let rel = self.relation(item, outer)?;
                scope.add(&item.alias, &rel.names());
                Some((item, rel))
            }
            None => None,
        };
        let mut joined = Vec::new();
        for j in &s.joins {
            if scope.cols.iter().any(|(a, _)| *a == j.item.alias) {
                return Err(Error::Sql(format!(
                    "alias {} repetido; use AS",
                    j.item.alias
                )));
            }
            let rel = self.relation(&j.item, outer)?;
            let mut inner_scope = Scope::default();
            inner_scope.add(&j.item.alias, &rel.names());
            let plan = self.join_plan(&rel, j.kind, j.on.as_ref(), &scope, &inner_scope);
            scope.add_using(&j.item.alias, &rel.names(), &j.using);
            joined.push((j, rel, plan));
        }

        // 2. Linhas da relação base (com plano de acesso e parada antecipada).
        // Se o acesso já entrega na ordem pedida, o ORDER BY sai de graça
        // (ASC: parada antecipada; DESC: só inverte no fim).
        let plain = s.joins.is_empty() && !grouped && !s.distinct && windows.is_empty();
        let mut access_order: Option<(Access, Option<f64>)> = None;
        if let Some((item, Relation::Table(t))) = &base {
            let mut base_scope = Scope::default();
            base_scope.add(&item.alias, &Self::base_names(&base));
            let wanted: Vec<usize> = if plain {
                order_by
                    .iter()
                    .filter_map(|o| match &o.expr {
                        Expr::Col(q, name)
                            if q.as_deref().is_none_or(|q| q == item.alias)
                                && o.nulls_first.is_none_or(|first| first != o.desc) =>
                        {
                            t.column(name).ok()
                        }
                        _ => None,
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let wanted = if wanted.len() == order_by.len() {
                wanted
            } else {
                Vec::new()
            };
            access_order =
                Some(self.plan_ordered(t, &item.alias, s.filter.as_ref(), &base_scope, &wanted));
        }
        if let (true, Some((item, Relation::Table(t)))) = (plain && windows.is_empty(), &base) {
            if let Some(knn) = self.knn_access(s, t, &item.alias, order_by, limit, offset) {
                access_order = Some(knn);
            }
        }
        let mut order_direction: Option<bool> = None; // Some(desc) quando o acesso ordena
        if plain && !order_by.is_empty() {
            if let (Some((item, Relation::Table(t))), Some((access, _))) = (&base, &access_order) {
                let ordered_cols: Vec<usize> = match access {
                    Access::Full
                    | Access::Range { .. }
                    | Access::Points(_)
                    | Access::Point(_)
                    | Access::FullText(..)
                    | Access::Spatial(..) => t.pk.clone(),
                    Access::Vector(..) => Vec::new(),
                    Access::Index(i, vals) => {
                        let idx = &t.indexes[*i];
                        idx.columns[vals.len()..]
                            .iter()
                            .chain(t.pk.iter())
                            .copied()
                            .collect()
                    }
                };
                let wanted: Option<Vec<(usize, bool)>> = order_by
                    .iter()
                    .map(|o| match &o.expr {
                        // A ordem do índice põe NULL primeiro em ASC e último em DESC.
                        Expr::Col(q, name)
                            if q.as_deref().is_none_or(|q| q == item.alias)
                                && o.nulls_first.is_none_or(|first| first != o.desc) =>
                        {
                            t.column(name).ok().map(|c| (c, o.desc))
                        }
                        _ => None,
                    })
                    .collect();
                if let Some(wanted) = wanted {
                    let all_asc = wanted.iter().all(|(_, d)| !d);
                    let all_desc = wanted.iter().all(|(_, d)| *d);
                    let is_prefix = !t.pk.is_empty()
                        && wanted.len() <= ordered_cols.len()
                        && wanted.iter().zip(&ordered_cols).all(|((c, _), o)| c == o);
                    if is_prefix && (all_asc || all_desc) {
                        order_direction = Some(all_desc);
                    }
                }
            }
        }
        let sorted_by_access = order_direction.is_some();
        let simple = plain && (order_by.is_empty() || order_direction == Some(false));
        let stop_after = limit.filter(|_| simple).map(|l| l + offset);
        let mut rows: Vec<Vec<Value>> = Vec::new();
        let started = std::time::Instant::now();
        let mut scanned = 0usize;
        match &base {
            None => {
                let row: Vec<Value> = Vec::new();
                if self.is_true(s.filter.as_ref(), &Ctx::new(&scope, &row, outer))? {
                    rows.push(row);
                }
            }
            Some((item, rel)) => {
                let mut base_scope = Scope::default();
                base_scope.add(&item.alias, &rel.names());
                let base_filter = if s.joins.is_empty() {
                    s.filter.as_ref()
                } else {
                    None
                };
                let mut failure = None;
                let mut keep = |row: Vec<Value>, rows: &mut Vec<Vec<Value>>| -> bool {
                    match self.is_true(base_filter, &Ctx::new(&base_scope, &row, outer)) {
                        Ok(true) => rows.push(row),
                        Ok(false) => {}
                        Err(e) => {
                            failure = Some(e);
                            return false;
                        }
                    }
                    stop_after.is_none_or(|n| rows.len() < n)
                };
                match rel {
                    Relation::Table(t) => {
                        let (access, est) = access_order.take().unwrap_or_else(|| {
                            self.plan_est(t, &item.alias, s.filter.as_ref(), &base_scope)
                        });
                        self.fetch(t, &access, &mut |_, row| {
                            scanned += 1;
                            Ok(keep(row, &mut rows))
                        })?;
                        self.note(format!(
                            "{} rows_read={scanned} rows_out={} time={:.2}ms",
                            access.describe_est(t, est),
                            rows.len(),
                            started.elapsed().as_secs_f64() * 1e3
                        ));
                    }
                    Relation::Derived(out, _) => {
                        for row in out.rows.iter().cloned() {
                            scanned += 1;
                            if !keep(row, &mut rows) {
                                break;
                            }
                        }
                        self.note(format!(
                            "SCAN SUBQUERY {} rows_read={scanned} rows_out={}",
                            item.alias,
                            rows.len()
                        ));
                    }
                }
                if let Some(e) = failure {
                    return Err(e);
                }
            }
        }

        // 3. Joins.
        let mut width = base.as_ref().map_or(0, |(_, r)| r.width());
        let joined: Vec<(&super::parser::Join, Relation, JoinPlan)> = joined
            .into_iter()
            .map(|(j, rel, plan)| {
                // Muitas linhas externas contra uma tabela interna pequena: um
                // hash join lê a interna uma vez em vez de uma busca por linha.
                let plan = match (&plan, &rel) {
                    (JoinPlan::Lookup { column, expr }, Relation::Table(t)) => {
                        let inner_rows =
                            self.stats(&t.name).ok().flatten().map(|st| st.rows as f64);
                        match inner_rows {
                            Some(n) if rows.len() as f64 > n * 4.0 + 64.0 => JoinPlan::Hash {
                                inner: Expr::Col(
                                    Some(j.item.alias.clone()),
                                    t.columns[*column].name.clone(),
                                ),
                                outer: expr.clone(),
                            },
                            _ => plan,
                        }
                    }
                    _ => plan,
                };
                (j, rel, plan)
            })
            .collect();
        for (j, rel, plan) in &joined {
            let partial = scope.slice(width);
            let combined = scope.slice(width + rel.width());
            let inner_width = rel.width();
            let needs_all_inner = matches!(j.kind, JoinKind::Right | JoinKind::Full);
            let materialized: Option<Vec<Vec<Value>>> = match (plan, rel) {
                (JoinPlan::Lookup { .. }, _) if !needs_all_inner => None,
                (_, Relation::Table(t)) => Some(self.all_rows(t)?),
                (_, Relation::Derived(out, _)) => Some(out.rows.clone()),
            };
            let mut inner_scope = Scope::default();
            inner_scope.add(&j.item.alias, &rel.names());
            let hash: Option<HashMap<Vec<u8>, Vec<usize>>> = match (plan, &materialized) {
                (JoinPlan::Hash { inner, .. }, Some(all)) => {
                    let mut map: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
                    for (i, r) in all.iter().enumerate() {
                        let v = self.eval(inner, &Ctx::new(&inner_scope, r, outer))?;
                        if !v.is_null() {
                            map.entry(hash_key(&v)).or_default().push(i);
                        }
                    }
                    Some(map)
                }
                _ => None,
            };
            let mut matched_inner = vec![false; materialized.as_ref().map_or(0, Vec::len)];
            let mut next = Vec::new();
            for outer_row in rows {
                let candidates: Vec<(Option<usize>, Vec<Value>)> =
                    match (plan, &materialized, &hash) {
                        (JoinPlan::Hash { outer: oe, .. }, Some(all), Some(map)) => {
                            let v = self.eval(oe, &Ctx::new(&partial, &outer_row, outer))?;
                            if v.is_null() {
                                Vec::new()
                            } else {
                                map.get(&hash_key(&v))
                                    .into_iter()
                                    .flatten()
                                    .map(|&i| (Some(i), all[i].clone()))
                                    .collect()
                            }
                        }
                        (_, Some(all), _) => all
                            .iter()
                            .enumerate()
                            .map(|(i, r)| (Some(i), r.clone()))
                            .collect(),
                        (JoinPlan::Lookup { column, expr }, None, _) => {
                            let Relation::Table(t) = rel else {
                                unreachable!("lookup só em tabela")
                            };
                            let v = self.eval(expr, &Ctx::new(&partial, &outer_row, outer))?;
                            let ty = t.columns[*column].ty;
                            let mut found = Vec::new();
                            // `coluna_texto = número` compara como número (`'05' = 5`): lê tudo.
                            if ty == Type::Text && v.as_f64().is_some() {
                                self.fetch(t, &Access::Full, &mut |_, r| {
                                    found.push((None, r));
                                    Ok(true)
                                })?;
                            } else if let Ok(v) = v.coerce(ty) {
                                if !v.is_null() {
                                    let access = if t.pk == [*column] {
                                        Access::Point(vec![v])
                                    } else {
                                        let i = t
                                            .indexes
                                            .iter()
                                            .position(|i| {
                                                i.is_btree() && i.columns.first() == Some(column)
                                            })
                                            .expect("índice");
                                        Access::Index(i, vec![v])
                                    };
                                    self.fetch(t, &access, &mut |_, r| {
                                        found.push((None, r));
                                        Ok(true)
                                    })?;
                                }
                            }
                            found
                        }
                        _ => unreachable!("plano de join sem linhas internas"),
                    };
                let mut matched = false;
                for (idx, inner_row) in candidates {
                    let mut row = outer_row.clone();
                    row.extend(inner_row);
                    if self.is_true(j.on.as_ref(), &Ctx::new(&combined, &row, outer))? {
                        matched = true;
                        if let Some(i) = idx {
                            matched_inner[i] = true;
                        }
                        next.push(row);
                    }
                }
                if !matched && matches!(j.kind, JoinKind::Left | JoinKind::Full) {
                    let mut row = outer_row;
                    row.extend(std::iter::repeat_n(Value::Null, inner_width));
                    next.push(row);
                }
            }
            if needs_all_inner {
                for (i, inner_row) in materialized.iter().flatten().enumerate() {
                    if !matched_inner[i] {
                        let mut row = vec![Value::Null; width];
                        row.extend(inner_row.iter().cloned());
                        next.push(row);
                    }
                }
            }
            self.note(format!(
                "{:?} JOIN {} USING {} rows_out={} time={:.2}ms",
                j.kind,
                j.item.alias,
                match plan {
                    JoinPlan::Lookup { .. } => "LOOKUP",
                    JoinPlan::Hash { .. } => "HASH",
                    JoinPlan::Nested => "NESTED LOOP",
                },
                next.len(),
                started.elapsed().as_secs_f64() * 1e3
            ));
            rows = next;
            width += inner_width;
        }
        let needs_residual = base.as_ref().is_some_and(|_| !s.joins.is_empty());
        if needs_residual {
            let mut kept = Vec::with_capacity(rows.len());
            for row in rows {
                if self.is_true(s.filter.as_ref(), &Ctx::new(&scope, &row, outer))? {
                    kept.push(row);
                }
            }
            rows = kept;
        }

        // 4. Nomes das colunas de saída.
        let mut columns = Vec::new();
        for item in &s.items {
            match item {
                SelectItem::Star(None) => {
                    if base.is_none() {
                        return Err(Error::Sql("SELECT * sem FROM".into()));
                    }
                    columns.extend(
                        scope
                            .cols
                            .iter()
                            .zip(&scope.hidden)
                            .filter(|(_, h)| !**h)
                            .map(|((_, c), _)| c.clone()),
                    )
                }
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
        let project = |ctx: &Ctx<'_>| -> Result<Vec<Value>> {
            let mut out = Vec::new();
            for item in &s.items {
                match item {
                    SelectItem::Star(None) => out.extend(
                        ctx.row
                            .iter()
                            .zip(&scope.hidden)
                            .filter(|(_, h)| !**h)
                            .map(|(v, _)| v.clone()),
                    ),
                    SelectItem::Star(Some(t)) => out.extend(
                        scope
                            .cols
                            .iter()
                            .zip(ctx.row)
                            .filter(|((a, _), _)| a == t)
                            .map(|(_, v)| v.clone()),
                    ),
                    SelectItem::Expr(e, _) => out.push(self.eval(e, ctx)?),
                }
            }
            Ok(out)
        };
        // Chave de ordenação: posição (ORDER BY 2), alias da saída ou expressão.
        let sort_key = |ctx: &Ctx<'_>, out: &[Value]| -> Result<Vec<Value>> {
            order_by
                .iter()
                .map(|item| match &item.expr {
                    Expr::Lit(Value::Int(k)) if *k >= 1 && (*k as usize) <= out.len() => {
                        Ok(out[*k as usize - 1].clone())
                    }
                    Expr::Lit(Value::Int(k)) => {
                        Err(Error::Sql(format!("ORDER BY {k} fora da lista")))
                    }
                    Expr::Col(None, name) if matches!(scope.lookup(None, name), Ok(None)) => {
                        match columns.iter().position(|c| c == name) {
                            Some(i) => Ok(out[i].clone()),
                            None => self.eval(&item.expr, ctx),
                        }
                    }
                    e => self.eval(e, ctx),
                })
                .collect()
        };

        // 5. Agrupamento: candidatos (linha, valores dos agregados).
        let mut cands: Vec<(Vec<Value>, Vec<Value>)> = Vec::new();
        if grouped {
            struct Group {
                first: Option<Vec<Value>>,
                states: Vec<AggState>,
                distinct: Vec<BTreeSet<Vec<u8>>>,
            }
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
                let ctx = Ctx::new(&scope, row, outer);
                let mut gk = Vec::new();
                for g in &s.group_by {
                    // GROUP BY 1 / alias da saída também valem.
                    let v = match g {
                        Expr::Lit(Value::Int(k)) if *k >= 1 && (*k as usize) <= s.items.len() => {
                            match &s.items[*k as usize - 1] {
                                SelectItem::Expr(e, _) => self.eval(e, &ctx)?,
                                SelectItem::Star(_) => {
                                    return Err(Error::Sql("GROUP BY de *".into()))
                                }
                            }
                        }
                        Expr::Col(None, name) if matches!(scope.lookup(None, name), Ok(None)) => {
                            let alias_expr = s.items.iter().find_map(|i| match i {
                                SelectItem::Expr(e, Some(a)) if a == name => Some(e),
                                _ => None,
                            });
                            match alias_expr {
                                Some(e) => self.eval(e, &ctx)?,
                                None => self.eval(g, &ctx)?,
                            }
                        }
                        e => self.eval(e, &ctx)?,
                    };
                    gk.extend(key_of(&v));
                }
                let group = groups.entry(gk).or_insert_with(new_group);
                if group.first.is_none() {
                    group.first = Some(row.clone());
                }
                for (i, a) in aggs.iter().enumerate() {
                    let Expr::Agg(_, args, distinct) = a else {
                        unreachable!()
                    };
                    let v = match args.first() {
                        None => Value::Int(1),
                        Some(e) => self.eval(e, &ctx)?,
                    };
                    if let Some(extra) = args.get(1) {
                        let x = self.eval(extra, &ctx)?;
                        group.states[i].set_extra(&x);
                    }
                    if *distinct && !v.is_null() && !group.distinct[i].insert(key_of(&v)) {
                        continue;
                    }
                    group.states[i].feed(v)?;
                }
            }
            let nulls = vec![Value::Null; scope.cols.len()];
            for (_, g) in groups {
                let vals: Vec<Value> = g.states.into_iter().map(AggState::finish).collect();
                let row = g.first.unwrap_or_else(|| nulls.clone());
                let ctx = Ctx {
                    scope: &scope,
                    row: &row,
                    aggs: Some((&aggs[..], &vals[..])),
                    outer,
                };
                if !self.is_true(s.having.as_ref(), &ctx)? {
                    continue;
                }
                cands.push((row, vals));
            }
        } else {
            cands = rows.into_iter().map(|r| (r, Vec::new())).collect();
        }

        // 6. Funções de janela sobre os candidatos.
        if !windows.is_empty() {
            let extra = self.windows(&windows, &aggs, &cands, &scope, outer)?;
            for ((_, vals), w) in cands.iter_mut().zip(extra) {
                vals.extend(w);
            }
        }
        let all_exprs: Vec<Expr> = aggs.iter().chain(windows.iter()).cloned().collect();

        // 7. Projeção.
        let mut output: Vec<(Vec<Value>, Vec<Value>)> = Vec::with_capacity(cands.len());
        for (row, vals) in &cands {
            let ctx = Ctx {
                scope: &scope,
                row,
                aggs: Some((&all_exprs[..], &vals[..])),
                outer,
            };
            let out = project(&ctx)?;
            output.push((sort_key(&ctx, &out)?, out));
        }

        // 8. DISTINCT, ORDER BY, OFFSET/LIMIT.
        if s.distinct {
            let mut seen = HashSet::new();
            output.retain(|(_, out)| seen.insert(row_key(out)));
        }
        if sorted_by_access {
            if order_direction == Some(true) {
                output.reverse();
            }
            self.note("ORDER BY satisfied by access order (no sort)".into());
        } else if !order_by.is_empty() {
            let wanted = limit.map(|l| l.saturating_add(offset));
            match wanted {
                // Top-N: separa as n menores em O(n) e ordena só elas.
                Some(n) if n > 0 && output.len() > n.saturating_mul(2) => {
                    output
                        .select_nth_unstable_by(n - 1, |(a, _), (b, _)| cmp_order(a, b, order_by));
                    output.truncate(n);
                    output.sort_by(|(a, _), (b, _)| cmp_order(a, b, order_by));
                    self.note(format!("TOP-N sort keep={n}"));
                }
                _ => {
                    output.sort_by(|(a, _), (b, _)| cmp_order(a, b, order_by));
                    self.note(format!("SORT rows={}", output.len()));
                }
            }
        }
        let rows: Vec<Vec<Value>> = output
            .into_iter()
            .skip(offset)
            .take(limit.unwrap_or(usize::MAX))
            .map(|(_, out)| out)
            .collect();
        self.note(format!(
            "RESULT rows={} time={:.2}ms",
            rows.len(),
            started.elapsed().as_secs_f64() * 1e3
        ));
        Ok(Output { columns, rows })
    }

    /// Nomes das colunas da relação base (para o escopo do plano).
    fn base_names(base: &Option<(&FromItem, Relation)>) -> Vec<String> {
        base.as_ref().map(|(_, r)| r.names()).unwrap_or_default()
    }

    /// Valores das funções de janela para cada candidato: `[linha][janela]`.
    fn windows(
        &self,
        windows: &[Expr],
        aggs: &[Expr],
        cands: &[(Vec<Value>, Vec<Value>)],
        scope: &Scope,
        outer: Option<&Ctx<'_>>,
    ) -> Result<Vec<Vec<Value>>> {
        let mut result: Vec<Vec<Value>> = vec![Vec::with_capacity(windows.len()); cands.len()];
        for w in windows {
            let Expr::Window(func, args, spec) = w else {
                unreachable!()
            };
            let (min, max) = match func {
                WinFn::RowNumber
                | WinFn::Rank
                | WinFn::DenseRank
                | WinFn::PercentRank
                | WinFn::CumeDist => (0, 0),
                WinFn::Ntile => (1, 1),
                WinFn::Lag | WinFn::Lead => (1, 3),
                WinFn::FirstValue | WinFn::LastValue => (1, 1),
                WinFn::NthValue => (2, 2),
                WinFn::Agg(AggFn::Count) => (0, 1),
                WinFn::Agg(AggFn::GroupConcat) => (1, 2),
                WinFn::Agg(_) => (1, 1),
            };
            if args.len() < min || args.len() > max {
                return Err(Error::Sql(format!(
                    "{}() em janela espera entre {min} e {max} argumento(s)",
                    func.name()
                )));
            }
            let mut input = WindowInput {
                func: *func,
                spec,
                args: Vec::with_capacity(cands.len()),
                partition: Vec::with_capacity(cands.len()),
                order: Vec::with_capacity(cands.len()),
            };
            for (row, vals) in cands {
                let ctx = Ctx {
                    scope,
                    row,
                    aggs: Some((aggs, vals)),
                    outer,
                };
                input.args.push(
                    args.iter()
                        .map(|a| self.eval(a, &ctx))
                        .collect::<Result<Vec<_>>>()?,
                );
                let mut pk = Vec::new();
                for p in &spec.partition_by {
                    pk.extend(key_of(&self.eval(p, &ctx)?));
                }
                input.partition.push(pk);
                input.order.push(
                    spec.order_by
                        .iter()
                        .map(|o| self.eval(&o.expr, &ctx))
                        .collect::<Result<Vec<_>>>()?,
                );
            }
            let values = window::evaluate(&input)?;
            for (slot, v) in result.iter_mut().zip(values) {
                slot.push(v);
            }
        }
        Ok(result)
    }

    pub(super) fn explain(&self, stmt: &Stmt, analyze: bool) -> Result<String> {
        if analyze {
            if let Stmt::Query(q) = stmt {
                self.analyze.set(true);
                let started = std::time::Instant::now();
                let out = self.query(q, None)?;
                self.analyze.set(false);
                let mut lines = std::mem::take(&mut *self.notes.borrow_mut());
                lines.push(format!(
                    "TOTAL rows={} time={:.2}ms",
                    out.rows.len(),
                    started.elapsed().as_secs_f64() * 1e3
                ));
                return Ok(lines.join("\n"));
            }
        }
        Ok(match stmt {
            Stmt::Query(q) => {
                let mut lines = Vec::new();
                for cte in &q.ctes {
                    lines.push(format!(
                        "CTE {}{}",
                        cte.name,
                        if cte.recursive { " (RECURSIVE)" } else { "" }
                    ));
                }
                for cte in &q.ctes {
                    let key = &cte.query as *const Query as usize;
                    let query = Rc::clone(
                        self.asts
                            .borrow_mut()
                            .entry(key)
                            .or_insert_with(|| Rc::new(cte.query.clone())),
                    );
                    self.ctes.borrow_mut().push(CteBinding::Def {
                        name: cte.name.clone(),
                        query,
                        key,
                        columns: cte.columns.clone(),
                        recursive: cte.recursive,
                    });
                }
                let limit = match &q.limit {
                    Some(e) => match self.eval(e, &Ctx::new(&Scope::default(), &[], None))? {
                        Value::Int(n) if n >= 0 => Some(n as usize),
                        _ => None,
                    },
                    None => None,
                };
                self.explain_set(&q.body, &mut lines, 0, &q.order_by, limit)?;
                if !q.order_by.is_empty() && !lines.iter().any(|l| l.contains("(ordered)")) {
                    lines.push("SORT".into());
                }
                if q.limit.is_some() || q.offset.is_some() {
                    lines.push("LIMIT/OFFSET".into());
                }
                lines.join("\n")
            }
            Stmt::Update { table, filter, .. } | Stmt::Delete { table, filter, .. } => {
                let t = load_table(self.src, table)?;
                let scope = table_scope(&t);
                let (access, est) = self.plan_est(&t, &t.name, filter.as_ref(), &scope);
                let mut line = access.describe_est(&t, est);
                if !t.triggers.is_empty() {
                    line.push_str(&format!("\nTRIGGERS {}", t.triggers.len()));
                }
                let children = self.children_of(&t.name)?;
                if !children.is_empty() {
                    line.push_str(&format!(
                        "\nFOREIGN KEY CHECK {}",
                        children
                            .iter()
                            .map(|c| c.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                line
            }
            Stmt::Insert { table, source, .. } => {
                let t = load_table(self.src, table)?;
                let mut line = format!(
                    "INSERT {} ({})",
                    t.name,
                    match source {
                        super::parser::InsertSource::Values(rows) => format!("{} rows", rows.len()),
                        super::parser::InsertSource::Query(_) => "SELECT".into(),
                        super::parser::InsertSource::Default => "DEFAULT VALUES".into(),
                    }
                );
                if !t.fks.is_empty() {
                    line.push_str(&format!(
                        "\nFOREIGN KEY LOOKUP {}",
                        t.fks
                            .iter()
                            .map(|f| f.parent.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                line
            }
            other => format!("{other:?}"),
        })
    }

    fn explain_set(
        &self,
        e: &SetExpr,
        lines: &mut Vec<String>,
        depth: usize,
        order_by: &[OrderItem],
        limit: Option<usize>,
    ) -> Result<()> {
        let pad = "  ".repeat(depth);
        match e {
            SetExpr::Values(rows) => {
                lines.push(format!("{pad}VALUES ({} rows)", rows.len()));
                Ok(())
            }
            SetExpr::SetOp {
                op,
                all,
                left,
                right,
            } => {
                lines.push(format!(
                    "{pad}COMPOUND {op:?}{}",
                    if *all { " ALL" } else { "" }
                ));
                self.explain_set(left, lines, depth + 1, &[], None)?;
                self.explain_set(right, lines, depth + 1, &[], None)
            }
            SetExpr::Select(s) => {
                let mut scope = Scope::default();
                let plain = s.joins.is_empty() && s.group_by.is_empty() && !s.distinct;
                let describe = |item: &FromItem,
                                rel: &Relation,
                                filter: Option<&Expr>,
                                scope: &Scope| match rel {
                    Relation::Table(t) => {
                        let wanted: Vec<usize> = if plain {
                            order_by
                                .iter()
                                .filter_map(|o| match &o.expr {
                                    Expr::Col(q, name)
                                        if q.as_deref().is_none_or(|q| q == item.alias)
                                            && o.nulls_first.is_none_or(|f| f != o.desc) =>
                                    {
                                        t.column(name).ok()
                                    }
                                    _ => None,
                                })
                                .collect()
                        } else {
                            Vec::new()
                        };
                        let wanted = if wanted.len() == order_by.len() {
                            wanted
                        } else {
                            Vec::new()
                        };
                        let (access, est) = self
                            .knn_access(s, t, &item.alias, order_by, limit, 0)
                            .unwrap_or_else(|| {
                                self.plan_ordered(t, &item.alias, filter, scope, &wanted)
                            });
                        let ordered = !wanted.is_empty()
                            && match &access {
                                Access::Index(i, vals) => {
                                    let cols: Vec<usize> = t.indexes[*i].columns[vals.len()..]
                                        .iter()
                                        .chain(t.pk.iter())
                                        .copied()
                                        .collect();
                                    wanted.len() <= cols.len()
                                        && wanted.iter().zip(&cols).all(|(a, b)| a == b)
                                }
                                _ => {
                                    wanted.len() <= t.pk.len()
                                        && wanted.iter().zip(&t.pk).all(|(a, b)| a == b)
                                }
                            };
                        let mut line = access.describe_est(t, est);
                        if ordered {
                            line.push_str(" (ordered)");
                        }
                        line
                    }
                    Relation::Derived(o, _) => {
                        format!("SCAN SUBQUERY {} ({} rows)", item.alias, o.rows.len())
                    }
                };
                match &s.from {
                    None => lines.push(format!("{pad}CONSTANT ROW")),
                    Some(item) => {
                        let rel = self.relation(item, None)?;
                        let mut base_scope = Scope::default();
                        base_scope.add(&item.alias, &rel.names());
                        lines.push(format!(
                            "{pad}{}",
                            describe(item, &rel, s.filter.as_ref(), &base_scope)
                        ));
                        scope.add(&item.alias, &rel.names());
                    }
                }
                for j in &s.joins {
                    let rel = self.relation(&j.item, None)?;
                    let mut inner_scope = Scope::default();
                    inner_scope.add(&j.item.alias, &rel.names());
                    let plan = self.join_plan(&rel, j.kind, j.on.as_ref(), &scope, &inner_scope);
                    let name = match &j.item.source {
                        FromSource::Table(t) => t.clone(),
                        FromSource::Query(_) => format!("SUBQUERY {}", j.item.alias),
                        FromSource::Function(f, ..) => format!("FUNCTION {f}()"),
                    };
                    lines.push(format!(
                        "{pad}{:?} JOIN {name} USING {}",
                        j.kind,
                        match &plan {
                            JoinPlan::Lookup { column, .. } => {
                                let Relation::Table(t) = &rel else {
                                    unreachable!()
                                };
                                format!("LOOKUP ON {} (index nested loop)", t.columns[*column].name)
                            }
                            JoinPlan::Hash { .. } => "HASH JOIN".to_string(),
                            JoinPlan::Nested => "SCAN (nested loop)".to_string(),
                        }
                    ));
                    scope.add(&j.item.alias, &rel.names());
                }
                let mut aggs = Vec::new();
                let mut windows = Vec::new();
                for item in &s.items {
                    if let SelectItem::Expr(e, _) = item {
                        collect_aggs(e, &mut aggs);
                        collect_windows(e, &mut windows);
                    }
                }
                if !s.group_by.is_empty() || !aggs.is_empty() {
                    lines.push(format!(
                        "{pad}AGGREGATE groups_by={} aggregates={}",
                        s.group_by.len(),
                        aggs.len()
                    ));
                }
                if !windows.is_empty() {
                    lines.push(format!("{pad}WINDOW functions={}", windows.len()));
                }
                let subqueries = s
                    .items
                    .iter()
                    .any(|i| matches!(i, SelectItem::Expr(e, _) if has_subquery(e)))
                    || s.filter.as_ref().is_some_and(has_subquery);
                if subqueries {
                    lines.push(format!("{pad}SUBQUERY (cache quando não correlacionada)"));
                }
                Ok(())
            }
        }
    }
}

/// Comparação SQL; `None` quando `op` não é de comparação.
fn compare(a: &Value, op: BinOp, b: &Value) -> Option<Value> {
    let cmp = |f: fn(Ordering) -> bool| truth(a.sql_cmp(b).map(f));
    Some(match op {
        BinOp::Eq => cmp(|o| o == Ordering::Equal),
        BinOp::Ne => cmp(|o| o != Ordering::Equal),
        BinOp::Lt => cmp(|o| o == Ordering::Less),
        BinOp::Le => cmp(|o| o != Ordering::Greater),
        BinOp::Gt => cmp(|o| o == Ordering::Greater),
        BinOp::Ge => cmp(|o| o != Ordering::Less),
        _ => return None,
    })
}

pub(super) fn conjuncts(e: &Expr, out: &mut Vec<Expr>) {
    match e {
        Expr::Bin(a, BinOp::And, b) => {
            conjuncts(a, out);
            conjuncts(b, out);
        }
        other => out.push(other.clone()),
    }
}

fn hash_key(v: &Value) -> Vec<u8> {
    // Valores iguais para o `=` precisam cair no mesmo balde: 1 = 1.0, 0.0 = -0.0 e,
    // como texto numérico compara com número, '05' = 5. O balde pode juntar a mais
    // ('05' e '5'): o ON é reavaliado em cada candidata.
    let number: Option<f64> = match v {
        Value::Text(s) => s.trim().parse().ok(),
        other => other.as_f64(),
    };
    match number {
        Some(x) => key_of(&Value::Real(if x == 0.0 { 0.0 } else { x })),
        None => key_of(v),
    }
}

fn in_list<'v>(x: &Value, values: impl Iterator<Item = &'v Value>, neg: bool) -> Value {
    if x.is_null() {
        return Value::Null;
    }
    let mut saw_null = false;
    for item in values {
        match x.sql_cmp(item) {
            Some(Ordering::Equal) => return Value::Bool(!neg),
            None => saw_null = true,
            _ => {}
        }
    }
    if saw_null {
        Value::Null
    } else {
        Value::Bool(neg)
    }
}

/// Estado de um agregado (também usado pelas funções de janela).
#[derive(Clone)]
pub(super) enum AggState {
    Count(i64),
    Sum(Option<Value>),
    Total(f64),
    Avg(f64, i64),
    Min(Option<Value>),
    Max(Option<Value>),
    GroupConcat {
        parts: Vec<String>,
        sep: Option<String>,
    },
    BoolAnd(Option<bool>),
    BoolOr(Option<bool>),
    /// Welford: n, média, M2; `pop` e `stddev` escolhem o resultado.
    Var {
        n: i64,
        mean: f64,
        m2: f64,
        pop: bool,
        stddev: bool,
    },
}

impl AggState {
    pub fn new(f: AggFn) -> Self {
        match f {
            AggFn::Count => Self::Count(0),
            AggFn::Sum => Self::Sum(None),
            AggFn::Total => Self::Total(0.0),
            AggFn::Avg => Self::Avg(0.0, 0),
            AggFn::Min => Self::Min(None),
            AggFn::Max => Self::Max(None),
            AggFn::GroupConcat => Self::GroupConcat {
                parts: Vec::new(),
                sep: None,
            },
            AggFn::BoolAnd => Self::BoolAnd(None),
            AggFn::BoolOr => Self::BoolOr(None),
            AggFn::StdDevPop | AggFn::StdDevSamp | AggFn::VarPop | AggFn::VarSamp => Self::Var {
                n: 0,
                mean: 0.0,
                m2: 0.0,
                pop: matches!(f, AggFn::StdDevPop | AggFn::VarPop),
                stddev: matches!(f, AggFn::StdDevPop | AggFn::StdDevSamp),
            },
        }
    }

    /// Segundo argumento (separador do `GROUP_CONCAT`).
    pub fn set_extra(&mut self, v: &Value) {
        if let Self::GroupConcat { sep, .. } = self {
            if !v.is_null() {
                *sep = Some(v.to_string());
            }
        }
    }

    pub fn feed(&mut self, v: Value) -> Result<()> {
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
            Self::Total(t) => {
                *t += v
                    .as_f64()
                    .ok_or_else(|| Error::Sql(format!("TOTAL de {}", v.type_name())))?
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
            Self::GroupConcat { parts, .. } => parts.push(v.to_string()),
            Self::BoolAnd(acc) => {
                let b = v.truth().unwrap_or(false);
                *acc = Some(acc.unwrap_or(true) && b);
            }
            Self::BoolOr(acc) => {
                let b = v.truth().unwrap_or(false);
                *acc = Some(acc.unwrap_or(false) || b);
            }
            Self::Var { n, mean, m2, .. } => {
                let x = v
                    .as_f64()
                    .ok_or_else(|| Error::Sql(format!("variância de {}", v.type_name())))?;
                *n += 1;
                let delta = x - *mean;
                *mean += delta / *n as f64;
                *m2 += delta * (x - *mean);
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Value {
        match self {
            Self::Count(n) => Value::Int(n),
            Self::Total(t) => Value::Real(t),
            Self::Avg(_, 0) => Value::Null,
            Self::Avg(s, n) => Value::Real(s / n as f64),
            Self::Sum(v) | Self::Min(v) | Self::Max(v) => v.unwrap_or(Value::Null),
            Self::GroupConcat { parts, sep } => {
                if parts.is_empty() {
                    Value::Null
                } else {
                    Value::Text(parts.join(sep.as_deref().unwrap_or(",")))
                }
            }
            Self::BoolAnd(b) | Self::BoolOr(b) => b.map_or(Value::Null, Value::Bool),
            Self::Var {
                n, m2, pop, stddev, ..
            } => {
                let denom = if pop { n } else { n - 1 };
                if n == 0 || denom <= 0 {
                    return Value::Null;
                }
                let var = m2 / denom as f64;
                Value::Real(if stddev { var.sqrt() } else { var })
            }
        }
    }
}

pub(super) fn table_scope(t: &Table) -> Scope {
    let mut s = Scope::default();
    s.add(
        &t.name,
        &t.columns.iter().map(|c| c.name.clone()).collect::<Vec<_>>(),
    );
    s
}

// ---------------------------------------------------------------------------
// Ponto de entrada de leitura
// ---------------------------------------------------------------------------

fn text_row(items: &[&str]) -> Vec<Value> {
    items.iter().map(|s| Value::Text(s.to_string())).collect()
}

/// Comandos de leitura (também usados por snapshots). `None` = é escrita.
pub(super) fn read(src: &dyn Source, stmt: &Stmt, params: &[Value]) -> Option<Result<ExecResult>> {
    let exec = Exec::new(src, params);
    Some(match stmt {
        Stmt::Query(q) => exec.query(q, None).map(Output::into_result),
        Stmt::ShowTables => (|| {
            let mut rows: Vec<Vec<Value>> = list_tables(src)?
                .into_iter()
                .map(|t| {
                    vec![
                        Value::Text(t.name),
                        Value::Text(
                            match t.kind {
                                TableKind::Table => "table",
                                TableKind::Materialized { .. } => "materialized view",
                            }
                            .into(),
                        ),
                        Value::Int(t.columns.len() as i64),
                        Value::Int(t.indexes.len() as i64),
                    ]
                })
                .collect();
            rows.extend(list_views(src)?.into_iter().map(|v| {
                vec![
                    Value::Text(v.name),
                    Value::Text("view".into()),
                    Value::Int(v.columns.len() as i64),
                    Value::Int(0),
                ]
            }));
            rows.sort_by(|a, b| a[0].total_cmp(&b[0]));
            Ok(ExecResult::Table {
                columns: ["name", "kind", "columns", "indexes"]
                    .map(String::from)
                    .to_vec(),
                rows,
            })
        })(),
        Stmt::ShowIndexes(table) => (|| {
            let tables = match table {
                Some(name) => vec![load_table(src, name)?],
                None => list_tables(src)?,
            };
            let mut rows = Vec::new();
            for t in &tables {
                for idx in &t.indexes {
                    let cols: Vec<&str> = idx
                        .columns
                        .iter()
                        .map(|&c| t.columns[c].name.as_str())
                        .collect();
                    rows.push(vec![
                        Value::Text(t.name.clone()),
                        Value::Text(idx.name.clone()),
                        Value::Text(cols.join(", ")),
                        Value::Bool(idx.unique),
                        Value::Bool(idx.auto),
                        Value::Text(idx.kind.name().into()),
                    ]);
                }
            }
            Ok(ExecResult::Table {
                columns: ["table", "index", "columns", "unique", "auto", "kind"]
                    .map(String::from)
                    .to_vec(),
                rows,
            })
        })(),
        Stmt::ShowUsers => (|| {
            let rows = crate::auth::list(src)?
                .into_iter()
                .map(|p| {
                    vec![
                        Value::Text(p.name),
                        Value::Text(if p.login { "user" } else { "role" }.into()),
                        Value::Bool(p.superuser),
                        Value::Text(p.roles.join(", ")),
                    ]
                })
                .collect();
            Ok(ExecResult::Table {
                columns: ["name", "kind", "superuser", "roles"]
                    .map(String::from)
                    .to_vec(),
                rows,
            })
        })(),
        Stmt::ShowGrants(who) => (|| {
            let all = crate::auth::list(src)?;
            let mut rows = Vec::new();
            for p in all
                .iter()
                .filter(|p| who.as_ref().is_none_or(|w| *w == p.name))
            {
                for g in &p.grants {
                    let privs: Vec<&str> = crate::auth::Privilege::from_bits(g.privileges)
                        .into_iter()
                        .map(|x| x.name())
                        .collect();
                    rows.push(vec![
                        Value::Text(p.name.clone()),
                        Value::Text(g.object.clone()),
                        Value::Text(privs.join(", ")),
                        Value::Text("direct".into()),
                    ]);
                }
                for role in &p.roles {
                    rows.push(vec![
                        Value::Text(p.name.clone()),
                        Value::Text(role.clone()),
                        Value::Text("MEMBER".into()),
                        Value::Text("role".into()),
                    ]);
                }
            }
            Ok(ExecResult::Table {
                columns: ["grantee", "object", "privileges", "via"]
                    .map(String::from)
                    .to_vec(),
                rows,
            })
        })(),
        Stmt::ShowCreate(name) => (|| {
            let (kind, sql) = match load_table(src, name) {
                Ok(t) => ("table", t.ddl()),
                Err(Error::UnknownTable(_)) => match load_view(src, name)? {
                    Some(v) => ("view", v.ddl()),
                    None => return Err(Error::UnknownTable(name.clone())),
                },
                Err(e) => return Err(e),
            };
            Ok(ExecResult::Table {
                columns: ["name", "kind", "sql"].map(String::from).to_vec(),
                rows: vec![text_row(&[name, kind, &sql])],
            })
        })(),
        Stmt::Describe(name) => (|| {
            let columns = [
                "column",
                "type",
                "pk",
                "not_null",
                "default",
                "index",
                "references",
            ]
            .map(String::from)
            .to_vec();
            match load_table(src, name) {
                Ok(t) => Ok(ExecResult::Table {
                    columns,
                    rows: t
                        .columns
                        .iter()
                        .enumerate()
                        .map(|(i, c)| {
                            let idx: Vec<_> = t
                                .indexes
                                .iter()
                                .filter(|x| x.columns.contains(&i))
                                .map(|x| x.name.clone())
                                .collect();
                            let fk = t.fks.iter().find(|f| f.columns.contains(&i)).map(|f| {
                                if f.parent_columns.is_empty() {
                                    f.parent.clone()
                                } else {
                                    format!("{}({})", f.parent, f.parent_columns.join(", "))
                                }
                            });
                            let in_pk = t.pk.contains(&i);
                            vec![
                                Value::Text(c.name.clone()),
                                Value::Text(c.ty.name().into()),
                                Value::Bool(in_pk),
                                Value::Bool(c.not_null || in_pk),
                                match (&c.default_sql, &c.default) {
                                    (Some(sql), _) => Value::Text(sql.clone()),
                                    (None, Some(Expr::Lit(v))) => v.clone(),
                                    (None, Some(Expr::Neg(x))) => match &**x {
                                        Expr::Lit(Value::Int(n)) => Value::Int(-n),
                                        Expr::Lit(Value::Real(r)) => Value::Real(-r),
                                        _ => Value::Null,
                                    },
                                    _ => Value::Null,
                                },
                                if idx.is_empty() {
                                    Value::Null
                                } else {
                                    Value::Text(idx.join(","))
                                },
                                fk.map_or(Value::Null, Value::Text),
                            ]
                        })
                        .collect(),
                }),
                Err(Error::UnknownTable(_)) => {
                    // View: colunas do resultado (consulta com LIMIT 0).
                    let view = exec
                        .view(name)?
                        .ok_or_else(|| Error::UnknownTable(name.clone()))?;
                    let (v, q) = &*view;
                    let mut probe: Query = (**q).clone();
                    probe.limit = Some(Expr::Lit(Value::Int(0)));
                    let out = exec.query(&probe, None)?;
                    let names = if v.columns.is_empty() {
                        out.columns
                    } else {
                        v.columns.clone()
                    };
                    Ok(ExecResult::Table {
                        columns,
                        rows: names
                            .into_iter()
                            .map(|n| {
                                vec![
                                    Value::Text(n),
                                    Value::Text("VIEW".into()),
                                    Value::Bool(false),
                                    Value::Bool(false),
                                    Value::Null,
                                    Value::Null,
                                    Value::Null,
                                ]
                            })
                            .collect(),
                    })
                }
                Err(e) => Err(e),
            }
        })(),
        Stmt::Explain(inner, analyze) => exec.explain(inner, *analyze).map(ExecResult::Ok),
        Stmt::ShowTriggers(table) => (|| {
            let tables = match table {
                Some(name) => vec![load_table(src, name)?],
                None => list_tables(src)?,
            };
            let mut rows = Vec::new();
            for t in &tables {
                for tr in &t.triggers {
                    rows.push(vec![
                        Value::Text(tr.name.clone()),
                        Value::Text(t.name.clone()),
                        Value::Text(
                            match tr.timing {
                                TriggerTiming::Before => "BEFORE",
                                TriggerTiming::After => "AFTER",
                            }
                            .into(),
                        ),
                        Value::Text(tr.event.sql()),
                        tr.when
                            .as_ref()
                            .map_or(Value::Null, |(_, sql)| Value::Text(sql.clone())),
                        Value::Int(tr.body.len() as i64),
                    ]);
                }
            }
            Ok(ExecResult::Table {
                columns: ["trigger", "table", "timing", "event", "when", "statements"]
                    .map(String::from)
                    .to_vec(),
                rows,
            })
        })(),
        _ => return None,
    })
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
            assert_eq!(like(t, p, false), want, "{t} LIKE {p}");
        }
        assert!(like("Abc", "A*", true));
        assert!(!like("abc", "A*", true));
        assert!(like("a.c", "a?c", true));
        assert!(like("caio", "[cd]*", true) && !like("ana", "[cd]*", true));
        assert!(like("x9", "?[0-9]", true) && like("b", "[^a]", true) && !like("a", "[!a]", true));
        assert!(like("a]", "a]", true) && like("[", "[", true));
    }
}
