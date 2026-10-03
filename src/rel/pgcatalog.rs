//! Catálogo PostgreSQL virtual (`pg_catalog.*`, `information_schema.*`) e as
//! funções `pg_*` que clientes como `psql`, ORMs e drivers consultam. As
//! tabelas são sintetizadas a cada consulta a partir do catálogo do Mini-DB.
//!
//! OIDs: tabela = 16384 + id·1024; índice = oid da tabela + 1 + posição;
//! view = 1 000 000 + posição; usuário = 10 000 + posição (10 = `minidb`).

use super::exec::{list_tables, list_views, IndexDef, Output, Table, TableKind};
use super::parser::{FkAction, IndexKind};
use super::value::{Type, Value};
use super::Source;
use crate::error::Result;

pub(super) const NS_CATALOG: i64 = 11;
pub(super) const NS_PUBLIC: i64 = 2200;
pub(super) const NS_INFO: i64 = 12;
pub(super) const OWNER: i64 = 10;

pub(super) fn t(s: &str) -> Value {
    Value::Text(s.to_string())
}

pub(super) fn i(n: i64) -> Value {
    Value::Int(n)
}

pub(super) fn b(v: bool) -> Value {
    Value::Bool(v)
}

pub(super) fn table_oid(t: &Table) -> i64 {
    16384 + t.id as i64 * 1024
}

pub(super) fn index_oid(t: &Table, pos: usize) -> i64 {
    table_oid(t) + 1 + pos as i64
}

fn type_oid(ty: Type) -> i64 {
    match ty {
        Type::Int => 20,
        Type::Real => 701,
        Type::Text => 25,
        Type::Bool => 16,
    }
}

pub(super) fn type_name_by_oid(oid: i64) -> &'static str {
    match oid {
        16 => "boolean",
        20 => "bigint",
        21 => "smallint",
        23 => "integer",
        25 => "text",
        700 => "real",
        701 => "double precision",
        1043 => "character varying",
        1082 => "date",
        1114 => "timestamp without time zone",
        1184 => "timestamp with time zone",
        1700 => "numeric",
        2950 => "uuid",
        3802 => "jsonb",
        114 => "json",
        _ => "text",
    }
}

fn pg_type_name(ty: Type) -> &'static str {
    match ty {
        Type::Int => "bigint",
        Type::Real => "double precision",
        Type::Text => "text",
        Type::Bool => "boolean",
    }
}

pub(super) fn out(columns: &[&str], rows: Vec<Vec<Value>>) -> Output {
    Output {
        columns: columns.iter().map(|c| c.to_string()).collect(),
        rows,
    }
}

/// Definição SQL de um índice, no estilo `pg_get_indexdef`.
fn indexdef(t: &Table, idx: &IndexDef) -> String {
    let cols: Vec<&str> = idx
        .columns
        .iter()
        .map(|&c| t.columns[c].name.as_str())
        .collect();
    let method = match idx.kind {
        IndexKind::BTree => "btree",
        IndexKind::FullText => "fulltext",
        IndexKind::Vector => "hnsw",
        IndexKind::Spatial => "zorder",
    };
    format!(
        "CREATE {}INDEX {} ON {} USING {method} ({})",
        if idx.unique { "UNIQUE " } else { "" },
        idx.name,
        t.name,
        cols.join(", ")
    )
}

/// ` ON DELETE CASCADE` etc. (vazio para NO ACTION, o padrão).
fn fk_rule(prefix: &str, a: &FkAction) -> String {
    let rule = match a {
        FkAction::NoAction => return String::new(),
        FkAction::Restrict => "RESTRICT",
        FkAction::Cascade => "CASCADE",
        FkAction::SetNull => "SET NULL",
        FkAction::SetDefault => "SET DEFAULT",
    };
    format!("{prefix}{rule}")
}

fn constraints(tables: &[Table]) -> Vec<Vec<Value>> {
    // oid, conname, connamespace, contype, condeferrable, condeferred, conrelid,
    // conindid, confrelid, conkey, confkey, conperiod, consrc
    let mut rows = Vec::new();
    for tb in tables {
        let oid = table_oid(tb);
        let key = |cols: &[usize]| {
            format!(
                "{{{}}}",
                cols.iter()
                    .map(|c| (c + 1).to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        if !tb.pk.is_empty() {
            rows.push(vec![
                i(oid + 500),
                t(&format!("{}_pkey", tb.name)),
                i(NS_PUBLIC),
                t("p"),
                b(false),
                b(false),
                i(oid),
                i(oid + 500),
                i(0),
                t(&key(&tb.pk)),
                Value::Null,
                b(false),
                t(&format!(
                    "PRIMARY KEY ({})",
                    tb.pk
                        .iter()
                        .map(|&c| tb.columns[c].name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            ]);
        }
        for (pos, idx) in tb.indexes.iter().enumerate() {
            if idx.unique {
                rows.push(vec![
                    i(oid + 600 + pos as i64),
                    t(&idx.name),
                    i(NS_PUBLIC),
                    t("u"),
                    b(false),
                    b(false),
                    i(oid),
                    i(index_oid(tb, pos)),
                    i(0),
                    t(&key(&idx.columns)),
                    Value::Null,
                    b(false),
                    t(&format!(
                        "UNIQUE ({})",
                        idx.columns
                            .iter()
                            .map(|&c| tb.columns[c].name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                ]);
            }
        }
        for (pos, fk) in tb.fks.iter().enumerate() {
            let parent = tables.iter().find(|p| p.name == fk.parent);
            let parent_cols = if fk.parent_columns.is_empty() {
                parent
                    .map(|p| {
                        p.pk.iter()
                            .map(|&c| p.columns[c].name.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            } else {
                fk.parent_columns.clone()
            };
            rows.push(vec![
                i(oid + 700 + pos as i64),
                t(&fk.name),
                i(NS_PUBLIC),
                t("f"),
                b(false),
                b(false),
                i(oid),
                i(0),
                i(parent.map_or(0, table_oid)),
                t(&key(&fk.columns)),
                Value::Null,
                b(false),
                t(&format!(
                    "FOREIGN KEY ({}) REFERENCES {}({}){}{}",
                    fk.columns
                        .iter()
                        .map(|&c| tb.columns[c].name.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    fk.parent,
                    parent_cols.join(", "),
                    fk_rule(" ON UPDATE ", &fk.on_update),
                    fk_rule(" ON DELETE ", &fk.on_delete),
                )),
            ]);
        }
        for (pos, ck) in tb.checks.iter().enumerate() {
            rows.push(vec![
                i(oid + 800 + pos as i64),
                t(ck.name
                    .as_deref()
                    .unwrap_or(&format!("{}_check{}", tb.name, pos + 1))),
                i(NS_PUBLIC),
                t("c"),
                b(false),
                b(false),
                i(oid),
                i(0),
                i(0),
                Value::Null,
                Value::Null,
                b(false),
                t(&format!("CHECK ({})", ck.sql)),
            ]);
        }
    }
    rows
}

/// Relação virtual `name` (sem esquema), ou `None` se não é do catálogo.
pub(super) fn relation(
    src: &dyn Source,
    name: &str,
    view_columns: &dyn Fn(&super::exec::View) -> Vec<String>,
) -> Result<Option<Output>> {
    if !name.starts_with("pg_") && !INFORMATION_SCHEMA.contains(&name) {
        return Ok(None);
    }
    let tables = list_tables(src)?;
    let mut views = list_views(src)?;
    for v in &mut views {
        if v.columns.is_empty() {
            v.columns = view_columns(v);
        }
    }
    let users = crate::auth::list(src)?;
    if let Some(o) = super::pgmore::relation(src, name, &tables, &views, &users)? {
        return Ok(Some(o));
    }
    let o = match name {
        "pg_namespace" => out(
            &["oid", "nspname", "nspowner", "nspacl"],
            vec![
                vec![i(NS_CATALOG), t("pg_catalog"), i(OWNER), Value::Null],
                vec![i(NS_PUBLIC), t("public"), i(OWNER), Value::Null],
                vec![i(NS_INFO), t("information_schema"), i(OWNER), Value::Null],
            ],
        ),
        "pg_class" => {
            let cols = [
                "oid",
                "relname",
                "relnamespace",
                "reltype",
                "relowner",
                "relam",
                "relfilenode",
                "reltablespace",
                "relpages",
                "reltuples",
                "reltoastrelid",
                "relhasindex",
                "relisshared",
                "relpersistence",
                "relkind",
                "relnatts",
                "relchecks",
                "relhasrules",
                "relhastriggers",
                "relhassubclass",
                "relrowsecurity",
                "relforcerowsecurity",
                "relispopulated",
                "relreplident",
                "relispartition",
                "reloftype",
                "relacl",
                "reloptions",
                "relpartbound",
            ];
            let mut rows = Vec::new();
            let row = |oid: i64,
                       name: &str,
                       kind: &str,
                       am: i64,
                       natts: i64,
                       checks: i64,
                       hasindex: bool,
                       triggers: bool| {
                vec![
                    i(oid),
                    t(name),
                    i(NS_PUBLIC),
                    i(0),
                    i(OWNER),
                    i(am),
                    i(oid),
                    i(0),
                    i(0),
                    Value::Real(-1.0),
                    i(0),
                    b(hasindex),
                    b(false),
                    t("p"),
                    t(kind),
                    i(natts),
                    i(checks),
                    b(false),
                    b(triggers),
                    b(false),
                    b(false),
                    b(false),
                    b(true),
                    t("d"),
                    b(false),
                    i(0),
                    Value::Null,
                    Value::Null,
                    Value::Null,
                ]
            };
            for tb in &tables {
                let kind = match tb.kind {
                    TableKind::Table => "r",
                    TableKind::Materialized { .. } => "m",
                };
                rows.push(row(
                    table_oid(tb),
                    &tb.name,
                    kind,
                    2,
                    tb.columns.len() as i64,
                    tb.checks.len() as i64,
                    !tb.indexes.is_empty() || !tb.pk.is_empty(),
                    // No PostgreSQL, chaves estrangeiras são gatilhos internos: o psql só
                    // mostra "Foreign-key constraints"/"Referenced by" se relhastriggers.
                    !tb.triggers.is_empty()
                        || !tb.fks.is_empty()
                        || tables
                            .iter()
                            .any(|o| o.fks.iter().any(|f| f.parent == tb.name)),
                ));
                for (pos, idx) in tb.indexes.iter().enumerate() {
                    rows.push(row(
                        index_oid(tb, pos),
                        &idx.name,
                        "i",
                        match idx.kind {
                            IndexKind::BTree => 403,
                            IndexKind::Vector => 3580,
                            IndexKind::FullText => 2742,
                            IndexKind::Spatial => 783,
                        },
                        idx.columns.len() as i64,
                        0,
                        false,
                        false,
                    ));
                }
                if !tb.pk.is_empty() {
                    rows.push(row(
                        table_oid(tb) + 500,
                        &format!("{}_pkey", tb.name),
                        "i",
                        403,
                        tb.pk.len() as i64,
                        0,
                        false,
                        false,
                    ));
                }
            }
            for (pos, v) in views.iter().enumerate() {
                rows.push(row(
                    1_000_000 + pos as i64,
                    &v.name,
                    "v",
                    0,
                    v.columns.len() as i64,
                    0,
                    false,
                    false,
                ));
            }
            out(&cols, rows)
        }
        "pg_attribute" => {
            let cols = [
                "attrelid",
                "attname",
                "atttypid",
                "attstattarget",
                "attlen",
                "attnum",
                "attndims",
                "attcacheoff",
                "atttypmod",
                "attbyval",
                "attstorage",
                "attalign",
                "attnotnull",
                "atthasdef",
                "atthasmissing",
                "attidentity",
                "attgenerated",
                "attisdropped",
                "attislocal",
                "attinhcount",
                "attcollation",
                "attacl",
                "attoptions",
                "attfdwoptions",
                "attcompression",
                "attstorage_desc",
            ];
            let mut rows = Vec::new();
            for tb in &tables {
                for (n, c) in tb.columns.iter().enumerate() {
                    rows.push(vec![
                        i(table_oid(tb)),
                        t(&c.name),
                        i(type_oid(c.ty)),
                        i(-1),
                        i(if c.ty == Type::Text { -1 } else { 8 }),
                        i(n as i64 + 1),
                        i(0),
                        i(-1),
                        i(-1),
                        b(c.ty != Type::Text),
                        t("p"),
                        t("d"),
                        b(c.not_null || c.primary || tb.pk.contains(&n)),
                        b(c.default.is_some()),
                        b(false),
                        t(if c.autoincrement { "d" } else { "" }),
                        t(""),
                        b(false),
                        b(true),
                        i(0),
                        i(0),
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        t(""),
                        Value::Null,
                    ]);
                }
            }
            for tb in &tables {
                let mut indexes: Vec<(i64, Vec<usize>)> = tb
                    .indexes
                    .iter()
                    .enumerate()
                    .map(|(pos, idx)| (index_oid(tb, pos), idx.columns.clone()))
                    .collect();
                if !tb.pk.is_empty() {
                    indexes.push((table_oid(tb) + 500, tb.pk.clone()));
                }
                for (oid, cols) in indexes {
                    for (n, &c) in cols.iter().enumerate() {
                        let col = &tb.columns[c];
                        rows.push(vec![
                            i(oid),
                            t(&col.name),
                            i(type_oid(col.ty)),
                            i(-1),
                            i(-1),
                            i(n as i64 + 1),
                            i(0),
                            i(-1),
                            i(-1),
                            b(false),
                            t("p"),
                            t("d"),
                            b(false),
                            b(false),
                            b(false),
                            t(""),
                            t(""),
                            b(false),
                            b(true),
                            i(0),
                            i(0),
                            Value::Null,
                            Value::Null,
                            Value::Null,
                            t(""),
                            Value::Null,
                        ]);
                    }
                }
            }
            for (pos, v) in views.iter().enumerate() {
                for (n, c) in v.columns.iter().enumerate() {
                    rows.push(vec![
                        i(1_000_000 + pos as i64),
                        t(c),
                        i(25),
                        i(-1),
                        i(-1),
                        i(n as i64 + 1),
                        i(0),
                        i(-1),
                        i(-1),
                        b(false),
                        t("p"),
                        t("d"),
                        b(false),
                        b(false),
                        b(false),
                        t(""),
                        t(""),
                        b(false),
                        b(true),
                        i(0),
                        i(0),
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        t(""),
                        Value::Null,
                    ]);
                }
            }
            out(&cols, rows)
        }
        "pg_attrdef" => {
            let mut rows = Vec::new();
            for tb in &tables {
                for (n, c) in tb.columns.iter().enumerate() {
                    if let Some(def) = c
                        .default_sql
                        .clone()
                        .or_else(|| c.default.as_ref().map(super::exec::expr_name))
                    {
                        rows.push(vec![
                            i(table_oid(tb) + 900 + n as i64),
                            i(table_oid(tb)),
                            i(n as i64 + 1),
                            t(&def),
                        ]);
                    }
                }
            }
            out(&["oid", "adrelid", "adnum", "adbin"], rows)
        }
        "pg_index" => {
            let cols = [
                "indexrelid",
                "indrelid",
                "indnatts",
                "indnkeyatts",
                "indisunique",
                "indnullsnotdistinct",
                "indisprimary",
                "indisexclusion",
                "indimmediate",
                "indisclustered",
                "indisvalid",
                "indcheckxmin",
                "indisready",
                "indislive",
                "indisreplident",
                "indkey",
                "indcollation",
                "indclass",
                "indoption",
                "indexprs",
                "indpred",
            ];
            let mut rows = Vec::new();
            let key = |cols: &[usize]| {
                cols.iter()
                    .map(|c| (c + 1).to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            for tb in &tables {
                for (pos, idx) in tb.indexes.iter().enumerate() {
                    rows.push(vec![
                        i(index_oid(tb, pos)),
                        i(table_oid(tb)),
                        i(idx.columns.len() as i64),
                        i(idx.columns.len() as i64),
                        b(idx.unique),
                        b(false),
                        b(false),
                        b(false),
                        b(true),
                        b(false),
                        b(true),
                        b(false),
                        b(true),
                        b(true),
                        b(false),
                        t(&key(&idx.columns)),
                        t("0"),
                        t("0"),
                        t("0"),
                        Value::Null,
                        Value::Null,
                    ]);
                }
                if !tb.pk.is_empty() {
                    rows.push(vec![
                        i(table_oid(tb) + 500),
                        i(table_oid(tb)),
                        i(tb.pk.len() as i64),
                        i(tb.pk.len() as i64),
                        b(true),
                        b(false),
                        b(true),
                        b(false),
                        b(true),
                        b(false),
                        b(true),
                        b(false),
                        b(true),
                        b(true),
                        b(false),
                        t(&key(&tb.pk)),
                        t("0"),
                        t("0"),
                        t("0"),
                        Value::Null,
                        Value::Null,
                    ]);
                }
            }
            out(&cols, rows)
        }
        "pg_constraint" => out(
            &[
                "oid",
                "conname",
                "connamespace",
                "contype",
                "condeferrable",
                "condeferred",
                "conrelid",
                "conindid",
                "confrelid",
                "conkey",
                "confkey",
                "conperiod",
                "consrc",
                "conparentid",
                "contypid",
                "convalidated",
                "conislocal",
                "coninhcount",
                "connoinherit",
                "confupdtype",
                "confdeltype",
                "confmatchtype",
            ],
            constraints(&tables)
                .into_iter()
                .map(|mut r| {
                    let fk = tables
                        .iter()
                        .flat_map(|tb| tb.fks.iter())
                        .find(|f| r[3] == t("f") && r[1] == t(&f.name));
                    let act = |a: Option<&FkAction>| match a {
                        Some(FkAction::NoAction) => "a",
                        Some(FkAction::Restrict) => "r",
                        Some(FkAction::Cascade) => "c",
                        Some(FkAction::SetNull) => "n",
                        Some(FkAction::SetDefault) => "d",
                        None => " ",
                    };
                    r.extend([
                        i(0),
                        i(0),
                        b(true),
                        b(true),
                        i(0),
                        b(true),
                        t(act(fk.map(|f| &f.on_update))),
                        t(act(fk.map(|f| &f.on_delete))),
                        t(if fk.is_some() { "s" } else { " " }),
                    ]);
                    r
                })
                .collect(),
        ),
        "pg_am" => out(
            &["oid", "amname", "amhandler", "amtype"],
            vec![
                vec![i(2), t("heap"), i(0), t("t")],
                vec![i(403), t("btree"), i(0), t("i")],
                vec![i(3580), t("hnsw"), i(0), t("i")],
                vec![i(2742), t("fulltext"), i(0), t("i")],
                vec![i(783), t("zorder"), i(0), t("i")],
            ],
        ),
        "pg_type" => {
            let cols = [
                "oid",
                "typname",
                "typnamespace",
                "typowner",
                "typlen",
                "typbyval",
                "typtype",
                "typcategory",
                "typrelid",
                "typelem",
                "typarray",
                "typcollation",
                "typnotnull",
                "typbasetype",
                "typtypmod",
                "typndims",
                "typdefault",
            ];
            let rows = [
                (16, "bool", 1, "B"),
                (20, "int8", 8, "N"),
                (21, "int2", 2, "N"),
                (23, "int4", 4, "N"),
                (25, "text", -1, "S"),
                (700, "float4", 4, "N"),
                (701, "float8", 8, "N"),
                (1043, "varchar", -1, "S"),
                (1082, "date", 4, "D"),
                (1114, "timestamp", 8, "D"),
                (1700, "numeric", -1, "N"),
                (2950, "uuid", 16, "U"),
                (114, "json", -1, "U"),
                (3802, "jsonb", -1, "U"),
                (26, "oid", 4, "N"),
                (19, "name", 64, "S"),
            ]
            .iter()
            .map(|(oid, name, len, cat)| {
                vec![
                    i(*oid),
                    t(name),
                    i(NS_CATALOG),
                    i(OWNER),
                    i(*len),
                    b(*len > 0),
                    t("b"),
                    t(cat),
                    i(0),
                    i(0),
                    i(0),
                    i(if *cat == "S" { 100 } else { 0 }),
                    b(false),
                    i(0),
                    i(-1),
                    i(0),
                    Value::Null,
                ]
            })
            .collect();
            out(&cols, rows)
        }
        "pg_roles" | "pg_authid" | "pg_user" | "pg_shadow" => {
            let cols = [
                "oid",
                "rolname",
                "rolsuper",
                "rolinherit",
                "rolcreaterole",
                "rolcreatedb",
                "rolcanlogin",
                "rolreplication",
                "rolbypassrls",
                "rolconnlimit",
                "rolvaliduntil",
                "rolconfig",
                "usename",
                "usesysid",
                "usesuper",
                "usecreatedb",
            ];
            let mut rows = vec![vec![
                i(OWNER),
                t("minidb"),
                b(true),
                b(true),
                b(true),
                b(true),
                b(true),
                b(false),
                b(false),
                i(-1),
                Value::Null,
                Value::Null,
                t("minidb"),
                i(OWNER),
                b(true),
                b(true),
            ]];
            for (pos, u) in users.iter().enumerate() {
                rows.push(vec![
                    i(10_000 + pos as i64),
                    t(&u.name),
                    b(u.superuser),
                    b(true),
                    b(u.superuser),
                    b(u.superuser),
                    b(u.login),
                    b(false),
                    b(false),
                    i(-1),
                    Value::Null,
                    Value::Null,
                    t(&u.name),
                    i(10_000 + pos as i64),
                    b(u.superuser),
                    b(u.superuser),
                ]);
            }
            out(&cols, rows)
        }
        "pg_database" => out(
            &[
                "oid",
                "datname",
                "datdba",
                "encoding",
                "datlocprovider",
                "datistemplate",
                "datallowconn",
                "datconnlimit",
                "dattablespace",
                "datcollate",
                "datctype",
                "daticulocale",
                "daticurules",
                "datcollversion",
                "datacl",
            ],
            vec![vec![
                i(1),
                t("minidb"),
                i(OWNER),
                i(6),
                t("c"),
                b(false),
                b(true),
                i(-1),
                i(1663),
                t("C"),
                t("C"),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
            ]],
        ),
        "pg_tablespace" => out(
            &["oid", "spcname", "spcowner", "spcacl", "spcoptions"],
            vec![vec![
                i(1663),
                t("pg_default"),
                i(OWNER),
                Value::Null,
                Value::Null,
            ]],
        ),
        "pg_settings" => {
            let rows = [
                ("server_version", "16.0"),
                ("server_encoding", "UTF8"),
                ("client_encoding", "UTF8"),
                ("DateStyle", "ISO, MDY"),
                ("TimeZone", "UTC"),
                ("max_connections", "1024"),
                ("search_path", "public"),
                ("standard_conforming_strings", "on"),
                ("integer_datetimes", "on"),
            ]
            .iter()
            .map(|(n, v)| vec![t(n), t(v), Value::Null, t(n), t("string"), t("user")])
            .collect();
            out(
                &[
                    "name",
                    "setting",
                    "unit",
                    "short_desc",
                    "vartype",
                    "context",
                ],
                rows,
            )
        }
        "pg_extension"
        | "pg_rewrite"
        | "pg_inherits"
        | "pg_policy"
        | "pg_statistic_ext"
        | "pg_publication"
        | "pg_publication_rel"
        | "pg_description"
        | "pg_enum"
        | "pg_range"
        | "pg_sequence"
        | "pg_partitioned_table"
        | "pg_foreign_table"
        | "pg_foreign_server"
        | "pg_event_trigger"
        | "pg_locks"
        | "pg_rules"
        | "pg_subscription"
        | "pg_replication_slots"
        | "pg_conversion"
        | "pg_shdescription"
        | "pg_seclabel"
        | "pg_default_acl"
        | "pg_init_privs"
        | "pg_largeobject"
        | "pg_user_mapping"
        | "pg_transform"
        | "pg_amop"
        | "pg_amproc"
        | "pg_attribute_stats"
        | "pg_publication_namespace"
        | "pg_subscription_rel"
        | "pg_stat_replication"
        | "pg_prepared_statements"
        | "pg_cursors"
        | "pg_shseclabel"
        | "pg_policies"
        | "pg_sequences"
        | "pg_db_role_setting"
        | "pg_foreign_data_wrapper"
        | "pg_ts_config_map"
        | "pg_shdepend"
        | "pg_user_mappings"
        | "pg_statistic_ext_data"
        | "pg_namespace_acl" => out(&empty_columns(name), Vec::new()),
        "pg_tables" => out(
            &[
                "schemaname",
                "tablename",
                "tableowner",
                "tablespace",
                "hasindexes",
                "hasrules",
                "hastriggers",
                "rowsecurity",
            ],
            tables
                .iter()
                .filter(|tb| tb.kind == TableKind::Table)
                .map(|tb| {
                    vec![
                        t("public"),
                        t(&tb.name),
                        t("minidb"),
                        Value::Null,
                        b(!tb.indexes.is_empty()),
                        b(false),
                        b(!tb.triggers.is_empty()),
                        b(false),
                    ]
                })
                .collect(),
        ),
        "pg_views" => out(
            &["schemaname", "viewname", "viewowner", "definition"],
            views
                .iter()
                .map(|v| vec![t("public"), t(&v.name), t("minidb"), t(&v.sql)])
                .collect(),
        ),
        "pg_indexes" => {
            let mut rows = Vec::new();
            for tb in &tables {
                for idx in &tb.indexes {
                    rows.push(vec![
                        t("public"),
                        t(&tb.name),
                        t(&idx.name),
                        Value::Null,
                        t(&indexdef(tb, idx)),
                    ]);
                }
            }
            out(
                &[
                    "schemaname",
                    "tablename",
                    "indexname",
                    "tablespace",
                    "indexdef",
                ],
                rows,
            )
        }
        // information_schema
        "tables" => {
            let mut rows: Vec<Vec<Value>> = tables
                .iter()
                .map(|tb| {
                    vec![
                        t("minidb"),
                        t("public"),
                        t(&tb.name),
                        t(if tb.kind == TableKind::Table {
                            "BASE TABLE"
                        } else {
                            "VIEW"
                        }),
                        t("YES"),
                    ]
                })
                .collect();
            rows.extend(
                views
                    .iter()
                    .map(|v| vec![t("minidb"), t("public"), t(&v.name), t("VIEW"), t("NO")]),
            );
            out(
                &[
                    "table_catalog",
                    "table_schema",
                    "table_name",
                    "table_type",
                    "is_insertable_into",
                ],
                rows,
            )
        }
        "columns" => {
            let mut rows = Vec::new();
            for tb in &tables {
                for (n, c) in tb.columns.iter().enumerate() {
                    rows.push(vec![
                        t("minidb"),
                        t("public"),
                        t(&tb.name),
                        t(&c.name),
                        i(n as i64 + 1),
                        c.default_sql.clone().map_or(Value::Null, |d| t(&d)),
                        t(if c.not_null || tb.pk.contains(&n) {
                            "NO"
                        } else {
                            "YES"
                        }),
                        t(pg_type_name(c.ty)),
                        t(pg_type_name(c.ty).split(' ').next().unwrap_or("text")),
                    ]);
                }
            }
            out(
                &[
                    "table_catalog",
                    "table_schema",
                    "table_name",
                    "column_name",
                    "ordinal_position",
                    "column_default",
                    "is_nullable",
                    "data_type",
                    "udt_name",
                ],
                rows,
            )
        }
        "table_constraints" => out(
            &[
                "constraint_catalog",
                "constraint_schema",
                "constraint_name",
                "table_schema",
                "table_name",
                "constraint_type",
            ],
            constraints(&tables)
                .into_iter()
                .map(|r| {
                    let table = tables
                        .iter()
                        .find(|tb| Value::Int(table_oid(tb)) == r[6])
                        .map(|tb| tb.name.clone())
                        .unwrap_or_default();
                    let kind = match &r[3] {
                        Value::Text(k) if k == "p" => "PRIMARY KEY",
                        Value::Text(k) if k == "u" => "UNIQUE",
                        Value::Text(k) if k == "f" => "FOREIGN KEY",
                        _ => "CHECK",
                    };
                    vec![
                        t("minidb"),
                        t("public"),
                        r[1].clone(),
                        t("public"),
                        t(&table),
                        t(kind),
                    ]
                })
                .collect(),
        ),
        "key_column_usage" => {
            let mut rows = Vec::new();
            for tb in &tables {
                for (pos, &c) in tb.pk.iter().enumerate() {
                    rows.push(vec![
                        t("minidb"),
                        t("public"),
                        t(&format!("{}_pkey", tb.name)),
                        t("public"),
                        t(&tb.name),
                        t(&tb.columns[c].name),
                        i(pos as i64 + 1),
                    ]);
                }
                for fk in &tb.fks {
                    for (pos, &c) in fk.columns.iter().enumerate() {
                        rows.push(vec![
                            t("minidb"),
                            t("public"),
                            t(&fk.name),
                            t("public"),
                            t(&tb.name),
                            t(&tb.columns[c].name),
                            i(pos as i64 + 1),
                        ]);
                    }
                }
            }
            out(
                &[
                    "constraint_catalog",
                    "constraint_schema",
                    "constraint_name",
                    "table_schema",
                    "table_name",
                    "column_name",
                    "ordinal_position",
                ],
                rows,
            )
        }
        "schemata" => out(
            &["catalog_name", "schema_name", "schema_owner"],
            vec![
                vec![t("minidb"), t("public"), t("minidb")],
                vec![t("minidb"), t("pg_catalog"), t("minidb")],
                vec![t("minidb"), t("information_schema"), t("minidb")],
            ],
        ),
        "views" => out(
            &[
                "table_catalog",
                "table_schema",
                "table_name",
                "view_definition",
            ],
            views
                .iter()
                .map(|v| vec![t("minidb"), t("public"), t(&v.name), t(&v.sql)])
                .collect(),
        ),
        "sequences" => out(&empty_columns(name), Vec::new()),
        _ => return Ok(None),
    };
    Ok(Some(o))
}

const INFORMATION_SCHEMA: &[&str] = &[
    "tables",
    "columns",
    "table_constraints",
    "key_column_usage",
    "schemata",
    "views",
    "routines",
    "sequences",
    "referential_constraints",
    "check_constraints",
    "triggers",
];

/// Colunas das relações vazias (o que `psql`/ORMs costumam referenciar).
fn empty_columns(name: &str) -> Vec<&'static str> {
    match name {
        "pg_rewrite" => vec![
            "oid",
            "rulename",
            "ev_class",
            "ev_type",
            "ev_enabled",
            "is_instead",
        ],
        "pg_inherits" => vec!["inhrelid", "inhparent", "inhseqno", "inhdetachpending"],
        "pg_policy" => vec![
            "oid",
            "polname",
            "polrelid",
            "polcmd",
            "polpermissive",
            "polroles",
            "polqual",
            "polwithcheck",
        ],
        "pg_statistic_ext" => vec![
            "oid",
            "stxrelid",
            "stxname",
            "stxnamespace",
            "stxkeys",
            "stxkind",
            "stxstattarget",
            "stxexprs",
        ],
        "pg_publication" => vec![
            "oid",
            "pubname",
            "puballtables",
            "pubinsert",
            "pubupdate",
            "pubdelete",
            "pubtruncate",
            "pubviaroot",
        ],
        "pg_publication_rel" => vec!["oid", "prpubid", "prrelid", "prqual", "prattrs"],
        "pg_publication_namespace" => vec!["oid", "pnpubid", "pnnspid"],
        "pg_subscription_rel" => vec!["srsubid", "srrelid", "srsubstate"],
        "pg_stat_replication" => vec!["pid", "usename", "application_name", "state", "sent_lsn"],
        "pg_prepared_statements" => vec!["name", "statement", "prepare_time", "parameter_types"],
        "pg_cursors" => vec!["name", "statement", "is_holdable", "is_scrollable"],
        "pg_shseclabel" => vec!["objoid", "classoid", "provider", "label"],
        "pg_policies" => vec![
            "schemaname",
            "tablename",
            "policyname",
            "permissive",
            "roles",
            "cmd",
            "qual",
            "with_check",
        ],
        "pg_sequences" => vec![
            "schemaname",
            "sequencename",
            "sequenceowner",
            "data_type",
            "start_value",
            "last_value",
        ],
        "pg_description" => vec!["objoid", "classoid", "objsubid", "description"],
        "pg_enum" => vec!["oid", "enumtypid", "enumsortorder", "enumlabel"],
        "pg_sequence" => vec![
            "seqrelid",
            "seqtypid",
            "seqstart",
            "seqincrement",
            "seqmax",
            "seqmin",
            "seqcache",
            "seqcycle",
        ],
        "pg_locks" => vec!["locktype", "database", "relation", "pid", "mode", "granted"],
        "pg_rules" => vec!["schemaname", "tablename", "rulename", "definition"],
        "pg_range" => vec!["rngtypid", "rngsubtype", "rngmultitypid"],
        "pg_partitioned_table" => vec!["partrelid", "partstrat", "partnatts", "partdefid"],
        "pg_foreign_table" => vec!["ftrelid", "ftserver", "ftoptions"],
        "pg_foreign_server" => vec!["oid", "srvname", "srvowner", "srvfdw", "srvoptions"],
        "pg_event_trigger" => vec![
            "oid",
            "evtname",
            "evtevent",
            "evtowner",
            "evtfoid",
            "evtenabled",
        ],
        "pg_subscription" => vec!["oid", "subname", "subenabled", "subconninfo"],
        "pg_replication_slots" => vec!["slot_name", "plugin", "slot_type", "active"],
        "pg_conversion" => vec![
            "oid",
            "conname",
            "connamespace",
            "conforencoding",
            "contoencoding",
        ],
        "pg_shdescription" => vec!["objoid", "classoid", "description"],
        "pg_seclabel" => vec!["objoid", "classoid", "objsubid", "provider", "label"],
        "pg_default_acl" => vec![
            "oid",
            "defaclrole",
            "defaclnamespace",
            "defaclobjtype",
            "defaclacl",
        ],
        "pg_init_privs" => vec!["objoid", "classoid", "objsubid", "privtype", "initprivs"],
        "pg_largeobject" => vec!["loid", "pageno", "data"],
        "pg_user_mapping" => vec!["oid", "umuser", "umserver", "umoptions"],
        "pg_transform" => vec!["oid", "trftype", "trflang"],
        "pg_db_role_setting" => vec!["setdatabase", "setrole", "setconfig"],
        "pg_foreign_data_wrapper" => vec![
            "oid",
            "fdwname",
            "fdwowner",
            "fdwhandler",
            "fdwvalidator",
            "fdwacl",
            "fdwoptions",
        ],
        "pg_ts_config_map" => vec!["mapcfg", "maptokentype", "mapseqno", "mapdict"],
        "pg_shdepend" => vec![
            "dbid",
            "classid",
            "objid",
            "objsubid",
            "refclassid",
            "refobjid",
            "deptype",
        ],
        "pg_user_mappings" => vec!["umid", "srvid", "srvname", "umuser", "usename", "umoptions"],
        "pg_statistic_ext_data" => vec!["stxoid", "stxdndistinct", "stxddependencies"],
        "pg_amop" | "pg_amproc" => vec!["oid", "amopfamily", "amoplefttype", "amoprighttype"],
        "pg_attribute_stats" => vec!["attrelid", "attnum"],
        "sequences" => vec![
            "sequence_catalog",
            "sequence_schema",
            "sequence_name",
            "data_type",
        ],
        _ => vec!["oid"],
    }
}

fn oid_arg(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Int(n) => Some(*n),
        Value::Text(s) => s.trim().parse().ok(),
        Value::Real(x) => Some(*x as i64),
        _ => None,
    }
}

/// Funções que dependem do catálogo; `None` = não é uma delas.
pub(super) fn function(src: &dyn Source, name: &str, args: &[Value]) -> Result<Option<Value>> {
    if let Some(v) = super::pgmore::function(src, name, args)? {
        return Ok(Some(v));
    }
    let v = match name {
        "pg_get_indexdef" => {
            let Some(oid) = oid_arg(args.first()) else {
                return Ok(Some(Value::Null));
            };
            let tables = list_tables(src)?;
            let mut found = Value::Null;
            for tb in &tables {
                for (pos, idx) in tb.indexes.iter().enumerate() {
                    if index_oid(tb, pos) == oid {
                        found = t(&indexdef(tb, idx));
                    }
                }
                if table_oid(tb) + 500 == oid && !tb.pk.is_empty() {
                    found = t(&format!(
                        "CREATE UNIQUE INDEX {}_pkey ON {} USING btree ({})",
                        tb.name,
                        tb.name,
                        tb.pk
                            .iter()
                            .map(|&c| tb.columns[c].name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
            found
        }
        "pg_get_constraintdef" => {
            let Some(oid) = oid_arg(args.first()) else {
                return Ok(Some(Value::Null));
            };
            constraints(&list_tables(src)?)
                .into_iter()
                .find(|r| r[0] == Value::Int(oid))
                .map(|r| r[12].clone())
                .unwrap_or(Value::Null)
        }
        "pg_get_viewdef" => {
            let views = list_views(src)?;
            match args.first() {
                Some(Value::Text(name)) if name.parse::<i64>().is_err() => views
                    .iter()
                    .find(|v| v.name == *name)
                    .map_or(Value::Null, |v| t(&v.sql)),
                other => oid_arg(other)
                    .and_then(|oid| oid.checked_sub(1_000_000))
                    .and_then(|i| usize::try_from(i).ok())
                    .and_then(|i| views.get(i))
                    .map_or(Value::Null, |v| t(&v.sql)),
            }
        }
        // oid → nome (`conrelid::regclass`); nome/texto numérico → oid
        "to_regclass" | "regclass" if matches!(args.first(), Some(Value::Int(_))) => {
            let oid = oid_arg(args.first()).unwrap_or(0);
            let tables = list_tables(src)?;
            let found = tables.iter().find_map(|tb| {
                if table_oid(tb) == oid {
                    Some(tb.name.clone())
                } else if !tb.pk.is_empty() && table_oid(tb) + 500 == oid {
                    Some(format!("{}_pkey", tb.name))
                } else {
                    tb.indexes
                        .iter()
                        .enumerate()
                        .find(|(pos, _)| index_oid(tb, *pos) == oid)
                        .map(|(_, idx)| idx.name.clone())
                }
            });
            found.map_or_else(|| i(oid), |n| t(&n))
        }
        "to_regclass" | "regclass" => match args.first() {
            Some(Value::Text(name)) if name.parse::<i64>().is_ok() => {
                i(name.parse::<i64>().unwrap_or(0))
            }
            Some(Value::Text(name)) => {
                let name = name.trim_start_matches("public.").trim_matches('"');
                list_tables(src)?
                    .iter()
                    .find(|tb| tb.name == name)
                    .map_or(Value::Null, |tb| i(table_oid(tb)))
            }
            _ => Value::Null,
        },
        "pg_relation_size" | "pg_total_relation_size" | "pg_table_size" | "pg_indexes_size" => i(0),
        _ => return Ok(None),
    };
    Ok(Some(v))
}
