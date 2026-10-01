//! Catálogo PostgreSQL, parte 2: relações com conteúdo real além das básicas
//! de `pgcatalog` — funções/agregados (`pg_proc`, `pg_aggregate`), operadores,
//! conversões, gatilhos, estatísticas do `ANALYZE`, views materializadas,
//! papéis, dependências, sessão/TLS da conexão (`pg_stat_activity`,
//! `pg_stat_ssl`) e as visões `information_schema` correspondentes.
//! Relações de recursos que o Mini-DB não tem (publicações, partições,
//! tipos enum, tabelas estrangeiras...) continuam existindo, porém vazias.

use super::exec::{load_stats, Output, Table, TableKind, View};
use super::parser::{FkAction, TriggerEvent, TriggerTiming};
use super::pgcatalog::{b, i, index_oid, out, t, table_oid, NS_CATALOG, OWNER};
use super::value::Value;
use super::Source;
use crate::auth::Principal;
use crate::error::Result;

/// OIDs de objetos próprios desta parte (longe dos de tabelas/índices).
const PROC_BASE: i64 = 30_000;
const OP_BASE: i64 = 40_000;
const TRIGGER_BASE: i64 = 2_000_000;

/// Funções escalares: (nome, nº de argumentos, tipo de retorno, variádica).
/// O nome vem de `func.rs`; aridade e retorno são a assinatura documentada.
const TEXT: i64 = 25;
const INT8: i64 = 20;
const FLOAT8: i64 = 701;
const BOOL: i64 = 16;

const SCALARS: &[&str] = &[
    "abs",
    "acos",
    "array_get",
    "array_length",
    "array_of",
    "array_to_string",
    "array_upper",
    "ascii",
    "asin",
    "atan",
    "atan2",
    "byte_length",
    "cardinality",
    "cbrt",
    "ceil",
    "ceiling",
    "char",
    "char_length",
    "character_length",
    "chr",
    "coalesce",
    "concat",
    "concat_ws",
    "contains",
    "cos",
    "current_catalog",
    "current_database",
    "current_date",
    "current_role",
    "current_schema",
    "current_schemas",
    "current_setting",
    "current_time",
    "current_timestamp",
    "current_user",
    "date",
    "date_add",
    "date_diff",
    "date_sub",
    "dateadd",
    "datediff",
    "datesub",
    "datetime",
    "degrees",
    "ends_with",
    "endswith",
    "exp",
    "floor",
    "format",
    "format_type",
    "fts_highlight",
    "fts_tokens",
    "gen_random_uuid",
    "greatest",
    "hex",
    "if",
    "ifnull",
    "iif",
    "in_array",
    "initcap",
    "instr",
    "is_true",
    "json",
    "json_array",
    "json_array_length",
    "json_extract",
    "json_object",
    "json_pretty",
    "json_query",
    "json_type",
    "json_valid",
    "json_value",
    "julianday",
    "least",
    "left",
    "length",
    "ln",
    "localtime",
    "localtimestamp",
    "log",
    "log10",
    "log2",
    "lower",
    "lpad",
    "ltrim",
    "match",
    "mid",
    "mod",
    "now",
    "nullif",
    "nvl",
    "octet_length",
    "pg_backend_pid",
    "pg_current_xact_id",
    "pg_encoding_to_char",
    "pg_get_expr",
    "pg_get_userbyid",
    "pg_is_in_recovery",
    "pg_postmaster_start_time",
    "pg_size_pretty",
    "pg_typeof",
    "pi",
    "position",
    "pow",
    "power",
    "printf",
    "quote",
    "quote_ident",
    "quote_literal",
    "quote_nullable",
    "radians",
    "rand",
    "random",
    "regexp",
    "regexp_count",
    "regexp_extract",
    "regexp_like",
    "regexp_matches",
    "regexp_replace",
    "regexp_split_to_array",
    "regexp_substr",
    "repeat",
    "replace",
    "replicate",
    "reverse",
    "right",
    "round",
    "rpad",
    "rtrim",
    "session_user",
    "set_config",
    "sha256",
    "sign",
    "sin",
    "split_part",
    "sqrt",
    "ssl_cipher",
    "ssl_client_dn",
    "ssl_is_used",
    "ssl_version",
    "st_distance",
    "st_distance_sphere",
    "st_dwithin",
    "starts_with",
    "startswith",
    "strftime",
    "strpos",
    "substr",
    "substring",
    "tan",
    "time",
    "to_char",
    "to_number",
    "to_text",
    "tonumber",
    "tostring",
    "trim",
    "trunc",
    "truncate",
    "txid_current",
    "typeof",
    "unicode",
    "unixepoch",
    "upper",
    "user",
    "uuid",
    "uuid4",
    "vec_add",
    "vec_cosine",
    "vec_dims",
    "vec_distance",
    "vec_dot",
    "vec_l2",
    "vec_norm",
    "vec_normalize",
    "vec_sub",
    "version",
];

const AGGREGATES: &[&str] = &[
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "total",
    "string_agg",
    "group_concat",
    "bool_and",
    "bool_or",
    "every",
    "stddev",
    "stddev_pop",
    "stddev_samp",
    "var_pop",
    "var_samp",
    "variance",
];

const WINDOWS: &[&str] = &[
    "row_number",
    "rank",
    "dense_rank",
    "percent_rank",
    "cume_dist",
    "ntile",
    "lag",
    "lead",
    "first_value",
    "last_value",
    "nth_value",
];

fn arity(name: &str) -> i64 {
    match name {
        "current_catalog"
        | "current_database"
        | "current_date"
        | "current_role"
        | "current_schema"
        | "current_time"
        | "current_timestamp"
        | "current_user"
        | "gen_random_uuid"
        | "localtime"
        | "localtimestamp"
        | "now"
        | "pg_backend_pid"
        | "pg_current_xact_id"
        | "pg_is_in_recovery"
        | "pg_postmaster_start_time"
        | "pi"
        | "rand"
        | "random"
        | "session_user"
        | "ssl_cipher"
        | "ssl_client_dn"
        | "ssl_is_used"
        | "ssl_version"
        | "txid_current"
        | "user"
        | "uuid"
        | "uuid4"
        | "version" => 0,
        "atan2"
        | "contains"
        | "date_diff"
        | "datediff"
        | "ends_with"
        | "endswith"
        | "instr"
        | "left"
        | "log"
        | "mod"
        | "nullif"
        | "pow"
        | "power"
        | "regexp_like"
        | "regexp_count"
        | "regexp_split_to_array"
        | "repeat"
        | "right"
        | "split_part"
        | "starts_with"
        | "startswith"
        | "strpos"
        | "vec_add"
        | "vec_cosine"
        | "vec_distance"
        | "vec_dot"
        | "vec_l2"
        | "vec_sub"
        | "st_distance"
        | "st_distance_sphere"
        | "fts_highlight"
        | "set_config"
        | "position"
        | "in_array"
        | "array_get" => 2,
        "lpad" | "rpad" | "replace" | "regexp_replace" | "st_dwithin" | "date_add" | "date_sub"
        | "dateadd" | "datesub" | "substr" | "substring" | "set_config_3" => 3,
        _ => 1,
    }
}

fn returns(name: &str) -> i64 {
    match name {
        "abs" | "acos" | "asin" | "atan" | "atan2" | "cbrt" | "ceil" | "ceiling" | "cos"
        | "degrees" | "exp" | "floor" | "ln" | "log" | "log10" | "log2" | "pi" | "pow"
        | "power" | "radians" | "rand" | "random" | "round" | "sin" | "sqrt" | "tan" | "trunc"
        | "truncate" | "vec_cosine" | "vec_distance" | "vec_dot" | "vec_l2" | "vec_norm"
        | "st_distance" | "st_distance_sphere" | "julianday" => FLOAT8,
        "array_length" | "array_upper" | "ascii" | "byte_length" | "cardinality"
        | "char_length" | "character_length" | "instr" | "length" | "mod" | "octet_length"
        | "pg_backend_pid" | "pg_current_xact_id" | "position" | "regexp_count" | "sign"
        | "strpos" | "txid_current" | "unicode" | "unixepoch" | "vec_dims"
        | "json_array_length" => INT8,
        "contains" | "ends_with" | "endswith" | "in_array" | "is_true" | "json_valid"
        | "pg_is_in_recovery" | "regexp_like" | "ssl_is_used" | "st_dwithin" | "starts_with"
        | "startswith" | "match" => BOOL,
        "current_date" | "date" => 1082,
        "now"
        | "current_timestamp"
        | "localtimestamp"
        | "pg_postmaster_start_time"
        | "datetime" => 1184,
        _ => TEXT,
    }
}

fn variadic(name: &str) -> bool {
    matches!(
        name,
        "coalesce"
            | "concat"
            | "concat_ws"
            | "greatest"
            | "least"
            | "format"
            | "printf"
            | "json_array"
            | "json_object"
            | "array_of"
    )
}

/// (nome, tipo de entrada) de todas as funções, agregados e janelas com OID
/// estável = posição + `PROC_BASE`.
fn procs() -> Vec<(&'static str, char)> {
    let mut v: Vec<(&'static str, char)> = SCALARS.iter().map(|n| (*n, 'f')).collect();
    v.extend(AGGREGATES.iter().map(|n| (*n, 'a')));
    v.extend(WINDOWS.iter().map(|n| (*n, 'w')));
    v
}

fn proc_oid(name: &str) -> i64 {
    procs()
        .iter()
        .position(|(n, _)| *n == name)
        .map_or(0, |p| PROC_BASE + p as i64)
}

fn pg_proc() -> Output {
    let cols = [
        "oid",
        "proname",
        "pronamespace",
        "proowner",
        "prolang",
        "procost",
        "prorows",
        "provariadic",
        "prosupport",
        "prokind",
        "prosecdef",
        "proleakproof",
        "proisstrict",
        "proretset",
        "provolatile",
        "proparallel",
        "pronargs",
        "pronargdefaults",
        "prorettype",
        "proargtypes",
        "proallargtypes",
        "proargmodes",
        "proargnames",
        "prosrc",
        "probin",
        "proconfig",
        "proacl",
    ];
    let rows = procs()
        .into_iter()
        .enumerate()
        .map(|(pos, (name, kind))| {
            let (nargs, ret) = match kind {
                'f' => (arity(name), returns(name)),
                'a' if name == "count" => (1, INT8),
                'a' if matches!(name, "bool_and" | "bool_or" | "every") => (1, BOOL),
                'a' if matches!(name, "string_agg" | "group_concat") => (2, TEXT),
                'a' => (1, FLOAT8),
                _ => (
                    if matches!(name, "lag" | "lead" | "nth_value" | "ntile") {
                        2
                    } else {
                        0
                    },
                    if name == "percent_rank" || name == "cume_dist" {
                        FLOAT8
                    } else {
                        INT8
                    },
                ),
            };
            let arg_ty = if matches!(
                name,
                "abs"
                    | "sqrt"
                    | "round"
                    | "floor"
                    | "ceil"
                    | "ceiling"
                    | "exp"
                    | "ln"
                    | "sin"
                    | "cos"
                    | "tan"
                    | "sum"
                    | "avg"
                    | "min"
                    | "max"
                    | "total"
                    | "trunc"
                    | "pow"
                    | "power"
                    | "log"
                    | "mod"
                    | "sign"
            ) {
                FLOAT8
            } else {
                TEXT
            };
            let argtypes = (0..nargs)
                .map(|_| arg_ty.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            vec![
                i(PROC_BASE + pos as i64),
                t(name),
                i(NS_CATALOG),
                i(OWNER),
                i(12),
                Value::Real(1.0),
                Value::Real(0.0),
                i(if variadic(name) { 2276 } else { 0 }),
                i(0),
                t(&kind.to_string()),
                b(false),
                b(false),
                b(!matches!(
                    name,
                    "coalesce" | "ifnull" | "nvl" | "concat" | "concat_ws"
                )),
                b(false),
                t(
                    if matches!(
                        name,
                        "now" | "random" | "rand" | "gen_random_uuid" | "uuid" | "uuid4"
                    ) {
                        "v"
                    } else {
                        "i"
                    },
                ),
                t("s"),
                i(nargs),
                i(0),
                i(ret),
                t(&argtypes),
                Value::Null,
                Value::Null,
                Value::Null,
                t(name),
                Value::Null,
                Value::Null,
                Value::Null,
            ]
        })
        .collect();
    out(&cols, rows)
}

fn pg_aggregate() -> Output {
    let rows = AGGREGATES
        .iter()
        .map(|n| {
            vec![
                i(proc_oid(n)),
                t("n"),
                i(0),
                i(proc_oid(n)),
                i(0),
                i(0),
                t(n),
            ]
        })
        .collect();
    out(
        &[
            "aggfnoid",
            "aggkind",
            "aggnumdirectargs",
            "aggtransfn",
            "aggfinalfn",
            "aggsortop",
            "aggname",
        ],
        rows,
    )
}

fn pg_operator() -> Output {
    // nome, tipo esquerdo, direito, resultado
    let ops: &[(&str, i64, i64, i64)] = &[
        ("+", INT8, INT8, INT8),
        ("-", INT8, INT8, INT8),
        ("*", INT8, INT8, INT8),
        ("/", INT8, INT8, INT8),
        ("%", INT8, INT8, INT8),
        ("+", FLOAT8, FLOAT8, FLOAT8),
        ("-", FLOAT8, FLOAT8, FLOAT8),
        ("*", FLOAT8, FLOAT8, FLOAT8),
        ("/", FLOAT8, FLOAT8, FLOAT8),
        ("=", INT8, INT8, BOOL),
        ("<>", INT8, INT8, BOOL),
        ("<", INT8, INT8, BOOL),
        (">", INT8, INT8, BOOL),
        ("<=", INT8, INT8, BOOL),
        (">=", INT8, INT8, BOOL),
        ("=", TEXT, TEXT, BOOL),
        ("<>", TEXT, TEXT, BOOL),
        ("<", TEXT, TEXT, BOOL),
        (">", TEXT, TEXT, BOOL),
        ("<=", TEXT, TEXT, BOOL),
        (">=", TEXT, TEXT, BOOL),
        ("=", FLOAT8, FLOAT8, BOOL),
        ("<", FLOAT8, FLOAT8, BOOL),
        (">", FLOAT8, FLOAT8, BOOL),
        ("||", TEXT, TEXT, TEXT),
        ("~~", TEXT, TEXT, BOOL),
        ("!~~", TEXT, TEXT, BOOL),
        ("~~*", TEXT, TEXT, BOOL),
        ("!~~*", TEXT, TEXT, BOOL),
        ("~", TEXT, TEXT, BOOL),
        ("~*", TEXT, TEXT, BOOL),
        ("!~", TEXT, TEXT, BOOL),
        ("!~*", TEXT, TEXT, BOOL),
        ("<->", TEXT, TEXT, FLOAT8),
        ("<=>", TEXT, TEXT, FLOAT8),
        ("<#>", TEXT, TEXT, FLOAT8),
        ("@@", TEXT, TEXT, BOOL),
        ("->", TEXT, TEXT, TEXT),
        ("->>", TEXT, TEXT, TEXT),
    ];
    let rows = ops
        .iter()
        .enumerate()
        .map(|(pos, (n, l, r, res))| {
            vec![
                i(OP_BASE + pos as i64),
                t(n),
                i(NS_CATALOG),
                i(OWNER),
                t("b"),
                b(matches!(*n, "=")),
                b(matches!(*n, "=")),
                i(*l),
                i(*r),
                i(*res),
                i(0),
            ]
        })
        .collect();
    out(
        &[
            "oid",
            "oprname",
            "oprnamespace",
            "oprowner",
            "oprkind",
            "oprcanmerge",
            "oprcanhash",
            "oprleft",
            "oprright",
            "oprresult",
            "oprcode",
        ],
        rows,
    )
}

fn pg_cast() -> Output {
    let pairs: &[(i64, i64, &str)] = &[
        (INT8, FLOAT8, "i"),
        (FLOAT8, INT8, "a"),
        (INT8, TEXT, "a"),
        (FLOAT8, TEXT, "a"),
        (BOOL, TEXT, "a"),
        (BOOL, INT8, "e"),
        (TEXT, INT8, "e"),
        (TEXT, FLOAT8, "e"),
        (TEXT, BOOL, "e"),
        (INT8, BOOL, "e"),
        (INT8, 23, "i"),
        (23, INT8, "i"),
        (INT8, 21, "a"),
        (21, INT8, "i"),
    ];
    let rows = pairs
        .iter()
        .enumerate()
        .map(|(pos, (s, tg, ctx))| {
            vec![i(50_000 + pos as i64), i(*s), i(*tg), i(0), t(ctx), t("b")]
        })
        .collect();
    out(
        &[
            "oid",
            "castsource",
            "casttarget",
            "castfunc",
            "castcontext",
            "castmethod",
        ],
        rows,
    )
}

fn pg_opclass() -> Output {
    // Um conjunto de classes de operadores por método de acesso do Mini-DB.
    let classes: &[(i64, &str, i64)] = &[
        (403, "int8_ops", INT8),
        (403, "float8_ops", FLOAT8),
        (403, "text_ops", TEXT),
        (403, "bool_ops", BOOL),
        (3580, "vector_l2_ops", TEXT),
        (3580, "vector_cosine_ops", TEXT),
        (3580, "vector_ip_ops", TEXT),
        (2742, "text_fts_ops", TEXT),
        (783, "spatial_z_ops", FLOAT8),
    ];
    let rows = classes
        .iter()
        .enumerate()
        .map(|(pos, (am, n, ty))| {
            vec![
                i(60_000 + pos as i64),
                i(*am),
                t(n),
                i(NS_CATALOG),
                i(*ty),
                b(true),
            ]
        })
        .collect();
    out(
        &[
            "oid",
            "opcmethod",
            "opcname",
            "opcnamespace",
            "opcintype",
            "opcdefault",
        ],
        rows,
    )
}

fn pg_language() -> Output {
    let row = |oid: i64, name: &str, trusted: bool| {
        vec![
            i(oid),
            t(name),
            i(OWNER),
            b(false),
            b(trusted),
            i(0),
            i(0),
            i(0),
            Value::Null,
        ]
    };
    out(
        &[
            "oid",
            "lanname",
            "lanowner",
            "lanispl",
            "lanpltrusted",
            "lanplcallfoid",
            "laninline",
            "lanvalidator",
            "lanacl",
        ],
        vec![
            row(12, "internal", false),
            row(13, "c", false),
            row(14, "sql", true),
        ],
    )
}

/// Recursos embutidos que o Mini-DB expõe como "extensões".
const EXTENSIONS: &[(&str, &str)] = &[
    (
        "minidb_fulltext",
        "busca de texto completo (BM25, radicais PT/EN)",
    ),
    (
        "minidb_vector",
        "índice vetorial HNSW (cosine, L2, produto interno)",
    ),
    ("minidb_spatial", "índice espacial por curva Z (2D/3D)"),
];

fn pg_extension() -> Output {
    out(
        &[
            "oid",
            "extname",
            "extowner",
            "extnamespace",
            "extrelocatable",
            "extversion",
        ],
        EXTENSIONS
            .iter()
            .enumerate()
            .map(|(pos, (n, _))| {
                vec![
                    i(70_000 + pos as i64),
                    t(n),
                    i(OWNER),
                    i(NS_CATALOG),
                    b(false),
                    t("1.2"),
                ]
            })
            .collect(),
    )
}

fn pg_available_extensions() -> Output {
    out(
        &["name", "default_version", "installed_version", "comment"],
        EXTENSIONS
            .iter()
            .map(|(n, c)| vec![t(n), t("1.2"), t("1.2"), t(c)])
            .collect(),
    )
}

fn pg_collation() -> Output {
    out(
        &[
            "oid",
            "collname",
            "collnamespace",
            "collowner",
            "collprovider",
            "collencoding",
            "collcollate",
            "collctype",
        ],
        vec![
            vec![
                i(100),
                t("default"),
                i(NS_CATALOG),
                i(OWNER),
                t("d"),
                i(-1),
                Value::Null,
                Value::Null,
            ],
            vec![
                i(950),
                t("C"),
                i(NS_CATALOG),
                i(OWNER),
                t("c"),
                i(-1),
                t("C"),
                t("C"),
            ],
            vec![
                i(951),
                t("POSIX"),
                i(NS_CATALOG),
                i(OWNER),
                t("c"),
                i(-1),
                t("POSIX"),
                t("POSIX"),
            ],
        ],
    )
}

fn text_search(name: &str) -> Output {
    let langs = ["simple", "portuguese", "english"];
    match name {
        "pg_ts_config" => out(
            &["oid", "cfgname", "cfgnamespace", "cfgowner", "cfgparser"],
            langs
                .iter()
                .enumerate()
                .map(|(p, n)| vec![i(80_000 + p as i64), t(n), i(NS_CATALOG), i(OWNER), i(3722)])
                .collect(),
        ),
        "pg_ts_dict" => out(
            &[
                "oid",
                "dictname",
                "dictnamespace",
                "dictowner",
                "dicttemplate",
            ],
            langs
                .iter()
                .enumerate()
                .map(|(p, n)| {
                    let dn = if *n == "simple" {
                        "simple".to_string()
                    } else {
                        format!("{n}_stem")
                    };
                    vec![
                        i(80_100 + p as i64),
                        t(&dn),
                        i(NS_CATALOG),
                        i(OWNER),
                        i(3727),
                    ]
                })
                .collect(),
        ),
        "pg_ts_parser" => out(
            &["oid", "prsname", "prsnamespace"],
            vec![vec![i(3722), t("default"), i(NS_CATALOG)]],
        ),
        _ => out(
            &["oid", "tmplname", "tmplnamespace"],
            vec![
                vec![i(3727), t("snowball"), i(NS_CATALOG)],
                vec![i(3728), t("simple"), i(NS_CATALOG)],
            ],
        ),
    }
}

fn timezones() -> Output {
    out(
        &["name", "abbrev", "utc_offset", "is_dst"],
        ["UTC", "Etc/UTC", "GMT", "Etc/GMT", "Zulu"]
            .iter()
            .map(|n| vec![t(n), t("UTC"), t("00:00:00"), b(false)])
            .collect(),
    )
}

fn trigger_oid(tb: &Table, pos: usize) -> i64 {
    TRIGGER_BASE + tb.id as i64 * 1024 + pos as i64
}

fn pg_trigger(tables: &[Table]) -> Output {
    let mut rows = Vec::new();
    for tb in tables {
        for (pos, tr) in tb.triggers.iter().enumerate() {
            // bits do PostgreSQL: 1 = por linha, 2 = BEFORE, 4 = INSERT, 8 = DELETE, 16 = UPDATE
            let mut ty = 1;
            if tr.timing == TriggerTiming::Before {
                ty |= 2;
            }
            ty |= match tr.event {
                TriggerEvent::Insert => 4,
                TriggerEvent::Delete => 8,
                TriggerEvent::Update(_) => 16,
            };
            rows.push(vec![
                i(trigger_oid(tb, pos)),
                t(&tr.name),
                i(table_oid(tb)),
                t("O"),
                b(false),
                i(0),
                i(0),
                i(ty),
                i(0),
                t(&tr
                    .body
                    .iter()
                    .map(|(s, _)| s.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")),
            ]);
        }
    }
    out(
        &[
            "oid",
            "tgname",
            "tgrelid",
            "tgenabled",
            "tgisinternal",
            "tgconstraint",
            "tgfoid",
            "tgtype",
            "tgparentid",
            "tgdef",
        ],
        rows,
    )
}

fn is_triggers(tables: &[Table]) -> Output {
    let mut rows = Vec::new();
    for tb in tables {
        for tr in &tb.triggers {
            let event = match tr.event {
                TriggerEvent::Insert => "INSERT",
                TriggerEvent::Delete => "DELETE",
                TriggerEvent::Update(_) => "UPDATE",
            };
            rows.push(vec![
                t("minidb"),
                t("public"),
                t(&tr.name),
                t(event),
                t("minidb"),
                t("public"),
                t(&tb.name),
                t(&tr
                    .body
                    .iter()
                    .map(|(s, _)| s.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")),
                t("ROW"),
                t(if tr.timing == TriggerTiming::Before {
                    "BEFORE"
                } else {
                    "AFTER"
                }),
            ]);
        }
    }
    out(
        &[
            "trigger_catalog",
            "trigger_schema",
            "trigger_name",
            "event_manipulation",
            "event_object_catalog",
            "event_object_schema",
            "event_object_table",
            "action_statement",
            "action_orientation",
            "action_timing",
        ],
        rows,
    )
}

fn rule(a: &FkAction) -> &'static str {
    match a {
        FkAction::NoAction => "NO ACTION",
        FkAction::Restrict => "RESTRICT",
        FkAction::Cascade => "CASCADE",
        FkAction::SetNull => "SET NULL",
        FkAction::SetDefault => "SET DEFAULT",
    }
}

fn referential(tables: &[Table]) -> Output {
    let mut rows = Vec::new();
    for tb in tables {
        for fk in &tb.fks {
            rows.push(vec![
                t("minidb"),
                t("public"),
                t(&fk.name),
                t("minidb"),
                t("public"),
                t(&format!("{}_pkey", fk.parent)),
                t("NONE"),
                t(rule(&fk.on_update)),
                t(rule(&fk.on_delete)),
            ]);
        }
    }
    out(
        &[
            "constraint_catalog",
            "constraint_schema",
            "constraint_name",
            "unique_constraint_catalog",
            "unique_constraint_schema",
            "unique_constraint_name",
            "match_option",
            "update_rule",
            "delete_rule",
        ],
        rows,
    )
}

fn check_constraints(tables: &[Table]) -> Output {
    let mut rows = Vec::new();
    for tb in tables {
        for (pos, ck) in tb.checks.iter().enumerate() {
            rows.push(vec![
                t("minidb"),
                t("public"),
                t(ck.name
                    .as_deref()
                    .unwrap_or(&format!("{}_check{}", tb.name, pos + 1))),
                t(&ck.sql),
            ]);
        }
        for (pos, c) in tb.columns.iter().enumerate() {
            if c.not_null && !tb.pk.contains(&pos) {
                rows.push(vec![
                    t("minidb"),
                    t("public"),
                    t(&format!("{}_{}_not_null", tb.name, c.name)),
                    t(&format!("{} IS NOT NULL", c.name)),
                ]);
            }
        }
    }
    out(
        &[
            "constraint_catalog",
            "constraint_schema",
            "constraint_name",
            "check_clause",
        ],
        rows,
    )
}

fn routines() -> Output {
    let rows = procs()
        .into_iter()
        .filter(|(_, k)| *k == 'f')
        .map(|(n, _)| {
            let ret = match returns(n) {
                INT8 => "bigint",
                FLOAT8 => "double precision",
                BOOL => "boolean",
                1082 => "date",
                1184 => "timestamp with time zone",
                _ => "text",
            };
            vec![
                t("minidb"),
                t("pg_catalog"),
                t(&format!("{n}_{}", proc_oid(n))),
                t("minidb"),
                t("pg_catalog"),
                t(n),
                t("FUNCTION"),
                t(ret),
                t("INTERNAL"),
            ]
        })
        .collect();
    out(
        &[
            "specific_catalog",
            "specific_schema",
            "specific_name",
            "routine_catalog",
            "routine_schema",
            "routine_name",
            "routine_type",
            "data_type",
            "external_language",
        ],
        rows,
    )
}

fn matviews(tables: &[Table]) -> Output {
    out(
        &[
            "schemaname",
            "matviewname",
            "matviewowner",
            "tablespace",
            "hasindexes",
            "ispopulated",
            "definition",
        ],
        tables
            .iter()
            .filter_map(|tb| match &tb.kind {
                TableKind::Materialized { sql, .. } => Some(vec![
                    t("public"),
                    t(&tb.name),
                    t("minidb"),
                    Value::Null,
                    b(!tb.indexes.is_empty()),
                    b(true),
                    t(sql),
                ]),
                TableKind::Table => None,
            })
            .collect(),
    )
}

/// `pg_stat_*_tables`: contagens vindas do último `ANALYZE` (0/NULL sem ele).
fn stat_tables(src: &dyn Source, tables: &[Table]) -> Result<Output> {
    let mut rows = Vec::new();
    for tb in tables.iter().filter(|tb| tb.kind == TableKind::Table) {
        let stats = load_stats(src, &tb.name)?;
        rows.push(vec![
            i(table_oid(tb)),
            t("public"),
            t(&tb.name),
            i(0),
            i(0),
            i(0),
            i(0),
            i(0),
            i(0),
            i(0),
            i(stats.as_ref().map_or(0, |s| s.rows as i64)),
            i(0),
            stats.as_ref().map_or(Value::Null, |s| t(&s.analyzed_at)),
        ]);
    }
    Ok(out(
        &[
            "relid",
            "schemaname",
            "relname",
            "seq_scan",
            "seq_tup_read",
            "idx_scan",
            "idx_tup_fetch",
            "n_tup_ins",
            "n_tup_upd",
            "n_tup_del",
            "n_live_tup",
            "n_dead_tup",
            "last_analyze",
        ],
        rows,
    ))
}

fn stat_indexes(tables: &[Table]) -> Output {
    let mut rows = Vec::new();
    for tb in tables {
        for (pos, idx) in tb.indexes.iter().enumerate() {
            rows.push(vec![
                i(table_oid(tb)),
                i(index_oid(tb, pos)),
                t("public"),
                t(&tb.name),
                t(&idx.name),
                i(0),
                i(0),
                i(0),
            ]);
        }
    }
    out(
        &[
            "relid",
            "indexrelid",
            "schemaname",
            "relname",
            "indexrelname",
            "idx_scan",
            "idx_tup_read",
            "idx_tup_fetch",
        ],
        rows,
    )
}

/// `pg_stats` / `pg_statistic` a partir do `ANALYZE` (`ColStats`).
fn pg_stats(src: &dyn Source, tables: &[Table], raw: bool) -> Result<Output> {
    let mut rows = Vec::new();
    for tb in tables.iter().filter(|tb| tb.kind == TableKind::Table) {
        let Some(stats) = load_stats(src, &tb.name)? else {
            continue;
        };
        for (pos, cs) in stats.columns.iter().enumerate() {
            let Some(col) = tb.columns.get(pos) else {
                continue;
            };
            let frac = if stats.rows == 0 {
                0.0
            } else {
                cs.nulls as f64 / stats.rows as f64
            };
            let bounds = match (&cs.min, &cs.max) {
                (Some(lo), Some(hi)) => t(&format!("{{{lo},{hi}}}")),
                _ => Value::Null,
            };
            if raw {
                rows.push(vec![
                    i(table_oid(tb)),
                    i(pos as i64 + 1),
                    Value::Real(frac),
                    i(cs.distinct as i64),
                ]);
            } else {
                rows.push(vec![
                    t("public"),
                    t(&tb.name),
                    t(&col.name),
                    b(false),
                    Value::Real(frac),
                    Value::Real(cs.distinct as f64),
                    Value::Null,
                    bounds,
                ]);
            }
        }
    }
    Ok(if raw {
        out(
            &["starelid", "staattnum", "stanullfrac", "stadistinct"],
            rows,
        )
    } else {
        out(
            &[
                "schemaname",
                "tablename",
                "attname",
                "inherited",
                "null_frac",
                "n_distinct",
                "most_common_vals",
                "histogram_bounds",
            ],
            rows,
        )
    })
}

/// Papéis (`pg_auth_members`): quem pertence a qual papel.
fn auth_members(users: &[Principal]) -> Output {
    let oid = |name: &str| {
        users
            .iter()
            .position(|u| u.name == name)
            .map_or(0, |p| 10_000 + p as i64)
    };
    let mut rows = Vec::new();
    for u in users {
        for role in &u.roles {
            rows.push(vec![i(oid(role)), i(oid(&u.name)), i(OWNER), b(false)]);
        }
    }
    out(&["roleid", "member", "grantor", "admin_option"], rows)
}

/// Dependências: índices e restrições dependem da tabela (`deptype = 'a'`).
fn pg_depend(tables: &[Table]) -> Output {
    let mut rows = Vec::new();
    for tb in tables {
        let oid = table_oid(tb);
        for (pos, _) in tb.indexes.iter().enumerate() {
            rows.push(vec![
                i(1259),
                i(index_oid(tb, pos)),
                i(0),
                i(1259),
                i(oid),
                i(0),
                t("a"),
            ]);
        }
        for pos in 0..tb.fks.len() {
            rows.push(vec![
                i(2606),
                i(oid + 700 + pos as i64),
                i(0),
                i(1259),
                i(oid),
                i(0),
                t("a"),
            ]);
        }
        for pos in 0..tb.checks.len() {
            rows.push(vec![
                i(2606),
                i(oid + 800 + pos as i64),
                i(0),
                i(1259),
                i(oid),
                i(0),
                t("a"),
            ]);
        }
        for pos in 0..tb.triggers.len() {
            rows.push(vec![
                i(2620),
                i(trigger_oid(tb, pos)),
                i(0),
                i(1259),
                i(oid),
                i(0),
                t("a"),
            ]);
        }
    }
    out(
        &[
            "classid",
            "objid",
            "objsubid",
            "refclassid",
            "refobjid",
            "refobjsubid",
            "deptype",
        ],
        rows,
    )
}

/// Sessão e TLS da conexão que executa a consulta.
fn pg_stat_activity(users: &[Principal]) -> Output {
    let info = super::func::conn_info();
    let user = super::func::current_user_name();
    let _ = users;
    out(
        &[
            "datid",
            "datname",
            "pid",
            "usesysid",
            "usename",
            "application_name",
            "client_addr",
            "backend_start",
            "state",
            "query",
            "backend_type",
        ],
        vec![vec![
            i(1),
            t("minidb"),
            i(info.pid),
            i(OWNER),
            t(&user),
            t(""),
            info.client_addr.as_deref().map_or(Value::Null, t),
            Value::Null,
            t("active"),
            Value::Null,
            t("client backend"),
        ]],
    )
}

fn pg_stat_ssl() -> Output {
    let info = super::func::conn_info();
    out(
        &[
            "pid",
            "ssl",
            "version",
            "cipher",
            "bits",
            "client_dn",
            "client_serial",
            "issuer_dn",
        ],
        vec![vec![
            i(info.pid),
            b(info.ssl),
            if info.ssl { t("TLSv1.3") } else { Value::Null },
            if info.ssl {
                t("TLS_CHACHA20_POLY1305_SHA256")
            } else {
                Value::Null
            },
            if info.ssl { i(256) } else { Value::Null },
            info.client_dn.as_deref().map_or(Value::Null, t),
            Value::Null,
            info.client_issuer.as_deref().map_or(Value::Null, t),
        ]],
    )
}

fn pg_stat_database() -> Output {
    out(
        &[
            "datid",
            "datname",
            "numbackends",
            "xact_commit",
            "xact_rollback",
            "stats_reset",
        ],
        vec![vec![
            i(1),
            t("minidb"),
            i(1),
            Value::Null,
            Value::Null,
            Value::Null,
        ]],
    )
}

/// Assinatura (argumentos, retorno) da função com o `oid` dado.
fn signature(oid: i64) -> Option<(String, String)> {
    let (name, kind) = *procs().get(usize::try_from(oid.checked_sub(PROC_BASE)?).ok()?)?;
    let (nargs, ret) = match kind {
        'f' => (arity(name), returns(name)),
        'a' if name == "count" => (1, INT8),
        'a' if matches!(name, "bool_and" | "bool_or" | "every") => (1, BOOL),
        'a' if matches!(name, "string_agg" | "group_concat") => (2, TEXT),
        'a' => (1, FLOAT8),
        _ => (
            if matches!(name, "lag" | "lead" | "nth_value" | "ntile") {
                2
            } else {
                0
            },
            if matches!(name, "percent_rank" | "cume_dist") {
                FLOAT8
            } else {
                INT8
            },
        ),
    };
    let arg_ty = if matches!(
        name,
        "abs"
            | "sqrt"
            | "round"
            | "floor"
            | "ceil"
            | "ceiling"
            | "exp"
            | "ln"
            | "sin"
            | "cos"
            | "tan"
            | "sum"
            | "avg"
            | "min"
            | "max"
            | "total"
            | "trunc"
            | "pow"
            | "power"
            | "log"
            | "mod"
            | "sign"
    ) {
        FLOAT8
    } else {
        TEXT
    };
    let ty = super::pgcatalog::type_name_by_oid(arg_ty);
    let args = if variadic(name) {
        "VARIADIC \"any\"".to_string()
    } else {
        (0..nargs).map(|_| ty).collect::<Vec<_>>().join(", ")
    };
    Some((args, super::pgcatalog::type_name_by_oid(ret).to_string()))
}

/// Funções `pg_get_*` desta parte: assinaturas e definição de gatilhos.
pub(super) fn function(src: &dyn Source, name: &str, args: &[Value]) -> Result<Option<Value>> {
    let oid = match args.first() {
        Some(Value::Int(n)) => Some(*n),
        Some(Value::Text(s)) => s.parse().ok(),
        _ => None,
    };
    Ok(match name {
        "pg_get_function_result" => {
            Some(oid.and_then(signature).map_or(Value::Null, |(_, r)| t(&r)))
        }
        "pg_get_function_arguments" | "pg_get_function_identity_arguments" => {
            Some(oid.and_then(signature).map_or(Value::Null, |(a, _)| t(&a)))
        }
        "pg_get_triggerdef" => {
            let tables = super::exec::list_tables(src)?;
            Some(
                tables
                    .iter()
                    .flat_map(|tb| {
                        tb.triggers
                            .iter()
                            .enumerate()
                            .map(move |(p, tr)| (tb, p, tr))
                    })
                    .find(|(tb, p, _)| Some(trigger_oid(tb, *p)) == oid)
                    .map_or(Value::Null, |(tb, _, tr)| {
                        t(&format!(
                            "CREATE TRIGGER {} {} {} ON {} FOR EACH ROW BEGIN {}; END",
                            tr.name,
                            if tr.timing == TriggerTiming::Before {
                                "BEFORE"
                            } else {
                                "AFTER"
                            },
                            tr.event.sql(),
                            tb.name,
                            tr.body
                                .iter()
                                .map(|(s, _)| s.as_str())
                                .collect::<Vec<_>>()
                                .join("; ")
                        ))
                    }),
            )
        }
        _ => None,
    })
}

pub(super) fn relation(
    src: &dyn Source,
    name: &str,
    tables: &[Table],
    _views: &[View],
    users: &[Principal],
) -> Result<Option<Output>> {
    Ok(Some(match name {
        "pg_proc" => pg_proc(),
        "pg_aggregate" => pg_aggregate(),
        "pg_operator" => pg_operator(),
        "pg_cast" => pg_cast(),
        "pg_opclass" => pg_opclass(),
        "pg_language" => pg_language(),
        "pg_extension" => pg_extension(),
        "pg_available_extensions" => pg_available_extensions(),
        "pg_collation" => pg_collation(),
        "pg_ts_config" | "pg_ts_dict" | "pg_ts_parser" | "pg_ts_template" => text_search(name),
        "pg_timezone_names" | "pg_timezone_abbrevs" => timezones(),
        "pg_trigger" => pg_trigger(tables),
        "triggers" => is_triggers(tables),
        "referential_constraints" => referential(tables),
        "check_constraints" => check_constraints(tables),
        "routines" => routines(),
        "pg_matviews" => matviews(tables),
        "pg_stat_user_tables" | "pg_stat_all_tables" | "pg_stat_sys_tables" => {
            if name == "pg_stat_sys_tables" {
                stat_tables(src, &[])?
            } else {
                stat_tables(src, tables)?
            }
        }
        "pg_stat_user_indexes" | "pg_stat_all_indexes" => stat_indexes(tables),
        "pg_stats" => pg_stats(src, tables, false)?,
        "pg_statistic" => pg_stats(src, tables, true)?,
        "pg_auth_members" => auth_members(users),
        "pg_depend" => pg_depend(tables),
        "pg_stat_activity" => pg_stat_activity(users),
        "pg_stat_ssl" => pg_stat_ssl(),
        "pg_stat_database" => pg_stat_database(),
        _ => return Ok(None),
    }))
}
