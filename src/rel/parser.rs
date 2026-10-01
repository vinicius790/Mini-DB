//! Lexer e parser recursivo do SQL relacional.
//!
//! Gramática (resumo): `[WITH [RECURSIVE] cte [(cols)] AS (consulta), ...]
//! consulta` onde consulta é `SELECT ... | VALUES ... [UNION|INTERSECT|EXCEPT
//! [ALL] ...]* [ORDER BY ... [NULLS FIRST|LAST]] [LIMIT] [OFFSET]`; `FROM`
//! aceita tabelas, views, subconsultas com alias (e colunas), vírgula e
//! `[INNER|LEFT|RIGHT|FULL] [OUTER] JOIN ... ON` / `CROSS JOIN`. Expressões
//! com `CASE`, `CAST`/`::`, funções de janela (`OVER`), subconsultas
//! escalares, `IN`/`ANY`/`ALL`/`EXISTS`, `IS [NOT] DISTINCT FROM`, `LIKE`/
//! `GLOB`, operadores bit a bit e parâmetros `?`, `?N`, `$N`. DML com
//! `INSERT [OR REPLACE|IGNORE] ... VALUES | SELECT | DEFAULT VALUES`,
//! `ON CONFLICT`, `UPDATE`, `DELETE`, todos com `RETURNING`. DDL com chaves
//! primárias e índices compostos, `CHECK`, `FOREIGN KEY ... ON DELETE/UPDATE`,
//! `DEFAULT <expressão>`, `AUTOINCREMENT`, `ALTER TABLE` completo, views e
//! `TRUNCATE`. Controle de transação: `BEGIN`/`COMMIT`/`ROLLBACK`/`SAVEPOINT`.

use super::value::{Type, Value};
use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    Real(f64),
    Sym(&'static str),
    /// `?` (sem número), `?N` ou `$N` (1-based).
    Param(Option<usize>),
}

/// Tokens e a posição `[início, fim)` de cada um no texto.
type Span = (usize, usize);

fn lex(src: &str) -> Result<(Vec<Tok>, Vec<Span>)> {
    const SYMS: [&str; 32] = [
        "!~*", "<->", "<=>", "<#>", "!~", "~*", "<>", "!=", "[", "]", "<=", ">=", "||", "<<", ">>",
        "::", "(", ")", ",", ".", "*", "+", "-", "/", "%", "=", "<", ">", ";", "&", "|", "~",
    ];
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut spans = Vec::new();
    let mut i = 0;
    let digits = |i: &mut usize| -> Option<usize> {
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        src[start..*i].parse().ok()
    };
    'outer: while i < b.len() {
        let c = b[i];
        let start = i;
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        } else if src[i..].starts_with("--") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        } else if src[i..].starts_with("/*") {
            let end = src[i + 2..]
                .find("*/")
                .ok_or_else(|| Error::Sql("comentário /* sem fechamento".into()))?;
            i += end + 4;
            continue;
        } else if c == b'?' || c == b'$' {
            i += 1;
            let n = digits(&mut i);
            if c == b'$' && n.is_none() {
                return Err(Error::Sql("parâmetro $ precisa de número ($1)".into()));
            }
            if n == Some(0) {
                return Err(Error::Sql("parâmetros começam em 1".into()));
            }
            out.push(Tok::Param(n));
        } else if c == b'\''
            || c == b'"'
            || c == b'`'
            || (c == b'['
                && !b.get(i.wrapping_sub(1)).is_some_and(|p| {
                    p.is_ascii_alphanumeric() || *p == b'_' || *p == b')' || *p == b']'
                })
                && b.get(i + 1) != Some(&b']'))
            || ((c == b'E' || c == b'e') && b.get(i + 1) == Some(&b'\''))
        {
            // E'...' (PostgreSQL): escapes com barra invertida.
            let escapes = c == b'E' || c == b'e';
            if escapes {
                i += 1;
            }
            let c = if escapes { b'\'' } else { c };
            let close = match c {
                b'[' => b']',
                q => q,
            };
            let mut s = Vec::new();
            i += 1;
            loop {
                match b.get(i) {
                    None => return Err(Error::Sql("texto sem aspas de fechamento".into())),
                    Some(b'\\') if escapes && i + 1 < b.len() => {
                        s.push(match b[i + 1] {
                            b'n' => b'\n',
                            b't' => b'\t',
                            b'r' => b'\r',
                            other => other,
                        });
                        i += 2;
                    }
                    Some(&q) if q == close && c != b'[' && b.get(i + 1) == Some(&c) => {
                        s.push(c);
                        i += 2;
                    }
                    Some(&q) if q == close => {
                        i += 1;
                        break;
                    }
                    Some(&x) => {
                        s.push(x);
                        i += 1;
                    }
                }
            }
            let s = String::from_utf8(s).map_err(|_| Error::Sql("UTF-8 inválido".into()))?;
            out.push(if c == b'\'' {
                Tok::Str(s)
            } else {
                // Identificador entre aspas mantém maiúsculas (como no PostgreSQL).
                Tok::Ident(s)
            });
        } else if c.is_ascii_digit() || (c == b'.' && b.get(i + 1).is_some_and(u8::is_ascii_digit))
        {
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
                i += 1;
                if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
                    i += 1;
                }
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            let t = &src[start..i];
            out.push(match t.parse::<i64>() {
                Ok(n) => Tok::Int(n),
                Err(_) => {
                    let x: f64 = t
                        .parse()
                        .map_err(|_| Error::Sql(format!("número inválido: {t}")))?;
                    if !x.is_finite() {
                        return Err(Error::Sql(format!("número fora do intervalo: {t}")));
                    }
                    Tok::Real(x)
                }
            });
        } else if c.is_ascii_alphabetic() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push(Tok::Ident(src[start..i].to_ascii_lowercase()));
        } else {
            for s in SYMS {
                if src[i..].starts_with(s) {
                    out.push(Tok::Sym(s));
                    i += s.len();
                    spans.push((start, i));
                    continue 'outer;
                }
            }
            let ch = src[i..].chars().next().unwrap_or('?');
            return Err(Error::Sql(format!("caractere inesperado {ch:?}")));
        }
        spans.push((start, i));
    }
    Ok((out, spans))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Concat,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BitAnd,
    BitOr,
    Shl,
    Shr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggFn {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    /// `TOTAL`: soma sempre REAL (0.0 sem linhas).
    Total,
    /// `GROUP_CONCAT(x [, sep])` / `STRING_AGG(x, sep)`.
    GroupConcat,
    BoolAnd,
    BoolOr,
    StdDevPop,
    StdDevSamp,
    VarPop,
    VarSamp,
}

impl AggFn {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "count" => Self::Count,
            "sum" => Self::Sum,
            "avg" => Self::Avg,
            "min" => Self::Min,
            "max" => Self::Max,
            "total" => Self::Total,
            "group_concat" | "string_agg" | "listagg" => Self::GroupConcat,
            "bool_and" | "every" => Self::BoolAnd,
            "bool_or" => Self::BoolOr,
            "stddev_pop" => Self::StdDevPop,
            "stddev" | "stddev_samp" => Self::StdDevSamp,
            "var_pop" => Self::VarPop,
            "variance" | "var_samp" => Self::VarSamp,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Sum => "sum",
            Self::Avg => "avg",
            Self::Min => "min",
            Self::Max => "max",
            Self::Total => "total",
            Self::GroupConcat => "group_concat",
            Self::BoolAnd => "bool_and",
            Self::BoolOr => "bool_or",
            Self::StdDevPop => "stddev_pop",
            Self::StdDevSamp => "stddev",
            Self::VarPop => "var_pop",
            Self::VarSamp => "variance",
        }
    }
}

/// Função de janela (`... OVER (...)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WinFn {
    RowNumber,
    Rank,
    DenseRank,
    PercentRank,
    CumeDist,
    Ntile,
    Lag,
    Lead,
    FirstValue,
    LastValue,
    NthValue,
    Agg(AggFn),
}

impl WinFn {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "row_number" => Self::RowNumber,
            "rank" => Self::Rank,
            "dense_rank" => Self::DenseRank,
            "percent_rank" => Self::PercentRank,
            "cume_dist" => Self::CumeDist,
            "ntile" => Self::Ntile,
            "lag" => Self::Lag,
            "lead" => Self::Lead,
            "first_value" => Self::FirstValue,
            "last_value" => Self::LastValue,
            "nth_value" => Self::NthValue,
            other => Self::Agg(AggFn::parse(other)?),
        })
    }

    pub fn name(self) -> String {
        match self {
            Self::Agg(a) => a.name().to_string(),
            other => format!("{other:?}").to_lowercase(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OrderItem {
    pub expr: Expr,
    pub desc: bool,
    /// `NULLS FIRST` (`Some(true)`) / `NULLS LAST`; `None` = padrão (NULL primeiro
    /// em ASC, último em DESC).
    pub nulls_first: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    UnboundedPreceding,
    Preceding(u64),
    CurrentRow,
    Following(u64),
    UnboundedFollowing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    /// `ROWS` (por posição) ou `RANGE` (por pares no ORDER BY).
    pub rows: bool,
    pub start: Bound,
    pub end: Bound,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WindowSpec {
    pub partition_by: Vec<Expr>,
    pub order_by: Vec<OrderItem>,
    pub frame: Option<Frame>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Lit(Value),
    /// Parâmetro posicional (0-based), substituído antes da execução.
    Param(usize),
    Col(Option<String>, String),
    Neg(Box<Expr>),
    Not(Box<Expr>),
    BitNot(Box<Expr>),
    Bin(Box<Expr>, BinOp, Box<Expr>),
    IsNull(Box<Expr>, bool),
    /// `a IS [NOT] DISTINCT FROM b` (NULL-safe).
    IsDistinct(Box<Expr>, Box<Expr>, bool),
    /// `x [NOT] LIKE p` (o último `bool` = `GLOB`: `*`/`?`, sensível a caixa).
    Like(Box<Expr>, Box<Expr>, bool, bool),
    In(Box<Expr>, Vec<Expr>, bool),
    InQuery(Box<Expr>, Box<Query>, bool),
    /// `x op ANY|ALL (SELECT ...)`; o `bool` é ALL.
    Quantified(Box<Expr>, BinOp, bool, Box<Query>),
    Exists(Box<Query>, bool),
    /// Subconsulta escalar: primeira coluna da primeira linha (ou NULL).
    Subquery(Box<Query>),
    Between(Box<Expr>, Box<Expr>, Box<Expr>, bool),
    Case {
        operand: Option<Box<Expr>>,
        whens: Vec<(Expr, Expr)>,
        otherwise: Option<Box<Expr>>,
    },
    Cast(Box<Expr>, Type),
    Func(String, Vec<Expr>),
    /// Agregado; argumentos vazios = `COUNT(*)`. O `bool` é DISTINCT.
    Agg(AggFn, Vec<Expr>, bool),
    /// Função de janela.
    Window(WinFn, Vec<Expr>, Box<WindowSpec>),
    /// `MATCH (colunas) AGAINST (consulta)`: pontuação BM25 pelo índice full-text
    /// (0 quando não casa).
    Match {
        columns: Vec<Expr>,
        query: Box<Expr>,
    },
}

/// Tipo de índice secundário.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexKind {
    BTree,
    FullText,
    Vector,
    Spatial,
}

impl IndexKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::BTree => "btree",
            Self::FullText => "fulltext",
            Self::Vector => "vector",
            Self::Spatial => "spatial",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "btree" => Self::BTree,
            "fulltext" => Self::FullText,
            "vector" => Self::Vector,
            "spatial" => Self::Spatial,
            _ => return None,
        })
    }
}

/// Ação referencial de uma chave estrangeira.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FkAction {
    #[default]
    NoAction,
    Restrict,
    Cascade,
    SetNull,
    SetDefault,
}

impl FkAction {
    pub fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "no action" => Self::NoAction,
            "restrict" => Self::Restrict,
            "cascade" => Self::Cascade,
            "set null" => Self::SetNull,
            "set default" => Self::SetDefault,
            _ => return None,
        })
    }

    pub fn sql(self) -> &'static str {
        match self {
            Self::NoAction => "NO ACTION",
            Self::Restrict => "RESTRICT",
            Self::Cascade => "CASCADE",
            Self::SetNull => "SET NULL",
            Self::SetDefault => "SET DEFAULT",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ForeignKey {
    pub name: Option<String>,
    pub columns: Vec<String>,
    pub parent: String,
    /// Vazio = chave primária da tabela pai.
    pub parent_columns: Vec<String>,
    pub on_delete: FkAction,
    pub on_update: FkAction,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Check {
    pub name: Option<String>,
    pub expr: Expr,
    /// Texto original (gravado no catálogo).
    pub sql: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColumnDef {
    pub name: String,
    pub ty: Type,
    pub primary: bool,
    pub not_null: bool,
    pub unique: bool,
    pub autoincrement: bool,
    /// `DEFAULT <expressão>`, avaliada a cada INSERT.
    pub default: Option<Expr>,
    /// Texto original do DEFAULT quando não é literal (para o catálogo).
    pub default_sql: Option<String>,
    /// Valor das linhas gravadas antes de `ADD COLUMN` (só no catálogo).
    pub fill: Option<Value>,
    /// `CHECK` de coluna (vira restrição de tabela).
    pub check: Option<Check>,
    /// `REFERENCES` de coluna (vira chave estrangeira de tabela).
    pub references: Option<ForeignKey>,
}

impl ColumnDef {
    pub fn new(name: String, ty: Type) -> Self {
        Self {
            name,
            ty,
            primary: false,
            not_null: false,
            unique: false,
            autoincrement: false,
            default: None,
            default_sql: None,
            fill: None,
            check: None,
            references: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SelectItem {
    Star(Option<String>),
    Expr(Expr, Option<String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinKind {
    Inner,
    Left,
    Right,
    Full,
    Cross,
}

/// Fonte de linhas no `FROM`: tabela, view ou CTE pelo nome, ou subconsulta.
#[derive(Clone, Debug, PartialEq)]
pub enum Source {
    Table(String),
    Query(Box<Query>),
    /// Função de tabela: `generate_series(a, b)`, `unnest(array)`.
    /// Terceiro campo: `WITH ORDINALITY` (acrescenta a coluna `ordinality`).
    Function(String, Vec<Expr>, bool),
}

#[derive(Clone, Debug, PartialEq)]
pub struct FromItem {
    pub source: Source,
    pub alias: String,
    /// Renomeia as colunas: `(SELECT ...) AS v (a, b)`.
    pub columns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Join {
    pub item: FromItem,
    pub on: Option<Expr>,
    pub kind: JoinKind,
    /// Colunas de `USING (...)`: as do lado direito ficam ocultas sem qualificador.
    pub using: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Select {
    pub distinct: bool,
    pub items: Vec<SelectItem>,
    /// `None` = `SELECT` sem `FROM` (uma linha, sem colunas).
    pub from: Option<FromItem>,
    pub joins: Vec<Join>,
    pub filter: Option<Expr>,
    pub group_by: Vec<Expr>,
    pub having: Option<Expr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetOp {
    Union,
    Intersect,
    Except,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SetExpr {
    Select(Box<Select>),
    /// `VALUES (...), (...)` como consulta (colunas `column1`, `column2`...).
    Values(Vec<Vec<Expr>>),
    SetOp {
        op: SetOp,
        all: bool,
        left: Box<SetExpr>,
        right: Box<SetExpr>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cte {
    pub name: String,
    pub columns: Vec<String>,
    pub query: Query,
    /// `WITH RECURSIVE` e o corpo é `base UNION [ALL] passo` referenciando o
    /// próprio nome.
    pub recursive: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Query {
    pub ctes: Vec<Cte>,
    pub body: SetExpr,
    pub order_by: Vec<OrderItem>,
    pub limit: Option<Expr>,
    pub offset: Option<Expr>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum InsertSource {
    Values(Vec<Vec<Expr>>),
    Query(Box<Query>),
    /// `DEFAULT VALUES`.
    Default,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OnConflict {
    Nothing,
    Update {
        sets: Vec<(String, Expr)>,
        filter: Option<Expr>,
    },
    /// `INSERT OR REPLACE` / `REPLACE INTO`: a linha nova substitui a antiga.
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerTiming {
    Before,
    After,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TriggerEvent {
    Insert,
    /// `UPDATE [OF colunas]` (vazio = qualquer coluna).
    Update(Vec<String>),
    Delete,
}

impl TriggerEvent {
    pub fn sql(&self) -> String {
        match self {
            Self::Insert => "INSERT".into(),
            Self::Delete => "DELETE".into(),
            Self::Update(cols) if cols.is_empty() => "UPDATE".into(),
            Self::Update(cols) => format!("UPDATE OF {}", cols.join(", ")),
        }
    }
}

/// Gatilho por linha: `NEW.c`/`OLD.c` são substituídos pelos valores da linha
/// antes de cada comando do corpo executar.
#[derive(Clone, Debug, PartialEq)]
pub struct TriggerDef {
    pub name: String,
    pub timing: TriggerTiming,
    pub event: TriggerEvent,
    pub table: String,
    pub when: Option<(Expr, String)>,
    /// Comandos do corpo (texto original e AST).
    pub body: Vec<(String, Stmt)>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ColumnChange {
    SetDefault(Expr, String),
    DropDefault,
    SetNotNull,
    DropNotNull,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    CreateTable {
        name: String,
        columns: Vec<ColumnDef>,
        /// Chave primária composta (`PRIMARY KEY (a, b)`).
        primary_key: Vec<String>,
        /// Restrições `UNIQUE (a, b)` de tabela.
        uniques: Vec<Vec<String>>,
        checks: Vec<Check>,
        foreign_keys: Vec<ForeignKey>,
        if_not_exists: bool,
    },
    DropTable {
        name: String,
        if_exists: bool,
    },
    CreateIndex {
        name: String,
        table: String,
        columns: Vec<String>,
        unique: bool,
        if_not_exists: bool,
        kind: IndexKind,
        /// `WITH (chave = valor, ...)`.
        options: Vec<(String, String)>,
    },
    /// Reconstrói um índice (útil para índices vetoriais após muitas remoções).
    Reindex(String),
    DropIndex {
        name: String,
        if_exists: bool,
    },
    AddColumn {
        table: String,
        column: ColumnDef,
    },
    DropColumn {
        table: String,
        column: String,
        if_exists: bool,
    },
    RenameColumn {
        table: String,
        from: String,
        to: String,
    },
    RenameTable {
        table: String,
        to: String,
    },
    AlterColumn {
        table: String,
        column: String,
        change: ColumnChange,
    },
    CreateView {
        name: String,
        columns: Vec<String>,
        query: Box<Query>,
        /// Texto da consulta (gravado no catálogo).
        sql: String,
        or_replace: bool,
        if_not_exists: bool,
        /// `CREATE MATERIALIZED VIEW`: linhas guardadas numa tabela.
        materialized: bool,
        /// `WITH AUTO REFRESH`: recalculada no mesmo lote de cada escrita nas bases.
        auto_refresh: bool,
    },
    DropView {
        name: String,
        if_exists: bool,
        materialized: bool,
    },
    RefreshView(String),
    CreateTrigger {
        trigger: Box<TriggerDef>,
        if_not_exists: bool,
    },
    DropTrigger {
        name: String,
        if_exists: bool,
    },
    /// `ANALYZE [tabela]`: estatísticas para o planejador.
    Analyze(Option<String>),
    Notify {
        channel: String,
        payload: Option<Expr>,
    },
    Listen(String),
    /// `None` = todos os canais.
    Unlisten(Option<String>),
    Truncate(String),
    Insert {
        table: String,
        columns: Option<Vec<String>>,
        source: InsertSource,
        on_conflict: Option<OnConflict>,
        returning: Vec<SelectItem>,
    },
    Query(Box<Query>),
    Update {
        table: String,
        sets: Vec<(String, Expr)>,
        filter: Option<Expr>,
        returning: Vec<SelectItem>,
    },
    Delete {
        table: String,
        filter: Option<Expr>,
        returning: Vec<SelectItem>,
    },
    /// `CREATE USER` (`login`) ou `CREATE ROLE` (`!login`).
    CreateUser {
        name: String,
        password: Option<String>,
        superuser: bool,
        login: bool,
        if_not_exists: bool,
    },
    AlterUser {
        name: String,
        password: Option<String>,
        superuser: Option<bool>,
    },
    DropUser {
        name: String,
        if_exists: bool,
    },
    /// `GRANT privs ON obj TO ...` (`object = Some`) ou `GRANT papéis TO ...`.
    Grant {
        privileges: Vec<String>,
        object: Option<String>,
        roles: Vec<String>,
        to: Vec<String>,
    },
    Revoke {
        privileges: Vec<String>,
        object: Option<String>,
        roles: Vec<String>,
        from: Vec<String>,
    },
    ShowUsers,
    ShowGrants(Option<String>),
    ShowTables,
    ShowIndexes(Option<String>),
    ShowTriggers(Option<String>),
    ShowCreate(String),
    Describe(String),
    /// `EXPLAIN [ANALYZE]`: o `bool` executa a consulta e mede.
    Explain(Box<Stmt>, bool),
    Begin {
        serializable: bool,
    },
    Commit,
    Rollback {
        to: Option<String>,
    },
    Savepoint(String),
    Release(String),
}

impl Stmt {
    /// `BEGIN`/`COMMIT`/`ROLLBACK`/`SAVEPOINT`/`RELEASE`.
    pub fn is_transaction_control(&self) -> bool {
        matches!(
            self,
            Self::Begin { .. }
                | Self::Commit
                | Self::Rollback { .. }
                | Self::Savepoint(_)
                | Self::Release(_)
        )
    }
}

struct Parser<'s> {
    src: &'s str,
    toks: Vec<Tok>,
    spans: Vec<Span>,
    pos: usize,
    /// Próximo número para `?` sem índice.
    next_param: usize,
    /// Maior índice de parâmetro usado (+1).
    params: usize,
    /// Profundidade atual de expressões aninhadas (limita a recursão).
    depth: usize,
}

/// Cada nível de parênteses consome ~3 unidades (`expr`, `not`, `unary`): o
/// limite equivale a ~100 níveis. Limita a recursão do parser, não a altura da
/// árvore de cadeias longas de operadores (`1 + 1 + ...`), montadas em laço.
const MAX_EXPR_DEPTH: usize = 300;

/// Comando analisado e quantos parâmetros ele espera.
pub fn parse(sql: &str) -> Result<(Stmt, usize)> {
    let mut p = Parser::new(sql)?;
    let stmt = p.statement()?;
    while p.eat_sym(";") {}
    if p.pos != p.toks.len() {
        return Err(Error::Sql(format!(
            "sobra após o comando: {:?} (vários comandos: use um script)",
            p.toks[p.pos]
        )));
    }
    Ok((stmt, p.params))
}

/// Uma expressão isolada (DEFAULT/CHECK gravados no catálogo).
pub fn parse_expr(sql: &str) -> Result<Expr> {
    let mut p = Parser::new(sql)?;
    let e = p.expr()?;
    if p.pos != p.toks.len() {
        return Err(Error::Sql(format!("sobra após a expressão: {sql}")));
    }
    Ok(e)
}

/// Divide um script nos seus comandos (respeita aspas, comentários e o corpo
/// `BEGIN ... END` de `CREATE TRIGGER`).
pub fn split_statements(sql: &str) -> Result<Vec<&str>> {
    let (toks, spans) = lex(sql)?;
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    let mut in_trigger = false;
    let mut body_depth = 0usize;
    let mut case_depth = 0usize;
    for (i, (t, (s, _))) in toks.iter().zip(&spans).enumerate() {
        if start.is_none() && *t != Tok::Sym(";") {
            start = Some(*s);
            in_trigger = matches!(t, Tok::Ident(w) if w == "create")
                && toks[i..]
                    .iter()
                    .take(4)
                    .any(|x| matches!(x, Tok::Ident(w) if w == "trigger"));
            body_depth = 0;
            case_depth = 0;
        }
        match t {
            Tok::Ident(w) if w == "case" => case_depth += 1,
            Tok::Ident(w) if w == "begin" && in_trigger => body_depth += 1,
            Tok::Ident(w) if w == "end" => {
                if case_depth > 0 {
                    case_depth -= 1;
                } else {
                    body_depth = body_depth.saturating_sub(1);
                }
            }
            Tok::Sym(";") if body_depth == 0 => {
                if let Some(from) = start.take() {
                    out.push(sql[from..*s].trim());
                }
            }
            _ => {}
        }
    }
    if let Some(from) = start {
        out.push(sql[from..].trim());
    }
    Ok(out)
}

const RESERVED: &[&str] = &[
    "select",
    "from",
    "where",
    "group",
    "order",
    "by",
    "having",
    "limit",
    "offset",
    "join",
    "left",
    "right",
    "full",
    "inner",
    "cross",
    "outer",
    "on",
    "and",
    "or",
    "not",
    "as",
    "set",
    "values",
    "asc",
    "desc",
    "is",
    "null",
    "like",
    "glob",
    "in",
    "between",
    "distinct",
    "union",
    "intersect",
    "except",
    "all",
    "case",
    "when",
    "then",
    "else",
    "end",
    "exists",
    "with",
    "conflict",
    "do",
    "over",
    "returning",
    "using",
    "window",
    "natural",
];

impl<'s> Parser<'s> {
    fn new(src: &'s str) -> Result<Self> {
        let (toks, spans) = lex(src)?;
        Ok(Parser {
            src,
            toks,
            spans,
            pos: 0,
            next_param: 0,
            params: 0,
            depth: 0,
        })
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            self.depth -= 1;
            return Err(Error::Sql("expressão aninhada demais".into()));
        }
        Ok(())
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(w)) if w == kw)
    }

    fn peek_kw_at(&self, offset: usize, kw: &str) -> bool {
        matches!(self.toks.get(self.pos + offset), Some(Tok::Ident(w)) if w == kw)
    }

    fn peek_sym(&self, s: &str) -> bool {
        matches!(self.peek(), Some(Tok::Sym(x)) if *x == s)
    }

    fn peek_sym_at(&self, offset: usize, s: &str) -> bool {
        matches!(self.toks.get(self.pos + offset), Some(Tok::Sym(x)) if *x == s)
    }

    fn eat_kw(&mut self, kw: &str) -> bool {
        let hit = self.peek_kw(kw);
        self.pos += hit as usize;
        hit
    }

    fn kw(&mut self, kw: &str) -> Result<()> {
        if self.eat_kw(kw) {
            Ok(())
        } else {
            Err(self.expected(&kw.to_uppercase()))
        }
    }

    fn eat_sym(&mut self, s: &str) -> bool {
        let hit = self.peek_sym(s);
        self.pos += hit as usize;
        hit
    }

    fn sym(&mut self, s: &str) -> Result<()> {
        if self.eat_sym(s) {
            Ok(())
        } else {
            Err(self.expected(s))
        }
    }

    fn expected(&self, what: &str) -> Error {
        match self.peek() {
            Some(t) => Error::Sql(format!("esperava {what}, encontrou {t:?}")),
            None => Error::Sql(format!("esperava {what}, fim do comando")),
        }
    }

    fn ident(&mut self) -> Result<String> {
        match self.peek() {
            Some(Tok::Ident(w)) => {
                let w = w.clone();
                self.pos += 1;
                Ok(w)
            }
            _ => Err(self.expected("identificador")),
        }
    }

    /// Literal de texto (`'...'`).
    fn string(&mut self) -> Result<String> {
        match self.peek() {
            Some(Tok::Str(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(s)
            }
            _ => Err(self.expected("texto entre aspas simples")),
        }
    }

    fn ident_list(&mut self) -> Result<Vec<String>> {
        self.sym("(")?;
        let mut out = vec![self.ident()?];
        while self.eat_sym(",") {
            out.push(self.ident()?);
        }
        self.sym(")")?;
        Ok(out)
    }

    fn opt_ident_list(&mut self) -> Result<Vec<String>> {
        if self.peek_sym("(") {
            self.ident_list()
        } else {
            Ok(Vec::new())
        }
    }

    fn if_exists(&mut self, not: bool) -> Result<bool> {
        if !self.eat_kw("if") {
            return Ok(false);
        }
        if not {
            self.kw("not")?;
        }
        self.kw("exists")?;
        Ok(true)
    }

    /// Texto original dos tokens `[from, self.pos)`.
    fn text_since(&self, from: usize) -> String {
        if from >= self.pos {
            return String::new();
        }
        self.src[self.spans[from].0..self.spans[self.pos - 1].1].to_string()
    }

    /// `(` seguido de SELECT/WITH/VALUES abre uma subconsulta.
    fn at_subquery(&self) -> bool {
        self.peek_sym("(")
            && (self.peek_kw_at(1, "select")
                || self.peek_kw_at(1, "with")
                || self.peek_kw_at(1, "values")
                || (self.toks.get(self.pos + 1) == Some(&Tok::Sym("("))
                    && self.at_subquery_from(1)))
    }

    fn at_subquery_from(&self, offset: usize) -> bool {
        let mut o = offset;
        while self.toks.get(self.pos + o) == Some(&Tok::Sym("(")) {
            o += 1;
        }
        self.peek_kw_at(o, "select") || self.peek_kw_at(o, "with") || self.peek_kw_at(o, "values")
    }

    fn statement(&mut self) -> Result<Stmt> {
        // `EXPLAIN EXPLAIN ...` e `CREATE TRIGGER` no corpo de um gatilho recorrem por aqui.
        self.enter()?;
        let r = self.statement_inner();
        self.depth -= 1;
        r
    }

    fn statement_inner(&mut self) -> Result<Stmt> {
        if self.peek_kw("select") || self.peek_kw("with") || self.peek_kw("values") {
            return Ok(Stmt::Query(Box::new(self.query()?)));
        }
        let word = self.ident()?;
        match word.as_str() {
            "explain" => {
                self.eat_kw("query");
                self.eat_kw("plan");
                let analyze = self.eat_kw("analyze");
                Ok(Stmt::Explain(Box::new(self.statement()?), analyze))
            }
            "analyze" | "analyse" => {
                self.eat_kw("table");
                Ok(Stmt::Analyze(match self.peek() {
                    Some(Tok::Ident(_)) => Some(self.ident()?),
                    _ => None,
                }))
            }
            "refresh" => {
                self.eat_kw("materialized");
                self.kw("view")?;
                Ok(Stmt::RefreshView(self.ident()?))
            }
            "reindex" => {
                self.eat_kw("index");
                Ok(Stmt::Reindex(self.ident()?))
            }
            "notify" => {
                let channel = self.ident()?;
                let payload = if self.eat_sym(",") {
                    Some(self.expr()?)
                } else {
                    None
                };
                Ok(Stmt::Notify { channel, payload })
            }
            "listen" => Ok(Stmt::Listen(self.ident()?)),
            "unlisten" => Ok(Stmt::Unlisten(if self.eat_sym("*") {
                None
            } else {
                Some(self.ident()?)
            })),
            "insert" => self.insert(false),
            "replace" => self.insert(true),
            "update" => self.update(),
            "delete" => {
                self.kw("from")?;
                let table = self.ident()?;
                let filter = self.where_clause()?;
                let returning = self.returning()?;
                Ok(Stmt::Delete {
                    table,
                    filter,
                    returning,
                })
            }
            "create" if self.peek_kw("user") || self.peek_kw("role") => {
                let login = self.ident()? == "user";
                let if_not_exists = self.if_exists(true)?;
                let name = self.ident()?;
                let mut password = None;
                let mut superuser = false;
                loop {
                    if self.eat_kw("with") {
                        continue;
                    }
                    if self.eat_kw("password") {
                        password = Some(self.string()?);
                    } else if self.eat_kw("superuser") {
                        superuser = true;
                    } else if self.eat_kw("nosuperuser") || self.eat_kw("login") {
                    } else {
                        break;
                    }
                }
                if login && password.is_none() {
                    return Err(Error::Sql("CREATE USER exige PASSWORD 'senha'".into()));
                }
                Ok(Stmt::CreateUser {
                    name,
                    password,
                    superuser,
                    login,
                    if_not_exists,
                })
            }
            "alter" if self.peek_kw("user") || self.peek_kw("role") => {
                self.ident()?;
                let name = self.ident()?;
                let mut password = None;
                let mut superuser = None;
                loop {
                    if self.eat_kw("with") {
                        continue;
                    }
                    if self.eat_kw("password") {
                        password = Some(self.string()?);
                    } else if self.eat_kw("superuser") {
                        superuser = Some(true);
                    } else if self.eat_kw("nosuperuser") {
                        superuser = Some(false);
                    } else {
                        break;
                    }
                }
                if password.is_none() && superuser.is_none() {
                    return Err(Error::Sql(
                        "ALTER USER: informe PASSWORD 'senha', SUPERUSER ou NOSUPERUSER".into(),
                    ));
                }
                Ok(Stmt::AlterUser {
                    name,
                    password,
                    superuser,
                })
            }
            "drop" if self.peek_kw("user") || self.peek_kw("role") => {
                self.ident()?;
                let if_exists = self.if_exists(false)?;
                Ok(Stmt::DropUser {
                    name: self.ident()?,
                    if_exists,
                })
            }
            "grant" | "revoke" => {
                let grant = word == "grant";
                let mut names = vec![self.ident()?];
                while self.eat_sym(",") {
                    names.push(self.ident()?);
                }
                let (privileges, object, roles) = if self.eat_kw("on") {
                    self.eat_kw("table");
                    let object = if self.eat_sym("*") {
                        "*".to_string()
                    } else {
                        self.ident()?
                    };
                    for n in &names {
                        if crate::auth::Privilege::parse(n).is_none() {
                            return Err(Error::Sql(format!(
                                "privilégio desconhecido {n} (SELECT, INSERT, UPDATE, DELETE, CREATE, ALL)"
                            )));
                        }
                    }
                    (names, Some(object), Vec::new())
                } else {
                    (Vec::new(), None, names)
                };
                self.eat_kw("privileges");
                self.kw(if grant { "to" } else { "from" })?;
                let mut who = vec![self.ident()?];
                while self.eat_sym(",") {
                    who.push(self.ident()?);
                }
                Ok(if grant {
                    Stmt::Grant {
                        privileges,
                        object,
                        roles,
                        to: who,
                    }
                } else {
                    Stmt::Revoke {
                        privileges,
                        object,
                        roles,
                        from: who,
                    }
                })
            }
            "create" => self.create(),
            "drop" => self.drop(),
            "alter" => self.alter(),
            "truncate" => {
                self.eat_kw("table");
                Ok(Stmt::Truncate(self.ident()?))
            }
            "show" => {
                if self.eat_kw("tables") {
                    Ok(Stmt::ShowTables)
                } else if self.eat_kw("users") || self.eat_kw("roles") {
                    Ok(Stmt::ShowUsers)
                } else if self.eat_kw("grants") {
                    Ok(Stmt::ShowGrants(if self.eat_kw("for") {
                        Some(self.ident()?)
                    } else {
                        None
                    }))
                } else if self.eat_kw("indexes") || self.eat_kw("index") || self.eat_kw("keys") {
                    if self.eat_kw("from") || self.eat_kw("on") || self.eat_kw("in") {
                        Ok(Stmt::ShowIndexes(Some(self.ident()?)))
                    } else {
                        Ok(Stmt::ShowIndexes(None))
                    }
                } else if self.eat_kw("triggers") {
                    if self.eat_kw("from") || self.eat_kw("on") || self.eat_kw("in") {
                        Ok(Stmt::ShowTriggers(Some(self.ident()?)))
                    } else {
                        Ok(Stmt::ShowTriggers(None))
                    }
                } else if self.eat_kw("create") {
                    self.eat_kw("table");
                    self.eat_kw("view");
                    Ok(Stmt::ShowCreate(self.ident()?))
                } else if self.eat_kw("columns") {
                    if !self.eat_kw("from") {
                        self.kw("in")?;
                    }
                    Ok(Stmt::Describe(self.ident()?))
                } else {
                    Err(self.expected("TABLES, INDEXES, COLUMNS, USERS, GRANTS ou CREATE TABLE"))
                }
            }
            "describe" | "desc" => Ok(Stmt::Describe(self.ident()?)),
            "begin" | "start" => {
                self.eat_kw("transaction");
                self.eat_kw("work");
                self.eat_kw("deferred");
                self.eat_kw("immediate");
                self.eat_kw("exclusive");
                let mut serializable = false;
                if self.eat_kw("isolation") {
                    self.kw("level")?;
                    serializable = if self.eat_kw("serializable") {
                        true
                    } else if self.eat_kw("snapshot") {
                        false
                    } else if self.eat_kw("repeatable") {
                        self.kw("read")?;
                        false
                    } else if self.eat_kw("read") {
                        if !self.eat_kw("committed") {
                            self.kw("uncommitted")?;
                        }
                        false
                    } else {
                        return Err(self.expected("SERIALIZABLE ou SNAPSHOT"));
                    };
                }
                Ok(Stmt::Begin { serializable })
            }
            "commit" | "end" => {
                self.eat_kw("transaction");
                self.eat_kw("work");
                Ok(Stmt::Commit)
            }
            "rollback" => {
                self.eat_kw("transaction");
                self.eat_kw("work");
                let to = if self.eat_kw("to") {
                    self.eat_kw("savepoint");
                    Some(self.ident()?)
                } else {
                    None
                };
                Ok(Stmt::Rollback { to })
            }
            "savepoint" => Ok(Stmt::Savepoint(self.ident()?)),
            "release" => {
                self.eat_kw("savepoint");
                Ok(Stmt::Release(self.ident()?))
            }
            other => Err(Error::Sql(format!("comando desconhecido: {other}"))),
        }
    }

    fn drop(&mut self) -> Result<Stmt> {
        let mut kind = self.ident()?;
        let materialized = kind == "materialized";
        if materialized {
            self.kw("view")?;
            kind = "view".into();
        }
        let if_exists = self.if_exists(false)?;
        let name = self.ident()?;
        self.eat_kw("cascade");
        self.eat_kw("restrict");
        Ok(match kind.as_str() {
            "table" => Stmt::DropTable { name, if_exists },
            "index" => Stmt::DropIndex { name, if_exists },
            "view" => Stmt::DropView {
                name,
                if_exists,
                materialized,
            },
            "trigger" => Stmt::DropTrigger { name, if_exists },
            other => return Err(Error::Sql(format!("DROP {other} não é suportado"))),
        })
    }

    fn alter(&mut self) -> Result<Stmt> {
        self.kw("table")?;
        self.if_exists(false)?;
        let table = self.ident()?;
        if self.eat_kw("add") {
            if self.eat_kw("constraint") || self.peek_kw("check") || self.peek_kw("foreign") {
                return Err(Error::Sql(
                    "ADD CONSTRAINT não é suportado: declare CHECK/FOREIGN KEY no CREATE TABLE"
                        .into(),
                ));
            }
            self.eat_kw("column");
            self.if_exists(true)?;
            return Ok(Stmt::AddColumn {
                table,
                column: self.column_def()?,
            });
        }
        if self.eat_kw("drop") {
            self.eat_kw("column");
            let if_exists = self.if_exists(false)?;
            let column = self.ident()?;
            self.eat_kw("cascade");
            self.eat_kw("restrict");
            return Ok(Stmt::DropColumn {
                table,
                column,
                if_exists,
            });
        }
        if self.eat_kw("rename") {
            if self.eat_kw("to") {
                return Ok(Stmt::RenameTable {
                    table,
                    to: self.ident()?,
                });
            }
            self.eat_kw("column");
            let from = self.ident()?;
            self.kw("to")?;
            return Ok(Stmt::RenameColumn {
                table,
                from,
                to: self.ident()?,
            });
        }
        if self.eat_kw("alter") || self.eat_kw("modify") {
            self.eat_kw("column");
            let column = self.ident()?;
            let change = if self.eat_kw("set") {
                if self.eat_kw("default") {
                    let from = self.pos;
                    let e = self.expr()?;
                    ColumnChange::SetDefault(e, self.text_since(from))
                } else {
                    self.kw("not")?;
                    self.kw("null")?;
                    ColumnChange::SetNotNull
                }
            } else {
                self.kw("drop")?;
                if self.eat_kw("default") {
                    ColumnChange::DropDefault
                } else {
                    self.kw("not")?;
                    self.kw("null")?;
                    ColumnChange::DropNotNull
                }
            };
            return Ok(Stmt::AlterColumn {
                table,
                column,
                change,
            });
        }
        Err(self.expected("ADD, DROP, RENAME ou ALTER COLUMN"))
    }

    fn create(&mut self) -> Result<Stmt> {
        let unique = self.eat_kw("unique");
        let kind = if self.eat_kw("fulltext") {
            IndexKind::FullText
        } else if self.eat_kw("vector") {
            IndexKind::Vector
        } else if self.eat_kw("spatial") {
            IndexKind::Spatial
        } else {
            IndexKind::BTree
        };
        if kind != IndexKind::BTree {
            if unique {
                return Err(Error::Sql(
                    "índice full-text/vetorial/espacial não pode ser UNIQUE".into(),
                ));
            }
            self.kw("index")?;
            return self.create_index(false, kind);
        }
        let or_replace = !unique && self.eat_kw("or") && {
            self.kw("replace")?;
            true
        };
        let materialized = !unique && self.eat_kw("materialized");
        if !unique && self.eat_kw("view") {
            let if_not_exists = self.if_exists(true)?;
            let name = self.ident()?;
            let columns = self.opt_ident_list()?;
            let mut auto_refresh = false;
            if self.eat_kw("with") {
                if self.eat_kw("auto") {
                    self.kw("refresh")?;
                    auto_refresh = true;
                } else {
                    self.kw("manual")?;
                    self.kw("refresh")?;
                }
            }
            self.kw("as")?;
            let from = self.pos;
            let query = self.query()?;
            let sql = self.text_since(from);
            if self.eat_kw("with") {
                // WITH [NO] DATA (PostgreSQL) é aceito; o conteúdo é sempre calculado.
                self.eat_kw("no");
                self.kw("data")?;
            }
            if auto_refresh && !materialized {
                return Err(Error::Sql("AUTO REFRESH só em MATERIALIZED VIEW".into()));
            }
            return Ok(Stmt::CreateView {
                name,
                columns,
                query: Box::new(query),
                sql,
                or_replace,
                if_not_exists,
                materialized,
                auto_refresh,
            });
        }
        if materialized {
            return Err(self.expected("VIEW"));
        }
        if !unique && self.peek_kw("trigger") {
            self.pos += 1;
            return self.create_trigger(or_replace);
        }
        if or_replace {
            return Err(self.expected("VIEW"));
        }
        if !unique && self.eat_kw("table") {
            return self.create_table();
        }
        self.kw("index")?;
        self.create_index(unique, IndexKind::BTree)
    }

    fn create_index(&mut self, unique: bool, kind: IndexKind) -> Result<Stmt> {
        let if_not_exists = self.if_exists(true)?;
        let name = self.ident()?;
        self.kw("on")?;
        let table = self.ident()?;
        if self.eat_kw("using") {
            let method = self.ident()?;
            if IndexKind::parse(&method).is_none_or(|k| k != kind)
                && method != "hnsw"
                && method != "zorder"
            {
                return Err(Error::Sql(format!(
                    "método de índice desconhecido {method}"
                )));
            }
        }
        let columns = self.ident_list()?;
        let mut options = Vec::new();
        if self.eat_kw("with") {
            self.sym("(")?;
            loop {
                let key = self.ident()?;
                self.sym("=")?;
                let value = match self.peek().cloned() {
                    Some(Tok::Ident(w)) => {
                        self.pos += 1;
                        w
                    }
                    Some(Tok::Str(s)) => {
                        self.pos += 1;
                        s
                    }
                    Some(Tok::Int(n)) => {
                        self.pos += 1;
                        n.to_string()
                    }
                    Some(Tok::Real(x)) => {
                        self.pos += 1;
                        x.to_string()
                    }
                    _ => return Err(self.expected("valor da opção")),
                };
                options.push((key, value));
                if !self.eat_sym(",") {
                    break;
                }
            }
            self.sym(")")?;
        }
        Ok(Stmt::CreateIndex {
            name,
            table,
            columns,
            unique,
            if_not_exists,
            kind,
            options,
        })
    }

    /// `CREATE TRIGGER nome BEFORE|AFTER INSERT|UPDATE [OF a, b]|DELETE ON t
    /// [FOR EACH ROW] [WHEN (cond)] BEGIN cmd; ... END`.
    fn create_trigger(&mut self, or_replace: bool) -> Result<Stmt> {
        let if_not_exists = self.if_exists(true)? || or_replace;
        let name = self.ident()?;
        let timing = if self.eat_kw("before") {
            TriggerTiming::Before
        } else if self.eat_kw("after") {
            TriggerTiming::After
        } else if self.eat_kw("instead") {
            return Err(Error::Sql("INSTEAD OF não é suportado".into()));
        } else {
            return Err(self.expected("BEFORE ou AFTER"));
        };
        let event = if self.eat_kw("insert") {
            TriggerEvent::Insert
        } else if self.eat_kw("delete") {
            TriggerEvent::Delete
        } else {
            self.kw("update")?;
            let cols = if self.eat_kw("of") {
                let mut cols = vec![self.ident()?];
                while self.eat_sym(",") {
                    cols.push(self.ident()?);
                }
                cols
            } else {
                Vec::new()
            };
            TriggerEvent::Update(cols)
        };
        if self.eat_kw("or") {
            return Err(Error::Sql(
                "um gatilho por evento: crie um gatilho para cada um".into(),
            ));
        }
        self.kw("on")?;
        let table = self.ident()?;
        if self.eat_kw("for") {
            self.kw("each")?;
            if self.eat_kw("statement") {
                return Err(Error::Sql("FOR EACH STATEMENT não é suportado".into()));
            }
            self.kw("row")?;
        }
        let when = if self.eat_kw("when") {
            let parens = self.eat_sym("(");
            let from = self.pos;
            let e = self.expr()?;
            let text = self.text_since(from);
            if parens {
                self.sym(")")?;
            }
            Some((e, text))
        } else {
            None
        };
        self.kw("begin")?;
        let mut body = Vec::new();
        loop {
            if self.eat_kw("end") {
                break;
            }
            if self.peek().is_none() {
                return Err(self.expected("END"));
            }
            let from = self.pos;
            let stmt = self.statement()?;
            let text = self.text_since(from);
            if let Stmt::Query(q) = &stmt {
                if !text.to_ascii_lowercase().contains("raise") {
                    return Err(Error::Sql(
                        "corpo de gatilho só aceita INSERT/UPDATE/DELETE/NOTIFY e SELECT RAISE(...)".into(),
                    ));
                }
                let _ = q;
            }
            body.push((text, stmt));
            if !self.eat_sym(";") && !self.peek_kw("end") {
                return Err(self.expected("; ou END"));
            }
        }
        if body.is_empty() {
            return Err(Error::Sql("gatilho sem comandos no corpo".into()));
        }
        Ok(Stmt::CreateTrigger {
            trigger: Box::new(TriggerDef {
                name,
                timing,
                event,
                table,
                when,
                body,
            }),
            if_not_exists,
        })
    }

    fn create_table(&mut self) -> Result<Stmt> {
        let if_not_exists = self.if_exists(true)?;
        let name = self.ident()?;
        self.sym("(")?;
        let mut columns = Vec::new();
        let mut primary_key = Vec::new();
        let mut uniques = Vec::new();
        let mut checks = Vec::new();
        let mut foreign_keys = Vec::new();
        loop {
            let cname = if self.eat_kw("constraint") {
                Some(self.ident()?)
            } else {
                None
            };
            if self.eat_kw("primary") {
                self.kw("key")?;
                if !primary_key.is_empty() {
                    return Err(Error::Sql("PRIMARY KEY repetida".into()));
                }
                primary_key = self.ident_list()?;
            } else if self.eat_kw("unique") {
                // UNIQUE (a, b) como restrição de tabela vira índice único.
                uniques.push(self.ident_list()?);
            } else if self.eat_kw("check") {
                checks.push(self.check(cname)?);
            } else if self.eat_kw("foreign") {
                self.kw("key")?;
                let cols = self.ident_list()?;
                foreign_keys.push(self.references(cname, cols)?);
            } else if cname.is_some() {
                return Err(self.expected("PRIMARY KEY, UNIQUE, CHECK ou FOREIGN KEY"));
            } else {
                columns.push(self.column_def()?);
            }
            if !self.eat_sym(",") {
                break;
            }
        }
        self.sym(")")?;
        // Opções de tabela (WITHOUT ROWID, ENGINE=...) são aceitas e ignoradas.
        while self.peek().is_some() && !self.peek_sym(";") {
            self.pos += 1;
        }
        let inline: Vec<String> = columns
            .iter()
            .filter(|c| c.primary)
            .map(|c| c.name.clone())
            .collect();
        if !inline.is_empty() {
            if !primary_key.is_empty() || inline.len() > 1 {
                return Err(Error::Sql(
                    "use uma única declaração de PRIMARY KEY (para chave composta: PRIMARY KEY (a, b))"
                        .into(),
                ));
            }
            primary_key = inline;
        }
        for c in &mut columns {
            if let Some(check) = c.check.take() {
                checks.push(check);
            }
            if let Some(mut fk) = c.references.take() {
                fk.columns = vec![c.name.clone()];
                foreign_keys.push(fk);
            }
        }
        Ok(Stmt::CreateTable {
            name,
            columns,
            primary_key,
            uniques,
            checks,
            foreign_keys,
            if_not_exists,
        })
    }

    fn check(&mut self, name: Option<String>) -> Result<Check> {
        self.sym("(")?;
        let from = self.pos;
        let expr = self.expr()?;
        let sql = self.text_since(from);
        self.sym(")")?;
        Ok(Check { name, expr, sql })
    }

    /// `REFERENCES pai [(cols)] [ON DELETE ação] [ON UPDATE ação]`.
    fn references(&mut self, name: Option<String>, columns: Vec<String>) -> Result<ForeignKey> {
        self.kw("references")?;
        let parent = self.ident()?;
        let parent_columns = self.opt_ident_list()?;
        let mut fk = ForeignKey {
            name,
            columns,
            parent,
            parent_columns,
            on_delete: FkAction::NoAction,
            on_update: FkAction::NoAction,
        };
        loop {
            if self.eat_kw("on") {
                let is_delete = if self.eat_kw("delete") {
                    true
                } else {
                    self.kw("update")?;
                    false
                };
                let first = self.ident()?;
                let word = match first.as_str() {
                    "no" | "set" => format!("{first} {}", self.ident()?),
                    _ => first,
                };
                let action = FkAction::parse(&word)
                    .ok_or_else(|| Error::Sql(format!("ação referencial desconhecida {word}")))?;
                if is_delete {
                    fk.on_delete = action;
                } else {
                    fk.on_update = action;
                }
            } else if self.eat_kw("deferrable") || self.eat_kw("initially") {
                self.pos += 1;
            } else if self.eat_kw("match") {
                self.ident()?;
            } else if self.eat_kw("not") && self.peek_kw("deferrable") {
                self.pos += 1;
            } else {
                return Ok(fk);
            }
        }
    }

    fn type_name(&mut self) -> Result<(Type, bool)> {
        let ty_word = self.ident()?;
        let mut autoinc = false;
        let ty = match ty_word.as_str() {
            "serial" | "bigserial" | "smallserial" => {
                autoinc = true;
                Type::Int
            }
            "double" => {
                self.eat_kw("precision");
                Type::Real
            }
            "character" | "national" => {
                self.eat_kw("varying");
                self.eat_kw("character");
                self.eat_kw("varying");
                Type::Text
            }
            "timestamp" | "time" => {
                if self.eat_kw("with") || self.eat_kw("without") {
                    self.kw("time")?;
                    self.kw("zone")?;
                }
                Type::Text
            }
            other => Type::parse(other)
                .ok_or_else(|| Error::Sql(format!("tipo desconhecido {ty_word}")))?,
        };
        if self.eat_sym("(") {
            // VARCHAR(n) / DECIMAL(p, s): tamanho aceito e ignorado.
            while !self.eat_sym(")") {
                if self.peek().is_none() {
                    return Err(self.expected(")"));
                }
                self.pos += 1;
            }
        }
        self.eat_kw("unsigned");
        Ok((ty, autoinc))
    }

    fn column_def(&mut self) -> Result<ColumnDef> {
        let name = self.ident()?;
        let (ty, autoinc) = self.type_name()?;
        let mut col = ColumnDef::new(name, ty);
        col.autoincrement = autoinc;
        loop {
            if self.eat_kw("constraint") {
                self.ident()?;
            }
            if self.eat_kw("primary") {
                self.kw("key")?;
                col.primary = true;
                self.eat_kw("asc");
                self.eat_kw("desc");
                if self.eat_kw("autoincrement") || self.eat_kw("auto_increment") {
                    col.autoincrement = true;
                }
            } else if self.eat_kw("autoincrement") || self.eat_kw("auto_increment") {
                col.autoincrement = true;
            } else if self.eat_kw("generated") {
                if self.eat_kw("always") || self.eat_kw("by") {
                    self.eat_kw("default");
                }
                self.kw("as")?;
                self.kw("identity")?;
                if self.eat_sym("(") {
                    while !self.eat_sym(")") {
                        if self.peek().is_none() {
                            return Err(self.expected(")"));
                        }
                        self.pos += 1;
                    }
                }
                col.autoincrement = true;
            } else if self.eat_kw("not") {
                self.kw("null")?;
                col.not_null = true;
            } else if self.eat_kw("unique") {
                col.unique = true;
            } else if self.eat_kw("default") {
                let (e, text) = if self.eat_sym("(") {
                    let from = self.pos;
                    let e = self.expr()?;
                    let text = self.text_since(from);
                    self.sym(")")?;
                    (e, text)
                } else {
                    let from = self.pos;
                    let e = self.unary()?;
                    (e, self.text_since(from))
                };
                col.default_sql = match &e {
                    Expr::Lit(_) => None,
                    Expr::Neg(inner) if matches!(**inner, Expr::Lit(_)) => None,
                    _ => Some(text),
                };
                col.default = Some(e);
            } else if self.eat_kw("check") {
                col.check = Some(self.check(None)?);
            } else if self.peek_kw("references") {
                col.references = Some(self.references(None, Vec::new())?);
            } else if self.eat_kw("collate") {
                self.ident()?;
            } else if self.eat_kw("null") {
            } else {
                return Ok(col);
            }
        }
    }

    fn returning(&mut self) -> Result<Vec<SelectItem>> {
        if !self.eat_kw("returning") {
            return Ok(Vec::new());
        }
        self.select_items()
    }

    fn insert(&mut self, replace: bool) -> Result<Stmt> {
        let mut on_conflict = if replace {
            Some(OnConflict::Replace)
        } else {
            None
        };
        if !replace && self.eat_kw("or") {
            if self.eat_kw("replace") {
                on_conflict = Some(OnConflict::Replace);
            } else if self.eat_kw("ignore") {
                on_conflict = Some(OnConflict::Nothing);
            } else {
                self.kw("abort")?;
            }
        }
        self.kw("into")?;
        let table = self.ident()?;
        self.eat_kw("as").then(|| self.ident()).transpose()?;
        let columns = if self.peek_sym("(") && !self.at_subquery() {
            Some(self.ident_list()?)
        } else {
            None
        };
        let source = if self.eat_kw("default") {
            self.kw("values")?;
            InsertSource::Default
        } else if self.eat_kw("values") {
            InsertSource::Values(self.value_rows()?)
        } else if self.peek_kw("select") || self.peek_kw("with") || self.at_subquery() {
            let wrapped = self.eat_sym("(");
            let q = self.query()?;
            if wrapped {
                self.sym(")")?;
            }
            InsertSource::Query(Box::new(q))
        } else {
            return Err(self.expected("VALUES, SELECT ou DEFAULT VALUES"));
        };
        if self.eat_kw("on") {
            self.kw("conflict")?;
            if self.peek_sym("(") {
                // Alvo opcional: o conflito é detectado por PK e índices únicos.
                self.ident_list()?;
            }
            self.kw("do")?;
            on_conflict = Some(if self.eat_kw("nothing") {
                OnConflict::Nothing
            } else {
                self.kw("update")?;
                self.kw("set")?;
                let sets = self.assignments()?;
                let filter = self.where_clause()?;
                OnConflict::Update { sets, filter }
            });
        }
        let returning = self.returning()?;
        Ok(Stmt::Insert {
            table,
            columns,
            source,
            on_conflict,
            returning,
        })
    }

    fn value_rows(&mut self) -> Result<Vec<Vec<Expr>>> {
        let mut rows = Vec::new();
        loop {
            self.sym("(")?;
            let mut row = Vec::new();
            if !self.peek_sym(")") {
                row.push(self.expr()?);
                while self.eat_sym(",") {
                    row.push(self.expr()?);
                }
            }
            self.sym(")")?;
            rows.push(row);
            if !self.eat_sym(",") {
                return Ok(rows);
            }
        }
    }

    fn assignments(&mut self) -> Result<Vec<(String, Expr)>> {
        let mut sets = Vec::new();
        loop {
            let col = self.ident()?;
            if self.eat_sym(".") {
                // `t.col = ...` aceita o prefixo da própria tabela.
                let real = self.ident()?;
                self.sym("=")?;
                sets.push((real, self.expr()?));
            } else {
                self.sym("=")?;
                sets.push((col, self.expr()?));
            }
            if !self.eat_sym(",") {
                return Ok(sets);
            }
        }
    }

    fn update(&mut self) -> Result<Stmt> {
        self.eat_kw("or").then(|| self.ident()).transpose()?;
        let table = self.ident()?;
        self.eat_kw("as").then(|| self.ident()).transpose()?;
        self.kw("set")?;
        let sets = self.assignments()?;
        let filter = self.where_clause()?;
        let returning = self.returning()?;
        Ok(Stmt::Update {
            table,
            sets,
            filter,
            returning,
        })
    }

    fn where_clause(&mut self) -> Result<Option<Expr>> {
        if self.eat_kw("where") {
            Ok(Some(self.expr()?))
        } else {
            Ok(None)
        }
    }

    fn opt_alias(&mut self) -> Result<Option<String>> {
        if self.eat_kw("as") {
            return self.ident().map(Some);
        }
        match self.peek() {
            Some(Tok::Ident(w)) if !RESERVED.contains(&w.as_str()) => self.ident().map(Some),
            _ => Ok(None),
        }
    }

    fn table_ref(&mut self) -> Result<FromItem> {
        if self.at_subquery() {
            self.sym("(")?;
            let q = self.query()?;
            self.sym(")")?;
            let alias = self
                .opt_alias()?
                .ok_or_else(|| Error::Sql("subconsulta no FROM precisa de alias".into()))?;
            let columns = self.opt_ident_list()?;
            return Ok(FromItem {
                source: Source::Query(Box::new(q)),
                alias,
                columns,
            });
        }
        let mut table = self.ident()?;
        if self.eat_sym(".") {
            // esquema.tabela: pg_catalog/information_schema/public são ignorados.
            table = self.ident()?;
        }
        if self.eat_sym("(") {
            let mut args = Vec::new();
            if !self.peek_sym(")") {
                args.push(self.expr()?);
                while self.eat_sym(",") {
                    args.push(self.expr()?);
                }
            }
            self.sym(")")?;
            let ordinality = if self.eat_kw("with") {
                self.kw("ordinality")?;
                true
            } else {
                false
            };
            let alias = self.opt_alias()?.unwrap_or_else(|| table.clone());
            let columns = self.opt_ident_list()?;
            return Ok(FromItem {
                source: Source::Function(table, args, ordinality),
                alias,
                columns,
            });
        }
        let alias = self.opt_alias()?.unwrap_or_else(|| table.clone());
        let columns = self.opt_ident_list()?;
        Ok(FromItem {
            source: Source::Table(table),
            alias,
            columns,
        })
    }

    /// Consulta completa: CTEs, operações de conjunto, ORDER BY e LIMIT.
    pub(crate) fn query(&mut self) -> Result<Query> {
        // Também limita `((((SELECT ...))))`, que aninha sem passar por `expr`.
        self.enter()?;
        let r = self.query_inner();
        self.depth -= 1;
        r
    }

    fn query_inner(&mut self) -> Result<Query> {
        let mut ctes = Vec::new();
        if self.eat_kw("with") {
            let recursive = self.eat_kw("recursive");
            loop {
                let name = self.ident()?;
                let columns = self.opt_ident_list()?;
                self.kw("as")?;
                if self.eat_kw("not") {
                    self.kw("materialized")?;
                } else {
                    self.eat_kw("materialized");
                }
                self.sym("(")?;
                let q = self.query()?;
                self.sym(")")?;
                let is_recursive = recursive && references_cte(&q.body, &name);
                ctes.push(Cte {
                    name,
                    columns,
                    query: q,
                    recursive: is_recursive,
                });
                if !self.eat_sym(",") {
                    break;
                }
            }
        }
        let mut body = self.set_term()?;
        loop {
            let op = if self.eat_kw("union") {
                SetOp::Union
            } else if self.eat_kw("intersect") {
                SetOp::Intersect
            } else if self.eat_kw("except") {
                SetOp::Except
            } else {
                break;
            };
            let all = self.eat_kw("all");
            if !all {
                self.eat_kw("distinct");
            }
            let right = self.set_term()?;
            body = SetExpr::SetOp {
                op,
                all,
                left: Box::new(body),
                right: Box::new(right),
            };
        }
        let order_by = self.order_by()?;
        let mut limit = None;
        let mut offset = None;
        if self.eat_kw("limit") {
            limit = Some(self.expr()?);
            if self.eat_sym(",") {
                // LIMIT offset, count (MySQL)
                offset = limit.take();
                limit = Some(self.expr()?);
            }
        }
        if self.eat_kw("offset") {
            offset = Some(self.expr()?);
            self.eat_kw("rows");
            self.eat_kw("row");
        }
        if self.eat_kw("fetch") {
            if !self.eat_kw("first") {
                self.kw("next")?;
            }
            limit = Some(self.expr()?);
            self.eat_kw("rows");
            self.eat_kw("row");
            self.kw("only")?;
        }
        Ok(Query {
            ctes,
            body,
            order_by,
            limit,
            offset,
        })
    }

    fn order_by(&mut self) -> Result<Vec<OrderItem>> {
        let mut out = Vec::new();
        if !self.eat_kw("order") {
            return Ok(out);
        }
        self.kw("by")?;
        loop {
            let expr = self.expr()?;
            let desc = if self.eat_kw("desc") {
                true
            } else {
                self.eat_kw("asc");
                false
            };
            let nulls_first = if self.eat_kw("nulls") {
                Some(if self.eat_kw("first") {
                    true
                } else {
                    self.kw("last")?;
                    false
                })
            } else {
                None
            };
            out.push(OrderItem {
                expr,
                desc,
                nulls_first,
            });
            if !self.eat_sym(",") {
                return Ok(out);
            }
        }
    }

    fn set_term(&mut self) -> Result<SetExpr> {
        if self.eat_sym("(") {
            let q = self.query()?;
            self.sym(")")?;
            if !q.ctes.is_empty() || !q.order_by.is_empty() || q.limit.is_some() {
                return Err(Error::Sql(
                    "ORDER BY/LIMIT dentro de um termo de UNION: use uma subconsulta no FROM"
                        .into(),
                ));
            }
            return Ok(q.body);
        }
        if self.eat_kw("values") {
            let rows = self.value_rows()?;
            let width = rows[0].len();
            if rows.iter().any(|r| r.len() != width) {
                return Err(Error::Sql(
                    "VALUES com linhas de tamanhos diferentes".into(),
                ));
            }
            return Ok(SetExpr::Values(rows));
        }
        self.kw("select")?;
        Ok(SetExpr::Select(Box::new(self.select()?)))
    }

    fn select_items(&mut self) -> Result<Vec<SelectItem>> {
        let mut items = Vec::new();
        loop {
            if self.eat_sym("*") {
                items.push(SelectItem::Star(None));
            } else if matches!(
                (
                    self.toks.get(self.pos),
                    self.toks.get(self.pos + 1),
                    self.toks.get(self.pos + 2)
                ),
                (
                    Some(Tok::Ident(_)),
                    Some(Tok::Sym(".")),
                    Some(Tok::Sym("*"))
                )
            ) {
                let t = self.ident()?;
                self.pos += 2;
                items.push(SelectItem::Star(Some(t)));
            } else {
                let e = self.expr()?;
                let alias = self.opt_alias()?;
                items.push(SelectItem::Expr(e, alias));
            }
            if !self.eat_sym(",") {
                return Ok(items);
            }
        }
    }

    fn select(&mut self) -> Result<Select> {
        let distinct = self.eat_kw("distinct");
        if !distinct {
            self.eat_kw("all");
        }
        let items = self.select_items()?;
        let mut from = None;
        let mut joins = Vec::new();
        if self.eat_kw("from") {
            from = Some(self.table_ref()?);
            loop {
                if self.eat_sym(",") {
                    joins.push(Join {
                        item: self.table_ref()?,
                        on: None,
                        kind: JoinKind::Cross,
                        using: Vec::new(),
                    });
                    continue;
                }
                let kind = if self.eat_kw("cross") {
                    JoinKind::Cross
                } else if self.eat_kw("left") {
                    JoinKind::Left
                } else if self.eat_kw("right") {
                    JoinKind::Right
                } else if self.eat_kw("full") {
                    JoinKind::Full
                } else if self.eat_kw("inner") || self.peek_kw("join") {
                    JoinKind::Inner
                } else {
                    break;
                };
                if matches!(kind, JoinKind::Left | JoinKind::Right | JoinKind::Full) {
                    self.eat_kw("outer");
                }
                self.kw("join")?;
                let item = self.table_ref()?;
                let mut using = Vec::new();
                let on = if kind == JoinKind::Cross {
                    None
                } else if self.eat_kw("using") {
                    // USING (a, b) => ON esq.a = dir.a AND esq.b = dir.b
                    let cols = self.ident_list()?;
                    using = cols.clone();
                    let left_alias = from.as_ref().map(|f: &FromItem| f.alias.clone());
                    let mut cond: Option<Expr> = None;
                    for c in cols {
                        let l = match (&left_alias, joins.is_empty()) {
                            (Some(a), true) => Expr::Col(Some(a.clone()), c.clone()),
                            _ => Expr::Col(None, c.clone()),
                        };
                        let r = Expr::Col(Some(item.alias.clone()), c);
                        let eq = Expr::Bin(Box::new(l), BinOp::Eq, Box::new(r));
                        cond = Some(match cond {
                            None => eq,
                            Some(prev) => Expr::Bin(Box::new(prev), BinOp::And, Box::new(eq)),
                        });
                    }
                    cond
                } else {
                    self.kw("on")?;
                    Some(self.expr()?)
                };
                joins.push(Join {
                    item,
                    on,
                    kind,
                    using,
                });
            }
        }
        let filter = self.where_clause()?;
        let mut group_by = Vec::new();
        if self.eat_kw("group") {
            self.kw("by")?;
            group_by.push(self.expr()?);
            while self.eat_sym(",") {
                group_by.push(self.expr()?);
            }
        }
        let having = if self.eat_kw("having") {
            Some(self.expr()?)
        } else {
            None
        };
        Ok(Select {
            distinct,
            items,
            from,
            joins,
            filter,
            group_by,
            having,
        })
    }

    // --- Expressões (precedência crescente) ---

    pub(crate) fn expr(&mut self) -> Result<Expr> {
        self.enter()?;
        let r = self.expr_inner();
        self.depth -= 1;
        r
    }

    fn expr_inner(&mut self) -> Result<Expr> {
        let mut left = self.and()?;
        while self.eat_kw("or") {
            left = Expr::Bin(Box::new(left), BinOp::Or, Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr> {
        let mut left = self.not()?;
        while self.eat_kw("and") {
            left = Expr::Bin(Box::new(left), BinOp::And, Box::new(self.not()?));
        }
        Ok(left)
    }

    fn not(&mut self) -> Result<Expr> {
        self.enter()?;
        let r = self.not_inner();
        self.depth -= 1;
        r
    }

    fn not_inner(&mut self) -> Result<Expr> {
        if self.peek_kw("not") && self.peek_kw_at(1, "exists") {
            self.pos += 2;
            return self.exists(true);
        }
        if self.eat_kw("not") {
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.comparison()
    }

    fn exists(&mut self, negated: bool) -> Result<Expr> {
        self.sym("(")?;
        let q = self.query()?;
        self.sym(")")?;
        Ok(Expr::Exists(Box::new(q), negated))
    }

    fn comparison(&mut self) -> Result<Expr> {
        let left = self.bitwise()?;
        // Regex (PostgreSQL): a ~ b, a ~* b, a !~ b, a !~* b, OPERATOR(pg_catalog.~).
        let mut regex: Option<(bool, bool)> = match self.peek() {
            Some(Tok::Sym("~")) => Some((false, false)),
            Some(Tok::Sym("~*")) => Some((false, true)),
            Some(Tok::Sym("!~")) => Some((true, false)),
            Some(Tok::Sym("!~*")) => Some((true, true)),
            _ => None,
        };
        if regex.is_some() {
            self.pos += 1;
        } else if self.peek_kw("operator") && self.peek_sym_at(1, "(") {
            self.pos += 2;
            if matches!(self.peek(), Some(Tok::Ident(_))) {
                self.ident()?;
                self.sym(".")?;
            }
            let op = match self.peek() {
                Some(Tok::Sym(s)) => s.to_string(),
                _ => return Err(self.expected("operador")),
            };
            self.pos += 1;
            self.sym(")")?;
            regex = Some(match op.as_str() {
                "~" => (false, false),
                "~*" => (false, true),
                "!~" => (true, false),
                "!~*" => (true, true),
                "=" => {
                    let right = self.bitwise()?;
                    return Ok(Expr::Bin(Box::new(left), BinOp::Eq, Box::new(right)));
                }
                "<>" | "!=" => {
                    let right = self.bitwise()?;
                    return Ok(Expr::Bin(Box::new(left), BinOp::Ne, Box::new(right)));
                }
                other => return Err(Error::Sql(format!("OPERATOR({other}) não é suportado"))),
            });
        }
        if let Some((neg, ci)) = regex {
            let right = self.bitwise()?;
            let mut args = vec![left, right];
            if ci {
                args.push(Expr::Lit(Value::Text("i".into())));
            }
            let call = Expr::Func("regexp_like".into(), args);
            return Ok(if neg { Expr::Not(Box::new(call)) } else { call });
        }
        let op = match self.peek() {
            Some(Tok::Sym("=")) => BinOp::Eq,
            Some(Tok::Sym("<>" | "!=")) => BinOp::Ne,
            Some(Tok::Sym("<")) => BinOp::Lt,
            Some(Tok::Sym("<=")) => BinOp::Le,
            Some(Tok::Sym(">")) => BinOp::Gt,
            Some(Tok::Sym(">=")) => BinOp::Ge,
            _ => {
                if self.eat_kw("is") {
                    let neg = self.eat_kw("not");
                    if self.eat_kw("distinct") {
                        self.kw("from")?;
                        let right = self.bitwise()?;
                        return Ok(Expr::IsDistinct(Box::new(left), Box::new(right), neg));
                    }
                    if self.eat_kw("true") || self.eat_kw("false") {
                        let want =
                            matches!(self.toks[self.pos - 1], Tok::Ident(ref w) if w == "true");
                        // x IS TRUE: verdadeiro só se x é verdadeiro (NULL conta como falso).
                        let test =
                            Expr::Func("is_true".into(), vec![left, Expr::Lit(Value::Bool(want))]);
                        return Ok(if neg { Expr::Not(Box::new(test)) } else { test });
                    }
                    self.kw("null")?;
                    return Ok(Expr::IsNull(Box::new(left), neg));
                }
                let neg = self.eat_kw("not");
                if self.eat_kw("like") || self.eat_kw("ilike") {
                    let pat = self.bitwise()?;
                    if self.eat_kw("escape") {
                        return Err(Error::Sql("LIKE ... ESCAPE não é suportado".into()));
                    }
                    return Ok(Expr::Like(Box::new(left), Box::new(pat), neg, false));
                }
                if self.eat_kw("glob") {
                    let pat = self.bitwise()?;
                    return Ok(Expr::Like(Box::new(left), Box::new(pat), neg, true));
                }
                if self.eat_kw("in") {
                    if self.at_subquery() {
                        self.sym("(")?;
                        let q = self.query()?;
                        self.sym(")")?;
                        return Ok(Expr::InQuery(Box::new(left), Box::new(q), neg));
                    }
                    self.sym("(")?;
                    let mut list = Vec::new();
                    if !self.peek_sym(")") {
                        list.push(self.expr()?);
                        while self.eat_sym(",") {
                            list.push(self.expr()?);
                        }
                    }
                    self.sym(")")?;
                    return Ok(Expr::In(Box::new(left), list, neg));
                }
                if self.eat_kw("between") {
                    let lo = self.bitwise()?;
                    self.kw("and")?;
                    let hi = self.bitwise()?;
                    return Ok(Expr::Between(
                        Box::new(left),
                        Box::new(lo),
                        Box::new(hi),
                        neg,
                    ));
                }
                if neg {
                    return Err(self.expected("LIKE, GLOB, IN ou BETWEEN após NOT"));
                }
                return Ok(left);
            }
        };
        self.pos += 1;
        // x op ANY|SOME|ALL (subconsulta)
        let quant = if self.eat_kw("all") {
            Some(true)
        } else if self.eat_kw("any") || self.eat_kw("some") {
            Some(false)
        } else {
            None
        };
        if let Some(all) = quant {
            if !self.at_subquery() {
                // x = ANY (array): pertinência num array (texto '{a,b}' ou JSON).
                self.sym("(")?;
                let arr = self.expr()?;
                self.sym(")")?;
                let call = Expr::Func("in_array".into(), vec![left, arr]);
                return Ok(if op == BinOp::Ne {
                    Expr::Not(Box::new(call))
                } else {
                    call
                });
            }
            self.sym("(")?;
            let q = self.query()?;
            self.sym(")")?;
            return Ok(Expr::Quantified(Box::new(left), op, all, Box::new(q)));
        }
        Ok(Expr::Bin(Box::new(left), op, Box::new(self.bitwise()?)))
    }

    fn bitwise(&mut self) -> Result<Expr> {
        let mut left = self.additive()?;
        loop {
            let op = if self.eat_sym("&") {
                BinOp::BitAnd
            } else if self.eat_sym("|") {
                BinOp::BitOr
            } else if self.eat_sym("<<") {
                BinOp::Shl
            } else if self.eat_sym(">>") {
                BinOp::Shr
            } else {
                return Ok(left);
            };
            left = Expr::Bin(Box::new(left), op, Box::new(self.additive()?));
        }
    }

    fn additive(&mut self) -> Result<Expr> {
        let mut left = self.term()?;
        loop {
            let op = if self.eat_sym("+") {
                BinOp::Add
            } else if self.eat_sym("-") {
                BinOp::Sub
            } else if self.eat_sym("||") {
                BinOp::Concat
            } else {
                // Operadores vetoriais (pgvector): `<->` L2, `<=>` cosseno, `<#>` produto interno.
                let func = if self.eat_sym("<->") {
                    "vec_l2"
                } else if self.eat_sym("<=>") {
                    "vec_cosine"
                } else if self.eat_sym("<#>") {
                    "vec_dot"
                } else {
                    return Ok(left);
                };
                left = Expr::Func(func.into(), vec![left, self.term()?]);
                continue;
            };
            left = Expr::Bin(Box::new(left), op, Box::new(self.term()?));
        }
    }

    fn term(&mut self) -> Result<Expr> {
        let mut left = self.unary()?;
        loop {
            let op = if self.eat_sym("*") {
                BinOp::Mul
            } else if self.eat_sym("/") {
                BinOp::Div
            } else if self.eat_sym("%") {
                BinOp::Mod
            } else {
                return Ok(left);
            };
            left = Expr::Bin(Box::new(left), op, Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr> {
        self.enter()?;
        let r = self.unary_inner();
        self.depth -= 1;
        r
    }

    fn unary_inner(&mut self) -> Result<Expr> {
        if self.eat_sym("-") {
            return Ok(Expr::Neg(Box::new(self.unary()?)));
        }
        if self.eat_sym("+") {
            return self.unary();
        }
        if self.eat_sym("~") {
            return Ok(Expr::BitNot(Box::new(self.unary()?)));
        }
        let mut e = self.primary()?;
        loop {
            // x::tipo (PostgreSQL); tipos do catálogo (regclass, oid, name...) não convertem.
            if self.eat_sym("::") {
                if self.peek_kw("pg_catalog") && self.peek_sym_at(1, ".") {
                    self.pos += 2;
                }
                let save = self.pos;
                match self.type_name() {
                    Ok((ty, _)) => e = Expr::Cast(Box::new(e), ty),
                    Err(_) => {
                        self.pos = save;
                        let ty = self.ident()?;
                        if ty.eq_ignore_ascii_case("regclass") {
                            e = Expr::Func("regclass".into(), vec![e]);
                        }
                    }
                }
                if self.eat_sym("[") {
                    self.sym("]")?;
                }
            } else if self.eat_kw("collate") {
                self.ident()?;
                if self.eat_sym(".") {
                    self.ident()?;
                }
            } else if self.peek_sym("[") {
                self.pos += 1;
                let index = self.expr()?;
                self.sym("]")?;
                e = Expr::Func("array_get".into(), vec![e, index]);
            } else {
                break;
            }
        }
        Ok(e)
    }

    fn primary(&mut self) -> Result<Expr> {
        if self.at_subquery() {
            self.sym("(")?;
            let q = self.query()?;
            self.sym(")")?;
            return Ok(Expr::Subquery(Box::new(q)));
        }
        let tok = self
            .peek()
            .cloned()
            .ok_or_else(|| self.expected("expressão"))?;
        self.pos += 1;
        Ok(match tok {
            Tok::Int(n) => Expr::Lit(Value::Int(n)),
            Tok::Real(x) => Expr::Lit(Value::Real(x)),
            Tok::Str(s) => Expr::Lit(Value::Text(s)),
            Tok::Param(n) => {
                let index = match n {
                    Some(n) => n - 1,
                    None => {
                        let i = self.next_param;
                        self.next_param += 1;
                        i
                    }
                };
                self.params = self.params.max(index + 1);
                Expr::Param(index)
            }
            Tok::Sym("(") => {
                let e = self.expr()?;
                self.sym(")")?;
                e
            }
            Tok::Ident(w) => match w.as_str() {
                "null" => Expr::Lit(Value::Null),
                "true" => Expr::Lit(Value::Bool(true)),
                "false" => Expr::Lit(Value::Bool(false)),
                "exists" => self.exists(false)?,
                "case" => self.case()?,
                "current_timestamp" | "current_date" | "current_time" | "localtime"
                | "localtimestamp" | "current_user" | "session_user" | "current_role"
                | "current_catalog" | "current_schema"
                    if !self.peek_sym("(") =>
                {
                    Expr::Func(w, Vec::new())
                }
                "pg_catalog" | "information_schema" | "public"
                    if self.peek_sym(".") && self.peek_sym_at(2, "(") =>
                {
                    self.sym(".")?;
                    let f = self.ident()?;
                    self.sym("(")?;
                    self.call(f)?
                }
                "match" if self.peek_sym("(") => {
                    self.sym("(")?;
                    let mut columns = vec![self.expr()?];
                    while self.eat_sym(",") {
                        columns.push(self.expr()?);
                    }
                    self.sym(")")?;
                    self.kw("against")?;
                    self.sym("(")?;
                    let query = self.expr()?;
                    // Modificadores do MySQL (IN BOOLEAN MODE) são aceitos e ignorados.
                    if self.eat_kw("in") {
                        while !self.peek_sym(")") {
                            if self.peek().is_none() {
                                return Err(self.expected(")"));
                            }
                            self.pos += 1;
                        }
                    }
                    self.sym(")")?;
                    Expr::Match {
                        columns,
                        query: Box::new(query),
                    }
                }
                "raise" if self.peek_sym("(") => {
                    self.sym("(")?;
                    let kind = self.ident()?;
                    if !matches!(kind.as_str(), "abort" | "fail" | "rollback" | "ignore") {
                        return Err(Error::Sql(format!(
                            "RAISE({kind}): use ABORT, FAIL, ROLLBACK ou IGNORE"
                        )));
                    }
                    let msg = if self.eat_sym(",") {
                        self.expr()?
                    } else {
                        Expr::Lit(Value::Text("gatilho abortou o comando".into()))
                    };
                    self.sym(")")?;
                    Expr::Func("raise".into(), vec![Expr::Lit(Value::Text(kind)), msg])
                }
                "array" if self.peek_sym("(") && self.at_subquery() => {
                    self.sym("(")?;
                    let q = self.query()?;
                    self.sym(")")?;
                    Expr::Func("array_of".into(), vec![Expr::Subquery(Box::new(q))])
                }
                "array" if self.peek_sym("[") => {
                    self.pos += 1;
                    let mut items = Vec::new();
                    if !self.peek_sym("]") {
                        items.push(self.expr()?);
                        while self.eat_sym(",") {
                            items.push(self.expr()?);
                        }
                    }
                    self.sym("]")?;
                    Expr::Func("json_array".into(), items)
                }
                "cast" if self.peek_sym("(") => {
                    self.sym("(")?;
                    let e = self.expr()?;
                    self.kw("as")?;
                    let (ty, _) = self.type_name()?;
                    self.sym(")")?;
                    Expr::Cast(Box::new(e), ty)
                }
                "interval" if matches!(self.peek(), Some(Tok::Str(_))) => {
                    // INTERVAL '1 day' vira o modificador de datetime('1 day').
                    let Some(Tok::Str(s)) = self.peek().cloned() else {
                        unreachable!()
                    };
                    self.pos += 1;
                    Expr::Lit(Value::Text(s))
                }
                _ if self.eat_sym("(") => self.call(w)?,
                _ if self.eat_sym(".") => Expr::Col(Some(w), self.ident()?),
                _ => Expr::Col(None, w),
            },
            other => return Err(Error::Sql(format!("token inesperado {other:?}"))),
        })
    }

    fn case(&mut self) -> Result<Expr> {
        let operand = if self.peek_kw("when") {
            None
        } else {
            Some(Box::new(self.expr()?))
        };
        let mut whens = Vec::new();
        while self.eat_kw("when") {
            let cond = self.expr()?;
            self.kw("then")?;
            whens.push((cond, self.expr()?));
        }
        if whens.is_empty() {
            return Err(self.expected("WHEN"));
        }
        let otherwise = if self.eat_kw("else") {
            Some(Box::new(self.expr()?))
        } else {
            None
        };
        self.kw("end")?;
        Ok(Expr::Case {
            operand,
            whens,
            otherwise,
        })
    }

    /// Chamada de função (o `(` já foi consumido): agregado, janela ou escalar.
    fn call(&mut self, name: String) -> Result<Expr> {
        let agg = AggFn::parse(&name);
        let mut distinct = false;
        let mut args = Vec::new();
        if agg == Some(AggFn::Count) && self.eat_sym("*") {
            self.sym(")")?;
        } else {
            if agg.is_some() {
                distinct = self.eat_kw("distinct");
                if !distinct {
                    self.eat_kw("all");
                }
            }
            if !self.eat_sym(")") {
                args.push(self.expr()?);
                while self.eat_sym(",") {
                    args.push(self.expr()?);
                }
                if agg == Some(AggFn::GroupConcat) && self.eat_kw("order") {
                    return Err(Error::Sql(
                        "GROUP_CONCAT com ORDER BY interno não é suportado: ordene na subconsulta"
                            .into(),
                    ));
                }
                self.sym(")")?;
            }
        }
        if self.eat_kw("filter") {
            if agg.is_none() {
                return Err(Error::Sql(format!(
                    "FILTER (WHERE ...) só vale em agregados, não em {name}()"
                )));
            }
            self.sym("(")?;
            self.kw("where")?;
            let cond = self.expr()?;
            self.sym(")")?;
            // `agg(x) FILTER (WHERE c)` ≡ `agg(CASE WHEN c THEN x END)`: agregados
            // ignoram NULL. `COUNT(*)` conta as linhas em que `c` vale.
            let value = if args.is_empty() {
                if agg != Some(AggFn::Count) {
                    return Err(Error::Sql(format!("{name}() precisa de argumento")));
                }
                Expr::Lit(Value::Int(1))
            } else {
                args.remove(0)
            };
            args.insert(
                0,
                Expr::Case {
                    operand: None,
                    whens: vec![(cond, value)],
                    otherwise: None,
                },
            );
        }
        if self.eat_kw("over") {
            let f = WinFn::parse(&name)
                .ok_or_else(|| Error::Sql(format!("{name}() não é função de janela")))?;
            if distinct {
                return Err(Error::Sql("DISTINCT em função de janela".into()));
            }
            let spec = self.window_spec()?;
            return Ok(Expr::Window(f, args, Box::new(spec)));
        }
        if let Some(f) = agg {
            if args.is_empty() && f != AggFn::Count {
                return Err(Error::Sql(format!("{name}() precisa de argumento")));
            }
            return Ok(Expr::Agg(f, args, distinct));
        }
        if WinFn::parse(&name).is_some() {
            return Err(Error::Sql(format!("{name}() exige OVER (...)")));
        }
        Ok(Expr::Func(name, args))
    }

    fn window_spec(&mut self) -> Result<WindowSpec> {
        self.sym("(")?;
        let mut partition_by = Vec::new();
        if self.eat_kw("partition") {
            self.kw("by")?;
            partition_by.push(self.expr()?);
            while self.eat_sym(",") {
                partition_by.push(self.expr()?);
            }
        }
        let order_by = self.order_by()?;
        let frame = if self.eat_kw("rows") || self.eat_kw("range") || self.eat_kw("groups") {
            let rows = matches!(self.toks[self.pos - 1], Tok::Ident(ref w) if w == "rows");
            let (start, end) = if self.eat_kw("between") {
                let s = self.bound()?;
                self.kw("and")?;
                (s, self.bound()?)
            } else {
                (self.bound()?, Bound::CurrentRow)
            };
            if matches!(start, Bound::UnboundedFollowing)
                || matches!(end, Bound::UnboundedPreceding)
            {
                return Err(Error::Sql("moldura de janela invertida".into()));
            }
            if self.eat_kw("exclude") {
                return Err(Error::Sql("EXCLUDE em moldura não é suportado".into()));
            }
            Some(Frame { rows, start, end })
        } else {
            None
        };
        self.sym(")")?;
        Ok(WindowSpec {
            partition_by,
            order_by,
            frame,
        })
    }

    fn bound(&mut self) -> Result<Bound> {
        if self.eat_kw("unbounded") {
            return Ok(if self.eat_kw("preceding") {
                Bound::UnboundedPreceding
            } else {
                self.kw("following")?;
                Bound::UnboundedFollowing
            });
        }
        if self.eat_kw("current") {
            self.kw("row")?;
            return Ok(Bound::CurrentRow);
        }
        let n = match self.peek() {
            Some(Tok::Int(n)) if *n >= 0 => *n as u64,
            _ => return Err(self.expected("UNBOUNDED, CURRENT ROW ou inteiro não negativo")),
        };
        self.pos += 1;
        Ok(if self.eat_kw("preceding") {
            Bound::Preceding(n)
        } else {
            self.kw("following")?;
            Bound::Following(n)
        })
    }
}

/// A consulta menciona `name` em algum FROM (CTEs e subconsultas incluídas)?
pub fn query_mentions(q: &Query, name: &str) -> bool {
    q.ctes.iter().any(|c| query_mentions(&c.query, name)) || references_cte(&q.body, name)
}

/// A consulta menciona `name` no FROM (para detectar CTEs recursivas)?
fn references_cte(e: &SetExpr, name: &str) -> bool {
    fn in_query(q: &Query, name: &str) -> bool {
        references_cte(&q.body, name)
    }
    fn in_item(i: &FromItem, name: &str) -> bool {
        match &i.source {
            Source::Table(t) => t == name,
            Source::Query(q) => in_query(q, name),
            Source::Function(..) => false,
        }
    }
    match e {
        SetExpr::Values(_) => false,
        SetExpr::Select(s) => {
            s.from.as_ref().is_some_and(|f| in_item(f, name))
                || s.joins.iter().any(|j| in_item(&j.item, name))
        }
        SetExpr::SetOp { left, right, .. } => {
            references_cte(left, name) || references_cte(right, name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn select_of(stmt: Stmt) -> (Query, Select) {
        let Stmt::Query(q) = stmt else { panic!() };
        let SetExpr::Select(s) = q.body.clone() else {
            panic!()
        };
        (*q, *s)
    }

    #[test]
    fn filter_on_aggregates_is_rewritten_to_case() {
        let exprs = |sql: &str| -> Vec<Expr> {
            let (_, s) = select_of(parse(sql).unwrap().0);
            s.items
                .into_iter()
                .filter_map(|item| match item {
                    SelectItem::Expr(e, _) => Some(e),
                    SelectItem::Star(_) => None,
                })
                .collect()
        };
        assert_eq!(
            exprs("SELECT count(*) FILTER (WHERE x > 1), sum(y) FILTER (WHERE x > 1) FROM t"),
            exprs(
                "SELECT count(CASE WHEN x > 1 THEN 1 END), sum(CASE WHEN x > 1 THEN y END) FROM t"
            )
        );
        assert!(parse("SELECT lower(x) FILTER (WHERE x > 1) FROM t").is_err());
        assert!(parse("SELECT sum() FILTER (WHERE x > 1) FROM t").is_err());
    }

    #[test]
    fn rejects_non_finite_numbers_and_runaway_nesting() {
        assert!(parse("SELECT 1e999").is_err());
        assert!(parse("CREATE TABLE t (x REAL DEFAULT 1e999)").is_err());
        // Pilha folgada: o teste confere o limite do parser, não o tamanho da pilha.
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(|| {
                let parens = format!("SELECT {}1{}", "(".repeat(2_000), ")".repeat(2_000));
                assert!(parse(&parens).is_err());
                let nots = format!("SELECT {}true", "NOT ".repeat(2_000));
                assert!(parse(&nots).is_err());
                let queries = format!(
                    "SELECT * FROM {}SELECT 1{} q",
                    "(".repeat(2_000),
                    ")".repeat(2_000)
                );
                assert!(parse(&queries).is_err());
                let explains = format!("{}SELECT 1", "EXPLAIN ".repeat(2_000));
                assert!(parse(&explains).is_err());
                // Aninhamento comum continua valendo.
                let fine = format!("SELECT {}1{}", "(".repeat(40), ")".repeat(40));
                assert!(parse(&fine).is_ok());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn parses_full_select() {
        let (stmt, _) = parse(
            "SELECT u.name, COUNT(*) AS n FROM users u LEFT JOIN orders o ON o.user_id = u.id \
             WHERE u.age BETWEEN 18 AND 65 AND u.name LIKE 'a%' GROUP BY u.name \
             HAVING COUNT(*) > 1 ORDER BY n DESC NULLS LAST, 1 LIMIT 10 OFFSET 5;",
        )
        .unwrap();
        let (q, s) = select_of(stmt);
        assert_eq!(s.from.unwrap().alias, "u");
        assert_eq!(s.joins[0].kind, JoinKind::Left);
        assert!(s.having.is_some() && q.order_by[0].desc);
        assert_eq!(q.order_by[0].nulls_first, Some(false));
        assert_eq!(q.limit, Some(Expr::Lit(Value::Int(10))));
    }

    #[test]
    fn parses_subqueries_ctes_set_ops_case_cast_and_params() {
        let (stmt, params) = parse(
            "WITH big AS (SELECT id FROM t WHERE v > ?) \
             SELECT CASE WHEN x IN (SELECT id FROM big) THEN 'a' ELSE CAST(y AS TEXT) END \
             FROM t AS x0 CROSS JOIN (SELECT 1 AS one) d, u \
             WHERE EXISTS (SELECT 1 FROM u WHERE u.id = x0.id) AND z = $3 \
             UNION ALL SELECT (SELECT max(v) FROM t) FROM t2 ORDER BY 1 LIMIT ?2",
        )
        .unwrap();
        assert_eq!(params, 3);
        let Stmt::Query(q) = stmt else { panic!() };
        assert_eq!(q.ctes.len(), 1);
        assert!(matches!(
            q.body,
            SetExpr::SetOp {
                op: SetOp::Union,
                all: true,
                ..
            }
        ));
    }

    #[test]
    fn parses_ddl_and_rejects_garbage() {
        let (s, _) = parse(
            "CREATE TABLE t2 (a INTEGER, b TEXT NOT NULL DEFAULT 'x', c REAL CHECK (c > 0), \
             d INT REFERENCES p(id) ON DELETE CASCADE, e TEXT DEFAULT now(), \
             PRIMARY KEY (a, b), CONSTRAINT fk FOREIGN KEY (a) REFERENCES q ON UPDATE SET NULL)",
        )
        .unwrap();
        let Stmt::CreateTable {
            columns,
            primary_key,
            checks,
            foreign_keys,
            ..
        } = s
        else {
            panic!()
        };
        assert_eq!(primary_key, ["a", "b"]);
        assert_eq!(columns[1].default, Some(Expr::Lit(Value::Text("x".into()))));
        assert_eq!(columns[4].default_sql.as_deref(), Some("now()"));
        assert_eq!(checks[0].sql, "c > 0");
        assert_eq!(foreign_keys.len(), 2);
        assert_eq!(foreign_keys[0].on_update, FkAction::SetNull);
        assert_eq!(foreign_keys[1].on_delete, FkAction::Cascade);
        assert_eq!(foreign_keys[1].columns, ["d"]);
        for bad in [
            "SELECT",
            "SELECT * FROM",
            "INSERT INTO t VALUES (1",
            "SELECT 'a FROM t",
            "DROP x",
            "SELECT * FROM (SELECT 1)",
            "SELECT $0",
            "SELECT 1; SELECT 2",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_windows_recursive_ctes_and_returning() {
        let (s, _) = parse(
            "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 5) \
             SELECT x, SUM(x) OVER (ORDER BY x ROWS BETWEEN 1 PRECEDING AND CURRENT ROW), \
             row_number() OVER (PARTITION BY x % 2 ORDER BY x DESC) FROM n",
        )
        .unwrap();
        let Stmt::Query(q) = s else { panic!() };
        assert!(q.ctes[0].recursive);
        let SetExpr::Select(sel) = &q.body else {
            panic!()
        };
        assert!(
            matches!(&sel.items[1], SelectItem::Expr(Expr::Window(WinFn::Agg(AggFn::Sum), _, spec), _)
            if spec.frame == Some(Frame { rows: true, start: Bound::Preceding(1), end: Bound::CurrentRow }))
        );
        let (s, _) =
            parse("DELETE FROM t WHERE a > ALL (SELECT b FROM u) RETURNING *, a * 2 AS dbl")
                .unwrap();
        let Stmt::Delete {
            filter: Some(Expr::Quantified(..)),
            returning,
            ..
        } = s
        else {
            panic!()
        };
        assert_eq!(returning.len(), 2);
        assert!(parse("SELECT row_number() FROM t").is_err());
    }

    #[test]
    fn parses_upsert_insert_select_and_views() {
        let (s, _) = parse(
            "INSERT INTO t (a, b) SELECT a, b FROM u ON CONFLICT (a) DO UPDATE SET b = excluded.b WHERE t.b < excluded.b",
        )
        .unwrap();
        assert!(matches!(
            s,
            Stmt::Insert {
                source: InsertSource::Query(_),
                on_conflict: Some(OnConflict::Update { .. }),
                ..
            }
        ));
        let (s, _) = parse("INSERT OR IGNORE INTO t VALUES (1)").unwrap();
        assert!(matches!(
            s,
            Stmt::Insert {
                on_conflict: Some(OnConflict::Nothing),
                ..
            }
        ));
        let (s, _) = parse("REPLACE INTO t DEFAULT VALUES").unwrap();
        assert!(matches!(
            s,
            Stmt::Insert {
                source: InsertSource::Default,
                on_conflict: Some(OnConflict::Replace),
                ..
            }
        ));
        let (s, _) = parse("CREATE OR REPLACE VIEW v (a) AS SELECT x FROM t WHERE x > 1;").unwrap();
        let Stmt::CreateView {
            sql,
            or_replace: true,
            columns,
            ..
        } = s
        else {
            panic!()
        };
        assert_eq!(sql, "SELECT x FROM t WHERE x > 1");
        assert_eq!(columns, ["a"]);
        assert_eq!(
            split_statements("BEGIN; INSERT INTO t VALUES ('a;b'); -- x;\n COMMIT").unwrap(),
            ["BEGIN", "INSERT INTO t VALUES ('a;b')", "COMMIT"]
        );
        let script = "CREATE TRIGGER x AFTER INSERT ON t BEGIN INSERT INTO a VALUES (CASE WHEN 1 THEN 2 END); UPDATE b SET c = 1; END; SELECT 1";
        let parts = split_statements(script).unwrap();
        assert_eq!(parts.len(), 2, "{parts:?}");
        assert!(parts[0].ends_with("END") && parts[1] == "SELECT 1");
    }
}
