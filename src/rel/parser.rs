//! Lexer e parser recursivo do SQL relacional.

use super::value::{Type, Value};
use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    Real(f64),
    Sym(&'static str),
}

fn lex(src: &str) -> Result<Vec<Tok>> {
    const SYMS: [&str; 18] = [
        "<>", "!=", "<=", ">=", "||", "(", ")", ",", ".", "*", "+", "-", "/", "%", "=", "<", ">",
        ";",
    ];
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    'outer: while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if src[i..].starts_with("--") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'\'' || c == b'"' {
            let mut s = Vec::new();
            i += 1;
            loop {
                match b.get(i) {
                    None => return Err(Error::Sql("texto sem aspas de fechamento".into())),
                    Some(&q) if q == c && b.get(i + 1) == Some(&c) => {
                        s.push(c);
                        i += 2;
                    }
                    Some(&q) if q == c => {
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
            out.push(if c == b'"' {
                Tok::Ident(s.to_lowercase())
            } else {
                Tok::Str(s)
            });
        } else if c.is_ascii_digit() {
            let start = i;
            while i < b.len()
                && (b[i].is_ascii_digit() || b[i] == b'.' || b[i] == b'e' || b[i] == b'E')
            {
                i += 1;
            }
            let t = &src[start..i];
            out.push(match t.parse::<i64>() {
                Ok(n) => Tok::Int(n),
                Err(_) => Tok::Real(
                    t.parse()
                        .map_err(|_| Error::Sql(format!("número inválido: {t}")))?,
                ),
            });
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push(Tok::Ident(src[start..i].to_ascii_lowercase()));
        } else {
            for s in SYMS {
                if src[i..].starts_with(s) {
                    out.push(Tok::Sym(s));
                    i += s.len();
                    continue 'outer;
                }
            }
            return Err(Error::Sql(format!("caractere inesperado {:?}", c as char)));
        }
    }
    Ok(out)
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AggFn {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Lit(Value),
    Col(Option<String>, String),
    Neg(Box<Expr>),
    Not(Box<Expr>),
    Bin(Box<Expr>, BinOp, Box<Expr>),
    IsNull(Box<Expr>, bool),
    Like(Box<Expr>, Box<Expr>, bool),
    In(Box<Expr>, Vec<Expr>, bool),
    Between(Box<Expr>, Box<Expr>, Box<Expr>, bool),
    Func(String, Vec<Expr>),
    /// Agregado; `None` = `COUNT(*)`. O `bool` é DISTINCT.
    Agg(AggFn, Option<Box<Expr>>, bool),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ColumnDef {
    pub name: String,
    pub ty: Type,
    pub primary: bool,
    pub not_null: bool,
    pub unique: bool,
    pub default: Option<Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SelectItem {
    Star(Option<String>),
    Expr(Expr, Option<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Join {
    pub table: String,
    pub alias: String,
    pub on: Expr,
    pub left: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Select {
    pub distinct: bool,
    pub items: Vec<SelectItem>,
    pub from: String,
    pub alias: String,
    pub joins: Vec<Join>,
    pub filter: Option<Expr>,
    pub group_by: Vec<Expr>,
    pub having: Option<Expr>,
    pub order_by: Vec<(Expr, bool)>,
    pub limit: Option<u64>,
    pub offset: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    CreateTable {
        name: String,
        columns: Vec<ColumnDef>,
        if_not_exists: bool,
    },
    DropTable {
        name: String,
        if_exists: bool,
    },
    CreateIndex {
        name: String,
        table: String,
        column: String,
        unique: bool,
        if_not_exists: bool,
    },
    DropIndex {
        name: String,
        if_exists: bool,
    },
    AddColumn {
        table: String,
        column: ColumnDef,
    },
    Insert {
        table: String,
        columns: Option<Vec<String>>,
        rows: Vec<Vec<Expr>>,
    },
    Select(Box<Select>),
    Update {
        table: String,
        sets: Vec<(String, Expr)>,
        filter: Option<Expr>,
    },
    Delete {
        table: String,
        filter: Option<Expr>,
    },
    ShowTables,
    Describe(String),
    Explain(Box<Stmt>),
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

pub fn parse(sql: &str) -> Result<Stmt> {
    let mut p = Parser {
        toks: lex(sql)?,
        pos: 0,
    };
    let stmt = p.statement()?;
    while p.eat_sym(";") {}
    if p.pos != p.toks.len() {
        return Err(Error::Sql(format!(
            "sobra após o comando: {:?}",
            p.toks[p.pos]
        )));
    }
    Ok(stmt)
}

const RESERVED: &[&str] = &[
    "select", "from", "where", "group", "order", "by", "having", "limit", "offset", "join", "left",
    "inner", "on", "and", "or", "not", "as", "set", "values", "asc", "desc", "is", "null", "like",
    "in", "between", "distinct", "union", "cross", "outer",
];

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(w)) if w == kw)
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
        let hit = matches!(self.peek(), Some(Tok::Sym(x)) if *x == s);
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

    fn statement(&mut self) -> Result<Stmt> {
        let word = self.ident()?;
        match word.as_str() {
            "explain" => Ok(Stmt::Explain(Box::new(self.statement()?))),
            "select" => Ok(Stmt::Select(Box::new(self.select()?))),
            "insert" => self.insert(),
            "update" => self.update(),
            "delete" => {
                self.kw("from")?;
                let table = self.ident()?;
                let filter = self.where_clause()?;
                Ok(Stmt::Delete { table, filter })
            }
            "create" => {
                let unique = self.eat_kw("unique");
                if !unique && self.eat_kw("table") {
                    let if_not_exists = self.if_exists(true)?;
                    let name = self.ident()?;
                    self.sym("(")?;
                    let mut columns = vec![self.column_def()?];
                    let mut pk_clause = None;
                    while self.eat_sym(",") {
                        if self.eat_kw("primary") {
                            self.kw("key")?;
                            self.sym("(")?;
                            pk_clause = Some(self.ident()?);
                            self.sym(")")?;
                        } else {
                            columns.push(self.column_def()?);
                        }
                    }
                    self.sym(")")?;
                    if let Some(pk) = pk_clause {
                        let col = columns.iter_mut().find(|c| c.name == pk).ok_or_else(|| {
                            Error::Sql(format!("PRIMARY KEY em coluna inexistente {pk}"))
                        })?;
                        col.primary = true;
                    }
                    return Ok(Stmt::CreateTable {
                        name,
                        columns,
                        if_not_exists,
                    });
                }
                self.kw("index")?;
                let if_not_exists = self.if_exists(true)?;
                let name = self.ident()?;
                self.kw("on")?;
                let table = self.ident()?;
                self.sym("(")?;
                let column = self.ident()?;
                self.sym(")")?;
                Ok(Stmt::CreateIndex {
                    name,
                    table,
                    column,
                    unique,
                    if_not_exists,
                })
            }
            "drop" => {
                let table = self.eat_kw("table");
                if !table {
                    self.kw("index")?;
                }
                let if_exists = self.if_exists(false)?;
                let name = self.ident()?;
                Ok(if table {
                    Stmt::DropTable { name, if_exists }
                } else {
                    Stmt::DropIndex { name, if_exists }
                })
            }
            "alter" => {
                self.kw("table")?;
                let table = self.ident()?;
                self.kw("add")?;
                self.eat_kw("column");
                Ok(Stmt::AddColumn {
                    table,
                    column: self.column_def()?,
                })
            }
            "show" => {
                self.kw("tables")?;
                Ok(Stmt::ShowTables)
            }
            "describe" | "desc" => Ok(Stmt::Describe(self.ident()?)),
            other => Err(Error::Sql(format!("comando desconhecido: {other}"))),
        }
    }

    fn column_def(&mut self) -> Result<ColumnDef> {
        let name = self.ident()?;
        let ty_word = self.ident()?;
        let ty = Type::parse(&ty_word)
            .ok_or_else(|| Error::Sql(format!("tipo desconhecido {ty_word}")))?;
        if self.eat_sym("(") {
            // VARCHAR(n) / DECIMAL(p, s): tamanho aceito e ignorado.
            while !self.eat_sym(")") {
                if self.peek().is_none() {
                    return Err(self.expected(")"));
                }
                self.pos += 1;
            }
        }
        let mut col = ColumnDef {
            name,
            ty,
            primary: false,
            not_null: false,
            unique: false,
            default: None,
        };
        loop {
            if self.eat_kw("primary") {
                self.kw("key")?;
                col.primary = true;
            } else if self.eat_kw("not") {
                self.kw("null")?;
                col.not_null = true;
            } else if self.eat_kw("unique") {
                col.unique = true;
            } else if self.eat_kw("default") {
                col.default = Some(match self.unary()? {
                    Expr::Lit(v) => v,
                    Expr::Neg(inner) => match *inner {
                        Expr::Lit(Value::Int(n)) => Value::Int(-n),
                        Expr::Lit(Value::Real(x)) => Value::Real(-x),
                        _ => return Err(Error::Sql("DEFAULT precisa ser literal".into())),
                    },
                    _ => return Err(Error::Sql("DEFAULT precisa ser literal".into())),
                });
            } else if self.eat_kw("null") {
            } else {
                return Ok(col);
            }
        }
    }

    fn insert(&mut self) -> Result<Stmt> {
        self.kw("into")?;
        let table = self.ident()?;
        let columns = if self.eat_sym("(") {
            let mut cols = vec![self.ident()?];
            while self.eat_sym(",") {
                cols.push(self.ident()?);
            }
            self.sym(")")?;
            Some(cols)
        } else {
            None
        };
        self.kw("values")?;
        let mut rows = Vec::new();
        loop {
            self.sym("(")?;
            let mut row = vec![self.expr()?];
            while self.eat_sym(",") {
                row.push(self.expr()?);
            }
            self.sym(")")?;
            rows.push(row);
            if !self.eat_sym(",") {
                break;
            }
        }
        Ok(Stmt::Insert {
            table,
            columns,
            rows,
        })
    }

    fn update(&mut self) -> Result<Stmt> {
        let table = self.ident()?;
        self.kw("set")?;
        let mut sets = Vec::new();
        loop {
            let col = self.ident()?;
            self.sym("=")?;
            sets.push((col, self.expr()?));
            if !self.eat_sym(",") {
                break;
            }
        }
        let filter = self.where_clause()?;
        Ok(Stmt::Update {
            table,
            sets,
            filter,
        })
    }

    fn where_clause(&mut self) -> Result<Option<Expr>> {
        if self.eat_kw("where") {
            Ok(Some(self.expr()?))
        } else {
            Ok(None)
        }
    }

    fn alias(&mut self, default: &str) -> Result<String> {
        if self.eat_kw("as") {
            return self.ident();
        }
        match self.peek() {
            Some(Tok::Ident(w)) if !RESERVED.contains(&w.as_str()) => self.ident(),
            _ => Ok(default.to_string()),
        }
    }

    fn select(&mut self) -> Result<Select> {
        let distinct = self.eat_kw("distinct");
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
                let alias = if self.eat_kw("as") {
                    Some(self.ident()?)
                } else {
                    match self.peek() {
                        Some(Tok::Ident(w)) if !RESERVED.contains(&w.as_str()) => {
                            Some(self.ident()?)
                        }
                        _ => None,
                    }
                };
                items.push(SelectItem::Expr(e, alias));
            }
            if !self.eat_sym(",") {
                break;
            }
        }
        self.kw("from")?;
        let from = self.ident()?;
        let alias = self.alias(&from)?;
        let mut joins = Vec::new();
        loop {
            let left = if self.eat_kw("left") {
                self.eat_kw("outer");
                true
            } else {
                self.eat_kw("inner");
                false
            };
            if !self.eat_kw("join") {
                if left {
                    return Err(self.expected("JOIN"));
                }
                break;
            }
            let table = self.ident()?;
            let alias = self.alias(&table)?;
            self.kw("on")?;
            joins.push(Join {
                table,
                alias,
                on: self.expr()?,
                left,
            });
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
        let mut order_by = Vec::new();
        if self.eat_kw("order") {
            self.kw("by")?;
            loop {
                let e = self.expr()?;
                let desc = if self.eat_kw("desc") {
                    true
                } else {
                    self.eat_kw("asc");
                    false
                };
                order_by.push((e, desc));
                if !self.eat_sym(",") {
                    break;
                }
            }
        }
        let mut limit = None;
        let mut offset = 0;
        if self.eat_kw("limit") {
            limit = Some(self.count()?);
            if self.eat_kw("offset") {
                offset = self.count()?;
            }
        }
        Ok(Select {
            distinct,
            items,
            from,
            alias,
            joins,
            filter,
            group_by,
            having,
            order_by,
            limit,
            offset,
        })
    }

    fn count(&mut self) -> Result<u64> {
        match self.peek() {
            Some(Tok::Int(n)) if *n >= 0 => {
                let n = *n as u64;
                self.pos += 1;
                Ok(n)
            }
            _ => Err(self.expected("inteiro não negativo")),
        }
    }

    // --- Expressões (precedência crescente) ---

    pub(crate) fn expr(&mut self) -> Result<Expr> {
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
        if self.eat_kw("not") {
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.comparison()
    }

    fn comparison(&mut self) -> Result<Expr> {
        let left = self.additive()?;
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
                    self.kw("null")?;
                    return Ok(Expr::IsNull(Box::new(left), neg));
                }
                let neg = self.eat_kw("not");
                if self.eat_kw("like") {
                    return Ok(Expr::Like(Box::new(left), Box::new(self.additive()?), neg));
                }
                if self.eat_kw("in") {
                    self.sym("(")?;
                    let mut list = vec![self.expr()?];
                    while self.eat_sym(",") {
                        list.push(self.expr()?);
                    }
                    self.sym(")")?;
                    return Ok(Expr::In(Box::new(left), list, neg));
                }
                if self.eat_kw("between") {
                    let lo = self.additive()?;
                    self.kw("and")?;
                    let hi = self.additive()?;
                    return Ok(Expr::Between(
                        Box::new(left),
                        Box::new(lo),
                        Box::new(hi),
                        neg,
                    ));
                }
                if neg {
                    return Err(self.expected("LIKE, IN ou BETWEEN após NOT"));
                }
                return Ok(left);
            }
        };
        self.pos += 1;
        Ok(Expr::Bin(Box::new(left), op, Box::new(self.additive()?)))
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
                return Ok(left);
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
        if self.eat_sym("-") {
            return Ok(Expr::Neg(Box::new(self.unary()?)));
        }
        if self.eat_sym("+") {
            return self.unary();
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr> {
        let tok = self
            .peek()
            .cloned()
            .ok_or_else(|| self.expected("expressão"))?;
        self.pos += 1;
        Ok(match tok {
            Tok::Int(n) => Expr::Lit(Value::Int(n)),
            Tok::Real(x) => Expr::Lit(Value::Real(x)),
            Tok::Str(s) => Expr::Lit(Value::Text(s)),
            Tok::Sym("(") => {
                let e = self.expr()?;
                self.sym(")")?;
                e
            }
            Tok::Ident(w) => match w.as_str() {
                "null" => Expr::Lit(Value::Null),
                "true" => Expr::Lit(Value::Bool(true)),
                "false" => Expr::Lit(Value::Bool(false)),
                _ if self.eat_sym("(") => self.call(w)?,
                _ if self.eat_sym(".") => Expr::Col(Some(w), self.ident()?),
                _ => Expr::Col(None, w),
            },
            other => return Err(Error::Sql(format!("token inesperado {other:?}"))),
        })
    }

    fn call(&mut self, name: String) -> Result<Expr> {
        let agg = match name.as_str() {
            "count" => Some(AggFn::Count),
            "sum" => Some(AggFn::Sum),
            "avg" => Some(AggFn::Avg),
            "min" => Some(AggFn::Min),
            "max" => Some(AggFn::Max),
            _ => None,
        };
        if let Some(f) = agg {
            if f == AggFn::Count && self.eat_sym("*") {
                self.sym(")")?;
                return Ok(Expr::Agg(f, None, false));
            }
            let distinct = self.eat_kw("distinct");
            let arg = self.expr()?;
            self.sym(")")?;
            return Ok(Expr::Agg(f, Some(Box::new(arg)), distinct));
        }
        let mut args = Vec::new();
        if !self.eat_sym(")") {
            args.push(self.expr()?);
            while self.eat_sym(",") {
                args.push(self.expr()?);
            }
            self.sym(")")?;
        }
        Ok(Expr::Func(name, args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_select() {
        let s = parse(
            "SELECT u.name, COUNT(*) AS n FROM users u LEFT JOIN orders o ON o.user_id = u.id \
             WHERE u.age BETWEEN 18 AND 65 AND u.name LIKE 'a%' GROUP BY u.name \
             HAVING COUNT(*) > 1 ORDER BY n DESC, 1 LIMIT 10 OFFSET 5;",
        )
        .unwrap();
        let Stmt::Select(s) = s else { panic!() };
        assert_eq!(
            (s.alias.as_str(), s.joins.len(), s.limit, s.offset),
            ("u", 1, Some(10), 5)
        );
        assert!(s.joins[0].left && s.having.is_some() && s.order_by[0].1);
    }

    #[test]
    fn parses_ddl_and_rejects_garbage() {
        let s = parse(
            "CREATE TABLE t2 (id INTEGER, nome VARCHAR(40) NOT NULL DEFAULT 'x', PRIMARY KEY (id))",
        )
        .unwrap();
        let Stmt::CreateTable { columns, .. } = s else {
            panic!()
        };
        assert!(columns[0].primary && columns[1].not_null);
        assert_eq!(columns[1].default, Some(Value::Text("x".into())));
        for bad in [
            "SELECT",
            "SELECT * FROM",
            "INSERT INTO t VALUES (1",
            "SELECT 'a FROM t",
            "DROP x",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
