//! Parser e planejador de um subset SQL didático.
//!
//! Suporte:
//! - `SELECT * | COUNT(*) FROM kv [WHERE key = x | key >= x | key LIKE 'p%' | value = x] [ORDER BY key [ASC|DESC]] [LIMIT n]`
//! - `INSERT INTO kv [(key, value)] VALUES (k, v) [TTL segundos]`
//! - `UPDATE kv SET value = v WHERE key = k`
//! - `DELETE FROM kv WHERE key = k`
//! - `CREATE INDEX ON kv (value)`
//! - `BEGIN` / `COMMIT` / `ROLLBACK`
//! - `CHECKPOINT` / `VACUUM` / `EXPLAIN <stmt>`
//!
//! Literais: número, identificador, string com aspas simples ou duplas.

use crate::error::{Error, Result};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmp {
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pred {
    KeyCmp {
        op: Cmp,
        value: Vec<u8>,
    },
    ValueEq {
        value: Vec<u8>,
    },
    /// `key LIKE 'prefixo%'` — `_` é literal (não é curinga).
    KeyPrefix {
        prefix: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    Select {
        pred: Option<Pred>,
        order_desc: bool,
        limit: Option<usize>,
        /// `SELECT COUNT(*)`.
        count: bool,
    },
    Insert {
        key: Vec<u8>,
        value: Vec<u8>,
        /// `... TTL <segundos>`.
        ttl: Option<Duration>,
    },
    Update {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        key: Vec<u8>,
    },
    CreateValueIndex,
    Begin,
    Commit,
    Rollback,
    Checkpoint,
    Vacuum,
    Explain(Box<Statement>),
}

struct Lexer<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Lexer<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            s: s.as_bytes(),
            i: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn peek(&mut self) -> Option<Token> {
        let save = self.i;
        let t = self.next_token();
        self.i = save;
        t
    }

    fn next_token(&mut self) -> Option<Token> {
        self.skip_ws();
        if self.i >= self.s.len() {
            return None;
        }
        let c = self.s[self.i];
        if c == b'\'' || c == b'"' {
            return Some(self.string(c));
        }
        if c == b'=' {
            self.i += 1;
            return Some(Token::Eq);
        }
        if c == b'>' {
            self.i += 1;
            if self.i < self.s.len() && self.s[self.i] == b'=' {
                self.i += 1;
                return Some(Token::Ge);
            }
            return Some(Token::Gt);
        }
        if c == b'<' {
            self.i += 1;
            if self.i < self.s.len() && self.s[self.i] == b'=' {
                self.i += 1;
                return Some(Token::Le);
            }
            return Some(Token::Lt);
        }
        if c == b'(' {
            self.i += 1;
            return Some(Token::LParen);
        }
        if c == b')' {
            self.i += 1;
            return Some(Token::RParen);
        }
        if c == b',' {
            self.i += 1;
            return Some(Token::Comma);
        }
        if c == b';' {
            self.i += 1;
            return Some(Token::Semi);
        }
        if c == b'*' {
            self.i += 1;
            return Some(Token::Star);
        }
        let start = self.i;
        while self.i < self.s.len() {
            let b = self.s[self.i];
            if b.is_ascii_whitespace()
                || matches!(
                    b,
                    b'=' | b'>' | b'<' | b'(' | b')' | b',' | b';' | b'\'' | b'"'
                )
            {
                break;
            }
            self.i += 1;
        }
        let raw = std::str::from_utf8(&self.s[start..self.i]).unwrap_or("");
        Some(Token::Word(raw.to_string()))
    }

    fn string(&mut self, quote: u8) -> Token {
        self.i += 1;
        let mut out = Vec::new();
        while self.i < self.s.len() {
            let b = self.s[self.i];
            self.i += 1;
            if b == quote {
                break;
            }
            if b == b'\\' && self.i < self.s.len() {
                out.push(self.s[self.i]);
                self.i += 1;
                continue;
            }
            out.push(b);
        }
        Token::Lit(out)
    }
}

#[derive(Debug, Clone)]
enum Token {
    Word(String),
    Lit(Vec<u8>),
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
    LParen,
    RParen,
    Comma,
    Semi,
    Star,
}

fn word_eq(t: &Token, s: &str) -> bool {
    match t {
        Token::Word(w) => w.eq_ignore_ascii_case(s),
        _ => false,
    }
}

fn lit_from(t: Token) -> Result<Vec<u8>> {
    match t {
        Token::Lit(v) => Ok(v),
        Token::Word(w) => Ok(w.into_bytes()),
        _ => Err(Error::Sql("esperado literal".into())),
    }
}

pub fn parse_sql(input: &str) -> Result<Statement> {
    let mut lx = Lexer::new(input);
    let first = lx.next_token().ok_or_else(|| Error::Sql("vazio".into()))?;
    let stmt = if word_eq(&first, "EXPLAIN") {
        Statement::Explain(Box::new(parse_sql_from(&mut lx)?))
    } else {
        parse_kw(&mut lx, first)?
    };
    match lx.next_token() {
        None => {}
        Some(Token::Semi) if lx.next_token().is_none() => {}
        Some(_) => return Err(Error::Sql("lixo após o statement".into())),
    }
    Ok(stmt)
}

fn parse_sql_from(lx: &mut Lexer<'_>) -> Result<Statement> {
    let first = lx
        .next_token()
        .ok_or_else(|| Error::Sql("EXPLAIN sem statement".into()))?;
    parse_kw(lx, first)
}

fn parse_kw(lx: &mut Lexer<'_>, first: Token) -> Result<Statement> {
    if word_eq(&first, "SELECT") {
        return parse_select(lx);
    }
    if word_eq(&first, "INSERT") {
        return parse_insert(lx);
    }
    if word_eq(&first, "UPDATE") {
        return parse_update(lx);
    }
    if word_eq(&first, "DELETE") {
        return parse_delete(lx);
    }
    if word_eq(&first, "CREATE") {
        return parse_create(lx);
    }
    if word_eq(&first, "BEGIN") {
        return Ok(Statement::Begin);
    }
    if word_eq(&first, "COMMIT") {
        return Ok(Statement::Commit);
    }
    if word_eq(&first, "ROLLBACK") || word_eq(&first, "ABORT") {
        return Ok(Statement::Rollback);
    }
    if word_eq(&first, "CHECKPOINT") {
        return Ok(Statement::Checkpoint);
    }
    if word_eq(&first, "VACUUM") {
        return Ok(Statement::Vacuum);
    }
    Err(Error::Sql(format!("comando não suportado: {:?}", first)))
}

fn expect_word(lx: &mut Lexer<'_>, w: &str) -> Result<()> {
    let t = lx
        .next_token()
        .ok_or_else(|| Error::Sql(format!("esperado {w}")))?;
    if word_eq(&t, w) {
        Ok(())
    } else {
        Err(Error::Sql(format!("esperado {w}")))
    }
}

fn parse_select(lx: &mut Lexer<'_>) -> Result<Statement> {
    let star = lx
        .next_token()
        .ok_or_else(|| Error::Sql("esperado * ou colunas".into()))?;
    let mut count = false;
    match star {
        Token::Star => {}
        Token::Word(w) if w.eq_ignore_ascii_case("COUNT") => {
            let ok = matches!(lx.next_token(), Some(Token::LParen))
                && matches!(lx.next_token(), Some(Token::Star))
                && matches!(lx.next_token(), Some(Token::RParen));
            if !ok {
                return Err(Error::Sql("esperado COUNT(*)".into()));
            }
            count = true;
        }
        Token::Word(w) if w.eq_ignore_ascii_case("KEY") => {
            if !matches!(lx.next_token(), Some(Token::Comma)) {
                return Err(Error::Sql("esperado vírgula entre colunas".into()));
            }
            expect_word(lx, "VALUE")?;
        }
        Token::Word(w) if w.eq_ignore_ascii_case("VALUE") => {
            return Err(Error::Sql("SELECT deve listar key antes de value".into()));
        }
        _ => return Err(Error::Sql("SELECT aceita * ou key, value".into())),
    }
    expect_word(lx, "FROM")?;
    let table = lx
        .next_token()
        .ok_or_else(|| Error::Sql("esperado nome de tabela".into()))?;
    match table {
        Token::Word(w) if w.eq_ignore_ascii_case("kv") || w.eq_ignore_ascii_case("t") => {}
        Token::Word(w) => return Err(Error::UnknownTable(w)),
        _ => return Err(Error::Sql("esperado identificador de tabela".into())),
    }
    let mut pred = None;
    let mut order_desc = false;
    let mut limit = None;
    while let Some(tok) = lx.peek() {
        if word_eq(&tok, "WHERE") {
            let _ = lx.next_token();
            pred = Some(parse_pred(lx)?);
        } else if word_eq(&tok, "ORDER") {
            let _ = lx.next_token();
            expect_word(lx, "BY")?;
            let col = lx
                .next_token()
                .ok_or_else(|| Error::Sql("ORDER BY sem coluna".into()))?;
            if !word_eq(&col, "KEY") && !word_eq(&col, "K") {
                return Err(Error::Sql("ORDER BY só aceita key".into()));
            }
            if let Some(dir) = lx.peek() {
                if word_eq(&dir, "DESC") {
                    let _ = lx.next_token();
                    order_desc = true;
                } else if word_eq(&dir, "ASC") {
                    let _ = lx.next_token();
                }
            }
        } else if word_eq(&tok, "LIMIT") {
            let _ = lx.next_token();
            let n = lx
                .next_token()
                .ok_or_else(|| Error::Sql("LIMIT sem número".into()))?;
            let s = match n {
                Token::Word(w) => w,
                _ => return Err(Error::Sql("LIMIT inválido".into())),
            };
            limit = Some(
                s.parse::<usize>()
                    .map_err(|_| Error::Sql("LIMIT inválido".into()))?,
            );
        } else {
            break;
        }
    }
    Ok(Statement::Select {
        pred,
        order_desc,
        limit,
        count,
    })
}

fn parse_pred(lx: &mut Lexer<'_>) -> Result<Pred> {
    let col = lx
        .next_token()
        .ok_or_else(|| Error::Sql("esperado coluna".into()))?;
    let op_tok = lx
        .next_token()
        .ok_or_else(|| Error::Sql("esperado operador".into()))?;
    let val = lit_from(
        lx.next_token()
            .ok_or_else(|| Error::Sql("esperado literal".into()))?,
    )?;
    let op = match op_tok {
        Token::Eq => Cmp::Eq,
        Token::Ge => Cmp::Ge,
        Token::Gt => Cmp::Gt,
        Token::Le => Cmp::Le,
        Token::Lt => Cmp::Lt,
        Token::Word(w) if w.eq_ignore_ascii_case("LIKE") => {
            if !(word_eq(&col, "KEY") || word_eq(&col, "K")) {
                return Err(Error::Sql("LIKE só é suportado em key".into()));
            }
            return match val.split_last() {
                Some((b'%', prefix)) if !prefix.is_empty() && !prefix.contains(&b'%') => {
                    Ok(Pred::KeyPrefix {
                        prefix: prefix.to_vec(),
                    })
                }
                _ => Err(Error::Sql("LIKE aceita apenas 'prefixo%'".into())),
            };
        }
        _ => return Err(Error::Sql("operador WHERE não suportado".into())),
    };
    if word_eq(&col, "VALUE") || word_eq(&col, "VAL") {
        if op != Cmp::Eq {
            return Err(Error::Sql("WHERE value só aceita '='".into()));
        }
        return Ok(Pred::ValueEq { value: val });
    }
    if word_eq(&col, "KEY") || word_eq(&col, "K") {
        return Ok(Pred::KeyCmp { op, value: val });
    }
    Err(Error::Sql("coluna WHERE deve ser key ou value".into()))
}

fn parse_insert(lx: &mut Lexer<'_>) -> Result<Statement> {
    expect_word(lx, "INTO")?;
    expect_table(lx)?;
    if matches!(lx.peek(), Some(Token::LParen)) {
        let _ = lx.next_token();
        let key_col = lx.next_token();
        if !key_col.as_ref().is_some_and(|token| word_eq(token, "KEY")) {
            return Err(Error::Sql("a primeira coluna deve ser key".into()));
        }
        if !matches!(lx.next_token(), Some(Token::Comma)) {
            return Err(Error::Sql("esperado vírgula entre colunas".into()));
        }
        let value_col = lx.next_token();
        if !value_col
            .as_ref()
            .is_some_and(|token| word_eq(token, "VALUE"))
        {
            return Err(Error::Sql("a segunda coluna deve ser value".into()));
        }
        let rp = lx.next_token();
        if !matches!(rp, Some(Token::RParen)) {
            return Err(Error::Sql("esperado ) após lista de colunas".into()));
        }
    }
    expect_word(lx, "VALUES")?;
    let lp = lx.next_token();
    if !matches!(lp, Some(Token::LParen)) {
        return Err(Error::Sql("esperado ( após VALUES".into()));
    }
    let key = lit_from(
        lx.next_token()
            .ok_or_else(|| Error::Sql("esperado key".into()))?,
    )?;
    let comma = lx.next_token();
    if !matches!(comma, Some(Token::Comma)) {
        return Err(Error::Sql("esperado vírgula entre key e value".into()));
    }
    let value = lit_from(
        lx.next_token()
            .ok_or_else(|| Error::Sql("esperado value".into()))?,
    )?;
    let rp = lx.next_token();
    if !matches!(rp, Some(Token::RParen)) {
        return Err(Error::Sql("esperado ) após VALUES".into()));
    }
    let mut ttl = None;
    if lx.peek().is_some_and(|t| word_eq(&t, "TTL")) {
        let _ = lx.next_token();
        let secs = match lx.next_token() {
            Some(Token::Word(w)) => w.parse::<u64>().ok().filter(|s| *s > 0),
            _ => None,
        }
        .ok_or_else(|| Error::Sql("TTL espera segundos inteiros > 0".into()))?;
        ttl = Some(Duration::from_secs(secs));
    }
    Ok(Statement::Insert { key, value, ttl })
}

fn parse_update(lx: &mut Lexer<'_>) -> Result<Statement> {
    expect_table(lx)?;
    expect_word(lx, "SET")?;
    let col = lx
        .next_token()
        .ok_or_else(|| Error::Sql("esperado value".into()))?;
    if !word_eq(&col, "VALUE") && !word_eq(&col, "VAL") && !word_eq(&col, "V") {
        return Err(Error::Sql("UPDATE só altera value".into()));
    }
    let eq = lx.next_token();
    if !matches!(eq, Some(Token::Eq)) {
        return Err(Error::Sql("esperado =".into()));
    }
    let value = lit_from(
        lx.next_token()
            .ok_or_else(|| Error::Sql("esperado literal".into()))?,
    )?;
    expect_word(lx, "WHERE")?;
    let kcol = lx
        .next_token()
        .ok_or_else(|| Error::Sql("esperado key".into()))?;
    if !word_eq(&kcol, "KEY") && !word_eq(&kcol, "K") {
        return Err(Error::Sql("UPDATE WHERE deve ser key".into()));
    }
    let eq2 = lx.next_token();
    if !matches!(eq2, Some(Token::Eq)) {
        return Err(Error::Sql("esperado =".into()));
    }
    let key = lit_from(
        lx.next_token()
            .ok_or_else(|| Error::Sql("esperado key".into()))?,
    )?;
    Ok(Statement::Update { key, value })
}

fn parse_delete(lx: &mut Lexer<'_>) -> Result<Statement> {
    expect_word(lx, "FROM")?;
    expect_table(lx)?;
    expect_word(lx, "WHERE")?;
    let col = lx
        .next_token()
        .ok_or_else(|| Error::Sql("esperado key".into()))?;
    if !word_eq(&col, "KEY") && !word_eq(&col, "K") {
        return Err(Error::Sql("DELETE WHERE deve ser key".into()));
    }
    let eq = lx.next_token();
    if !matches!(eq, Some(Token::Eq)) {
        return Err(Error::Sql("esperado =".into()));
    }
    let key = lit_from(
        lx.next_token()
            .ok_or_else(|| Error::Sql("esperado literal".into()))?,
    )?;
    Ok(Statement::Delete { key })
}

fn parse_create(lx: &mut Lexer<'_>) -> Result<Statement> {
    expect_word(lx, "INDEX")?;
    if let Some(tok) = lx.peek() {
        if word_eq(&tok, "ON") {
            let _ = lx.next_token();
        } else if matches!(tok, Token::Word(_)) {
            let _ = lx.next_token(); // nome do índice
            expect_word(lx, "ON")?;
        }
    }
    expect_table(lx)?;
    if !matches!(lx.next_token(), Some(Token::LParen)) {
        return Err(Error::Sql("esperado ( após a tabela".into()));
    }
    let column = lx.next_token();
    if !column.as_ref().is_some_and(|token| word_eq(token, "VALUE")) {
        return Err(Error::Sql("índice deve usar a coluna value".into()));
    }
    if !matches!(lx.next_token(), Some(Token::RParen)) {
        return Err(Error::Sql("esperado ) no índice".into()));
    }
    Ok(Statement::CreateValueIndex)
}

fn expect_table(lx: &mut Lexer<'_>) -> Result<()> {
    let table = lx
        .next_token()
        .ok_or_else(|| Error::Sql("esperado nome de tabela".into()))?;
    match table {
        Token::Word(w) if w.eq_ignore_ascii_case("kv") || w.eq_ignore_ascii_case("t") => Ok(()),
        Token::Word(w) => Err(Error::UnknownTable(w)),
        _ => Err(Error::Sql("esperado identificador de tabela".into())),
    }
}

pub fn explain(stmt: &Statement) -> String {
    match stmt {
        Statement::Select {
            pred,
            order_desc,
            limit,
            count,
        } => {
            let acc = match pred {
                Some(Pred::KeyCmp { op: Cmp::Eq, .. }) => "primary point lookup",
                Some(Pred::KeyCmp {
                    op: Cmp::Ge | Cmp::Gt,
                    ..
                }) => "primary range scan from key",
                Some(Pred::KeyCmp { .. }) => "primary scan + filter",
                Some(Pred::ValueEq { .. }) => "secondary index by value",
                Some(Pred::KeyPrefix { .. }) => "primary prefix range scan",
                None => "full leaf chain scan",
            };
            let kind = if *count { "COUNT" } else { "SELECT" };
            format!("{kind} plan={acc} streaming=true order_desc={order_desc} limit={limit:?}")
        }
        Statement::Insert { ttl: None, .. } => "INSERT plan=wal+primary+secondary".into(),
        Statement::Insert { .. } => "INSERT plan=wal frame(put+expire)+primary+ttl".into(),
        Statement::Update { .. } => "UPDATE plan=point lookup + wal + index maintain".into(),
        Statement::Delete { .. } => "DELETE plan=point lookup + wal + index maintain".into(),
        Statement::CreateValueIndex => "CREATE INDEX plan=ensure secondary btree + backfill".into(),
        Statement::Begin => "BEGIN plan=open write-set".into(),
        Statement::Commit => "COMMIT plan=wal group + apply".into(),
        Statement::Rollback => "ROLLBACK plan=discard write-set".into(),
        Statement::Checkpoint => "CHECKPOINT plan=flush+sync+truncate wal".into(),
        Statement::Vacuum => "VACUUM plan=rebuild trees + checkpoint + shrink file".into(),
        Statement::Explain(inner) => format!("EXPLAIN {}", explain(inner)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_select_where_key() {
        let s =
            parse_sql("SELECT * FROM kv WHERE key = 'hero' ORDER BY key DESC LIMIT 10").unwrap();
        match s {
            Statement::Select {
                pred,
                order_desc,
                limit,
                ..
            } => {
                assert!(order_desc);
                assert_eq!(limit, Some(10));
                assert!(matches!(pred, Some(Pred::KeyCmp { op: Cmp::Eq, .. })));
            }
            _ => panic!("expected select"),
        }
    }

    #[test]
    fn parse_insert_values() {
        let s = parse_sql(r#"INSERT INTO kv (key, value) VALUES ("a", "1")"#).unwrap();
        match s {
            Statement::Insert { key, value, .. } => {
                assert_eq!(key, b"a");
                assert_eq!(value, b"1");
            }
            _ => panic!("expected insert"),
        }
    }
}
