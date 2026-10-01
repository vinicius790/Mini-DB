//! Expressões regulares (subconjunto POSIX/PCRE usado no SQL): literais, `.`,
//! `^`/`$`, classes `[a-z]`/`[^...]`, `\d \w \s \b` e negações, quantificadores
//! `* + ? {n,m}` (gulosos e preguiçosos `*?`), grupos `(...)`/`(?:...)` com
//! captura e alternância `|`, sinalizador `i`. Casamento por retrocesso com
//! limite de passos (padrões patológicos falham em vez de travar).

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
enum Node {
    Char(char),
    Any,
    Class(Vec<(char, char)>, bool),
    Start,
    End,
    WordBoundary(bool),
    Group(Box<Node>, Option<usize>),
    Alt(Vec<Node>),
    Seq(Vec<Node>),
    Repeat(Box<Node>, usize, Option<usize>, bool),
}

/// `(início, fim, capturas)` em índices de caracteres.
pub type Match = (usize, usize, Vec<Option<(usize, usize)>>);

#[derive(Debug, Clone)]
pub struct Regex {
    root: Node,
    groups: usize,
    ci: bool,
}

const MAX_STEPS: usize = 2_000_000;

struct Parser<'a> {
    chars: Vec<char>,
    pos: usize,
    groups: usize,
    depth: usize,
    src: &'a str,
}

/// Aninhamento máximo de grupos e tamanho máximo de texto (a busca é recursiva).
const MAX_GROUP_DEPTH: usize = 100;
const MAX_TEXT_CHARS: usize = 50_000;

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        self.pos += 1;
        c
    }

    fn err(&self, m: &str) -> Error {
        Error::Sql(format!("expressão regular inválida ({m}): {}", self.src))
    }

    fn alternation(&mut self) -> Result<Node> {
        let mut alts = vec![self.sequence()?];
        while self.peek() == Some('|') {
            self.pos += 1;
            alts.push(self.sequence()?);
        }
        Ok(if alts.len() == 1 {
            alts.pop().expect("um")
        } else {
            Node::Alt(alts)
        })
    }

    fn sequence(&mut self) -> Result<Node> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            items.push(self.quantified(atom)?);
        }
        Ok(Node::Seq(items))
    }

    fn quantified(&mut self, atom: Node) -> Result<Node> {
        let (min, max) = match self.peek() {
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('?') => (0, Some(1)),
            Some('{') => {
                let save = self.pos;
                self.pos += 1;
                let mut num = String::new();
                while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                    num.push(self.bump().expect("dígito"));
                }
                let Ok(min) = num.parse::<usize>() else {
                    self.pos = save;
                    return Ok(atom);
                };
                let max = if self.peek() == Some(',') {
                    self.pos += 1;
                    let mut n2 = String::new();
                    while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                        n2.push(self.bump().expect("dígito"));
                    }
                    if n2.is_empty() {
                        None
                    } else {
                        Some(n2.parse().map_err(|_| self.err("quantificador"))?)
                    }
                } else {
                    Some(min)
                };
                if self.peek() != Some('}') {
                    self.pos = save;
                    return Ok(atom);
                }
                (min, max)
            }
            _ => return Ok(atom),
        };
        self.pos += 1; // consome o quantificador (ou o '}')
        let lazy = self.peek() == Some('?');
        if lazy {
            self.pos += 1;
        }
        Ok(Node::Repeat(Box::new(atom), min, max, !lazy))
    }

    fn atom(&mut self) -> Result<Node> {
        let c = self.bump().ok_or_else(|| self.err("fim inesperado"))?;
        Ok(match c {
            '.' => Node::Any,
            '^' => Node::Start,
            '$' => Node::End,
            '(' => {
                let capture = if self.peek() == Some('?') {
                    self.pos += 1;
                    if self.bump() != Some(':') {
                        return Err(self.err("grupo (?"));
                    }
                    None
                } else {
                    self.groups += 1;
                    Some(self.groups)
                };
                self.depth += 1;
                if self.depth > MAX_GROUP_DEPTH {
                    return Err(self.err("grupos aninhados demais"));
                }
                let inner = self.alternation()?;
                self.depth -= 1;
                if self.bump() != Some(')') {
                    return Err(self.err("parêntese sem fechamento"));
                }
                Node::Group(Box::new(inner), capture)
            }
            '[' => self.class()?,
            '\\' => self.escape()?,
            '*' | '+' | '?' => return Err(self.err("quantificador sem alvo")),
            other => Node::Char(other),
        })
    }

    fn escape(&mut self) -> Result<Node> {
        let c = self.bump().ok_or_else(|| self.err("escape no fim"))?;
        Ok(match c {
            'd' => Node::Class(vec![('0', '9')], false),
            'D' => Node::Class(vec![('0', '9')], true),
            'w' => Node::Class(word_ranges(), false),
            'W' => Node::Class(word_ranges(), true),
            's' => Node::Class(space_ranges(), false),
            'S' => Node::Class(space_ranges(), true),
            'b' => Node::WordBoundary(true),
            'B' => Node::WordBoundary(false),
            'n' => Node::Char('\n'),
            't' => Node::Char('\t'),
            'r' => Node::Char('\r'),
            other => Node::Char(other),
        })
    }

    fn class(&mut self) -> Result<Node> {
        let negated = self.peek() == Some('^');
        if negated {
            self.pos += 1;
        }
        let mut ranges = Vec::new();
        let mut first = true;
        loop {
            let c = self
                .bump()
                .ok_or_else(|| self.err("classe sem fechamento"))?;
            if c == ']' && !first {
                break;
            }
            first = false;
            let lo = if c == '\\' {
                match self.bump().ok_or_else(|| self.err("escape"))? {
                    'd' => {
                        ranges.push(('0', '9'));
                        continue;
                    }
                    'w' => {
                        ranges.extend(word_ranges());
                        continue;
                    }
                    's' => {
                        ranges.extend(space_ranges());
                        continue;
                    }
                    'n' => '\n',
                    't' => '\t',
                    other => other,
                }
            } else if c == '[' && self.peek() == Some(':') {
                // [:alpha:] etc.
                let rest = &self.chars[self.pos..];
                let end = rest
                    .windows(2)
                    .enumerate()
                    .skip(1)
                    .find(|(_, w)| w[0] == ':' && w[1] == ']')
                    .map(|(i, _)| i)
                    .ok_or_else(|| self.err("classe POSIX"))?;
                let name: String = rest[1..end].iter().collect();
                self.pos += end + 2;
                ranges.extend(match name.as_str() {
                    "alpha" => vec![('a', 'z'), ('A', 'Z')],
                    "digit" => vec![('0', '9')],
                    "alnum" => vec![('a', 'z'), ('A', 'Z'), ('0', '9')],
                    "space" => space_ranges(),
                    "upper" => vec![('A', 'Z')],
                    "lower" => vec![('a', 'z')],
                    "punct" => vec![('!', '/'), (':', '@'), ('[', '`'), ('{', '~')],
                    _ => return Err(self.err("classe POSIX desconhecida")),
                });
                continue;
            } else {
                c
            };
            if self.peek() == Some('-') && self.chars.get(self.pos + 1).is_some_and(|&x| x != ']') {
                self.pos += 1;
                let hi = self.bump().expect("existe");
                ranges.push((lo, hi));
            } else {
                ranges.push((lo, lo));
            }
        }
        Ok(Node::Class(ranges, negated))
    }
}

fn word_ranges() -> Vec<(char, char)> {
    vec![('a', 'z'), ('A', 'Z'), ('0', '9'), ('_', '_')]
}

fn space_ranges() -> Vec<(char, char)> {
    vec![
        (' ', ' '),
        ('\t', '\t'),
        ('\n', '\n'),
        ('\r', '\r'),
        ('\u{0B}', '\u{0C}'),
    ]
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

struct Matcher<'r> {
    text: Vec<char>,
    ci: bool,
    steps: usize,
    caps: Vec<Option<(usize, usize)>>,
    _r: std::marker::PhantomData<&'r ()>,
}

impl Matcher<'_> {
    fn eq(&self, a: char, b: char) -> bool {
        if self.ci {
            a.to_lowercase().eq(b.to_lowercase())
        } else {
            a == b
        }
    }

    fn in_class(&self, c: char, ranges: &[(char, char)]) -> bool {
        let hit = |c: char| ranges.iter().any(|&(lo, hi)| c >= lo && c <= hi);
        hit(c) || (self.ci && (c.to_lowercase().any(hit) || c.to_uppercase().any(hit)))
    }

    /// Tenta casar `node` em `pos` e continua com `k`; devolve a posição final.
    fn m(
        &mut self,
        node: &Node,
        pos: usize,
        k: &mut dyn FnMut(&mut Self, usize) -> Option<usize>,
    ) -> Option<usize> {
        self.steps += 1;
        if self.steps > MAX_STEPS {
            return None;
        }
        match node {
            Node::Char(c) => {
                if pos < self.text.len() && self.eq(self.text[pos], *c) {
                    k(self, pos + 1)
                } else {
                    None
                }
            }
            Node::Any => {
                if pos < self.text.len() && self.text[pos] != '\n' {
                    k(self, pos + 1)
                } else {
                    None
                }
            }
            Node::Class(ranges, negated) => {
                if pos < self.text.len() && self.in_class(self.text[pos], ranges) != *negated {
                    k(self, pos + 1)
                } else {
                    None
                }
            }
            Node::Start => (pos == 0).then(|| k(self, pos)).flatten(),
            Node::End => (pos == self.text.len()).then(|| k(self, pos)).flatten(),
            Node::WordBoundary(want) => {
                let before = pos > 0 && is_word(self.text[pos - 1]);
                let after = pos < self.text.len() && is_word(self.text[pos]);
                ((before != after) == *want).then(|| k(self, pos)).flatten()
            }
            Node::Group(inner, cap) => {
                let cap = *cap;
                let saved = cap.and_then(|i| self.caps[i]);
                let r = self.m(inner, pos, &mut |me, end| {
                    if let Some(i) = cap {
                        let prev = me.caps[i];
                        me.caps[i] = Some((pos, end));
                        let r = k(me, end);
                        if r.is_none() {
                            me.caps[i] = prev;
                        }
                        r
                    } else {
                        k(me, end)
                    }
                });
                if r.is_none() {
                    if let Some(i) = cap {
                        self.caps[i] = saved;
                    }
                }
                r
            }
            Node::Alt(alts) => {
                for a in alts {
                    if let Some(r) = self.m(a, pos, k) {
                        return Some(r);
                    }
                }
                None
            }
            Node::Seq(items) => self.seq(items, pos, k),
            Node::Repeat(inner, min, max, greedy) => {
                self.repeat(inner, *min, *max, *greedy, pos, 0, k)
            }
        }
    }

    fn seq(
        &mut self,
        items: &[Node],
        pos: usize,
        k: &mut dyn FnMut(&mut Self, usize) -> Option<usize>,
    ) -> Option<usize> {
        match items.split_first() {
            None => k(self, pos),
            Some((first, rest)) => self.m(first, pos, &mut |me, p| me.seq(rest, p, k)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn repeat(
        &mut self,
        inner: &Node,
        min: usize,
        max: Option<usize>,
        greedy: bool,
        pos: usize,
        count: usize,
        k: &mut dyn FnMut(&mut Self, usize) -> Option<usize>,
    ) -> Option<usize> {
        let can_more = max.is_none_or(|m| count < m);
        if count < min {
            return self.more(inner, min, max, greedy, pos, count, k);
        }
        if greedy {
            if can_more {
                if let Some(r) = self.more(inner, min, max, greedy, pos, count, k) {
                    return Some(r);
                }
            }
            k(self, pos)
        } else {
            if let Some(r) = k(self, pos) {
                return Some(r);
            }
            if can_more {
                self.more(inner, min, max, greedy, pos, count, k)
            } else {
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn more(
        &mut self,
        inner: &Node,
        min: usize,
        max: Option<usize>,
        greedy: bool,
        pos: usize,
        count: usize,
        k: &mut dyn FnMut(&mut Self, usize) -> Option<usize>,
    ) -> Option<usize> {
        self.m(inner, pos, &mut |me, p| {
            if p == pos {
                return None; // repetição vazia: evita laço infinito
            }
            me.repeat(inner, min, max, greedy, p, count + 1, k)
        })
    }
}

impl Regex {
    pub fn new(pattern: &str, flags: &str) -> Result<Self> {
        let mut p = Parser {
            chars: pattern.chars().collect(),
            pos: 0,
            groups: 0,
            depth: 0,
            src: pattern,
        };
        let root = p.alternation()?;
        if p.pos < p.chars.len() {
            return Err(p.err("parêntese a mais"));
        }
        Ok(Self {
            root,
            groups: p.groups,
            ci: flags.contains('i'),
        })
    }

    /// Primeiro casamento a partir de `start`: `(início, fim, capturas)`.
    pub fn find_at(&self, text: &[char], start: usize) -> Option<Match> {
        if text.len() > MAX_TEXT_CHARS {
            return None;
        }
        let mut m = Matcher {
            text: text.to_vec(),
            ci: self.ci,
            steps: 0,
            caps: vec![None; self.groups + 1],
            _r: std::marker::PhantomData,
        };
        for s in start..=text.len() {
            m.steps = 0;
            m.caps = vec![None; self.groups + 1];
            if let Some(end) = m.m(&self.root, s, &mut |_, e| Some(e)) {
                m.caps[0] = Some((s, end));
                return Some((s, end, m.caps));
            }
            if m.steps > MAX_STEPS {
                return None;
            }
        }
        None
    }

    pub fn is_match(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        self.find_at(&chars, 0).is_some()
    }

    /// Todas as ocorrências (não sobrepostas).
    pub fn find_all(&self, text: &str) -> Vec<Match> {
        let chars: Vec<char> = text.chars().collect();
        let mut out = Vec::new();
        let mut pos = 0;
        while pos <= chars.len() {
            let Some((s, e, caps)) = self.find_at(&chars, pos) else {
                break;
            };
            out.push((s, e, caps));
            pos = if e == s { e + 1 } else { e };
        }
        out
    }

    /// Substitui (`all` = todas) usando `\\1`/`$1` nas capturas.
    pub fn replace(&self, text: &str, replacement: &str, all: bool) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut last = 0;
        for (s, e, caps) in self.find_all(text) {
            out.extend(&chars[last..s]);
            let rep: Vec<char> = replacement.chars().collect();
            let mut i = 0;
            while i < rep.len() {
                let c = rep[i];
                if (c == '\\' || c == '$') && i + 1 < rep.len() && rep[i + 1].is_ascii_digit() {
                    let g = rep[i + 1].to_digit(10).expect("dígito") as usize;
                    if let Some(Some((a, b))) = caps.get(g) {
                        out.extend(&chars[*a..*b]);
                    }
                    i += 2;
                } else if c == '\\' && i + 1 < rep.len() {
                    out.push(rep[i + 1]);
                    i += 2;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            last = e;
            if !all {
                break;
            }
        }
        out.extend(&chars[last..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, t: &str) -> bool {
        Regex::new(p, "").unwrap().is_match(t)
    }

    #[test]
    fn matches_common_patterns() {
        assert!(m("^(jogadores)$", "jogadores"));
        assert!(!m("^(jogadores)$", "jogadores2"));
        assert!(m("^pg_", "pg_toast"));
        assert!(!m("^pg_", "public"));
        assert!(m("a.c", "abc"));
        assert!(m("^\\d{3}-\\d{4}$", "123-4567"));
        assert!(!m("^\\d{3}-\\d{4}$", "12-4567"));
        assert!(m("colou?r", "color") && m("colou?r", "colour"));
        assert!(m("(ab)+c", "ababc") && !m("^(ab)+c$", "abac"));
        assert!(m("[A-Z][a-z]+", "Olá") && !m("^[^a-z]+$", "abc"));
        assert!(m("gato|cão", "um cão") && !m("gato|cão", "pato"));
        assert!(m("\\bfim\\b", "o fim.") && !m("\\bfim\\b", "afim"));
        assert!(Regex::new("GATO", "i").unwrap().is_match("um gato"));
        assert!(m("a*", ""));
        assert!(Regex::new("(", "").is_err());
        let r = Regex::new("(\\w+)@(\\w+)\\.com", "").unwrap();
        assert_eq!(
            r.replace("x ana@site.com y", "\\2:\\1", true),
            "x site:ana y"
        );
        assert_eq!(
            Regex::new("o", "").unwrap().replace("foo boo", "0", true),
            "f00 b00"
        );
        assert_eq!(
            Regex::new("o", "").unwrap().replace("foo boo", "0", false),
            "f0o boo"
        );
        assert_eq!(Regex::new("a+?", "").unwrap().find_all("aaa").len(), 3);
        assert_eq!(
            Regex::new("[[:digit:]]+", "")
                .unwrap()
                .find_all("a12b3")
                .len(),
            2
        );
    }
}
