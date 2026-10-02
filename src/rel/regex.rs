//! Expressões regulares (subconjunto POSIX/PCRE usado no SQL): literais, `.`,
//! `^`/`$`, classes `[a-z]`/`[^...]`, `\d \w \s \b` e negações, quantificadores
//! `* + ? {n,m}` (gulosos e preguiçosos `*?`), grupos `(...)`/`(?:...)` com
//! captura e alternância `|`, sinalizador `i`. O padrão é compilado para um programa
//! de instruções e casado por retrocesso numa máquina com pilha explícita (no heap, sem
//! recursão nativa), com limite de passos por posição inicial e por varredura
//! (padrões patológicos falham em vez de travar).

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
    prog: Vec<Inst>,
    /// Registradores da máquina: `2 * (groups + 1)` de captura, mais os dos laços.
    regs: usize,
    groups: usize,
    ci: bool,
}

const MAX_STEPS: usize = 2_000_000;
/// Passos de uma varredura inteira, somados entre as posições iniciais (`MAX_STEPS` vale
/// para cada uma; sem a soma o pior caso seria `MAX_STEPS` vezes o tamanho do texto).
/// Folga para buscas quadráticas legítimas: `[a-z]+\d` sobre 10 mil letras gasta 1e8.
const MAX_TOTAL_STEPS: usize = 100 * MAX_STEPS;
/// Molduras da pilha de retrocesso (16 bytes cada, no heap); acima disso a busca é
/// abandonada, como em `MAX_STEPS`. Cada instrução empilha no máximo uma, então o limite
/// só corta o que já estouraria os passos, mas fixa a memória em uns 32 MB.
const MAX_FRAMES: usize = MAX_STEPS;

struct Parser<'a> {
    chars: Vec<char>,
    pos: usize,
    groups: usize,
    depth: usize,
    src: &'a str,
}

/// Aninhamento máximo de grupos (o parser e o compilador são recursivos) e tamanho máximo
/// de texto.
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

/// Registrador de captura ainda não escrito.
const NONE: u32 = u32::MAX;

/// Instrução da máquina de retrocesso. Os registradores guardam posições e contadores
/// (`u32`: o texto tem no máximo `MAX_TEXT_CHARS` caracteres); os de captura ficam em
/// `2 * grupo` (início) e `2 * grupo + 1` (fim).
#[derive(Debug, Clone)]
enum Inst {
    Char(char),
    Any,
    Class(Vec<(char, char)>, bool),
    Start,
    End,
    WordBoundary(bool),
    /// Empilha um ponto de retrocesso em `.0` (mesma posição) e segue para a próxima
    /// instrução, que é a alternativa preferida.
    Split(usize),
    Jmp(usize),
    /// Grava a posição atual no registrador `.0`.
    Save(usize),
    /// Zera o registrador `.0` (contador de voltas).
    Zero(usize),
    /// Cabeça de um laço de grupo, que decide entre mais uma volta e a saída:
    /// `(contador, mínimo, máximo, guloso, saída)`. A volta começa na instrução seguinte.
    Loop(usize, usize, Option<usize>, bool, usize),
    /// Fim de uma volta: `(contador, registrador do início da volta, cabeça)`. Volta vazia
    /// é recusada (evita laço infinito); senão conta a volta e retorna à cabeça.
    LoopEnd(usize, usize, usize),
    /// Repetição de um átomo de um caractere (`Char`, `Any` ou `Class`) em laço, com um só
    /// ponto de retrocesso: `(átomo, mínimo, máximo, guloso)`.
    RepOne(Box<Inst>, usize, Option<usize>, bool),
    Match,
}

/// Entrada da pilha de retrocesso (no heap): as posições cabem em `u32` pelo mesmo motivo
/// dos registradores.
enum Frame {
    /// Retoma em `(instrução, posição)`.
    Choice(u32, u32),
    /// Desfaz uma escrita: `(registrador, valor antigo)`.
    Restore(u32, u32),
    /// `RepOne` guloso: retoma em `(instrução, posição, piso)` e, enquanto a posição
    /// estiver acima do piso, deixa uma moldura para a posição anterior.
    Greedy(u32, u32, u32),
    /// `RepOne` preguiçoso: `(a própria instrução, posição, fim)`; estende o casamento
    /// por mais um caractere (se a posição estiver antes de `fim`) e retoma na seguinte.
    Lazy(u32, u32, u32),
}

/// Instrução de um caractere equivalente ao nó, se ele for `Char`, `Any` ou `Class`.
fn single(node: &Node) -> Option<Inst> {
    match node {
        Node::Char(c) => Some(Inst::Char(*c)),
        Node::Any => Some(Inst::Any),
        Node::Class(ranges, negated) => Some(Inst::Class(ranges.clone(), *negated)),
        _ => None,
    }
}

struct Compiler {
    prog: Vec<Inst>,
    regs: usize,
}

impl Compiler {
    fn node(&mut self, node: &Node) {
        match node {
            Node::Char(_) | Node::Any | Node::Class(..) => self.prog.extend(single(node)),
            Node::Start => self.prog.push(Inst::Start),
            Node::End => self.prog.push(Inst::End),
            Node::WordBoundary(want) => self.prog.push(Inst::WordBoundary(*want)),
            Node::Group(inner, cap) => {
                if let Some(g) = *cap {
                    self.prog.push(Inst::Save(2 * g));
                    self.node(inner);
                    self.prog.push(Inst::Save(2 * g + 1));
                } else {
                    self.node(inner);
                }
            }
            Node::Alt(alts) => self.alt(alts),
            Node::Seq(items) => {
                for item in items {
                    self.node(item);
                }
            }
            Node::Repeat(inner, min, max, greedy) => self.repeat(inner, *min, *max, *greedy),
        }
    }

    /// `a|b|c`: cada alternativa, menos a última, é precedida de um `Split` para a próxima
    /// e termina num `Jmp` para o fim; a ordem das tentativas é a da escrita.
    fn alt(&mut self, alts: &[Node]) {
        let mut jumps = Vec::new();
        for (i, alt) in alts.iter().enumerate() {
            if i + 1 == alts.len() {
                self.node(alt);
                break;
            }
            let split = self.prog.len();
            self.prog.push(Inst::Split(0));
            self.node(alt);
            jumps.push(self.prog.len());
            self.prog.push(Inst::Jmp(0));
            self.prog[split] = Inst::Split(self.prog.len());
        }
        let end = self.prog.len();
        for j in jumps {
            self.prog[j] = Inst::Jmp(end);
        }
    }

    /// Repetição de `inner`: um átomo de um caractere vira `RepOne`; o resto, um laço com
    /// contador (sem desenrolar, para que `(ab){1000000}` não gaste memória).
    fn repeat(&mut self, inner: &Node, min: usize, max: Option<usize>, greedy: bool) {
        if let Some(atom) = single(inner) {
            self.prog.push(Inst::RepOne(Box::new(atom), min, max, greedy));
            return;
        }
        let (count, start) = (self.regs, self.regs + 1);
        self.regs += 2;
        self.prog.push(Inst::Zero(count));
        let head = self.prog.len();
        self.prog.push(Inst::Loop(count, min, max, greedy, 0));
        self.prog.push(Inst::Save(start));
        self.node(inner);
        self.prog.push(Inst::LoopEnd(count, start, head));
        self.prog[head] = Inst::Loop(count, min, max, greedy, self.prog.len());
    }
}

struct Matcher<'r> {
    text: &'r [char],
    ci: bool,
    steps: usize,
    regs: Vec<u32>,
    stack: Vec<Frame>,
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

    /// `inst` (`Char`, `Any` ou `Class`) casa o caractere em `pos`?
    fn one(&self, inst: &Inst, pos: usize) -> bool {
        let Some(&c) = self.text.get(pos) else {
            return false;
        };
        match inst {
            Inst::Char(x) => self.eq(c, *x),
            Inst::Any => c != '\n',
            Inst::Class(ranges, negated) => self.in_class(c, ranges) != *negated,
            _ => false,
        }
    }

    fn push_choice(&mut self, pc: usize, pos: usize) {
        self.stack.push(Frame::Choice(pc as u32, pos as u32));
    }

    /// Escreve um registrador guardando o valor antigo na pilha: o retrocesso o desfaz.
    fn set(&mut self, reg: usize, val: u32) {
        let frame = Frame::Restore(reg as u32, self.regs[reg]);
        self.stack.push(frame);
        self.regs[reg] = val;
    }

    /// Executa o programa a partir de `start` e devolve o fim do primeiro casamento, na
    /// ordem de preferência (gulosos e alternativas pela ordem escrita). Cada passo conta
    /// em `steps`; passou de `MAX_STEPS` (ou de `MAX_FRAMES`), a busca é abandonada.
    fn run(&mut self, prog: &[Inst], start: usize) -> Option<usize> {
        self.stack.clear();
        let (mut pc, mut pos) = (0, start);
        loop {
            self.steps += 1;
            if self.steps > MAX_STEPS || self.stack.len() > MAX_FRAMES {
                self.steps = MAX_STEPS + 1; // fundo demais: abandona a busca inteira
                return None;
            }
            // `Some((instrução, posição))` segue adiante; `None` é falha e retrocede.
            let next = match &prog[pc] {
                Inst::Match => return Some(pos),
                Inst::Start => (pos == 0).then_some((pc + 1, pos)),
                Inst::End => (pos == self.text.len()).then_some((pc + 1, pos)),
                Inst::WordBoundary(want) => {
                    let before = pos > 0 && is_word(self.text[pos - 1]);
                    let after = pos < self.text.len() && is_word(self.text[pos]);
                    ((before != after) == *want).then_some((pc + 1, pos))
                }
                Inst::Split(alt) => {
                    self.push_choice(*alt, pos);
                    Some((pc + 1, pos))
                }
                Inst::Jmp(to) => Some((*to, pos)),
                Inst::Save(reg) => {
                    self.set(*reg, pos as u32);
                    Some((pc + 1, pos))
                }
                Inst::Zero(reg) => {
                    self.set(*reg, 0);
                    Some((pc + 1, pos))
                }
                Inst::Loop(count, min, max, greedy, exit) => {
                    let n = self.regs[*count] as usize;
                    let can_more = max.is_none_or(|m| n < m);
                    if n < *min {
                        Some((pc + 1, pos))
                    } else if !can_more {
                        Some((*exit, pos))
                    } else if *greedy {
                        self.push_choice(*exit, pos);
                        Some((pc + 1, pos))
                    } else {
                        self.push_choice(pc + 1, pos);
                        Some((*exit, pos))
                    }
                }
                Inst::LoopEnd(count, begin, head) => {
                    if pos == self.regs[*begin] as usize {
                        None
                    } else {
                        self.set(*count, self.regs[*count] + 1);
                        Some((*head, pos))
                    }
                }
                Inst::RepOne(atom, min, max, greedy) => {
                    self.rep_one(pc, atom, *min, *max, *greedy, pos)
                }
                // `Char`, `Any` e `Class`.
                consume => self.one(consume, pos).then_some((pc + 1, pos + 1)),
            };
            (pc, pos) = next.or_else(|| self.backtrack(prog))?;
        }
    }

    /// `RepOne` em `pc`: laço de átomo único, sem pilha nativa nem uma moldura por
    /// caractere. Tenta primeiro o mais longo (guloso) ou o mais curto (preguiçoso).
    fn rep_one(
        &mut self,
        pc: usize,
        atom: &Inst,
        min: usize,
        max: Option<usize>,
        greedy: bool,
        pos: usize,
    ) -> Option<(usize, usize)> {
        let limit = max.map_or(usize::MAX, |m| m.max(min));
        if greedy {
            let mut n = 0;
            while n < limit && self.one(atom, pos + n) {
                n += 1;
            }
            self.steps += n;
            if n < min {
                return None;
            }
            if n > min {
                // Do mais longo para o mais curto: `n` agora, depois `n - 1` até `min`.
                let (next, below, floor) = (pc as u32 + 1, pos + n - 1, pos + min);
                let frame = Frame::Greedy(next, below as u32, floor as u32);
                self.stack.push(frame);
            }
            return Some((pc + 1, pos + n));
        }
        if !(0..min).all(|i| self.one(atom, pos + i)) {
            return None;
        }
        self.steps += min;
        let cur = pos + min;
        let end = pos.saturating_add(limit).min(self.text.len());
        if cur < end {
            let frame = Frame::Lazy(pc as u32, cur as u32, end as u32);
            self.stack.push(frame);
        }
        Some((pc + 1, cur))
    }

    /// Desfaz a pilha até o ponto de escolha mais recente e devolve onde retomar
    /// (`None`: acabaram as alternativas).
    fn backtrack(&mut self, prog: &[Inst]) -> Option<(usize, usize)> {
        while let Some(frame) = self.stack.pop() {
            match frame {
                Frame::Restore(reg, old) => self.regs[reg as usize] = old,
                Frame::Choice(pc, pos) => return Some((pc as usize, pos as usize)),
                Frame::Greedy(pc, pos, floor) => {
                    if pos > floor {
                        self.stack.push(Frame::Greedy(pc, pos - 1, floor));
                    }
                    return Some((pc as usize, pos as usize));
                }
                Frame::Lazy(pc, pos, end) => {
                    if let Inst::RepOne(atom, ..) = &prog[pc as usize] {
                        if self.one(atom, pos as usize) {
                            self.steps += 1;
                            if pos + 1 < end {
                                self.stack.push(Frame::Lazy(pc, pos + 1, end));
                            }
                            return Some((pc as usize + 1, pos as usize + 1));
                        }
                    }
                }
            }
        }
        None
    }

    /// Capturas do casamento `(start, end)`; o grupo 0 é o casamento inteiro.
    fn captures(&self, groups: usize, start: usize, end: usize) -> Vec<Option<(usize, usize)>> {
        let mut caps = vec![Some((start, end))];
        for g in 1..=groups {
            let (a, b) = (self.regs[2 * g], self.regs[2 * g + 1]);
            let set = a != NONE && b != NONE;
            caps.push(set.then_some((a as usize, b as usize)));
        }
        caps
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
        let mut compiler = Compiler {
            prog: Vec::new(),
            regs: 2 * (p.groups + 1),
        };
        compiler.node(&root);
        compiler.prog.push(Inst::Match);
        Ok(Self {
            prog: compiler.prog,
            regs: compiler.regs,
            groups: p.groups,
            ci: flags.contains('i'),
        })
    }

    /// Primeiro casamento a partir de `start`: `(início, fim, capturas)`.
    pub fn find_at(&self, text: &[char], start: usize) -> Option<Match> {
        let mut budget = MAX_TOTAL_STEPS;
        self.find_from(text, start, &mut budget)
    }

    /// `find_at` que desconta de `budget` os passos de cada posição inicial; estourado o
    /// orçamento, a busca é abandonada (`None`), como em `MAX_STEPS`.
    fn find_from(&self, text: &[char], start: usize, budget: &mut usize) -> Option<Match> {
        if text.len() > MAX_TEXT_CHARS {
            return None;
        }
        let mut m = Matcher {
            text,
            ci: self.ci,
            steps: 0,
            regs: vec![NONE; self.regs],
            stack: Vec::new(),
        };
        // Só as capturas precisam voltar a `NONE`: os registradores dos laços são
        // sempre escritos (`Zero`/`Save`) antes de lidos.
        let cap_regs = 2 * (self.groups + 1);
        for s in start..=text.len() {
            m.steps = 0;
            m.regs[..cap_regs].fill(NONE);
            let found = m.run(&self.prog, s);
            // Busca cortada pelo limite: um `Some` aqui seria um casamento truncado.
            if m.steps > MAX_STEPS || m.steps > *budget {
                return None;
            }
            *budget -= m.steps;
            if let Some(end) = found {
                return Some((s, end, m.captures(self.groups, s, end)));
            }
        }
        None
    }

    pub fn is_match(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        self.find_at(&chars, 0).is_some()
    }

    /// Todas as ocorrências (não sobrepostas). O orçamento de passos é um só para a
    /// varredura inteira: esgotado, devolve as ocorrências achadas até ali.
    pub fn find_all(&self, text: &str) -> Vec<Match> {
        let chars: Vec<char> = text.chars().collect();
        let mut out = Vec::new();
        let mut budget = MAX_TOTAL_STEPS;
        let mut pos = 0;
        while pos <= chars.len() {
            let Some((s, e, caps)) = self.find_from(&chars, pos, &mut budget) else {
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

    #[test]
    fn total_budget_is_shared_by_start_positions() {
        // `a+b` recua em cada uma das 100 posições iniciais (uns 200 passos cada) antes
        // de chegar ao `ab` do fim: nenhuma estoura sozinha, a soma passa de 10 mil.
        let re = Regex::new("a+b", "").unwrap();
        let text: Vec<char> = format!("{} ab", "a".repeat(100)).chars().collect();
        let (mut small, mut large) = (1_000, 1_000_000);
        assert!(re.find_from(&text, 0, &mut small).is_none());
        let found = re.find_from(&text, 0, &mut large);
        assert_eq!(found.map(|(s, e, _)| (s, e)), Some((101, 103)));
    }

    fn find(p: &str, t: &str) -> Match {
        let chars: Vec<char> = t.chars().collect();
        Regex::new(p, "").unwrap().find_at(&chars, 0).unwrap()
    }

    #[test]
    fn long_inputs_have_no_depth_limit() {
        let ab = "ab".repeat(10_000);
        assert!(m("(ab)*c", &format!("{ab}c")));
        assert!(!m("^(ab)*c", &ab));
        assert!(m("^(a|b)+$", &ab.repeat(2)));
        let literal = "ab".repeat(1_000);
        assert!(m(&format!("^{literal}$"), &literal));
        assert!(!m(&format!("^{literal}$"), &format!("{literal}x")));
    }

    #[test]
    fn pathological_patterns_return() {
        let long = "a".repeat(50_000);
        assert!(!m("(a*)*b", &long));
        assert!(m("(a|aa)+$", &long));
    }

    #[test]
    fn captures_and_lazy_quantifiers() {
        let (s, e, caps) = find("(a)(b)?", "ab");
        assert_eq!((s, e), (0, 2));
        assert_eq!(caps, vec![Some((0, 2)), Some((0, 1)), Some((1, 2))]);
        let (s, e, caps) = find("(a)(b)?", "ac");
        assert_eq!((s, e), (0, 1));
        assert_eq!(caps, vec![Some((0, 1)), Some((0, 1)), None]);
        let (s, e, _) = find("a+?b", "aaab");
        assert_eq!((s, e), (0, 4));
        assert_eq!(find("a+?", "aaa").1, 1);
        assert_eq!(find("a{2,3}?", "aaaa").1, 2);
        assert_eq!(find("a{2,3}", "aaaa").1, 3);
        // A ordem das alternativas decide, e uma volta vazia não vira captura.
        let (_, e, caps) = find("(a|ab)(c|bcd)(d*)", "abcd");
        assert_eq!(e, 4);
        let want = vec![Some((0, 4)), Some((0, 1)), Some((1, 4)), Some((4, 4))];
        assert_eq!(caps, want);
        let (_, e, caps) = find("(a*)*", "aa");
        assert_eq!(e, 2);
        assert_eq!(caps, vec![Some((0, 2)), Some((0, 2))]);
    }
}
