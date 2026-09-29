//! Encoder/decoder JSON mínimo (objetos string/número/bool/null/array).
//! Suficiente para a API HTTP e para export JSONL — sem serde.

use crate::error::{Error, Result};
use std::collections::BTreeMap;

const MAX_JSON_DEPTH: usize = 128;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(i64),
    Float(f64),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> Self {
        Json::Object(BTreeMap::new())
    }

    pub fn put(mut self, k: &str, v: Json) -> Self {
        if let Json::Object(m) = &mut self {
            m.insert(k.to_string(), v);
        }
        self
    }

    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.get(k),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn stringify(&self) -> String {
        let mut out = String::new();
        write_json(self, &mut out);
        out
    }

    pub fn parse(input: &str) -> Result<Json> {
        let mut p = Parser {
            s: input.as_bytes(),
            i: 0,
            depth: 0,
        };
        p.skip_ws();
        let v = p.value()?;
        p.skip_ws();
        if p.i != p.s.len() {
            return Err(Error::Other("JSON possui conteúdo após o valor".into()));
        }
        Ok(v)
    }
}

fn write_json(v: &Json, out: &mut String) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(n) => out.push_str(&n.to_string()),
        // `Debug` preserva o ponto decimal (`3.0`) e usa expoente em valores
        // extremos (`1e300`), garantindo que o valor volte a ser lido como float.
        Json::Float(n) => out.push_str(&format!("{n:?}")),
        Json::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\u{0008}' => out.push_str("\\b"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\u{000C}' => out.push_str("\\f"),
                    c if c <= '\u{001F}' => {
                        use std::fmt::Write as _;
                        write!(out, "\\u{:04x}", c as u32).unwrap();
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Json::Array(xs) => {
            out.push('[');
            for (i, x) in xs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(x, out);
            }
            out.push(']');
        }
        Json::Object(m) => {
            out.push('{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(&Json::String(k.clone()), out);
                out.push(':');
                write_json(v, out);
            }
            out.push('}');
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }

    fn value(&mut self) -> Result<Json> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') | Some(b'[') => {
                if self.depth >= MAX_JSON_DEPTH {
                    return Err(Error::Other("JSON nesting is too deep".into()));
                }
                self.depth += 1;
                let value = if self.peek() == Some(b'{') {
                    self.object()
                } else {
                    self.array()
                };
                self.depth -= 1;
                value
            }
            Some(b'n') => self.ident("null").map(|_| Json::Null),
            Some(b't') => self.ident("true").map(|_| Json::Bool(true)),
            Some(b'f') => self.ident("false").map(|_| Json::Bool(false)),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            _ => Err(Error::Other("JSON inválido".into())),
        }
    }

    fn ident(&mut self, w: &str) -> Result<()> {
        for b in w.bytes() {
            if self.bump() != Some(b) {
                return Err(Error::Other("JSON inválido".into()));
            }
        }
        Ok(())
    }

    fn string(&mut self) -> Result<String> {
        if self.bump() != Some(b'"') {
            return Err(Error::Other("JSON string".into()));
        }
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(Error::Other("JSON string sem fechar".into())),
                Some(b'"') => return Ok(out),
                Some(b'\\') => match self.bump() {
                    Some(b'"') => out.push('"'),
                    Some(b'\\') => out.push('\\'),
                    Some(b'/') => out.push('/'),
                    Some(b'b') => out.push('\u{0008}'),
                    Some(b'f') => out.push('\u{000C}'),
                    Some(b'n') => out.push('\n'),
                    Some(b'r') => out.push('\r'),
                    Some(b't') => out.push('\t'),
                    Some(b'u') => out.push(self.unicode_escape()?),
                    None => return Err(Error::Other("escape".into())),
                    _ => return Err(Error::Other("escape JSON inválido".into())),
                },
                Some(0x00..=0x1f) => {
                    return Err(Error::Other("controle não escapado em JSON string".into()));
                }
                Some(c) if c.is_ascii() => out.push(c as char),
                Some(first) => {
                    let start = self.i - 1;
                    let width = match first {
                        0xC2..=0xDF => 2,
                        0xE0..=0xEF => 3,
                        0xF0..=0xF4 => 4,
                        _ => return Err(Error::Other("UTF-8 inválido em JSON string".into())),
                    };
                    let end = start + width;
                    let bytes = self
                        .s
                        .get(start..end)
                        .ok_or_else(|| Error::Other("UTF-8 incompleto em JSON string".into()))?;
                    let character = std::str::from_utf8(bytes)
                        .map_err(|_| Error::Other("UTF-8 inválido em JSON string".into()))?;
                    out.push_str(character);
                    self.i = end;
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char> {
        let first = self.hex_quad()?;
        let scalar = match first {
            0xD800..=0xDBFF => {
                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                    return Err(Error::Other("surrogate JSON incompleto".into()));
                }
                let second = self.hex_quad()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return Err(Error::Other("surrogate JSON inválido".into()));
                }
                0x10000 + (((first - 0xD800) as u32) << 10) + (second - 0xDC00) as u32
            }
            0xDC00..=0xDFFF => return Err(Error::Other("surrogate JSON isolado".into())),
            value => value as u32,
        };
        char::from_u32(scalar).ok_or_else(|| Error::Other("escape Unicode inválido".into()))
    }

    fn hex_quad(&mut self) -> Result<u16> {
        let mut value = 0u16;
        for _ in 0..4 {
            let digit = self
                .bump()
                .and_then(|byte| (byte as char).to_digit(16))
                .ok_or_else(|| Error::Other("escape Unicode inválido".into()))?;
            value = (value << 4) | digit as u16;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<Json> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }

        match self.peek() {
            Some(b'0') => {
                self.i += 1;
            }
            Some(b'1'..=b'9') => {
                self.i += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(Error::Other("número JSON inválido".into())),
        }

        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(Error::Other("fração JSON inválida".into()));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }

        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(Error::Other("expoente JSON inválido".into()));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }

        let s = std::str::from_utf8(&self.s[start..self.i])
            .map_err(|_| Error::Other("número JSON inválido".into()))?;
        if is_float {
            let value = s
                .parse::<f64>()
                .map_err(|_| Error::Other("número JSON inválido".into()))?;
            if !value.is_finite() {
                return Err(Error::Other("número JSON fora do intervalo".into()));
            }
            Ok(Json::Float(value))
        } else {
            s.parse::<i64>()
                .map(Json::Number)
                .map_err(|_| Error::Other("inteiro JSON fora do intervalo".into()))
        }
    }

    fn object(&mut self) -> Result<Json> {
        self.bump();
        let mut m = BTreeMap::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.bump();
                break;
            }
            if !m.is_empty() {
                if self.bump() != Some(b',') {
                    return Err(Error::Other("JSON objeto".into()));
                }
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    return Err(Error::Other("vírgula final em JSON objeto".into()));
                }
            }
            let k = self.string()?;
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(Error::Other("JSON :".into()));
            }
            let v = self.value()?;
            m.insert(k, v);
            self.skip_ws();
        }
        Ok(Json::Object(m))
    }

    fn array(&mut self) -> Result<Json> {
        self.bump();
        let mut xs = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.bump();
                break;
            }
            if !xs.is_empty() {
                if self.bump() != Some(b',') {
                    return Err(Error::Other("JSON array".into()));
                }
                self.skip_ws();
                if self.peek() == Some(b']') {
                    return Err(Error::Other("vírgula final em JSON array".into()));
                }
            }
            xs.push(self.value()?);
        }
        Ok(Json::Array(xs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_object() {
        let j = Json::obj()
            .put("key", Json::String("hero".into()))
            .put("ok", Json::Bool(true));
        let s = j.stringify();
        let p = Json::parse(&s).unwrap();
        assert_eq!(p.get("key").and_then(Json::as_str), Some("hero"));
    }

    #[test]
    fn roundtrip_utf8_and_unicode_escapes() {
        let raw = Json::parse(r#"{"text":"café 世界 😀"}"#).unwrap();
        assert_eq!(raw.get("text").and_then(Json::as_str), Some("café 世界 😀"));

        let escaped = Json::parse(r#""caf\u00e9 \ud83d\ude00""#).unwrap();
        assert_eq!(escaped.as_str(), Some("café 😀"));
        assert_eq!(Json::parse(&escaped.stringify()).unwrap(), escaped);
    }

    #[test]
    fn rejects_trailing_input_and_invalid_numbers() {
        for input in ["null trailing", "01", "1.", "1e", "--1", "1 2"] {
            assert!(Json::parse(input).is_err(), "accepted {input:?}");
        }
        assert_eq!(Json::parse("-1.25e+2").unwrap(), Json::Float(-125.0));
        for float in [3.0, 1e300, -0.5, 1e-7] {
            let json = Json::Float(float);
            assert_eq!(Json::parse(&json.stringify()).unwrap(), json);
        }
    }

    #[test]
    fn rejects_invalid_escapes_and_unescaped_controls() {
        for input in [
            r#""\x""#,
            r#""\ud800""#,
            "\"line\nbreak\"",
            "{\"key\":1,}",
            "[1,]",
        ] {
            assert!(Json::parse(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn limits_json_container_nesting() {
        let accepted = format!(
            "{}null{}",
            "[".repeat(MAX_JSON_DEPTH),
            "]".repeat(MAX_JSON_DEPTH)
        );
        assert!(Json::parse(&accepted).is_ok());

        let rejected = format!(
            "{}null{}",
            "[".repeat(MAX_JSON_DEPTH + 1),
            "]".repeat(MAX_JSON_DEPTH + 1)
        );
        assert!(Json::parse(&rejected).is_err());
    }
}
