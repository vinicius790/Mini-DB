//! Usuários, papéis e privilégios (`CREATE USER`, `GRANT`) e SCRAM-SHA-256.
//!
//! Principais ficam no catálogo em `FF 'u' nome` (JSON). Um papel é um
//! principal sem senha (`login = false`); um usuário herda os privilégios dos
//! papéis que recebeu (`GRANT papel TO usuário`). Enquanto não existe nenhum
//! usuário, o banco está em *modo aberto*: conexões de rede entram sem
//! autenticação (compatível com versões anteriores). O primeiro usuário criado
//! deve ser `SUPERUSER`, senão ninguém mais administraria o banco.

use crate::crypto::{self, hmac_sha256, sha256};
use crate::error::{Error, Result};
use crate::json::Json;
use crate::rel::parser::{Expr, InsertSource, OnConflict, Query, SetExpr, Source, Stmt};
use crate::rel::{expr_children, Source as Catalog};
use std::collections::HashSet;

pub const USER_PREFIX: &[u8] = &[0xFF, b'u'];
/// Iterações do PBKDF2 (o padrão do PostgreSQL).
pub const SCRAM_ITERATIONS: u32 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    Select,
    Insert,
    Update,
    Delete,
    /// DDL: criar/alterar/apagar objetos (na tabela ou, em `*`, no banco).
    Create,
    All,
}

impl Privilege {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "select" | "read" => Self::Select,
            "insert" => Self::Insert,
            "update" => Self::Update,
            "delete" => Self::Delete,
            "create" | "ddl" => Self::Create,
            "all" => Self::All,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Create => "CREATE",
            Self::All => "ALL",
        }
    }

    pub fn bits(self) -> u8 {
        match self {
            Self::Select => 1,
            Self::Insert => 2,
            Self::Update => 4,
            Self::Delete => 8,
            Self::Create => 16,
            Self::All => 31,
        }
    }

    pub fn from_bits(bits: u8) -> Vec<Self> {
        if bits & 31 == 31 {
            return vec![Self::All];
        }
        [
            Self::Select,
            Self::Insert,
            Self::Update,
            Self::Delete,
            Self::Create,
        ]
        .into_iter()
        .filter(|p| bits & p.bits() != 0)
        .collect()
    }
}

/// Credenciais SCRAM-SHA-256 (RFC 5802/7677): a senha em si nunca é guardada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scram {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub stored_key: [u8; 32],
    pub server_key: [u8; 32],
}

impl Scram {
    pub fn new(password: &str) -> Self {
        let salt = crypto::random_bytes::<16>().to_vec();
        Self::derive(password, salt, SCRAM_ITERATIONS)
    }

    pub fn derive(password: &str, salt: Vec<u8>, iterations: u32) -> Self {
        let salted = crypto::pbkdf2_sha256(password.as_bytes(), &salt, iterations);
        let client_key = hmac_sha256(&salted, &[b"Client Key"]);
        Self {
            stored_key: sha256(&client_key),
            server_key: hmac_sha256(&salted, &[b"Server Key"]),
            salt,
            iterations,
        }
    }

    /// Confere uma senha em claro (TCP `AUTH`, HTTP Basic).
    pub fn verify(&self, password: &str) -> bool {
        let other = Self::derive(password, self.salt.clone(), self.iterations);
        crypto::constant_time_eq(&other.stored_key, &self.stored_key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Nome da tabela/view, `kv` (chave-valor) ou `*` (todas).
    pub object: String,
    pub privileges: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
    pub login: bool,
    pub superuser: bool,
    pub scram: Option<Scram>,
    pub roles: Vec<String>,
    pub grants: Vec<Grant>,
}

impl Principal {
    pub fn user(name: &str, password: &str, superuser: bool) -> Self {
        Self {
            name: name.to_string(),
            login: true,
            superuser,
            scram: Some(Scram::new(password)),
            roles: Vec::new(),
            grants: Vec::new(),
        }
    }

    pub fn role(name: &str) -> Self {
        Self {
            name: name.to_string(),
            login: false,
            superuser: false,
            scram: None,
            roles: Vec::new(),
            grants: Vec::new(),
        }
    }

    pub fn grant(&mut self, object: &str, privileges: u8) {
        match self.grants.iter_mut().find(|g| g.object == object) {
            Some(g) => g.privileges |= privileges,
            None => self.grants.push(Grant {
                object: object.to_string(),
                privileges,
            }),
        }
    }

    pub fn revoke(&mut self, object: &str, privileges: u8) {
        for g in &mut self.grants {
            if g.object == object {
                g.privileges &= !privileges;
            }
        }
        self.grants.retain(|g| g.privileges != 0);
    }

    pub fn to_json(&self) -> Json {
        let mut j = Json::obj()
            .put("name", Json::String(self.name.clone()))
            .put("login", Json::Bool(self.login))
            .put("superuser", Json::Bool(self.superuser))
            .put(
                "roles",
                Json::Array(self.roles.iter().cloned().map(Json::String).collect()),
            )
            .put(
                "grants",
                Json::Array(
                    self.grants
                        .iter()
                        .map(|g| {
                            Json::obj()
                                .put("object", Json::String(g.object.clone()))
                                .put("privileges", Json::Number(g.privileges as i64))
                        })
                        .collect(),
                ),
            );
        if let Some(s) = &self.scram {
            j = j.put(
                "scram",
                Json::obj()
                    .put("salt", Json::String(crypto::to_hex(&s.salt)))
                    .put("iterations", Json::Number(s.iterations as i64))
                    .put("stored_key", Json::String(crypto::to_hex(&s.stored_key)))
                    .put("server_key", Json::String(crypto::to_hex(&s.server_key))),
            );
        }
        j
    }

    pub fn from_json(j: &Json) -> Result<Self> {
        let bad = || Error::Other("usuário corrompido no catálogo".into());
        let flag = |k: &str| matches!(j.get(k), Some(Json::Bool(true)));
        let list = |k: &str| match j.get(k) {
            Some(Json::Array(a)) => a.clone(),
            _ => Vec::new(),
        };
        let key32 = |v: Option<&Json>| -> Result<[u8; 32]> {
            let bytes = v
                .and_then(Json::as_str)
                .and_then(crypto::from_hex)
                .ok_or_else(bad)?;
            bytes.try_into().map_err(|_| bad())
        };
        let scram = match j.get("scram") {
            Some(s) => Some(Scram {
                salt: s
                    .get("salt")
                    .and_then(Json::as_str)
                    .and_then(crypto::from_hex)
                    .ok_or_else(bad)?,
                iterations: match s.get("iterations") {
                    Some(Json::Number(n)) => *n as u32,
                    _ => SCRAM_ITERATIONS,
                },
                stored_key: key32(s.get("stored_key"))?,
                server_key: key32(s.get("server_key"))?,
            }),
            None => None,
        };
        Ok(Self {
            name: j.get("name").and_then(Json::as_str).ok_or_else(bad)?.into(),
            login: flag("login"),
            superuser: flag("superuser"),
            scram,
            roles: list("roles")
                .iter()
                .filter_map(|r| r.as_str().map(str::to_string))
                .collect(),
            grants: list("grants")
                .iter()
                .filter_map(|g| {
                    Some(Grant {
                        object: g.get("object")?.as_str()?.to_string(),
                        privileges: match g.get("privileges") {
                            Some(Json::Number(n)) => *n as u8,
                            _ => 0,
                        },
                    })
                })
                .collect(),
        })
    }
}

pub fn key(name: &str) -> Vec<u8> {
    let mut k = USER_PREFIX.to_vec();
    k.extend_from_slice(name.as_bytes());
    k
}

pub(crate) fn load(src: &dyn Catalog, name: &str) -> Result<Option<Principal>> {
    match src.get(&key(name))? {
        Some(raw) => {
            let j = Json::parse(&String::from_utf8_lossy(&raw))?;
            Principal::from_json(&j).map(Some)
        }
        None => Ok(None),
    }
}

pub(crate) fn list(src: &dyn Catalog) -> Result<Vec<Principal>> {
    let end = crate::db::prefix_successor(USER_PREFIX).expect("prefixo");
    let mut out = Vec::new();
    let mut failure = None;
    src.scan(USER_PREFIX, Some(&end), &mut |_, raw| {
        match Json::parse(&String::from_utf8_lossy(&raw)).and_then(|j| Principal::from_json(&j)) {
            Ok(p) => out.push(p),
            Err(e) => {
                failure = Some(e);
                return Ok(false);
            }
        }
        Ok(true)
    })?;
    failure.map_or(Ok(out), Err)
}

/// Há algum usuário com senha? (Sem nenhum, a rede entra em modo aberto.)
pub(crate) fn has_users(src: &dyn Catalog) -> Result<bool> {
    Ok(list(src)?.iter().any(|p| p.login))
}

/// Usuário + senha em claro → principal (erro genérico para não vazar nomes).
pub(crate) fn authenticate(src: &dyn Catalog, name: &str, password: &str) -> Result<Principal> {
    let denied = || Error::Unauthorized;
    let p = load(src, name)?;
    let verdict = p
        .as_ref()
        .and_then(|p| p.scram.as_ref().filter(|_| p.login))
        .map(|s| s.verify(password));
    if verdict.is_none() {
        // Mesmo custo (PBKDF2) para usuário inexistente: não revela se ele existe.
        let _ = Scram::derive(password, vec![0u8; 16], SCRAM_ITERATIONS);
    }
    match (verdict, p) {
        (Some(true), Some(p)) => Ok(p),
        _ => Err(denied()),
    }
}

// ---------------------------------------------------------------------------
// Autorização
// ---------------------------------------------------------------------------

/// O que um comando exige de quem o executa.
#[derive(Debug, PartialEq, Eq)]
pub enum Requirement {
    /// Qualquer sessão autenticada.
    Any,
    Superuser,
    /// Todos os pares `(objeto, privilégio)`.
    Privileges(Vec<(String, Privilege)>),
}

fn tables_of_query(q: &Query, out: &mut Vec<String>, ctes: &mut Vec<String>) {
    let before = ctes.len();
    for c in &q.ctes {
        ctes.push(c.name.clone());
        tables_of_query(&c.query, out, ctes);
    }
    tables_of_set(&q.body, out, ctes);
    for o in &q.order_by {
        tables_of_expr(&o.expr, out, ctes);
    }
    ctes.truncate(before);
}

fn tables_of_set(e: &SetExpr, out: &mut Vec<String>, ctes: &mut Vec<String>) {
    match e {
        SetExpr::Values(rows) => {
            for r in rows {
                for x in r {
                    tables_of_expr(x, out, ctes);
                }
            }
        }
        SetExpr::SetOp { left, right, .. } => {
            tables_of_set(left, out, ctes);
            tables_of_set(right, out, ctes);
        }
        SetExpr::Select(s) => {
            let items = s.from.iter().chain(s.joins.iter().map(|j| &j.item));
            for item in items {
                match &item.source {
                    Source::Table(t) if !ctes.iter().any(|c| c == t) => out.push(t.clone()),
                    Source::Table(_) => {}
                    Source::Query(q) => tables_of_query(q, out, ctes),
                    Source::Function(_, args, _) => {
                        for a in args {
                            tables_of_expr(a, out, ctes);
                        }
                    }
                }
            }
            for j in &s.joins {
                if let Some(on) = &j.on {
                    tables_of_expr(on, out, ctes);
                }
            }
            for item in &s.items {
                if let crate::rel::parser::SelectItem::Expr(e, _) = item {
                    tables_of_expr(e, out, ctes);
                }
            }
            for e in s
                .filter
                .iter()
                .chain(s.having.iter())
                .chain(s.group_by.iter())
            {
                tables_of_expr(e, out, ctes);
            }
        }
    }
}

fn tables_of_expr(e: &Expr, out: &mut Vec<String>, ctes: &mut Vec<String>) {
    match e {
        Expr::InQuery(_, q, _)
        | Expr::Quantified(_, _, _, q)
        | Expr::Exists(q, _)
        | Expr::Subquery(q) => tables_of_query(q, out, ctes),
        _ => {}
    }
    for c in expr_children(e) {
        tables_of_expr(c, out, ctes);
    }
}

fn reads(q: &Query) -> Vec<(String, Privilege)> {
    let mut tables = Vec::new();
    tables_of_query(q, &mut tables, &mut Vec::new());
    tables.sort();
    tables.dedup();
    tables.into_iter().map(|t| (t, Privilege::Select)).collect()
}

fn reads_expr(exprs: &[&Expr]) -> Vec<(String, Privilege)> {
    let mut tables = Vec::new();
    for e in exprs {
        tables_of_expr(e, &mut tables, &mut Vec::new());
    }
    tables.into_iter().map(|t| (t, Privilege::Select)).collect()
}

/// Expressões de uma lista `RETURNING` (para conferir subconsultas).
fn returning_exprs(items: &[crate::rel::parser::SelectItem]) -> Vec<&Expr> {
    items
        .iter()
        .filter_map(|i| match i {
            crate::rel::parser::SelectItem::Expr(e, _) => Some(e),
            _ => None,
        })
        .collect()
}

/// Privilégios que `stmt` exige.
pub fn required(stmt: &Stmt) -> Requirement {
    use Privilege::*;
    let one = |t: &str, p: Privilege| Requirement::Privileges(vec![(t.to_string(), p)]);
    match stmt {
        Stmt::Query(q) => Requirement::Privileges(reads(q)),
        Stmt::Insert {
            table,
            source,
            on_conflict,
            returning,
            ..
        } => {
            let mut need = vec![(table.clone(), Insert)];
            let mut exprs: Vec<&Expr> = returning_exprs(returning);
            if let Some(OnConflict::Update { sets, filter }) = on_conflict {
                exprs.extend(sets.iter().map(|(_, e)| e));
                exprs.extend(filter.iter());
            }
            if matches!(
                on_conflict,
                Some(OnConflict::Update { .. } | OnConflict::Replace)
            ) {
                need.push((table.clone(), Update));
            }
            match source {
                InsertSource::Query(q) => need.extend(reads(q)),
                InsertSource::Values(rows) => exprs.extend(rows.iter().flatten()),
                InsertSource::Default => {}
            }
            need.extend(reads_expr(&exprs));
            Requirement::Privileges(need)
        }
        Stmt::Update {
            table,
            sets,
            filter,
            returning,
        } => {
            let mut need = vec![(table.clone(), Update)];
            let mut exprs: Vec<&Expr> = sets.iter().map(|(_, e)| e).chain(filter.iter()).collect();
            exprs.extend(returning_exprs(returning));
            need.extend(reads_expr(&exprs));
            Requirement::Privileges(need)
        }
        Stmt::Delete {
            table,
            filter,
            returning,
        } => {
            let mut need = vec![(table.clone(), Delete)];
            let mut exprs: Vec<&Expr> = filter.iter().collect();
            exprs.extend(returning_exprs(returning));
            need.extend(reads_expr(&exprs));
            Requirement::Privileges(need)
        }
        Stmt::Notify { payload, .. } => {
            Requirement::Privileges(reads_expr(&payload.iter().collect::<Vec<_>>()))
        }
        Stmt::Truncate(t) => one(t, Delete),
        Stmt::CreateTable { .. } => one("*", Create),
        Stmt::CreateView { query, .. } => {
            let mut need = vec![("*".to_string(), Create)];
            need.extend(reads(query));
            Requirement::Privileges(need)
        }
        Stmt::CreateIndex { table, .. }
        | Stmt::AddColumn { table, .. }
        | Stmt::DropColumn { table, .. }
        | Stmt::RenameColumn { table, .. }
        | Stmt::RenameTable { table, .. }
        | Stmt::AlterColumn { table, .. } => one(table, Create),
        // O corpo roda sem nova conferência: quem cria precisa poder fazer o que ele faz.
        Stmt::CreateTrigger { trigger, .. } => {
            let mut need = vec![(trigger.table.clone(), Create)];
            if let Some((cond, _)) = &trigger.when {
                need.extend(reads_expr(&[cond]));
            }
            for (_, body) in &trigger.body {
                match required(body) {
                    Requirement::Privileges(p) => need.extend(p),
                    Requirement::Superuser => return Requirement::Superuser,
                    Requirement::Any => {}
                }
            }
            Requirement::Privileges(need)
        }
        Stmt::DropTable { name, .. } | Stmt::DropView { name, .. } | Stmt::RefreshView(name) => {
            one(name, Create)
        }
        Stmt::Reindex(name) => one(name, Create),
        Stmt::Analyze(Some(t)) => one(t, Create),
        Stmt::DropIndex { .. } | Stmt::DropTrigger { .. } | Stmt::Analyze(None) => one("*", Create),
        Stmt::CreateUser { .. }
        | Stmt::AlterUser { .. }
        | Stmt::DropUser { .. }
        | Stmt::Grant { .. }
        | Stmt::Revoke { .. }
        | Stmt::ShowUsers => Requirement::Superuser,
        Stmt::ShowGrants(_)
        | Stmt::ShowTables
        | Stmt::ShowIndexes(_)
        | Stmt::ShowTriggers(_)
        | Stmt::ShowCreate(_)
        | Stmt::Describe(_)
        | Stmt::Listen(_)
        | Stmt::Unlisten(_)
        | Stmt::Begin { .. }
        | Stmt::Commit
        | Stmt::Rollback { .. }
        | Stmt::Savepoint(_)
        | Stmt::Release(_) => Requirement::Any,
        Stmt::Explain(inner, _) => required(inner),
    }
}

/// Privilégios efetivos (próprios + dos papéis, recursivamente).
pub(crate) fn effective(src: &dyn Catalog, who: &Principal) -> Result<Vec<Grant>> {
    let mut grants = who.grants.clone();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue = who.roles.clone();
    while let Some(role) = queue.pop() {
        if !seen.insert(role.clone()) {
            continue;
        }
        if let Some(r) = load(src, &role)? {
            grants.extend(r.grants);
            queue.extend(r.roles);
        }
    }
    Ok(grants)
}

fn allows(grants: &[Grant], object: &str, p: Privilege) -> bool {
    grants
        .iter()
        .filter(|g| g.object == "*" || g.object == object)
        .any(|g| g.privileges & p.bits() == p.bits())
}

/// Confere se `who` pode executar `stmt`; superusuário pode tudo.
pub(crate) fn authorize(src: &dyn Catalog, who: &Principal, stmt: &Stmt) -> Result<()> {
    if who.superuser {
        return Ok(());
    }
    match required(stmt) {
        Requirement::Any => Ok(()),
        Requirement::Superuser => Err(Error::Forbidden(format!(
            "{}: só superusuário administra usuários e permissões",
            who.name
        ))),
        Requirement::Privileges(need) => {
            let grants = effective(src, who)?;
            for (object, p) in need {
                if !allows(&grants, &object, p) {
                    return Err(Error::Forbidden(format!(
                        "{} não tem {} em {object}",
                        who.name,
                        p.name()
                    )));
                }
            }
            Ok(())
        }
    }
}

/// Um privilégio avulso (comandos chave-valor: objeto `kv`).
pub(crate) fn authorize_object(
    src: &dyn Catalog,
    who: &Principal,
    object: &str,
    p: Privilege,
) -> Result<()> {
    if who.superuser || allows(&effective(src, who)?, object, p) {
        return Ok(());
    }
    Err(Error::Forbidden(format!(
        "{} não tem {} em {object}",
        who.name,
        p.name()
    )))
}

// ---------------------------------------------------------------------------
// SCRAM-SHA-256 do lado do servidor (protocolo PostgreSQL)
// ---------------------------------------------------------------------------

/// Estado de uma negociação SCRAM. Usuário inexistente recebe credenciais
/// fictícias e falha na prova, sem revelar que não existe.
pub struct ScramServer {
    scram: Scram,
    valid_user: bool,
    client_first_bare: String,
    server_first: String,
    server_nonce: String,
}

impl ScramServer {
    /// Processa `client-first-message`; devolve `server-first-message`.
    pub fn start(
        principal: Option<&Principal>,
        user: &str,
        client_first: &str,
    ) -> Result<(Self, String)> {
        let bad = || Error::Unauthorized;
        // gs2-header: "n,," | "y,," | "p=...,,"
        let (_, bare) = client_first.split_once(",,").ok_or_else(bad)?;
        let mut nonce = None;
        for attr in bare.split(',') {
            if let Some(r) = attr.strip_prefix("r=") {
                nonce = Some(r.to_string());
            }
        }
        let client_nonce = nonce.ok_or_else(bad)?;
        let (scram, valid_user) = match principal.and_then(|p| p.scram.clone()) {
            Some(s) if principal.is_some_and(|p| p.login) => (s, true),
            // Sal fictício estável por nome: repetir a tentativa não revela quem existe.
            _ => {
                let seed = [b"minidb-mock-salt".as_slice(), user.as_bytes()].concat();
                let salt = sha256(&seed)[..16].to_vec();
                (Scram::derive("", salt, SCRAM_ITERATIONS), false)
            }
        };
        let server_nonce = format!(
            "{client_nonce}{}",
            crypto::base64_encode(&crypto::random_bytes::<18>())
        );
        let server_first = format!(
            "r={server_nonce},s={},i={}",
            crypto::base64_encode(&scram.salt),
            scram.iterations
        );
        Ok((
            Self {
                scram,
                valid_user,
                client_first_bare: bare.to_string(),
                server_first: server_first.clone(),
                server_nonce,
            },
            server_first,
        ))
    }

    /// Processa `client-final-message`; devolve `server-final-message` (`v=`).
    pub fn finish(&self, client_final: &str) -> Result<String> {
        let bad = || Error::Unauthorized;
        let without_proof = client_final
            .rsplit_once(",p=")
            .map(|(a, _)| a)
            .ok_or_else(bad)?;
        let mut proof = None;
        let mut nonce = None;
        for attr in client_final.split(',') {
            if let Some(p) = attr.strip_prefix("p=") {
                proof = Some(crypto::base64_decode(p).ok_or_else(bad)?);
            } else if let Some(r) = attr.strip_prefix("r=") {
                nonce = Some(r);
            }
        }
        if nonce != Some(self.server_nonce.as_str()) {
            return Err(bad());
        }
        let proof = proof.ok_or_else(bad)?;
        let auth_message = format!(
            "{},{},{without_proof}",
            self.client_first_bare, self.server_first
        );
        let client_signature = hmac_sha256(&self.scram.stored_key, &[auth_message.as_bytes()]);
        if proof.len() != 32 {
            return Err(bad());
        }
        let client_key: Vec<u8> = proof
            .iter()
            .zip(client_signature.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let ok = crypto::constant_time_eq(&sha256(&client_key), &self.scram.stored_key);
        if !(ok && self.valid_user) {
            return Err(bad());
        }
        let server_signature = hmac_sha256(&self.scram.server_key, &[auth_message.as_bytes()]);
        Ok(format!("v={}", crypto::base64_encode(&server_signature)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scram_roundtrip_like_a_client() {
        let p = Principal::user("ana", "segredo", false);
        let s = p.scram.clone().unwrap();
        assert!(s.verify("segredo"));
        assert!(!s.verify("Segredo"));
        // Cliente
        let client_nonce = "rOprNGfwEbeRWgbNEkqO";
        let client_first = format!("n,,n=ana,r={client_nonce}");
        let (server, server_first) = ScramServer::start(Some(&p), &p.name, &client_first).unwrap();
        let attrs: Vec<&str> = server_first.split(',').collect();
        let combined = attrs[0].strip_prefix("r=").unwrap();
        let salt = crypto::base64_decode(attrs[1].strip_prefix("s=").unwrap()).unwrap();
        let iters: u32 = attrs[2].strip_prefix("i=").unwrap().parse().unwrap();
        let salted = crypto::pbkdf2_sha256(b"segredo", &salt, iters);
        let client_key = hmac_sha256(&salted, &[b"Client Key"]);
        let stored = sha256(&client_key);
        let without_proof = format!("c=biws,r={combined}");
        let auth = format!("n=ana,r={client_nonce},{server_first},{without_proof}");
        let sig = hmac_sha256(&stored, &[auth.as_bytes()]);
        let proof: Vec<u8> = client_key
            .iter()
            .zip(sig.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let client_final = format!("{without_proof},p={}", crypto::base64_encode(&proof));
        let v = server.finish(&client_final).unwrap();
        let server_key = hmac_sha256(&salted, &[b"Server Key"]);
        let expected = hmac_sha256(&server_key, &[auth.as_bytes()]);
        assert_eq!(v, format!("v={}", crypto::base64_encode(&expected)));
        // Prova errada e usuário inexistente falham.
        let mut wrong = proof.clone();
        wrong[0] ^= 1;
        assert!(server
            .finish(&format!(
                "{without_proof},p={}",
                crypto::base64_encode(&wrong)
            ))
            .is_err());
        let (ghost, _) = ScramServer::start(None, "ghost", &client_first).unwrap();
        assert!(ghost.finish(&client_final).is_err());
    }

    #[test]
    fn json_roundtrip_and_privileges() {
        let mut p = Principal::user("bob", "x", true);
        p.roles.push("leitores".into());
        p.grant("jogos", Privilege::Select.bits() | Privilege::Insert.bits());
        p.grant("jogos", Privilege::Update.bits());
        let back = Principal::from_json(&p.to_json()).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.grants[0].privileges, 7);
        p.revoke("jogos", Privilege::Insert.bits());
        assert_eq!(
            Privilege::from_bits(p.grants[0].privileges),
            [Privilege::Select, Privilege::Update]
        );
        p.revoke("jogos", 31);
        assert!(p.grants.is_empty());
        assert_eq!(Privilege::from_bits(31), [Privilege::All]);
    }
}
