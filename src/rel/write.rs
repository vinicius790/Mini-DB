//! Planejamento de escritas relacionais: cada comando vira um lote atômico
//! de puts/deletes (via [`Pending`]) sem tocar o banco até o commit.
//!
//! Aqui vivem DDL (tabelas, índices, views, `ALTER TABLE`, `TRUNCATE`), DML
//! (`INSERT`/`UPDATE`/`DELETE` com `RETURNING` e upsert) e a integridade:
//! `NOT NULL`, `CHECK`, `UNIQUE`, chaves primárias, autoincremento e chaves
//! estrangeiras com `ON DELETE`/`ON UPDATE` (`CASCADE`, `SET NULL`,
//! `SET DEFAULT`, `RESTRICT`/`NO ACTION`), aplicadas em cascata dentro do
//! mesmo lote.

use super::exec::ColStats;
use super::exec::{
    catalog_key, columns_of, encode_tuple, fetch_from, fts_stats, has_agg_or_window, has_subquery,
    list_tables, load_table, load_view, posting_prefix, stats_key, table_scope, unknown_column,
    view_key, Access, Ctx, Exec, Fk, HnswStore, IndexDef, Output, Pending, Scope, Stats, Table,
    TableKind, View, FTS_DOC, FTS_STATS, MAX_PK_BYTES, TABLE_SEQ, VEC_ENTRY, VEC_NODE,
};
use super::parser::IndexKind;
use super::parser::{
    Check, ColumnChange, ColumnDef, Expr, FkAction, ForeignKey, InsertSource, OnConflict, Query,
    SelectItem, Stmt,
};
use super::parser::{TriggerDef, TriggerEvent, TriggerTiming};
use super::rewrite;
use super::search::{self, NodeStore};
use super::value::{encode_row, Type, Value};
use super::Source;
use crate::auth;
use crate::db::{prefix_successor, ExecResult, Op};
use crate::error::{Error, Result};
use crate::events::{Change, ChangeKind};
use std::collections::{BTreeSet, HashSet};

/// Resultado do planejamento de uma escrita: lote atômico, resposta e eventos
/// a publicar depois do commit.
pub(crate) struct WritePlan {
    pub ops: Vec<Op>,
    pub result: ExecResult,
    pub changes: Vec<Change>,
    pub notifications: Vec<(String, String)>,
}

/// Planeja um comando de escrita: devolve o lote atômico, o resultado e os
/// eventos (mudanças de linhas, NOTIFY) do comando.
pub(super) fn plan_write(src: &dyn Source, stmt: &Stmt, params: &[Value]) -> Result<WritePlan> {
    let exec = Exec::new(src, params);
    let pending = Pending::default();
    let result = plan_into(&exec, stmt, &pending)?;
    // Views materializadas automáticas das tabelas alteradas.
    let touched: BTreeSet<String> = pending
        .changes
        .borrow()
        .iter()
        .map(|c| c.table.clone())
        .collect();
    let mut refreshed = HashSet::new();
    for table in touched {
        for mv in exec.auto_views_of(&table)? {
            if refreshed.insert(mv.name.clone()) {
                refresh_materialized(&exec, &pending, &mv)?;
            }
        }
    }
    let changes = std::mem::take(&mut *pending.changes.borrow_mut());
    let notifications = std::mem::take(&mut *pending.notifications.borrow_mut());
    Ok(WritePlan {
        ops: pending.into_ops(),
        result,
        changes,
        notifications,
    })
}

/// Executa o comando sobre `pending` (também usado pelos corpos de gatilho).
pub(super) fn plan_into(exec: &Exec<'_>, stmt: &Stmt, pending: &Pending) -> Result<ExecResult> {
    let src = exec.src;
    let result = match stmt {
        Stmt::CreateTable {
            name,
            columns,
            primary_key,
            uniques,
            checks,
            foreign_keys,
            if_not_exists,
        } => ExecResult::Ok(create_table(
            exec,
            pending,
            name,
            columns,
            primary_key,
            uniques,
            checks,
            foreign_keys,
            *if_not_exists,
        )?),
        Stmt::DropTable { name, if_exists } => match load_table(src, name) {
            Err(Error::UnknownTable(_)) if *if_exists => ExecResult::Ok("DROP TABLE 0".into()),
            Err(Error::UnknownTable(_)) if load_view(src, name)?.is_some() => {
                return Err(Error::Sql(format!("{name} é uma view: use DROP VIEW")))
            }
            t => {
                let t = t?;
                let children = exec.children_of(&t.name)?;
                if let Some(c) = children.iter().find(|c| c.name != t.name) {
                    return Err(Error::Constraint(format!(
                        "tabela {} é referenciada por FOREIGN KEY de {}; remova a tabela filha primeiro",
                        t.name, c.name
                    )));
                }
                if matches!(t.kind, TableKind::Materialized { .. }) {
                    return Err(Error::Sql(format!(
                        "{} é view materializada: use DROP MATERIALIZED VIEW",
                        t.name
                    )));
                }
                drop_rows_and_indexes(src, &t, pending)?;
                pending.del(t.rowid_key());
                pending.del(stats_key(&t.name));
                pending.del(catalog_key(&t.name));
                ExecResult::Ok(format!("DROP TABLE {}", t.name))
            }
        },
        Stmt::Truncate(name) => {
            let t = load_table(src, name)?;
            for child in exec.children_of(&t.name)?.iter() {
                if child.name == t.name {
                    continue;
                }
                // Numa transação, nenhuma filha pode aparecer até o commit.
                let rows = child.row_prefix();
                src.guard_unchanged(&rows, &prefix_successor(&rows).expect("prefixo"));
                let mut any = false;
                fetch_from(src, child, &Access::Full, &mut |_, _| {
                    any = true;
                    Ok(false)
                })?;
                if any {
                    return Err(Error::Constraint(format!(
                        "TRUNCATE em {} bloqueado: {} tem linhas com FOREIGN KEY para ela",
                        t.name, child.name
                    )));
                }
            }
            drop_rows_and_indexes(src, &t, pending)?;
            pending.del(t.rowid_key());
            ExecResult::Ok(format!("TRUNCATE {}", t.name))
        }
        Stmt::CreateIndex {
            name,
            table,
            columns,
            unique,
            if_not_exists,
            kind,
            options,
        } => {
            if let Some(owner) = list_tables(src)?
                .into_iter()
                .find(|t| t.indexes.iter().any(|i| i.name == *name))
            {
                if *if_not_exists {
                    return Ok(ExecResult::Ok(format!(
                        "CREATE INDEX {name} (já existe em {})",
                        owner.name
                    )));
                }
                return Err(Error::Sql(format!("índice {name} já existe")));
            }
            let mut t = load_table(src, table)?;
            if matches!(t.kind, TableKind::Materialized { .. }) {
                return Err(Error::Sql(format!("índice em view materializada: {table}")));
            }
            let cols = columns
                .iter()
                .map(|c| t.column(c))
                .collect::<Result<Vec<_>>>()?;
            let idx = IndexDef {
                name: name.clone(),
                columns: cols,
                unique: *unique,
                id: t.next_index_id,
                auto: false,
                kind: *kind,
                options: options.clone(),
            };
            validate_index(&t, &idx)?;
            t.next_index_id += 1;
            let rows = build_index(src, &t, &idx, pending)?;
            t.indexes.push(idx);
            save_table(pending, &t);
            ExecResult::Ok(format!("CREATE INDEX {name} rows={rows}"))
        }
        Stmt::Reindex(name) => {
            let mut tables = list_tables(src)?;
            let owner = tables
                .iter()
                .position(|t| t.indexes.iter().any(|i| i.name == *name));
            let (mut t, only) = match owner {
                Some(pos) => (tables.swap_remove(pos), Some(name.clone())),
                None => (load_table(src, name)?, None),
            };
            let mut rows = 0;
            let indexes = std::mem::take(&mut t.indexes);
            for idx in &indexes {
                if only.as_ref().is_some_and(|n| *n != idx.name) {
                    continue;
                }
                let p = t.index_prefix(idx);
                for (k, _) in pending.entries(src, &p, &prefix_successor(&p).expect("p"))? {
                    pending.del(k);
                }
                rows = build_index(src, &t, idx, pending)?;
            }
            t.indexes = indexes;
            ExecResult::Ok(format!("REINDEX {name} rows={rows}"))
        }
        Stmt::DropIndex { name, if_exists } => {
            match list_tables(src)?
                .into_iter()
                .find(|t| t.indexes.iter().any(|i| i.name == *name))
            {
                None if *if_exists => ExecResult::Ok("DROP INDEX 0".into()),
                None => return Err(Error::UnknownIndex(name.clone())),
                Some(mut t) => {
                    let pos = t
                        .indexes
                        .iter()
                        .position(|i| i.name == *name)
                        .expect("achado");
                    let idx = t.indexes.remove(pos);
                    let p = t.index_prefix(&idx);
                    for (k, _) in pending.entries(src, &p, &prefix_successor(&p).expect("p"))? {
                        pending.del(k);
                    }
                    save_table(pending, &t);
                    ExecResult::Ok(format!("DROP INDEX {name}"))
                }
            }
        }
        Stmt::AddColumn { table, column } => {
            ExecResult::Ok(add_column(exec, pending, table, column)?)
        }
        Stmt::DropColumn {
            table,
            column,
            if_exists,
        } => ExecResult::Ok(drop_column(exec, pending, table, column, *if_exists)?),
        Stmt::RenameColumn { table, from, to } => {
            ExecResult::Ok(rename_column(src, pending, table, from, to)?)
        }
        Stmt::RenameTable { table, to } => {
            ExecResult::Ok(rename_table(src, pending, table, to)?)
        }
        Stmt::AlterColumn {
            table,
            column,
            change,
        } => ExecResult::Ok(alter_column(exec, pending, table, column, change)?),
        Stmt::CreateView {
            name,
            columns,
            query,
            sql,
            or_replace,
            if_not_exists,
            materialized,
            auto_refresh,
        } => {
            if *materialized {
                ExecResult::Ok(create_materialized(
                    exec,
                    pending,
                    name,
                    columns,
                    query,
                    sql,
                    *auto_refresh,
                    *or_replace,
                    *if_not_exists,
                )?)
            } else {
                ExecResult::Ok(create_view(
                    exec,
                    pending,
                    name,
                    columns,
                    query,
                    sql,
                    *or_replace,
                    *if_not_exists,
                )?)
            }
        }
        Stmt::DropView {
            name,
            if_exists,
            materialized,
        } => {
            if *materialized {
                match load_table(src, name) {
                    Ok(t) if matches!(t.kind, TableKind::Materialized { .. }) => {
                        drop_rows_and_indexes(src, &t, pending)?;
                        pending.del(t.rowid_key());
                        pending.del(stats_key(&t.name));
                        pending.del(catalog_key(&t.name));
                        ExecResult::Ok(format!("DROP MATERIALIZED VIEW {name}"))
                    }
                    Ok(_) => {
                        return Err(Error::Sql(format!("{name} é uma tabela: use DROP TABLE")))
                    }
                    Err(Error::UnknownTable(_)) if *if_exists => {
                        ExecResult::Ok("DROP MATERIALIZED VIEW 0".into())
                    }
                    Err(e) => return Err(e),
                }
            } else {
                match load_view(src, name)? {
                    None if *if_exists => ExecResult::Ok("DROP VIEW 0".into()),
                    None if load_table(src, name).is_ok() => {
                        return Err(Error::Sql(format!(
                            "{name} é uma tabela ou view materializada: use DROP TABLE / DROP MATERIALIZED VIEW"
                        )))
                    }
                    None => return Err(Error::UnknownTable(name.clone())),
                    Some(_) => {
                        pending.del(view_key(name));
                        ExecResult::Ok(format!("DROP VIEW {name}"))
                    }
                }
            }
        }
        Stmt::Insert {
            table,
            columns,
            source,
            on_conflict,
            returning,
        } => insert(
            exec,
            pending,
            table,
            columns.as_deref(),
            source,
            on_conflict.as_ref(),
            returning,
        )?,
        Stmt::Update {
            table,
            sets,
            filter,
            returning,
        } => {
            let t = exec.table(table)?;
            writable(&t)?;
            let targets = matching(exec, &t, filter.as_ref())?;
            let sets = sets
                .iter()
                .map(|(c, e)| Ok((t.column(c)?, e)))
                .collect::<Result<Vec<_>>>()?;
            let scope = table_scope(&t);
            let mut new_rows = Vec::with_capacity(targets.len());
            for (_, old) in &targets {
                let mut row = old.clone();
                for (c, e) in &sets {
                    row[*c] = exec.eval(e, &Ctx::new(&scope, old, None))?;
                }
                new_rows.push(row);
            }
            let written = update_rows(exec, pending, &t, targets, new_rows)?;
            match returning.is_empty() {
                true => ExecResult::Ok(format!("UPDATE {}", written.len())),
                false => returning_rows(exec, &t, returning, &written)?,
            }
        }
        Stmt::Delete {
            table,
            filter,
            returning,
        } => {
            let t = exec.table(table)?;
            writable(&t)?;
            let targets = matching(exec, &t, filter.as_ref())?;
            let old = delete_rows(exec, pending, &t, targets)?;
            match returning.is_empty() {
                true => ExecResult::Ok(format!("DELETE {}", old.len())),
                false => returning_rows(exec, &t, returning, &old)?,
            }
        }
        Stmt::Begin { .. }
        | Stmt::Commit
        | Stmt::Rollback { .. }
        | Stmt::Savepoint(_)
        | Stmt::Release(_) => {
            return Err(Error::Sql(
                "controle de transação (BEGIN/COMMIT/ROLLBACK/SAVEPOINT) só em sessão: use Session ou uma conexão TCP".into(),
            ))
        }
        Stmt::Listen(_) | Stmt::Unlisten(_) => {
            return Err(Error::Sql(
                "LISTEN/UNLISTEN só em sessão (Session ou conexão TCP)".into(),
            ))
        }
        Stmt::Notify { channel, payload } => {
            let empty = Scope::default();
            let payload = match payload {
                Some(e) => exec.eval(e, &Ctx::new(&empty, &[], None))?.to_string(),
                None => String::new(),
            };
            pending.notify(channel.clone(), payload);
            ExecResult::Ok(format!("NOTIFY {channel}"))
        }
        Stmt::Analyze(table) => {
            let tables = match table {
                Some(name) => vec![load_table(src, name)?],
                None => list_tables(src)?,
            };
            let mut total = 0usize;
            for t in &tables {
                total += analyze_table(exec, pending, t)?;
            }
            ExecResult::Ok(format!("ANALYZE tables={} rows={total}", tables.len()))
        }
        Stmt::RefreshView(name) => {
            let t = load_table(src, name)?;
            if !matches!(t.kind, TableKind::Materialized { .. }) {
                return Err(Error::Sql(format!("{name} não é view materializada")));
            }
            let n = refresh_materialized(exec, pending, &t)?;
            ExecResult::Ok(format!("REFRESH MATERIALIZED VIEW {name} rows={n}"))
        }
        Stmt::CreateTrigger {
            trigger,
            if_not_exists,
        } => ExecResult::Ok(create_trigger(exec, pending, trigger, *if_not_exists)?),
        Stmt::DropTrigger { name, if_exists } => {
            match list_tables(src)?
                .into_iter()
                .find(|t| t.triggers.iter().any(|tr| tr.name == *name))
            {
                None if *if_exists => ExecResult::Ok("DROP TRIGGER 0".into()),
                None => return Err(Error::Sql(format!("gatilho {name} não existe"))),
                Some(mut t) => {
                    t.triggers.retain(|tr| tr.name != *name);
                    save_table(pending, &t);
                    ExecResult::Ok(format!("DROP TRIGGER {name}"))
                }
            }
        }
        Stmt::CreateUser {
            name,
            password,
            superuser,
            login,
            if_not_exists,
        } => {
            if auth::load(src, name)?.is_some() {
                if *if_not_exists {
                    return Ok(ExecResult::Ok(format!("CREATE USER {name} (já existe)")));
                }
                return Err(Error::Sql(format!("usuário ou papel {name} já existe")));
            }
            let p = match password {
                Some(pw) if *login => auth::Principal::user(name, pw, *superuser),
                _ => auth::Principal::role(name),
            };
            if *login && !*superuser && !auth::has_users(src)? {
                return Err(Error::Sql(
                    "o primeiro usuário precisa ser SUPERUSER (senão ninguém administra o banco)"
                        .into(),
                ));
            }
            pending.put(auth::key(name), p.to_json().stringify().into_bytes());
            ExecResult::Ok(format!(
                "CREATE {} {name}",
                if *login { "USER" } else { "ROLE" }
            ))
        }
        Stmt::AlterUser {
            name,
            password,
            superuser,
        } => {
            let mut p = auth::load(src, name)?
                .ok_or_else(|| Error::Sql(format!("usuário {name} não existe")))?;
            if let Some(pw) = password {
                if !p.login {
                    return Err(Error::Sql(format!("{name} é um papel, não tem senha")));
                }
                p.scram = Some(auth::Scram::new(pw));
            }
            if let Some(s) = superuser {
                p.superuser = *s;
            }
            pending.put(auth::key(name), p.to_json().stringify().into_bytes());
            ExecResult::Ok(format!("ALTER USER {name}"))
        }
        Stmt::DropUser { name, if_exists } => {
            if auth::load(src, name)?.is_none() {
                if *if_exists {
                    return Ok(ExecResult::Ok("DROP USER 0".into()));
                }
                return Err(Error::Sql(format!("usuário {name} não existe")));
            }
            // Tira o papel de quem o recebeu.
            for mut other in auth::list(src)? {
                if other.roles.iter().any(|r| r == name) {
                    other.roles.retain(|r| r != name);
                    pending.put(auth::key(&other.name), other.to_json().stringify().into_bytes());
                }
            }
            pending.del(auth::key(name));
            ExecResult::Ok(format!("DROP USER {name}"))
        }
        Stmt::Grant {
            privileges,
            object,
            roles,
            to,
        }
        | Stmt::Revoke {
            privileges,
            object,
            roles,
            from: to,
        } => {
            let grant = matches!(stmt, Stmt::Grant { .. });
            let bits = privileges
                .iter()
                .filter_map(|p| auth::Privilege::parse(p))
                .fold(0u8, |acc, p| acc | p.bits());
            for role in roles {
                match auth::load(src, role)? {
                    Some(_) => {}
                    None => return Err(Error::Sql(format!("papel {role} não existe"))),
                }
            }
            if let Some(obj) = object {
                if obj != "*" && obj != "kv" && load_table(src, obj).is_err() {
                    return Err(Error::UnknownTable(obj.clone()));
                }
            }
            for who in to {
                let mut p = auth::load(src, who)?
                    .ok_or_else(|| Error::Sql(format!("usuário ou papel {who} não existe")))?;
                match object {
                    Some(obj) if grant => p.grant(obj, bits),
                    Some(obj) => p.revoke(obj, bits),
                    None if grant => {
                        for role in roles {
                            if role == who {
                                return Err(Error::Sql(format!("{who} não pode receber a si mesmo")));
                            }
                            if !p.roles.contains(role) {
                                p.roles.push(role.clone());
                            }
                        }
                    }
                    None => p.roles.retain(|r| !roles.contains(r)),
                }
                pending.put(auth::key(who), p.to_json().stringify().into_bytes());
            }
            ExecResult::Ok(if grant { "GRANT" } else { "REVOKE" }.into())
        }
        Stmt::Query(_)
        | Stmt::ShowTables
        | Stmt::ShowUsers
        | Stmt::ShowGrants(_)
        | Stmt::ShowIndexes(_)
        | Stmt::ShowTriggers(_)
        | Stmt::ShowCreate(_)
        | Stmt::Describe(_)
        | Stmt::Explain(..) => unreachable!("leitura"),
    };
    Ok(result)
}

fn save_table(pending: &Pending, t: &Table) {
    pending.put(catalog_key(&t.name), t.to_json().stringify().into_bytes());
}

fn drop_rows_and_indexes(src: &dyn Source, t: &Table, pending: &Pending) -> Result<()> {
    let mut ranges = vec![t.row_prefix()];
    ranges.extend(t.indexes.iter().map(|i| t.index_prefix(i)));
    for start in ranges {
        let end = prefix_successor(&start).expect("prefixo");
        for (k, _) in pending.entries(src, &start, &end)? {
            pending.del(k);
        }
    }
    Ok(())
}

/// Grava as entradas de um índice novo para todas as linhas; devolve quantas.
fn build_index(src: &dyn Source, t: &Table, idx: &IndexDef, pending: &Pending) -> Result<usize> {
    let mut rows = Vec::new();
    fetch_from(src, t, &Access::Full, &mut |pk, row| {
        rows.push((pk, row));
        Ok(true)
    })?;
    let mut seen = HashSet::new();
    for (pk, row) in &rows {
        if !idx.is_btree() {
            index_put(src, t, idx, pending, pk, row)?;
            continue;
        }
        let vals: Vec<&Value> = idx.columns.iter().map(|&c| &row[c]).collect();
        if idx.unique && !vals.iter().any(|v| v.is_null()) && !seen.insert(encode_tuple(&vals)) {
            return Err(Error::Constraint(format!(
                "valores duplicados impedem UNIQUE {}",
                idx.name
            )));
        }
        pending.put(t.index_key(idx, row, pk), pk.clone());
    }
    Ok(rows.len())
}

fn validate_index(t: &Table, idx: &IndexDef) -> Result<()> {
    let numeric = |c: &usize| matches!(t.columns[*c].ty, Type::Int | Type::Real);
    let bad = |m: &str| Err(Error::Sql(format!("índice {}: {m}", idx.name)));
    if idx.unique && !idx.is_btree() {
        return bad("UNIQUE só em índice B-tree");
    }
    for (k, v) in &idx.options {
        match (idx.kind, k.as_str()) {
            (IndexKind::Vector, "metric") if search::Metric::parse(v).is_none() => {
                return bad(&format!("métrica {v} desconhecida (cosine, l2, dot)"));
            }
            (IndexKind::Vector, "metric" | "m" | "ef_construction" | "dims") => {}
            _ => {
                return bad(&format!(
                    "opção {k} não se aplica a índice {}",
                    idx.kind.name()
                ))
            }
        }
    }
    match idx.kind {
        IndexKind::BTree | IndexKind::FullText => Ok(()),
        IndexKind::Vector if idx.columns.len() != 1 => bad("índice vetorial usa uma coluna"),
        IndexKind::Vector => Ok(()),
        IndexKind::Spatial if !(2..=3).contains(&idx.columns.len()) => {
            bad("índice espacial usa 2 ou 3 colunas")
        }
        IndexKind::Spatial if !idx.columns.iter().all(numeric) => {
            bad("colunas do índice espacial precisam ser numéricas")
        }
        IndexKind::Spatial => Ok(()),
    }
}

fn fts_add_stats(
    src: &dyn Source,
    pending: &Pending,
    prefix: &[u8],
    docs: i64,
    len: i64,
) -> Result<()> {
    let (d, l) = fts_stats(&PendingView { src, pending }, prefix)?;
    let mut k = prefix.to_vec();
    k.push(FTS_STATS);
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&(d as i64 + docs).max(0).to_le_bytes());
    v.extend_from_slice(&(l as i64 + len).max(0).to_le_bytes());
    pending.put(k, v);
    Ok(())
}

/// Vetor da coluna indexada (NULL/vazio = não entra no índice).
fn row_vector(idx: &IndexDef, row: &[Value]) -> Result<Option<Vec<f32>>> {
    let v = &row[idx.columns[0]];
    if v.is_null() {
        return Ok(None);
    }
    let vec = search::parse_vector(&v.to_string())?;
    if let Some(dims) = idx.option("dims").and_then(|d| d.parse::<usize>().ok()) {
        if vec.len() != dims {
            return Err(Error::Constraint(format!(
                "índice {} espera {dims} dimensões, recebeu {}",
                idx.name,
                vec.len()
            )));
        }
    }
    Ok(Some(vec))
}

fn spatial_key(t: &Table, idx: &IndexDef, row: &[Value], pk: &[u8]) -> Option<Vec<u8>> {
    let coords: Option<Vec<f64>> = idx.columns.iter().map(|&c| row[c].as_f64()).collect();
    let mut k = t.index_prefix(idx);
    k.extend_from_slice(&search::morton(&coords?).to_be_bytes());
    k.extend_from_slice(pk);
    Some(k)
}

/// Entrada de uma linha num índice full-text, vetorial ou espacial.
fn index_put(
    src: &dyn Source,
    t: &Table,
    idx: &IndexDef,
    pending: &Pending,
    pk: &[u8],
    row: &[Value],
) -> Result<()> {
    let prefix = t.index_prefix(idx);
    match idx.kind {
        IndexKind::BTree => pending.put(t.index_key(idx, row, pk), pk.to_vec()),
        IndexKind::FullText => {
            let positions = search::term_positions(&t.fts_text(idx, row));
            let len: usize = positions.values().map(Vec::len).sum();
            for (term, pos) in &positions {
                let mut k = posting_prefix(&prefix, term);
                k.extend_from_slice(pk);
                pending.put(k, search::encode_positions(pos));
            }
            let mut dk = prefix.clone();
            dk.push(FTS_DOC);
            dk.extend_from_slice(pk);
            pending.put(dk, (len as u32).to_le_bytes().to_vec());
            fts_add_stats(src, pending, &prefix, 1, len as i64)?;
        }
        IndexKind::Vector => {
            if let Some(v) = row_vector(idx, row)? {
                let store = HnswStore {
                    src,
                    pending: Some(pending),
                    prefix,
                };
                search::hnsw_insert(&store, idx.hnsw(), pk, v)?;
            }
        }
        IndexKind::Spatial => {
            if let Some(k) = spatial_key(t, idx, row, pk) {
                pending.put(k, Vec::new());
            }
        }
    }
    Ok(())
}

fn index_del(
    src: &dyn Source,
    t: &Table,
    idx: &IndexDef,
    pending: &Pending,
    pk: &[u8],
    row: &[Value],
) -> Result<()> {
    let prefix = t.index_prefix(idx);
    match idx.kind {
        IndexKind::BTree => pending.del(t.index_key(idx, row, pk)),
        IndexKind::FullText => {
            let positions = search::term_positions(&t.fts_text(idx, row));
            let len: usize = positions.values().map(Vec::len).sum();
            for term in positions.keys() {
                let mut k = posting_prefix(&prefix, term);
                k.extend_from_slice(pk);
                pending.del(k);
            }
            let mut dk = prefix.clone();
            dk.push(FTS_DOC);
            dk.extend_from_slice(pk);
            pending.del(dk);
            fts_add_stats(src, pending, &prefix, -1, -(len as i64))?;
        }
        IndexKind::Vector => {
            // ponytail: tombstone — vizinhos continuam apontando para o nó
            // apagado (a busca ignora); REINDEX compacta o grafo.
            let store = HnswStore {
                src,
                pending: Some(pending),
                prefix: prefix.clone(),
            };
            let node = store.get_node(pk)?;
            let mut nk = prefix.clone();
            nk.push(VEC_NODE);
            nk.extend_from_slice(pk);
            pending.del(nk);
            let mut ek = prefix.clone();
            ek.push(VEC_ENTRY);
            if store.entry()?.is_some_and(|(e, _)| e == pk) {
                let mut replacement = None;
                for level in node.iter().flat_map(|n| n.neighbors.iter()).rev() {
                    for cand in level {
                        if cand != pk && store.get_node(cand)?.is_some() {
                            replacement = Some(cand.clone());
                            break;
                        }
                    }
                    if replacement.is_some() {
                        break;
                    }
                }
                if replacement.is_none() {
                    let mut np = prefix.clone();
                    np.push(VEC_NODE);
                    replacement = pending
                        .entries(src, &np, &prefix_successor(&np).expect("p"))?
                        .into_iter()
                        .map(|(k, _)| k[np.len()..].to_vec())
                        .find(|id| id != pk);
                }
                match replacement {
                    Some(id) => {
                        let level = store
                            .get_node(&id)?
                            .map_or(0, |n| n.neighbors.len().saturating_sub(1));
                        store.set_entry(&id, level)?;
                    }
                    None => pending.del(ek),
                }
            }
        }
        IndexKind::Spatial => {
            if let Some(k) = spatial_key(t, idx, row, pk) {
                pending.del(k);
            }
        }
    }
    Ok(())
}

/// Leitura que enxerga as escritas pendentes (para estatísticas de índice).
struct PendingView<'a> {
    src: &'a dyn Source,
    pending: &'a Pending,
}

impl Source for PendingView<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.pending.get(self.src, key)
    }

    fn scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        visit: &mut dyn FnMut(Vec<u8>, Vec<u8>) -> Result<bool>,
    ) -> Result<()> {
        let end = end
            .map(<[u8]>::to_vec)
            .unwrap_or_else(|| prefix_successor(start).expect("p"));
        for (k, v) in self.pending.entries(self.src, start, &end)? {
            if !visit(k, v)? {
                break;
            }
        }
        Ok(())
    }

    fn guard_unchanged(&self, start: &[u8], end: &[u8]) {
        self.src.guard_unchanged(start, end);
    }

    fn guard_present(&self, start: &[u8], end: &[u8]) {
        self.src.guard_present(start, end);
    }
}

pub(super) fn matching(
    exec: &Exec<'_>,
    t: &Table,
    filter: Option<&Expr>,
) -> Result<Vec<(Vec<u8>, Vec<Value>)>> {
    let scope = table_scope(t);
    let access = exec.plan(t, &t.name, filter, &scope);
    let mut out = Vec::new();
    let mut failure = None;
    exec.fetch(t, &access, &mut |pk, row| {
        match exec.is_true(filter, &Ctx::new(&scope, &row, None)) {
            Ok(true) => out.push((pk, row)),
            Ok(false) => {}
            Err(e) => {
                failure = Some(e);
                return Ok(false);
            }
        }
        Ok(true)
    })?;
    failure.map_or(Ok(out), Err)
}

fn remove_row(
    src: &dyn Source,
    t: &Table,
    pending: &Pending,
    pk: &[u8],
    row: &[Value],
) -> Result<()> {
    pending.del(t.row_key(pk));
    for idx in &t.indexes {
        index_del(src, t, idx, pending, pk, row)?;
    }
    Ok(())
}

/// `RETURNING`: projeta as linhas afetadas no escopo da tabela.
fn returning_rows(
    exec: &Exec<'_>,
    t: &Table,
    items: &[SelectItem],
    rows: &[Vec<Value>],
) -> Result<ExecResult> {
    let scope = table_scope(t);
    let mut columns = Vec::new();
    for item in items {
        match item {
            SelectItem::Star(_) => columns.extend(t.columns.iter().map(|c| c.name.clone())),
            SelectItem::Expr(e, alias) => {
                columns.push(alias.clone().unwrap_or_else(|| super::exec::expr_name(e)))
            }
        }
    }
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let ctx = Ctx::new(&scope, row, None);
        let mut projected = Vec::with_capacity(columns.len());
        for item in items {
            match item {
                SelectItem::Star(_) => projected.extend_from_slice(row),
                SelectItem::Expr(e, _) => projected.push(exec.eval(e, &ctx)?),
            }
        }
        out.push(projected);
    }
    Ok(Output { columns, rows: out }.into_result())
}

/// Resultado de tentar gravar uma linha nova.
enum Written {
    Ok(Vec<Value>),
    /// Conflito de PK/UNIQUE com a linha existente de chave `pk`.
    Conflict(Vec<u8>),
}

fn evaluate_default(exec: &Exec<'_>, col: &ColumnDef) -> Result<Value> {
    let empty = Scope::default();
    match &col.default {
        None => Ok(Value::Null),
        Some(e) => exec.eval(e, &Ctx::new(&empty, &[], None))?.coerce(col.ty),
    }
}

fn check_constraints(exec: &Exec<'_>, t: &Table, row: &[Value]) -> Result<()> {
    if t.checks.is_empty() {
        return Ok(());
    }
    let scope = table_scope(t);
    let ctx = Ctx::new(&scope, row, None);
    for c in &t.checks {
        if exec.eval(&c.expr, &ctx)?.truth() == Some(false) {
            return Err(Error::Constraint(format!(
                "CHECK {}violado em {}: {}",
                c.name.as_ref().map(|n| format!("{n} ")).unwrap_or_default(),
                t.name,
                c.sql
            )));
        }
    }
    Ok(())
}

/// Posições, na tabela pai, das colunas referenciadas pela chave estrangeira.
fn parent_columns(parent: &Table, fk: &Fk) -> Result<Vec<usize>> {
    if fk.parent_columns.is_empty() {
        if parent.pk.is_empty() {
            return Err(Error::Sql(format!(
                "FOREIGN KEY {} referencia {} sem chave primária: informe as colunas",
                fk.name, parent.name
            )));
        }
        return Ok(parent.pk.clone());
    }
    fk.parent_columns.iter().map(|c| parent.column(c)).collect()
}

/// A tabela pai tem uma linha com `values` nas colunas `cols`?
fn parent_has(src: &dyn Source, parent: &Table, cols: &[usize], values: &[&Value]) -> Result<bool> {
    if cols == parent.pk.as_slice() {
        let key = parent.row_key(&encode_tuple(values));
        let found = src.get(&key)?.is_some();
        if found {
            // Numa transação, o pai precisa continuar existindo até o commit.
            let mut end = key.clone();
            end.push(0);
            src.guard_present(&key, &end);
        }
        return Ok(found);
    }
    let Some(i) = parent.unique_index_on(cols) else {
        return Err(Error::Sql(format!(
            "colunas referenciadas em {} precisam ser PRIMARY KEY ou UNIQUE",
            parent.name
        )));
    };
    let idx = &parent.indexes[i];
    // Reordena os valores conforme as colunas do índice.
    let ordered: Vec<&Value> = idx
        .columns
        .iter()
        .map(|c| values[cols.iter().position(|x| x == c).expect("mesmas colunas")])
        .collect();
    let p = parent.index_lookup(idx, &ordered);
    let wanted = encode_tuple(&ordered);
    let mut pks = Vec::new();
    src.scan(&p, Some(&prefix_successor(&p).expect("p")), &mut |_, pk| {
        pks.push(pk);
        Ok(true)
    })?;
    for pk in pks {
        if let Some(raw) = src.get(&parent.row_key(&pk))? {
            let row = parent.decode(&raw)?;
            let theirs: Vec<&Value> = idx.columns.iter().map(|&c| &row[c]).collect();
            if encode_tuple(&theirs) == wanted {
                src.guard_present(&p, &prefix_successor(&p).expect("p"));
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Lado filho: toda chave estrangeira não nula precisa existir no pai.
fn check_foreign_keys(exec: &Exec<'_>, pending: &Pending, t: &Table, row: &[Value]) -> Result<()> {
    if t.fks.is_empty() {
        return Ok(());
    }
    let overlay = pending.source(exec.src);
    for fk in &t.fks {
        let values: Vec<&Value> = fk.columns.iter().map(|&c| &row[c]).collect();
        if values.iter().any(|v| v.is_null()) {
            continue;
        }
        let parent_rc;
        let parent: &Table = if fk.parent == t.name {
            t
        } else {
            parent_rc = exec.table(&fk.parent)?;
            &parent_rc
        };
        let cols = parent_columns(parent, fk)?;
        if !parent_has(&overlay, parent, &cols, &values)? {
            let shown: Vec<String> = values.iter().map(ToString::to_string).collect();
            return Err(Error::Constraint(format!(
                "FOREIGN KEY {} violada: {}({}) não existe em {}",
                fk.name,
                fk.columns
                    .iter()
                    .map(|&c| t.columns[c].name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                shown.join(", "),
                parent.name
            )));
        }
    }
    Ok(())
}

/// Linhas de `child` cujas colunas da FK valem `values` (lidas com as
/// escritas pendentes aplicadas).
fn referencing_rows(
    exec: &Exec<'_>,
    pending: &Pending,
    child: &Table,
    fk: &Fk,
    values: &[&Value],
) -> Result<Vec<(Vec<u8>, Vec<Value>)>> {
    let overlay = pending.source(exec.src);
    let owned: Vec<Value> = values.iter().map(|v| (*v).clone()).collect();
    let access = match child.index_prefixed_by(&fk.columns) {
        Some(i) => Access::Index(i, owned.clone()),
        None => Access::Full,
    };
    // Numa transação, as filhas desta chave não podem mudar até o commit: outra
    // sessão poderia inserir uma filha do pai que está sendo apagado/alterado.
    let guarded = match child.index_prefixed_by(&fk.columns) {
        Some(i) => child.index_lookup(&child.indexes[i], values),
        None => child.row_prefix(),
    };
    let src = exec.src;
    src.guard_unchanged(&guarded, &prefix_successor(&guarded).expect("p"));
    let wanted = encode_tuple(values);
    let mut out = Vec::new();
    fetch_from(&overlay, child, &access, &mut |pk, row| {
        let theirs: Vec<&Value> = fk.columns.iter().map(|&c| &row[c]).collect();
        if encode_tuple(&theirs) == wanted {
            out.push((pk, row));
        }
        Ok(true)
    })?;
    Ok(out)
}

/// Linhas filhas alcançadas por ações referenciais: pk -> (linha, mudanças).
type Touched = std::collections::BTreeMap<Vec<u8>, (Vec<Value>, Vec<(usize, Value)>)>;

/// Lado pai: linhas removidas (`new = None`) ou alteradas disparam as ações
/// referenciais das tabelas filhas. Todas as chaves estrangeiras de uma mesma
/// linha filha são aplicadas juntas, como no fim do comando.
fn propagate_to_children(
    exec: &Exec<'_>,
    pending: &Pending,
    parent: &Table,
    old_rows: &[Vec<Value>],
    new_rows: Option<&[Vec<Value>]>,
) -> Result<()> {
    let children = exec.children_of(&parent.name)?;
    if children.is_empty() {
        return Ok(());
    }
    for child in children.iter() {
        // pk da linha filha -> (linha, alterações pendentes por coluna)
        let mut touched: Touched = Touched::new();
        let mut to_delete: Vec<(Vec<u8>, Vec<Value>)> = Vec::new();
        for fk in child.fks.iter().filter(|f| f.parent == parent.name) {
            let cols = parent_columns(parent, fk)?;
            let action = if new_rows.is_some() {
                fk.on_update
            } else {
                fk.on_delete
            };
            for (i, old) in old_rows.iter().enumerate() {
                let old_vals: Vec<&Value> = cols.iter().map(|&c| &old[c]).collect();
                if old_vals.iter().any(|v| v.is_null()) {
                    continue;
                }
                let new_vals: Option<Vec<&Value>> =
                    new_rows.map(|rows| cols.iter().map(|&c| &rows[i][c]).collect());
                if let Some(nv) = &new_vals {
                    if encode_tuple(nv) == encode_tuple(&old_vals) {
                        continue;
                    }
                }
                let refs = referencing_rows(exec, pending, child, fk, &old_vals)?;
                if refs.is_empty() {
                    continue;
                }
                match action {
                    FkAction::NoAction | FkAction::Restrict => {
                        return Err(Error::Constraint(format!(
                            "{} em {} bloqueado: {} linha(s) de {} referenciam ({}) via {}",
                            if new_rows.is_some() {
                                "UPDATE"
                            } else {
                                "DELETE"
                            },
                            parent.name,
                            refs.len(),
                            child.name,
                            old_vals
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                            fk.name
                        )));
                    }
                    FkAction::Cascade if new_rows.is_none() => {
                        for (pk, row) in refs {
                            touched.remove(&pk);
                            if !to_delete.iter().any(|(p, _)| *p == pk) {
                                to_delete.push((pk, row));
                            }
                        }
                    }
                    FkAction::Cascade | FkAction::SetNull | FkAction::SetDefault => {
                        for (pk, row) in refs {
                            if to_delete.iter().any(|(p, _)| *p == pk) {
                                continue;
                            }
                            let entry = touched.entry(pk).or_insert_with(|| (row, Vec::new()));
                            for (k, &c) in fk.columns.iter().enumerate() {
                                let v = match action {
                                    FkAction::Cascade => {
                                        new_vals.as_ref().expect("update")[k].clone()
                                    }
                                    FkAction::SetNull => Value::Null,
                                    _ => evaluate_default(exec, &child.columns[c])?,
                                };
                                entry.1.push((c, v));
                            }
                        }
                    }
                }
            }
        }
        if !to_delete.is_empty() {
            delete_rows(exec, pending, child, to_delete)?;
        }
        if !touched.is_empty() {
            let mut targets = Vec::with_capacity(touched.len());
            let mut updated = Vec::with_capacity(touched.len());
            for (pk, (row, changes)) in touched {
                let mut r = row.clone();
                for (c, v) in changes {
                    r[c] = v;
                }
                targets.push((pk, row));
                updated.push(r);
            }
            update_rows(exec, pending, child, targets, updated)?;
        }
    }
    Ok(())
}

/// Remove linhas (e entradas de índice), dispara gatilhos e propaga
/// `ON DELETE`. Devolve as linhas apagadas.
fn delete_rows(
    exec: &Exec<'_>,
    pending: &Pending,
    t: &Table,
    targets: Vec<(Vec<u8>, Vec<Value>)>,
) -> Result<Vec<Vec<Value>>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let mut kept = Vec::with_capacity(targets.len());
    for (pk, row) in targets {
        if fire_triggers(
            exec,
            pending,
            t,
            TriggerTiming::Before,
            &TriggerEvent::Delete,
            Some(&row),
            None,
        )? {
            kept.push((pk, row));
        }
    }
    for (pk, row) in &kept {
        remove_row(exec.src, t, pending, pk, row)?;
    }
    let old: Vec<Vec<Value>> = kept.into_iter().map(|(_, r)| r).collect();
    for row in &old {
        record_change(pending, t, ChangeKind::Delete, Some(row), None);
        fire_triggers(
            exec,
            pending,
            t,
            TriggerTiming::After,
            &TriggerEvent::Delete,
            Some(row),
            None,
        )?;
    }
    propagate_to_children(exec, pending, t, &old, None)?;
    Ok(old)
}

fn record_change(
    pending: &Pending,
    t: &Table,
    kind: ChangeKind,
    old: Option<&[Value]>,
    new: Option<&[Value]>,
) {
    if matches!(t.kind, TableKind::Materialized { .. }) {
        return;
    }
    pending.change(Change {
        lsn: 0,
        table: t.name.clone(),
        kind,
        columns: t.columns.iter().map(|c| c.name.clone()).collect(),
        old: old.map(<[Value]>::to_vec),
        new: new.map(<[Value]>::to_vec),
    });
}

/// Escritas diretas em views materializadas são recusadas.
fn writable(t: &Table) -> Result<()> {
    if matches!(t.kind, TableKind::Materialized { .. }) {
        return Err(Error::Sql(format!(
            "{} é view materializada (somente leitura): use REFRESH MATERIALIZED VIEW",
            t.name
        )));
    }
    Ok(())
}

/// Substitui linhas: remove as antigas, grava as novas (com validações) e
/// propaga `ON UPDATE`. Devolve as linhas gravadas.
fn update_rows(
    exec: &Exec<'_>,
    pending: &Pending,
    t: &Table,
    targets: Vec<(Vec<u8>, Vec<Value>)>,
    new_rows: Vec<Vec<Value>>,
) -> Result<Vec<Vec<Value>>> {
    // Gatilhos BEFORE UPDATE podem ignorar linhas (RAISE(IGNORE)).
    let mut pairs = Vec::with_capacity(targets.len());
    let changed_cols = |old: &[Value], new: &[Value]| -> Vec<String> {
        t.columns
            .iter()
            .enumerate()
            .filter(|(i, _)| old[*i] != new[*i])
            .map(|(_, c)| c.name.clone())
            .collect()
    };
    for ((pk, old), new) in targets.into_iter().zip(new_rows) {
        let event = TriggerEvent::Update(changed_cols(&old, &new));
        if fire_triggers(
            exec,
            pending,
            t,
            TriggerTiming::Before,
            &event,
            Some(&old),
            Some(&new),
        )? {
            pairs.push((pk, old, new));
        }
    }
    // Primeiro remove todas as versões antigas: trocas de PK/UNIQUE entre
    // linhas do mesmo UPDATE não geram falso conflito.
    for (pk, old, _) in &pairs {
        remove_row(exec.src, t, pending, pk, old)?;
    }
    let mut written = Vec::with_capacity(pairs.len());
    let mut old_rows = Vec::with_capacity(pairs.len());
    for (_, old, new) in pairs {
        match write_row(exec, t, pending, new, false, false)? {
            Written::Ok(r) => {
                record_change(pending, t, ChangeKind::Update, Some(&old), Some(&r));
                written.push(r);
                old_rows.push(old);
            }
            Written::Conflict(_) => unreachable!("sem detecção"),
        }
    }
    check_fks_all(exec, pending, t, &written)?;
    for (old, new) in old_rows.iter().zip(&written) {
        let event = TriggerEvent::Update(changed_cols(old, new));
        fire_triggers(
            exec,
            pending,
            t,
            TriggerTiming::After,
            &event,
            Some(old),
            Some(new),
        )?;
    }
    propagate_to_children(exec, pending, t, &old_rows, Some(&written))?;
    Ok(written)
}

/// Lado filho para todas as linhas gravadas, com o lote inteiro visível.
fn check_fks_all(exec: &Exec<'_>, pending: &Pending, t: &Table, rows: &[Vec<Value>]) -> Result<()> {
    if t.fks.is_empty() {
        return Ok(());
    }
    for row in rows {
        check_foreign_keys(exec, pending, t, row)?;
    }
    Ok(())
}

/// Valida tipos/restrições e grava linha + entradas de índice. Com
/// `detect_conflict`, um conflito de chave vira [`Written::Conflict`].
fn write_row(
    exec: &Exec<'_>,
    t: &Table,
    pending: &Pending,
    mut row: Vec<Value>,
    autoinc: bool,
    detect_conflict: bool,
) -> Result<Written> {
    // Chaves estrangeiras são conferidas no fim do comando (`check_fks_all`):
    // linhas do mesmo lote podem referenciar umas às outras em qualquer ordem.
    let src = exec.src;
    if row.len() != t.columns.len() {
        return Err(Error::Sql(format!(
            "{} valores para {} colunas",
            row.len(),
            t.columns.len()
        )));
    }
    for (i, col) in t.columns.iter().enumerate() {
        row[i] = std::mem::replace(&mut row[i], Value::Null).coerce(col.ty)?;
    }
    let seq_key = t.rowid_key();
    let next = pending
        .get(src, &seq_key)?
        .and_then(|v| v.try_into().ok())
        .map(i64::from_le_bytes)
        .unwrap_or(1);
    let mut assigned = false;
    for (i, col) in t.columns.iter().enumerate() {
        let auto_pk = autoinc && t.pk == [i] && col.ty == Type::Int;
        if row[i].is_null() && (col.autoincrement || auto_pk) {
            row[i] = Value::Int(next);
            assigned = true;
        }
    }
    let pk_values: Vec<Value> = if t.pk.is_empty() {
        assigned = true;
        vec![Value::Int(next)]
    } else {
        for &c in &t.pk {
            if row[c].is_null() {
                return Err(Error::Constraint(format!(
                    "PRIMARY KEY {} não pode ser NULL",
                    t.columns[c].name
                )));
            }
        }
        t.pk.iter().map(|&c| row[c].clone()).collect()
    };
    for (i, col) in t.columns.iter().enumerate() {
        if col.not_null && row[i].is_null() {
            return Err(Error::Constraint(format!(
                "{}.{} é NOT NULL",
                t.name, col.name
            )));
        }
    }
    let pk = encode_tuple(&pk_values.iter().collect::<Vec<_>>());
    if pk.len() > MAX_PK_BYTES {
        return Err(Error::Constraint(format!(
            "chave primária de {} bytes excede o máximo de {MAX_PK_BYTES}",
            pk.len()
        )));
    }
    let row_key = t.row_key(&pk);
    if pending.get(src, &row_key)?.is_some() {
        if detect_conflict {
            return Ok(Written::Conflict(pk));
        }
        let shown: Vec<String> = pk_values.iter().map(ToString::to_string).collect();
        return Err(Error::Constraint(format!(
            "chave primária duplicada ({}) em {}",
            shown.join(", "),
            t.name
        )));
    }
    for idx in &t.indexes {
        let vals: Vec<&Value> = idx.columns.iter().map(|&c| &row[c]).collect();
        if !idx.unique || vals.iter().any(|v| v.is_null()) {
            continue;
        }
        // Entradas podem estar truncadas: confere o valor real de cada candidata.
        let p = t.index_lookup(idx, &vals);
        // Numa transação, ninguém pode gravar o mesmo valor único até o commit.
        src.guard_unchanged(&p, &prefix_successor(&p).expect("p"));
        let wanted = encode_tuple(&vals);
        for (_, other_pk) in pending.entries(src, &p, &prefix_successor(&p).expect("p"))? {
            let Some(raw) = pending.get(src, &t.row_key(&other_pk))? else {
                continue;
            };
            let other = t.decode(&raw)?;
            let theirs: Vec<&Value> = idx.columns.iter().map(|&c| &other[c]).collect();
            if encode_tuple(&theirs) == wanted {
                if detect_conflict {
                    return Ok(Written::Conflict(other_pk));
                }
                let shown: Vec<String> = vals.iter().map(ToString::to_string).collect();
                return Err(Error::Constraint(format!(
                    "valor duplicado ({}) em {} (UNIQUE {})",
                    shown.join(", "),
                    t.name,
                    idx.name
                )));
            }
        }
    }
    check_constraints(exec, t, &row)?;
    // Sequência: acompanha o maior inteiro usado em PK/autoincremento.
    let mut high = if assigned { Some(next) } else { None };
    if let [Value::Int(n)] = pk_values.as_slice() {
        if *n >= next {
            high = Some(high.map_or(*n, |h| h.max(*n)));
        }
    }
    for (i, col) in t.columns.iter().enumerate() {
        if let (true, Value::Int(n)) = (col.autoincrement, &row[i]) {
            if *n >= next {
                high = Some(high.map_or(*n, |h| h.max(*n)));
            }
        }
    }
    if let Some(h) = high {
        pending.put(seq_key, h.saturating_add(1).to_le_bytes().to_vec());
    }
    for idx in &t.indexes {
        index_put(src, t, idx, pending, &pk, &row)?;
    }
    pending.put(row_key, encode_row(&row));
    Ok(Written::Ok(row))
}

fn reserved_name(name: &str) -> Result<()> {
    if matches!(name, "kv" | "t" | "excluded") {
        return Err(Error::Sql(format!(
            "{name} é um nome reservado (tabela chave-valor / upsert)"
        )));
    }
    Ok(())
}

fn name_in_use(src: &dyn Source, name: &str) -> Result<Option<&'static str>> {
    match load_table(src, name) {
        Ok(_) => return Ok(Some("tabela")),
        Err(Error::UnknownTable(_)) => {}
        Err(e) => return Err(e),
    }
    Ok(load_view(src, name)?.map(|_| "view"))
}

/// Confere que uma expressão de CHECK/DEFAULT só usa o que pode.
fn validate_check(t_name: &str, columns: &[ColumnDef], check: &Check) -> Result<()> {
    if has_subquery(&check.expr) || has_agg_or_window(&check.expr) {
        return Err(Error::Sql(format!(
            "CHECK em {t_name} não pode ter subconsulta, agregado ou janela"
        )));
    }
    let mut refs = Vec::new();
    columns_of(&check.expr, &mut refs);
    for (q, c) in refs {
        if q.as_deref().is_some_and(|q| q != t_name) || !columns.iter().any(|col| col.name == c) {
            return Err(unknown_column(q.as_deref(), &c));
        }
    }
    Ok(())
}

fn validate_default(col: &ColumnDef) -> Result<()> {
    if let Some(e) = &col.default {
        let mut refs = Vec::new();
        columns_of(e, &mut refs);
        if !refs.is_empty() || has_subquery(e) || has_agg_or_window(e) {
            return Err(Error::Sql(format!(
                "DEFAULT de {} só pode usar constantes e funções",
                col.name
            )));
        }
    }
    Ok(())
}

/// Monta a chave estrangeira validando contra a tabela pai (ou a própria).
fn resolve_fk(
    src: &dyn Source,
    t_name: &str,
    columns: &[ColumnDef],
    fk: &ForeignKey,
    index: usize,
) -> Result<Fk> {
    let position = |c: &String| {
        columns
            .iter()
            .position(|x| x.name == *c)
            .ok_or_else(|| Error::Sql(format!("coluna inexistente {c}")))
    };
    let cols = fk
        .columns
        .iter()
        .map(position)
        .collect::<Result<Vec<_>>>()?;
    if cols.is_empty() {
        return Err(Error::Sql("FOREIGN KEY sem colunas".into()));
    }
    let name = fk.name.clone().unwrap_or_else(|| {
        format!(
            "{t_name}_{}_fkey{}",
            fk.columns.join("_"),
            if index > 0 {
                index.to_string()
            } else {
                String::new()
            }
        )
    });
    let resolved = Fk {
        name,
        columns: cols.clone(),
        parent: fk.parent.clone(),
        parent_columns: fk.parent_columns.clone(),
        on_delete: fk.on_delete,
        on_update: fk.on_update,
    };
    // Tabela pai: a própria (autorreferência) ou uma existente.
    let self_ref = fk.parent == t_name;
    let parent_owned;
    let parent: Option<&Table> = if self_ref {
        None
    } else {
        parent_owned = load_table(src, &fk.parent).map_err(|e| match e {
            Error::UnknownTable(p) => {
                Error::Sql(format!("FOREIGN KEY referencia tabela inexistente {p}"))
            }
            other => other,
        })?;
        Some(&parent_owned)
    };
    let (parent_cols, parent_types): (Vec<String>, Vec<Type>) = match parent {
        Some(p) => {
            let pcols = parent_columns(p, &resolved)?;
            let ok = pcols == p.pk || p.unique_index_on(&pcols).is_some();
            if !ok {
                return Err(Error::Sql(format!(
                    "FOREIGN KEY {}: colunas referenciadas em {} precisam ser PRIMARY KEY ou UNIQUE",
                    resolved.name, p.name
                )));
            }
            (
                pcols.iter().map(|&c| p.columns[c].name.clone()).collect(),
                pcols.iter().map(|&c| p.columns[c].ty).collect(),
            )
        }
        None => {
            // Autorreferência: só a chave primária da própria tabela.
            if !fk.parent_columns.is_empty() {
                let types = fk
                    .parent_columns
                    .iter()
                    .map(|c| position(c).map(|i| columns[i].ty))
                    .collect::<Result<Vec<_>>>()?;
                (fk.parent_columns.clone(), types)
            } else {
                let pk: Vec<&ColumnDef> = columns.iter().filter(|c| c.primary).collect();
                if pk.is_empty() {
                    return Err(Error::Sql(format!(
                        "FOREIGN KEY {} autorreferente exige PRIMARY KEY declarada na coluna ou colunas explícitas",
                        resolved.name
                    )));
                }
                (
                    pk.iter().map(|c| c.name.clone()).collect(),
                    pk.iter().map(|c| c.ty).collect(),
                )
            }
        }
    };
    if parent_cols.len() != cols.len() {
        return Err(Error::Sql(format!(
            "FOREIGN KEY {}: {} coluna(s) referenciando {} coluna(s)",
            resolved.name,
            cols.len(),
            parent_cols.len()
        )));
    }
    for (&c, ty) in cols.iter().zip(&parent_types) {
        if columns[c].ty != *ty {
            return Err(Error::Sql(format!(
                "FOREIGN KEY {}: {} é {} mas a coluna referenciada é {}",
                resolved.name,
                columns[c].name,
                columns[c].ty.name(),
                ty.name()
            )));
        }
    }
    if matches!(fk.on_delete, FkAction::SetNull) || matches!(fk.on_update, FkAction::SetNull) {
        for &c in &cols {
            if columns[c].not_null || columns[c].primary {
                return Err(Error::Sql(format!(
                    "FOREIGN KEY {}: SET NULL em coluna NOT NULL ({})",
                    resolved.name, columns[c].name
                )));
            }
        }
    }
    Ok(resolved)
}

#[allow(clippy::too_many_arguments)]
fn create_table(
    exec: &Exec<'_>,
    pending: &Pending,
    name: &str,
    columns: &[ColumnDef],
    primary_key: &[String],
    uniques: &[Vec<String>],
    checks: &[Check],
    foreign_keys: &[ForeignKey],
    if_not_exists: bool,
) -> Result<String> {
    reserved_name(name)?;
    match name_in_use(exec.src, name)? {
        Some(_) if if_not_exists => return Ok(format!("CREATE TABLE {name} (já existe)")),
        Some(kind) => return Err(Error::Sql(format!("{kind} {name} já existe"))),
        None => {}
    }
    if columns.is_empty() {
        return Err(Error::Sql("tabela sem colunas".into()));
    }
    let mut names = BTreeSet::new();
    for c in columns {
        if !names.insert(c.name.as_str()) {
            return Err(Error::Sql(format!("coluna {} repetida", c.name)));
        }
        if c.autoincrement && c.ty != Type::Int {
            return Err(Error::Sql(format!(
                "AUTOINCREMENT/SERIAL exige INTEGER ({})",
                c.name
            )));
        }
        validate_default(c)?;
    }
    let position = |c: &String| {
        columns
            .iter()
            .position(|x| x.name == *c)
            .ok_or_else(|| Error::Sql(format!("coluna inexistente {c}")))
    };
    let pk = primary_key
        .iter()
        .map(position)
        .collect::<Result<Vec<_>>>()?;
    if pk.iter().collect::<HashSet<_>>().len() != pk.len() {
        return Err(Error::Sql("coluna repetida na PRIMARY KEY".into()));
    }
    for c in checks {
        validate_check(name, columns, c)?;
    }
    let id = exec
        .src
        .get(TABLE_SEQ)?
        .and_then(|v| v.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(1);
    let mut columns = columns.to_vec();
    for (i, c) in columns.iter_mut().enumerate() {
        // `primary` marca colunas da PK (usado pela autorreferência).
        c.primary = pk.contains(&i);
        if let Some(Expr::Lit(v)) = &c.default {
            let coerced = v.clone().coerce(c.ty)?;
            c.default = Some(Expr::Lit(coerced));
        }
        c.check = None;
        c.references = None;
    }
    let mut t = Table {
        name: name.to_string(),
        id,
        pk,
        indexes: Vec::new(),
        checks: checks.to_vec(),
        fks: Vec::new(),
        triggers: Vec::new(),
        kind: TableKind::Table,
        next_index_id: 1,
        columns,
    };
    let mut unique_sets: Vec<Vec<usize>> = (0..t.columns.len())
        .filter(|&i| t.columns[i].unique && t.pk != [i])
        .map(|i| vec![i])
        .collect();
    for u in uniques {
        unique_sets.push(u.iter().map(position).collect::<Result<Vec<_>>>()?);
    }
    for cols in unique_sets {
        let label: Vec<&str> = cols.iter().map(|&c| t.columns[c].name.as_str()).collect();
        t.indexes.push(IndexDef::btree(
            format!("{name}_{}_key", label.join("_")),
            cols,
            true,
            t.next_index_id,
            true,
        ));
        t.next_index_id += 1;
    }
    for (i, fk) in foreign_keys.iter().enumerate() {
        let resolved = resolve_fk(exec.src, name, &t.columns, fk, i)?;
        if t.fks.iter().any(|f| f.name == resolved.name) {
            return Err(Error::Sql(format!(
                "FOREIGN KEY {} repetida",
                resolved.name
            )));
        }
        // Índice para achar filhas ao apagar/alterar o pai.
        if t.index_prefixed_by(&resolved.columns).is_none() && t.pk[..] != resolved.columns[..] {
            let label: Vec<&str> = resolved
                .columns
                .iter()
                .map(|&c| t.columns[c].name.as_str())
                .collect();
            t.indexes.push(IndexDef::btree(
                format!("{name}_{}_fkey_idx", label.join("_")),
                resolved.columns.clone(),
                false,
                t.next_index_id,
                true,
            ));
            t.next_index_id += 1;
        }
        t.fks.push(resolved);
    }
    pending.put(TABLE_SEQ.to_vec(), (id + 1).to_le_bytes().to_vec());
    save_table(pending, &t);
    Ok(format!("CREATE TABLE {name}"))
}

fn insert(
    exec: &Exec<'_>,
    pending: &Pending,
    table: &str,
    columns: Option<&[String]>,
    source: &InsertSource,
    on_conflict: Option<&OnConflict>,
    returning: &[SelectItem],
) -> Result<ExecResult> {
    let t = match exec.table(table) {
        Ok(t) => t,
        Err(Error::UnknownTable(name)) if load_view(exec.src, &name)?.is_some() => {
            return Err(Error::Sql(format!("view {name} é somente leitura")))
        }
        Err(e) => return Err(e),
    };
    writable(&t)?;
    insert_rows(exec, pending, &t, columns, source, on_conflict, returning)
}

/// Insere em `t` (também usado pelo REFRESH de views materializadas).
fn insert_rows(
    exec: &Exec<'_>,
    pending: &Pending,
    t: &Table,
    columns: Option<&[String]>,
    source: &InsertSource,
    on_conflict: Option<&OnConflict>,
    returning: &[SelectItem],
) -> Result<ExecResult> {
    let targets: Vec<usize> = match columns {
        Some(cols) => cols.iter().map(|c| t.column(c)).collect::<Result<_>>()?,
        None => (0..t.columns.len()).collect(),
    };
    let empty = Scope::default();
    let rows: Vec<Vec<Value>> = match source {
        InsertSource::Values(rows) => rows
            .iter()
            .map(|exprs| {
                exprs
                    .iter()
                    .map(|e| exec.eval(e, &Ctx::new(&empty, &[], None)))
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<_>>()?,
        InsertSource::Query(q) => exec.query(q, None)?.rows,
        InsertSource::Default => vec![Vec::new()],
    };
    let targets: &[usize] = if matches!(source, InsertSource::Default) {
        &[]
    } else {
        &targets
    };
    let scope = table_scope(t);
    let mut excluded = Scope::default();
    excluded.add(
        "excluded",
        &t.columns.iter().map(|c| c.name.clone()).collect::<Vec<_>>(),
    );
    let (mut inserted, mut updated) = (0usize, 0usize);
    let mut affected: Vec<Vec<Value>> = Vec::new();
    let mut fresh: Vec<Vec<Value>> = Vec::new();
    for values in rows {
        if values.len() != targets.len() {
            return Err(Error::Sql(format!(
                "{} valores para {} colunas",
                values.len(),
                targets.len()
            )));
        }
        let mut row: Vec<Value> = Vec::with_capacity(t.columns.len());
        for (i, c) in t.columns.iter().enumerate() {
            row.push(if targets.contains(&i) {
                Value::Null
            } else {
                evaluate_default(exec, c)?
            });
        }
        for (i, v) in targets.iter().zip(values) {
            row[*i] = v;
        }
        // Tipos antes dos gatilhos BEFORE, para NEW.c já vir convertido.
        for (i, c) in t.columns.iter().enumerate() {
            row[i] = std::mem::replace(&mut row[i], Value::Null).coerce(c.ty)?;
        }
        if !fire_triggers(
            exec,
            pending,
            t,
            TriggerTiming::Before,
            &TriggerEvent::Insert,
            None,
            Some(&row),
        )? {
            continue;
        }
        let mut attempts = 0;
        loop {
            attempts += 1;
            match write_row(exec, t, pending, row.clone(), true, on_conflict.is_some())? {
                Written::Ok(r) => {
                    inserted += 1;
                    record_change(pending, t, ChangeKind::Insert, None, Some(&r));
                    fire_triggers(
                        exec,
                        pending,
                        t,
                        TriggerTiming::After,
                        &TriggerEvent::Insert,
                        None,
                        Some(&r),
                    )?;
                    fresh.push(r.clone());
                    affected.push(r);
                    break;
                }
                Written::Conflict(pk) => {
                    match on_conflict.expect("detecção só com ON CONFLICT") {
                        OnConflict::Nothing => break,
                        OnConflict::Replace => {
                            let raw = pending
                                .get(exec.src, &t.row_key(&pk))?
                                .ok_or_else(|| Error::Other("linha em conflito sumiu".into()))?;
                            let existing = t.decode(&raw)?;
                            delete_rows(exec, pending, t, vec![(pk, existing)])?;
                            if attempts > t.indexes.len() + 2 {
                                return Err(Error::Other("REPLACE não convergiu".into()));
                            }
                            continue;
                        }
                        OnConflict::Update { sets, filter } => {
                            let raw = pending
                                .get(exec.src, &t.row_key(&pk))?
                                .ok_or_else(|| Error::Other("linha em conflito sumiu".into()))?;
                            let existing = t.decode(&raw)?;
                            // Colunas sem prefixo são da linha existente; `excluded.x` é
                            // a linha proposta (escopo externo).
                            let proposed: Vec<Value> = row
                                .iter()
                                .zip(&t.columns)
                                .map(|(v, c)| v.clone().coerce(c.ty))
                                .collect::<Result<_>>()?;
                            let outer = Ctx::new(&excluded, &proposed, None);
                            let ctx = Ctx::new(&scope, &existing, Some(&outer));
                            if !exec.is_true(filter.as_ref(), &ctx)? {
                                break;
                            }
                            let mut new_row = existing.clone();
                            for (c, e) in sets {
                                new_row[t.column(c)?] = exec.eval(e, &ctx)?;
                            }
                            let written =
                                update_rows(exec, pending, t, vec![(pk, existing)], vec![new_row])?;
                            affected.extend(written);
                            updated += 1;
                            break;
                        }
                    }
                }
            }
        }
    }
    // Linhas alteradas pelo upsert já foram conferidas em `update_rows`; as
    // inseridas são conferidas agora, com o lote completo.
    check_fks_all(exec, pending, t, &fresh)?;
    if !returning.is_empty() {
        return returning_rows(exec, t, returning, &affected);
    }
    Ok(ExecResult::Ok(if on_conflict.is_some() {
        format!("INSERT {inserted} UPDATE {updated}")
    } else {
        format!("INSERT {inserted}")
    }))
}

// ---------------------------------------------------------------------------
// ALTER TABLE
// ---------------------------------------------------------------------------

fn add_column(
    exec: &Exec<'_>,
    pending: &Pending,
    table: &str,
    column: &ColumnDef,
) -> Result<String> {
    let mut t = load_table(exec.src, table)?;
    if column.primary || column.unique {
        return Err(Error::Sql(
            "ADD COLUMN não aceita PRIMARY KEY/UNIQUE: crie um índice único depois".into(),
        ));
    }
    if column.not_null && column.default.is_none() {
        return Err(Error::Sql("ADD COLUMN NOT NULL exige DEFAULT".into()));
    }
    if t.column(&column.name).is_ok() {
        return Err(Error::Sql(format!("coluna {} já existe", column.name)));
    }
    if column.autoincrement && column.ty != Type::Int {
        return Err(Error::Sql("AUTOINCREMENT exige INTEGER".into()));
    }
    validate_default(column)?;
    let mut column = column.clone();
    // Linhas antigas recebem o valor do DEFAULT avaliado agora.
    column.fill = Some(evaluate_default(exec, &column)?);
    if let Some(Expr::Lit(v)) = &column.default {
        column.default = Some(Expr::Lit(v.clone().coerce(column.ty)?));
    }
    let check = column.check.take();
    let references = column.references.take();
    t.columns.push(column);
    let new_index = t.columns.len() - 1;
    if let Some(c) = check {
        validate_check(&t.name, &t.columns, &c)?;
        // A restrição vale para as linhas antigas com o valor de preenchimento.
        let fill = t.columns[new_index].fill.clone().unwrap_or(Value::Null);
        let mut probe: Vec<Value> = vec![Value::Null; t.columns.len()];
        probe[new_index] = fill;
        let mut probe_table = t.clone();
        probe_table.checks = vec![c.clone()];
        check_constraints(exec, &probe_table, &probe).map_err(|_| {
            Error::Constraint(format!(
                "CHECK ({}) falha para o DEFAULT das linhas existentes",
                c.sql
            ))
        })?;
        t.checks.push(c);
    }
    if let Some(mut fk) = references {
        fk.columns = vec![t.columns[new_index].name.clone()];
        let resolved = resolve_fk(exec.src, &t.name, &t.columns, &fk, t.fks.len())?;
        let fill = t.columns[new_index].fill.clone().unwrap_or(Value::Null);
        if !fill.is_null() {
            let mut any = false;
            fetch_from(exec.src, &t, &Access::Full, &mut |_, _| {
                any = true;
                Ok(false)
            })?;
            if any {
                let parent = exec.table(&resolved.parent)?;
                let cols = parent_columns(&parent, &resolved)?;
                if !parent_has(exec.src, &parent, &cols, &[&fill])? {
                    return Err(Error::Constraint(format!(
                        "DEFAULT {fill} não existe em {} (linhas existentes violariam a FOREIGN KEY)",
                        parent.name
                    )));
                }
            }
        }
        if t.index_prefixed_by(&resolved.columns).is_none() {
            let idx = IndexDef::btree(
                format!("{}_{}_fkey_idx", t.name, t.columns[new_index].name),
                resolved.columns.clone(),
                false,
                t.next_index_id,
                true,
            );
            t.next_index_id += 1;
            build_index(exec.src, &t, &idx, pending)?;
            t.indexes.push(idx);
        }
        t.fks.push(resolved);
    }
    save_table(pending, &t);
    Ok(format!("ALTER TABLE {} ADD COLUMN", t.name))
}

fn drop_column(
    exec: &Exec<'_>,
    pending: &Pending,
    table: &str,
    column: &str,
    if_exists: bool,
) -> Result<String> {
    let mut t = load_table(exec.src, table)?;
    let c = match t.column(column) {
        Ok(c) => c,
        Err(_) if if_exists => return Ok("ALTER TABLE DROP COLUMN 0".into()),
        Err(e) => return Err(e),
    };
    if t.pk.contains(&c) {
        return Err(Error::Sql(format!("{column} faz parte da PRIMARY KEY")));
    }
    if t.fks.iter().any(|f| f.columns.contains(&c)) {
        return Err(Error::Sql(format!("{column} faz parte de uma FOREIGN KEY")));
    }
    // Como no PostgreSQL, CHECKs que usam a coluna caem junto com ela.
    t.checks.retain(|check| {
        let mut refs = Vec::new();
        columns_of(&check.expr, &mut refs);
        !refs.iter().any(|(_, name)| name == column)
    });
    for child in exec.children_of(&t.name)?.iter() {
        for fk in child.fks.iter().filter(|f| f.parent == t.name) {
            let cols = parent_columns(&t, fk)?;
            if cols.contains(&c) {
                return Err(Error::Sql(format!(
                    "{column} é referenciada pela FOREIGN KEY {} de {}",
                    fk.name, child.name
                )));
            }
        }
    }
    if t.columns.len() == 1 {
        return Err(Error::Sql("tabela não pode ficar sem colunas".into()));
    }
    // Índices que usam a coluna somem; os demais remapeiam as posições.
    let mut kept = Vec::new();
    for idx in std::mem::take(&mut t.indexes) {
        if idx.columns.contains(&c) {
            let p = t.index_prefix(&idx);
            for (k, _) in pending.entries(exec.src, &p, &prefix_successor(&p).expect("p"))? {
                pending.del(k);
            }
        } else {
            kept.push(IndexDef {
                columns: idx
                    .columns
                    .iter()
                    .map(|&x| if x > c { x - 1 } else { x })
                    .collect(),
                ..idx
            });
        }
    }
    t.indexes = kept;
    let shift = |x: usize| if x > c { x - 1 } else { x };
    t.pk = t.pk.iter().map(|&x| shift(x)).collect();
    for fk in &mut t.fks {
        fk.columns = fk.columns.iter().map(|&x| shift(x)).collect();
    }
    // Reescreve as linhas sem a coluna.
    let mut rows = Vec::new();
    fetch_from(exec.src, &t, &Access::Full, &mut |pk, row| {
        rows.push((pk, row));
        Ok(true)
    })?;
    let n = rows.len();
    t.columns.remove(c);
    for (pk, mut row) in rows {
        row.remove(c);
        pending.put(t.row_key(&pk), encode_row(&row));
    }
    pending.del(stats_key(&t.name));
    save_table(pending, &t);
    Ok(format!("ALTER TABLE {} DROP COLUMN rows={n}", t.name))
}

/// Renomeia identificadores iguais a `from` no texto SQL de um CHECK.
fn rename_in_sql(sql: &str, from: &str, to: &str) -> String {
    let mut out = String::new();
    let mut word = String::new();
    let mut in_str = false;
    let flush = |word: &mut String, out: &mut String| {
        if !word.is_empty() {
            if word.eq_ignore_ascii_case(from) {
                out.push_str(to);
            } else {
                out.push_str(word);
            }
            word.clear();
        }
    };
    for ch in sql.chars() {
        if in_str {
            out.push(ch);
            if ch == '\'' {
                in_str = false;
            }
            continue;
        }
        if ch.is_alphanumeric() || ch == '_' {
            word.push(ch);
        } else {
            flush(&mut word, &mut out);
            if ch == '\'' {
                in_str = true;
            }
            out.push(ch);
        }
    }
    flush(&mut word, &mut out);
    out
}

fn rename_column(
    src: &dyn Source,
    pending: &Pending,
    table: &str,
    from: &str,
    to: &str,
) -> Result<String> {
    let mut t = load_table(src, table)?;
    let c = t.column(from)?;
    if t.column(to).is_ok() {
        return Err(Error::Sql(format!("coluna {to} já existe")));
    }
    t.columns[c].name = to.to_string();
    for check in &mut t.checks {
        check.sql = rename_in_sql(&check.sql, from, to);
        check.expr = super::parser::parse_expr(&check.sql)?;
    }
    for fk in &mut t.fks {
        if fk.parent == t.name {
            for pc in &mut fk.parent_columns {
                if pc == from {
                    *pc = to.to_string();
                }
            }
        }
    }
    // Filhas que referenciam a coluna pelo nome.
    for mut child in list_tables(src)? {
        if child.name == t.name {
            continue;
        }
        let mut changed = false;
        for fk in &mut child.fks {
            if fk.parent == t.name {
                for pc in &mut fk.parent_columns {
                    if pc == from {
                        *pc = to.to_string();
                        changed = true;
                    }
                }
            }
        }
        if changed {
            save_table(pending, &child);
        }
    }
    save_table(pending, &t);
    Ok(format!("ALTER TABLE {} RENAME COLUMN", t.name))
}

fn rename_table(src: &dyn Source, pending: &Pending, table: &str, to: &str) -> Result<String> {
    reserved_name(to)?;
    let mut t = load_table(src, table)?;
    if let Some(kind) = name_in_use(src, to)? {
        return Err(Error::Sql(format!("{kind} {to} já existe")));
    }
    for mut child in list_tables(src)? {
        if child.name == t.name {
            continue;
        }
        let mut changed = false;
        for fk in &mut child.fks {
            if fk.parent == t.name {
                fk.parent = to.to_string();
                changed = true;
            }
        }
        if changed {
            save_table(pending, &child);
        }
    }
    for fk in &mut t.fks {
        if fk.parent == t.name {
            fk.parent = to.to_string();
        }
    }
    if let Some(stats) = src.get(&stats_key(&t.name))? {
        pending.del(stats_key(&t.name));
        pending.put(stats_key(to), stats);
    }
    pending.del(catalog_key(&t.name));
    t.name = to.to_string();
    for tr in &mut t.triggers {
        tr.table = to.to_string();
    }
    save_table(pending, &t);
    Ok(format!("ALTER TABLE {table} RENAME TO {to}"))
}

fn alter_column(
    exec: &Exec<'_>,
    pending: &Pending,
    table: &str,
    column: &str,
    change: &ColumnChange,
) -> Result<String> {
    let mut t = load_table(exec.src, table)?;
    let c = t.column(column)?;
    let what = match change {
        ColumnChange::SetDefault(e, sql) => {
            let mut col = t.columns[c].clone();
            col.default = Some(e.clone());
            col.default_sql = match e {
                Expr::Lit(_) => None,
                Expr::Neg(inner) if matches!(**inner, Expr::Lit(_)) => None,
                _ => Some(sql.clone()),
            };
            validate_default(&col)?;
            if let Some(Expr::Lit(v)) = &col.default {
                col.default = Some(Expr::Lit(v.clone().coerce(col.ty)?));
            }
            // Confere que a expressão avalia.
            evaluate_default(exec, &col)?;
            t.columns[c] = col;
            "SET DEFAULT"
        }
        ColumnChange::DropDefault => {
            t.columns[c].default = None;
            t.columns[c].default_sql = None;
            "DROP DEFAULT"
        }
        ColumnChange::SetNotNull => {
            let mut nulls = 0usize;
            fetch_from(exec.src, &t, &Access::Full, &mut |_, row| {
                if row[c].is_null() {
                    nulls += 1;
                }
                Ok(true)
            })?;
            if nulls > 0 {
                return Err(Error::Constraint(format!(
                    "{nulls} linha(s) com {column} NULL impedem SET NOT NULL"
                )));
            }
            t.columns[c].not_null = true;
            "SET NOT NULL"
        }
        ColumnChange::DropNotNull => {
            if t.pk.contains(&c) {
                return Err(Error::Sql(format!("{column} é PRIMARY KEY")));
            }
            t.columns[c].not_null = false;
            "DROP NOT NULL"
        }
    };
    save_table(pending, &t);
    Ok(format!("ALTER TABLE {} ALTER COLUMN {what}", t.name))
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn create_view(
    exec: &Exec<'_>,
    pending: &Pending,
    name: &str,
    columns: &[String],
    query: &Query,
    sql: &str,
    or_replace: bool,
    if_not_exists: bool,
) -> Result<String> {
    reserved_name(name)?;
    match name_in_use(exec.src, name)? {
        Some("view") if or_replace => {}
        Some(_) if if_not_exists => return Ok(format!("CREATE VIEW {name} (já existe)")),
        Some(kind) => return Err(Error::Sql(format!("{kind} {name} já existe"))),
        None => {}
    }
    if super::parser::query_mentions(query, name) {
        return Err(Error::Sql(format!(
            "view {name} não pode referenciar a si mesma"
        )));
    }
    // Valida a consulta (colunas, tabelas) sem materializar tudo.
    let mut probe = query.clone();
    probe.limit = Some(Expr::Lit(Value::Int(0)));
    let out = exec.query(&probe, None)?;
    if !columns.is_empty() && columns.len() != out.columns.len() {
        return Err(Error::Sql(format!(
            "view {name} declara {} colunas, consulta devolve {}",
            columns.len(),
            out.columns.len()
        )));
    }
    let mut seen = HashSet::new();
    for c in if columns.is_empty() {
        &out.columns
    } else {
        columns
    } {
        if !seen.insert(c.clone()) {
            return Err(Error::Sql(format!(
                "coluna {c} repetida na view {name}; use aliases"
            )));
        }
    }
    let v = View {
        name: name.to_string(),
        columns: columns.to_vec(),
        sql: sql.to_string(),
    };
    pending.put(view_key(name), v.to_json().stringify().into_bytes());
    Ok(format!("CREATE VIEW {name}"))
}

// ---------------------------------------------------------------------------
// Gatilhos
// ---------------------------------------------------------------------------

const MAX_TRIGGER_DEPTH: usize = 16;

fn create_trigger(
    exec: &Exec<'_>,
    pending: &Pending,
    def: &TriggerDef,
    if_not_exists: bool,
) -> Result<String> {
    let mut t = load_table(exec.src, &def.table)?;
    if matches!(t.kind, TableKind::Materialized { .. }) {
        return Err(Error::Sql("gatilho em view materializada".into()));
    }
    for other in list_tables(exec.src)? {
        if other.triggers.iter().any(|tr| tr.name == def.name) {
            if if_not_exists {
                return Ok(format!("CREATE TRIGGER {} (já existe)", def.name));
            }
            return Err(Error::Sql(format!("gatilho {} já existe", def.name)));
        }
    }
    if let TriggerEvent::Update(cols) = &def.event {
        for c in cols {
            t.column(c)?;
        }
    }
    // Valida NEW/OLD e colunas do WHEN e do corpo com uma linha fictícia.
    let probe: Vec<Value> = t
        .columns
        .iter()
        .map(|c| match c.ty {
            Type::Int => Value::Int(0),
            Type::Real => Value::Real(0.0),
            Type::Text => Value::Text(String::new()),
            Type::Bool => Value::Bool(false),
        })
        .collect();
    let (old, new) = match def.event {
        TriggerEvent::Insert => (None, Some(&probe[..])),
        TriggerEvent::Delete => (Some(&probe[..]), None),
        TriggerEvent::Update(_) => (Some(&probe[..]), Some(&probe[..])),
    };
    let mut def = def.clone();
    def.table = t.name.clone();
    if let Some((e, _)) = &def.when {
        let bound = bind_row_refs_expr(e, &t, old, new)?;
        if has_subquery(&bound) {
            return Err(Error::Sql("WHEN de gatilho não aceita subconsulta".into()));
        }
        let mut refs = Vec::new();
        columns_of(&bound, &mut refs);
        if let Some((q, c)) = refs.first() {
            return Err(unknown_column(q.as_deref(), c));
        }
    }
    for (_, stmt) in &def.body {
        // Só confere que NEW/OLD referenciam colunas existentes.
        bind_row_refs(stmt, &t, old, new)?;
    }
    t.triggers.push(def.clone());
    save_table(pending, &t);
    Ok(format!("CREATE TRIGGER {}", def.name))
}

/// Troca `NEW.c`/`OLD.c` pelos valores da linha (erro se a coluna não existe).
fn bind_row_refs_expr(
    e: &Expr,
    t: &Table,
    old: Option<&[Value]>,
    new: Option<&[Value]>,
) -> Result<Expr> {
    let mut failure: Option<Error> = None;
    let mut f = |x: &Expr| -> Option<Expr> {
        let Expr::Col(Some(q), name) = x else {
            return None;
        };
        let row = match q.as_str() {
            "new" => new,
            "old" => old,
            _ => return None,
        };
        match (t.column(name), row) {
            (Ok(c), Some(row)) => Some(Expr::Lit(row[c].clone())),
            (Ok(_), None) => {
                failure = Some(Error::Sql(format!(
                    "{}.{name} não existe neste evento",
                    q.to_uppercase()
                )));
                Some(Expr::Lit(Value::Null))
            }
            (Err(e), _) => {
                failure = Some(e);
                Some(Expr::Lit(Value::Null))
            }
        }
    };
    let out = rewrite::map_expr(e, &mut f);
    match failure {
        Some(e) => Err(e),
        None => Ok(out),
    }
}

fn bind_row_refs(
    stmt: &Stmt,
    t: &Table,
    old: Option<&[Value]>,
    new: Option<&[Value]>,
) -> Result<Stmt> {
    let mut failure: Option<Error> = None;
    let mut f = |x: &Expr| -> Option<Expr> {
        let Expr::Col(Some(q), name) = x else {
            return None;
        };
        let row = match q.as_str() {
            "new" => new,
            "old" => old,
            _ => return None,
        };
        match (t.column(name), row) {
            (Ok(c), Some(row)) => Some(Expr::Lit(row[c].clone())),
            (Ok(_), None) => {
                failure = Some(Error::Sql(format!(
                    "{}.{name} não existe neste evento",
                    q.to_uppercase()
                )));
                Some(Expr::Lit(Value::Null))
            }
            (Err(e), _) => {
                failure = Some(e);
                Some(Expr::Lit(Value::Null))
            }
        }
    };
    let out = rewrite::map_stmt(stmt, &mut f);
    match failure {
        Some(e) => Err(e),
        None => Ok(out),
    }
}

/// Dispara os gatilhos de `t` para o evento. Devolve `false` quando um
/// gatilho BEFORE pediu `RAISE(IGNORE)` (a linha é pulada em silêncio).
fn fire_triggers(
    exec: &Exec<'_>,
    pending: &Pending,
    t: &Table,
    timing: TriggerTiming,
    event: &TriggerEvent,
    old: Option<&[Value]>,
    new: Option<&[Value]>,
) -> Result<bool> {
    if t.triggers.is_empty() {
        return Ok(true);
    }
    for tr in &t.triggers {
        if tr.timing != timing {
            continue;
        }
        let applies = match (&tr.event, event) {
            (TriggerEvent::Insert, TriggerEvent::Insert)
            | (TriggerEvent::Delete, TriggerEvent::Delete) => true,
            (TriggerEvent::Update(watch), TriggerEvent::Update(changed)) => {
                watch.is_empty() || watch.iter().any(|c| changed.contains(c))
            }
            _ => false,
        };
        if !applies {
            continue;
        }
        if exec.trigger_depth >= MAX_TRIGGER_DEPTH {
            return Err(Error::Sql(format!(
                "gatilhos aninhados demais ({MAX_TRIGGER_DEPTH}) em {}: laço entre gatilhos?",
                tr.name
            )));
        }
        let src = pending.source(exec.src);
        let inner = Exec::nested(&src, exec.params, exec.trigger_depth + 1);
        if let Some((cond, _)) = &tr.when {
            let bound = bind_row_refs_expr(cond, t, old, new)?;
            let empty = Scope::default();
            if inner.eval(&bound, &Ctx::new(&empty, &[], None))?.truth() != Some(true) {
                continue;
            }
        }
        for (_, stmt) in &tr.body {
            // Um `Exec` por comando: o cache de subconsultas usa o endereço da AST,
            // que é nova (e pode reaproveitar endereços) a cada comando do corpo.
            let inner = Exec::nested(&src, exec.params, exec.trigger_depth + 1);
            let bound = bind_row_refs(stmt, t, old, new)?;
            let result = match &bound {
                Stmt::Query(q) => inner.query(q, None).map(|_| ExecResult::Ok(String::new())),
                other => plan_into(&inner, other, pending),
            };
            match result {
                Ok(_) => {}
                Err(Error::Sql(m)) if m == RAISE_IGNORE => {
                    if timing == TriggerTiming::Before {
                        return Ok(false);
                    }
                    // Em AFTER, IGNORE só interrompe o corpo deste gatilho.
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(true)
}

/// Marcador interno de `RAISE(IGNORE)`.
pub(super) const RAISE_IGNORE: &str = "\u{0}raise-ignore";

// ---------------------------------------------------------------------------
// Views materializadas
// ---------------------------------------------------------------------------

fn infer_type(rows: &[Vec<Value>], col: usize) -> Type {
    for r in rows {
        match &r[col] {
            Value::Int(_) => return Type::Int,
            Value::Real(_) => return Type::Real,
            Value::Text(_) => return Type::Text,
            Value::Bool(_) => return Type::Bool,
            Value::Null => {}
        }
    }
    Type::Text
}

#[allow(clippy::too_many_arguments)]
fn create_materialized(
    exec: &Exec<'_>,
    pending: &Pending,
    name: &str,
    columns: &[String],
    query: &Query,
    sql: &str,
    auto: bool,
    or_replace: bool,
    if_not_exists: bool,
) -> Result<String> {
    reserved_name(name)?;
    match load_table(exec.src, name) {
        Ok(t) if matches!(t.kind, TableKind::Materialized { .. }) && or_replace => {
            drop_rows_and_indexes(exec.src, &t, pending)?;
            pending.del(t.rowid_key());
            pending.del(catalog_key(&t.name));
        }
        Ok(_) if if_not_exists => {
            return Ok(format!("CREATE MATERIALIZED VIEW {name} (já existe)"))
        }
        Ok(_) => return Err(Error::Sql(format!("{name} já existe"))),
        Err(Error::UnknownTable(_)) => {
            if load_view(exec.src, name)?.is_some() {
                return Err(Error::Sql(format!("view {name} já existe")));
            }
        }
        Err(e) => return Err(e),
    }
    if super::parser::query_mentions(query, name) {
        return Err(Error::Sql(format!(
            "{name} não pode referenciar a si mesma"
        )));
    }
    let out = exec.query(query, None)?;
    if !columns.is_empty() && columns.len() != out.columns.len() {
        return Err(Error::Sql(format!(
            "{name} declara {} colunas, consulta devolve {}",
            columns.len(),
            out.columns.len()
        )));
    }
    let names: Vec<String> = if columns.is_empty() {
        out.columns.clone()
    } else {
        columns.to_vec()
    };
    let mut seen = HashSet::new();
    for c in &names {
        if !seen.insert(c.clone()) {
            return Err(Error::Sql(format!(
                "coluna {c} repetida em {name}; use aliases"
            )));
        }
    }
    let cols: Vec<ColumnDef> = names
        .iter()
        .enumerate()
        .map(|(i, n)| ColumnDef::new(n.clone(), infer_type(&out.rows, i)))
        .collect();
    let id = exec
        .src
        .get(TABLE_SEQ)?
        .and_then(|v| v.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(1);
    let t = Table {
        name: name.to_string(),
        id,
        pk: Vec::new(),
        indexes: Vec::new(),
        checks: Vec::new(),
        fks: Vec::new(),
        triggers: Vec::new(),
        kind: TableKind::Materialized {
            sql: sql.to_string(),
            auto,
        },
        next_index_id: 1,
        columns: cols,
    };
    pending.put(TABLE_SEQ.to_vec(), (id + 1).to_le_bytes().to_vec());
    save_table(pending, &t);
    let n = out.rows.len();
    fill_materialized(exec, pending, &t, out.rows)?;
    Ok(format!("CREATE MATERIALIZED VIEW {name} rows={n}"))
}

fn fill_materialized(
    exec: &Exec<'_>,
    pending: &Pending,
    t: &Table,
    rows: Vec<Vec<Value>>,
) -> Result<()> {
    let seq = t.rowid_key();
    let mut next: i64 = 1;
    for row in rows {
        let row: Vec<Value> = row
            .into_iter()
            .zip(&t.columns)
            .map(|(v, c)| v.coerce(c.ty))
            .collect::<Result<_>>()?;
        let pk = encode_tuple(&[&Value::Int(next)]);
        pending.put(t.row_key(&pk), encode_row(&row));
        next += 1;
    }
    pending.put(seq, next.to_le_bytes().to_vec());
    let _ = exec;
    Ok(())
}

/// Recalcula uma view materializada lendo pelas escritas pendentes.
fn refresh_materialized(exec: &Exec<'_>, pending: &Pending, t: &Table) -> Result<usize> {
    let TableKind::Materialized { sql, .. } = &t.kind else {
        return Err(Error::Sql(format!("{} não é view materializada", t.name)));
    };
    let (stmt, _) = super::parser::parse(sql)?;
    let Stmt::Query(q) = stmt else {
        return Err(Error::Sql("view materializada sem consulta".into()));
    };
    let src = pending.source(exec.src);
    let inner = Exec::nested(&src, exec.params, exec.trigger_depth);
    let out = inner.query(&q, None)?;
    if out.columns.len() != t.columns.len() {
        return Err(Error::Sql(format!(
            "consulta de {} passou a devolver {} colunas (esperava {})",
            t.name,
            out.columns.len(),
            t.columns.len()
        )));
    }
    drop_rows_and_indexes(exec.src, t, pending)?;
    let n = out.rows.len();
    fill_materialized(exec, pending, t, out.rows)?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// ANALYZE
// ---------------------------------------------------------------------------

/// Um scan completo: contagem, distintos (exatos até 1 M), nulos, mínimo e
/// máximo por coluna.
fn analyze_table(exec: &Exec<'_>, pending: &Pending, t: &Table) -> Result<usize> {
    const MAX_DISTINCT: usize = 1_000_000;
    let n = t.columns.len();
    let mut rows = 0usize;
    let mut distinct: Vec<HashSet<Vec<u8>>> = vec![HashSet::new(); n];
    let mut saturated = vec![false; n];
    let mut nulls = vec![0u64; n];
    let mut min: Vec<Option<Value>> = vec![None; n];
    let mut max: Vec<Option<Value>> = vec![None; n];
    fetch_from(exec.src, t, &Access::Full, &mut |_, row| {
        rows += 1;
        for (i, v) in row.iter().enumerate() {
            if v.is_null() {
                nulls[i] += 1;
                continue;
            }
            if !saturated[i] {
                distinct[i].insert(super::value::key_of(v));
                if distinct[i].len() >= MAX_DISTINCT {
                    saturated[i] = true;
                    distinct[i].clear();
                }
            }
            if min[i]
                .as_ref()
                .is_none_or(|m| v.total_cmp(m) == std::cmp::Ordering::Less)
            {
                min[i] = Some(v.clone());
            }
            if max[i]
                .as_ref()
                .is_none_or(|m| v.total_cmp(m) == std::cmp::Ordering::Greater)
            {
                max[i] = Some(v.clone());
            }
        }
        Ok(true)
    })?;
    let clip = |v: Option<Value>| match v {
        Some(Value::Text(s)) if s.len() > 64 => Some(Value::Text(s.chars().take(64).collect())),
        other => other,
    };
    let stats = Stats {
        rows: rows as u64,
        columns: (0..n)
            .map(|i| ColStats {
                distinct: if saturated[i] {
                    rows as u64
                } else {
                    distinct[i].len() as u64
                },
                nulls: nulls[i],
                min: clip(min[i].take()),
                max: clip(max[i].take()),
            })
            .collect(),
        analyzed_at: super::func::fmt_datetime(super::func::now_secs(), true),
    };
    pending.put(stats_key(&t.name), stats.to_json().stringify().into_bytes());
    Ok(rows)
}
