//! Reescrita de AST: substitui expressões em qualquer posição de um comando
//! (usado pelos gatilhos para trocar `NEW.c`/`OLD.c` pelos valores da linha).

use super::parser::{
    Cte, Expr, FromItem, InsertSource, Join, OnConflict, OrderItem, Query, Select, SelectItem,
    SetExpr, Source, Stmt, WindowSpec,
};

/// `f` devolve `Some(nova)` para substituir o nó inteiro ou `None` para descer.
pub type Mapper<'f> = dyn FnMut(&Expr) -> Option<Expr> + 'f;

pub fn map_expr(e: &Expr, f: &mut Mapper<'_>) -> Expr {
    if let Some(replaced) = f(e) {
        return replaced;
    }
    let m = |x: &Expr, f: &mut Mapper<'_>| Box::new(map_expr(x, f));
    match e {
        Expr::Lit(_) | Expr::Param(_) | Expr::Col(..) => e.clone(),
        Expr::Neg(x) => Expr::Neg(m(x, f)),
        Expr::Not(x) => Expr::Not(m(x, f)),
        Expr::BitNot(x) => Expr::BitNot(m(x, f)),
        Expr::Bin(a, op, b) => Expr::Bin(m(a, f), *op, m(b, f)),
        Expr::IsNull(x, n) => Expr::IsNull(m(x, f), *n),
        Expr::IsDistinct(a, b, n) => Expr::IsDistinct(m(a, f), m(b, f), *n),
        Expr::Like(a, b, n, g) => Expr::Like(m(a, f), m(b, f), *n, *g),
        Expr::In(x, list, n) => {
            Expr::In(m(x, f), list.iter().map(|i| map_expr(i, f)).collect(), *n)
        }
        Expr::InQuery(x, q, n) => Expr::InQuery(m(x, f), Box::new(map_query(q, f)), *n),
        Expr::Quantified(x, op, all, q) => {
            Expr::Quantified(m(x, f), *op, *all, Box::new(map_query(q, f)))
        }
        Expr::Exists(q, n) => Expr::Exists(Box::new(map_query(q, f)), *n),
        Expr::Subquery(q) => Expr::Subquery(Box::new(map_query(q, f))),
        Expr::Between(x, lo, hi, n) => Expr::Between(m(x, f), m(lo, f), m(hi, f), *n),
        Expr::Case {
            operand,
            whens,
            otherwise,
        } => Expr::Case {
            operand: operand.as_ref().map(|o| m(o, f)),
            whens: whens
                .iter()
                .map(|(w, t)| (map_expr(w, f), map_expr(t, f)))
                .collect(),
            otherwise: otherwise.as_ref().map(|o| m(o, f)),
        },
        Expr::Cast(x, ty) => Expr::Cast(m(x, f), *ty),
        Expr::Func(name, args) => {
            Expr::Func(name.clone(), args.iter().map(|a| map_expr(a, f)).collect())
        }
        Expr::Agg(fun, args, d) => {
            Expr::Agg(*fun, args.iter().map(|a| map_expr(a, f)).collect(), *d)
        }
        Expr::Match { columns, query } => Expr::Match {
            columns: columns.iter().map(|c| map_expr(c, f)).collect(),
            query: m(query, f),
        },
        Expr::Window(fun, args, spec) => Expr::Window(
            *fun,
            args.iter().map(|a| map_expr(a, f)).collect(),
            Box::new(WindowSpec {
                partition_by: spec.partition_by.iter().map(|p| map_expr(p, f)).collect(),
                order_by: map_order(&spec.order_by, f),
                frame: spec.frame,
            }),
        ),
    }
}

fn map_order(items: &[OrderItem], f: &mut Mapper<'_>) -> Vec<OrderItem> {
    items
        .iter()
        .map(|o| OrderItem {
            expr: map_expr(&o.expr, f),
            desc: o.desc,
            nulls_first: o.nulls_first,
        })
        .collect()
}

fn map_from(item: &FromItem, f: &mut Mapper<'_>) -> FromItem {
    FromItem {
        source: match &item.source {
            Source::Table(t) => Source::Table(t.clone()),
            Source::Query(q) => Source::Query(Box::new(map_query(q, f))),
            Source::Function(name, args, ordinality) => Source::Function(
                name.clone(),
                args.iter().map(|a| map_expr(a, f)).collect(),
                *ordinality,
            ),
        },
        alias: item.alias.clone(),
        columns: item.columns.clone(),
    }
}

fn map_select(s: &Select, f: &mut Mapper<'_>) -> Select {
    Select {
        distinct: s.distinct,
        items: s
            .items
            .iter()
            .map(|i| match i {
                SelectItem::Star(t) => SelectItem::Star(t.clone()),
                SelectItem::Expr(e, a) => SelectItem::Expr(map_expr(e, f), a.clone()),
            })
            .collect(),
        from: s.from.as_ref().map(|i| map_from(i, f)),
        joins: s
            .joins
            .iter()
            .map(|j| Join {
                item: map_from(&j.item, f),
                on: j.on.as_ref().map(|o| map_expr(o, f)),
                kind: j.kind,
                using: j.using.clone(),
            })
            .collect(),
        filter: s.filter.as_ref().map(|e| map_expr(e, f)),
        group_by: s.group_by.iter().map(|g| map_expr(g, f)).collect(),
        having: s.having.as_ref().map(|e| map_expr(e, f)),
    }
}

fn map_set(e: &SetExpr, f: &mut Mapper<'_>) -> SetExpr {
    match e {
        SetExpr::Select(s) => SetExpr::Select(Box::new(map_select(s, f))),
        SetExpr::Values(rows) => SetExpr::Values(
            rows.iter()
                .map(|r| r.iter().map(|x| map_expr(x, f)).collect())
                .collect(),
        ),
        SetExpr::SetOp {
            op,
            all,
            left,
            right,
        } => SetExpr::SetOp {
            op: *op,
            all: *all,
            left: Box::new(map_set(left, f)),
            right: Box::new(map_set(right, f)),
        },
    }
}

pub fn map_query(q: &Query, f: &mut Mapper<'_>) -> Query {
    Query {
        ctes: q
            .ctes
            .iter()
            .map(|c| Cte {
                name: c.name.clone(),
                columns: c.columns.clone(),
                query: map_query(&c.query, f),
                recursive: c.recursive,
            })
            .collect(),
        body: map_set(&q.body, f),
        order_by: map_order(&q.order_by, f),
        limit: q.limit.as_ref().map(|e| map_expr(e, f)),
        offset: q.offset.as_ref().map(|e| map_expr(e, f)),
    }
}

fn map_items(items: &[SelectItem], f: &mut Mapper<'_>) -> Vec<SelectItem> {
    items
        .iter()
        .map(|i| match i {
            SelectItem::Star(t) => SelectItem::Star(t.clone()),
            SelectItem::Expr(e, a) => SelectItem::Expr(map_expr(e, f), a.clone()),
        })
        .collect()
}

fn map_sets(sets: &[(String, Expr)], f: &mut Mapper<'_>) -> Vec<(String, Expr)> {
    sets.iter()
        .map(|(c, e)| (c.clone(), map_expr(e, f)))
        .collect()
}

/// Aplica `f` a todas as expressões de um comando DML/consulta; os demais
/// comandos voltam iguais.
pub fn map_stmt(stmt: &Stmt, f: &mut Mapper<'_>) -> Stmt {
    match stmt {
        Stmt::Query(q) => Stmt::Query(Box::new(map_query(q, f))),
        Stmt::Insert {
            table,
            columns,
            source,
            on_conflict,
            returning,
        } => Stmt::Insert {
            table: table.clone(),
            columns: columns.clone(),
            source: match source {
                InsertSource::Values(rows) => InsertSource::Values(
                    rows.iter()
                        .map(|r| r.iter().map(|x| map_expr(x, f)).collect())
                        .collect(),
                ),
                InsertSource::Query(q) => InsertSource::Query(Box::new(map_query(q, f))),
                InsertSource::Default => InsertSource::Default,
            },
            on_conflict: on_conflict.as_ref().map(|oc| match oc {
                OnConflict::Nothing => OnConflict::Nothing,
                OnConflict::Replace => OnConflict::Replace,
                OnConflict::Update { sets, filter } => OnConflict::Update {
                    sets: map_sets(sets, f),
                    filter: filter.as_ref().map(|e| map_expr(e, f)),
                },
            }),
            returning: map_items(returning, f),
        },
        Stmt::Update {
            table,
            sets,
            filter,
            returning,
        } => Stmt::Update {
            table: table.clone(),
            sets: map_sets(sets, f),
            filter: filter.as_ref().map(|e| map_expr(e, f)),
            returning: map_items(returning, f),
        },
        Stmt::Delete {
            table,
            filter,
            returning,
        } => Stmt::Delete {
            table: table.clone(),
            filter: filter.as_ref().map(|e| map_expr(e, f)),
            returning: map_items(returning, f),
        },
        Stmt::Notify { channel, payload } => Stmt::Notify {
            channel: channel.clone(),
            payload: payload.as_ref().map(|e| map_expr(e, f)),
        },
        other => other.clone(),
    }
}
