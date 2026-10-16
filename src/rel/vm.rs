//! Máquina virtual de bytecode para expressões puras, aritméticas e lógicas.

use std::cell::Cell;
use std::cmp::Ordering;
use std::rc::Rc;

use crate::error::{Error, Result};
use super::exec::{arith, compare, in_list, truth};
use super::parser::{BinOp, Expr};
use super::value::{Type, Value};

#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    Const(usize),
    Param(usize),
    Col {
        table: Option<String>,
        name: String,
    },
    Neg,
    Not,
    BitNot,
    Binary(BinOp),
    Compare(BinOp),
    Jump(usize),
    JumpIfFalseOrLeave(usize),
    JumpIfTrueOrLeave(usize),
    AndStep,
    OrStep,
    IsNull(bool),
    IsDistinct(bool),
    Between(bool),
    Cast(Type),
    CallFunc {
        name: String,
        argc: usize,
    },
    InList {
        count: usize,
        neg: bool,
    },
}

#[derive(Clone, Debug)]
pub struct Program {
    pub ops: Vec<Op>,
    pub constants: Vec<Value>,
}

enum CompileTask<'a> {
    Expr(&'a Expr),
    Emit(Op),
    EmitBin(BinOp),
    EmitCompare(BinOp),
    EmitAndJump(Rc<Cell<usize>>),
    PatchJumpAnd(Rc<Cell<usize>>),
    EmitOrJump(Rc<Cell<usize>>),
    PatchJumpOr(Rc<Cell<usize>>),
}

pub fn can_compile(root: &Expr) -> bool {
    let mut stack = vec![root];
    while let Some(e) = stack.pop() {
        match e {
            Expr::Lit(_) | Expr::Param(_) | Expr::Col(..) => {}
            Expr::Neg(x) | Expr::Not(x) | Expr::BitNot(x) | Expr::IsNull(x, _) | Expr::Cast(x, _) => {
                stack.push(x);
            }
            Expr::Bin(a, _, b) | Expr::IsDistinct(a, b, _) => {
                stack.push(a);
                stack.push(b);
            }
            Expr::Between(a, b, c, _) => {
                stack.push(a);
                stack.push(b);
                stack.push(c);
            }
            Expr::In(x, list, _) => {
                stack.push(x);
                stack.extend(list.iter());
            }
            Expr::Func(name, args) => {
                if name.starts_with("pg_get_")
                    || name.ends_with("regclass")
                    || (name.starts_with("pg_") && name.ends_with("_size"))
                {
                    return false;
                }
                stack.extend(args.iter());
            }
            _ => return false,
        }
    }
    true
}

pub fn compile(root: &Expr) -> Result<Program> {
    let mut ops = Vec::new();
    let mut constants = Vec::new();
    let mut tasks = vec![CompileTask::Expr(root)];

    while let Some(task) = tasks.pop() {
        match task {
            CompileTask::Expr(e) => match e {
                Expr::Lit(v) => {
                    let idx = constants.len();
                    constants.push(v.clone());
                    ops.push(Op::Const(idx));
                }
                Expr::Param(i) => {
                    ops.push(Op::Param(*i));
                }
                Expr::Col(t, name) => {
                    ops.push(Op::Col {
                        table: t.clone(),
                        name: name.clone(),
                    });
                }
                Expr::Neg(x) => {
                    tasks.push(CompileTask::Emit(Op::Neg));
                    tasks.push(CompileTask::Expr(x));
                }
                Expr::Not(x) => {
                    tasks.push(CompileTask::Emit(Op::Not));
                    tasks.push(CompileTask::Expr(x));
                }
                Expr::BitNot(x) => {
                    tasks.push(CompileTask::Emit(Op::BitNot));
                    tasks.push(CompileTask::Expr(x));
                }
                Expr::IsNull(x, neg) => {
                    tasks.push(CompileTask::Emit(Op::IsNull(*neg)));
                    tasks.push(CompileTask::Expr(x));
                }
                Expr::Cast(x, ty) => {
                    tasks.push(CompileTask::Emit(Op::Cast(*ty)));
                    tasks.push(CompileTask::Expr(x));
                }
                Expr::IsDistinct(a, b, neg) => {
                    tasks.push(CompileTask::Emit(Op::IsDistinct(*neg)));
                    tasks.push(CompileTask::Expr(b));
                    tasks.push(CompileTask::Expr(a));
                }
                Expr::Between(x, lo, hi, neg) => {
                    tasks.push(CompileTask::Emit(Op::Between(*neg)));
                    tasks.push(CompileTask::Expr(hi));
                    tasks.push(CompileTask::Expr(lo));
                    tasks.push(CompileTask::Expr(x));
                }
                Expr::In(x, list, neg) => {
                    tasks.push(CompileTask::Emit(Op::InList {
                        count: list.len(),
                        neg: *neg,
                    }));
                    for item in list.iter().rev() {
                        tasks.push(CompileTask::Expr(item));
                    }
                    tasks.push(CompileTask::Expr(x));
                }
                Expr::Func(name, args) => {
                    tasks.push(CompileTask::Emit(Op::CallFunc {
                        name: name.clone(),
                        argc: args.len(),
                    }));
                    for arg in args.iter().rev() {
                        tasks.push(CompileTask::Expr(arg));
                    }
                }
                Expr::Bin(a, BinOp::And, b) => {
                    let slot = Rc::new(Cell::new(0));
                    tasks.push(CompileTask::PatchJumpAnd(Rc::clone(&slot)));
                    tasks.push(CompileTask::Emit(Op::AndStep));
                    tasks.push(CompileTask::Expr(b));
                    tasks.push(CompileTask::EmitAndJump(slot));
                    tasks.push(CompileTask::Expr(a));
                }
                Expr::Bin(a, BinOp::Or, b) => {
                    let slot = Rc::new(Cell::new(0));
                    tasks.push(CompileTask::PatchJumpOr(Rc::clone(&slot)));
                    tasks.push(CompileTask::Emit(Op::OrStep));
                    tasks.push(CompileTask::Expr(b));
                    tasks.push(CompileTask::EmitOrJump(slot));
                    tasks.push(CompileTask::Expr(a));
                }
                Expr::Bin(a, op, b) => {
                    if matches!(
                        op,
                        BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge
                    ) {
                        tasks.push(CompileTask::EmitCompare(*op));
                    } else {
                        tasks.push(CompileTask::EmitBin(*op));
                    }
                    tasks.push(CompileTask::Expr(b));
                    tasks.push(CompileTask::Expr(a));
                }
                other => {
                    return Err(Error::Sql(format!(
                        "expressão não compilável para VM: {other:?}"
                    )));
                }
            },
            CompileTask::Emit(op) => ops.push(op),
            CompileTask::EmitBin(op) => ops.push(Op::Binary(op)),
            CompileTask::EmitCompare(op) => ops.push(Op::Compare(op)),
            CompileTask::EmitAndJump(slot) => {
                slot.set(ops.len());
                ops.push(Op::JumpIfFalseOrLeave(0));
            }
            CompileTask::PatchJumpAnd(slot) => {
                let target = ops.len();
                ops[slot.get()] = Op::JumpIfFalseOrLeave(target);
            }
            CompileTask::EmitOrJump(slot) => {
                slot.set(ops.len());
                ops.push(Op::JumpIfTrueOrLeave(0));
            }
            CompileTask::PatchJumpOr(slot) => {
                let target = ops.len();
                ops[slot.get()] = Op::JumpIfTrueOrLeave(target);
            }
        }
    }

    Ok(Program { ops, constants })
}

pub fn execute<F>(
    program: &Program,
    params: &[Value],
    mut resolve_col: F,
) -> Result<Value>
where
    F: FnMut(Option<&str>, &str) -> Result<Value>,
{
    let mut stack: Vec<Value> = Vec::with_capacity(16);
    let mut pc = 0;
    let ops = &program.ops;

    while pc < ops.len() {
        match &ops[pc] {
            Op::Const(i) => {
                let v = program
                    .constants
                    .get(*i)
                    .cloned()
                    .ok_or_else(|| Error::Sql("constante inválida na VM".into()))?;
                stack.push(v);
                pc += 1;
            }
            Op::Param(i) => {
                let v = params.get(*i).cloned().ok_or_else(|| {
                    Error::Sql(format!("parâmetro {} não informado", i + 1))
                })?;
                stack.push(v);
                pc += 1;
            }
            Op::Col { table, name } => {
                let v = resolve_col(table.as_deref(), name)?;
                stack.push(v);
                pc += 1;
            }
            Op::Neg => {
                let top = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let v = match top {
                    Value::Int(n) => Value::Int(
                        n.checked_neg()
                            .ok_or_else(|| Error::Sql("estouro".into()))?,
                    ),
                    Value::Real(x) => Value::Real(-x),
                    Value::Null => Value::Null,
                    other => return Err(Error::Sql(format!("negação de {}", other.type_name()))),
                };
                stack.push(v);
                pc += 1;
            }
            Op::Not => {
                let top = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                stack.push(truth(top.truth().map(|b| !b)));
                pc += 1;
            }
            Op::BitNot => {
                let top = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let v = match top {
                    Value::Int(n) => Value::Int(!n),
                    Value::Null => Value::Null,
                    other => return Err(Error::Sql(format!("~ de {}", other.type_name()))),
                };
                stack.push(v);
                pc += 1;
            }
            Op::Binary(op) => {
                let b = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let a = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                stack.push(arith(a, *op, b)?);
                pc += 1;
            }
            Op::Compare(op) => {
                let b = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let a = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let res = compare(&a, *op, &b).ok_or_else(|| {
                    Error::Sql(format!("operador de comparação inválido: {op:?}"))
                })?;
                stack.push(res);
                pc += 1;
            }
            Op::Jump(target) => {
                pc = *target;
            }
            Op::JumpIfFalseOrLeave(target) => {
                let top = stack.last().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                if top.truth() == Some(false) {
                    let last = stack.last_mut().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                    *last = Value::Bool(false);
                    pc = *target;
                } else {
                    pc += 1;
                }
            }
            Op::JumpIfTrueOrLeave(target) => {
                let top = stack.last().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                if top.truth() == Some(true) {
                    let last = stack.last_mut().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                    *last = Value::Bool(true);
                    pc = *target;
                } else {
                    pc += 1;
                }
            }
            Op::AndStep => {
                let b = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let a = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let res = truth(match (a.truth(), b.truth()) {
                    (_, Some(false)) => Some(false),
                    (Some(true), Some(true)) => Some(true),
                    _ => None,
                });
                stack.push(res);
                pc += 1;
            }
            Op::OrStep => {
                let b = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let a = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let res = truth(match (a.truth(), b.truth()) {
                    (_, Some(true)) => Some(true),
                    (Some(false), Some(false)) => Some(false),
                    _ => None,
                });
                stack.push(res);
                pc += 1;
            }
            Op::IsNull(neg) => {
                let top = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                stack.push(Value::Bool(top.is_null() != *neg));
                pc += 1;
            }
            Op::IsDistinct(neg) => {
                let b = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let a = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let same = match (a.is_null(), b.is_null()) {
                    (true, true) => true,
                    (false, false) => a.sql_cmp(&b) == Some(Ordering::Equal),
                    _ => false,
                };
                stack.push(Value::Bool(same == *neg));
                pc += 1;
            }
            Op::Between(neg) => {
                let hi = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let lo = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let x = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                let ge = x.sql_cmp(&lo).map(|o| o != Ordering::Less);
                let le = x.sql_cmp(&hi).map(|o| o != Ordering::Greater);
                let v = truth(match (ge, le) {
                    (Some(false), _) | (_, Some(false)) => Some(*neg),
                    (Some(true), Some(true)) => Some(!neg),
                    _ => None,
                });
                stack.push(v);
                pc += 1;
            }
            Op::Cast(ty) => {
                let top = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                stack.push(super::func::cast(top, *ty)?);
                pc += 1;
            }
            Op::CallFunc { name, argc } => {
                let mut args = Vec::with_capacity(*argc);
                for _ in 0..*argc {
                    args.push(stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?);
                }
                args.reverse();
                stack.push(super::func::call(name, args)?);
                pc += 1;
            }
            Op::InList { count, neg } => {
                let mut items = Vec::with_capacity(*count);
                for _ in 0..*count {
                    items.push(stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?);
                }
                items.reverse();
                let x = stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?;
                stack.push(in_list(&x, items.iter(), *neg));
                pc += 1;
            }
        }
    }

    if stack.len() == 1 {
        Ok(stack.pop().ok_or_else(|| Error::Sql("pilha vazia na VM".into()))?)
    } else {
        Err(Error::Sql(format!(
            "erro na VM de expressões: pilha com {} valores ao terminar",
            stack.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_arithmetic() {
        // (10 + 20) * 3 = 90
        let expr = Expr::Bin(
            Box::new(Expr::Bin(
                Box::new(Expr::Lit(Value::Int(10))),
                BinOp::Add,
                Box::new(Expr::Lit(Value::Int(20))),
            )),
            BinOp::Mul,
            Box::new(Expr::Lit(Value::Int(3))),
        );
        assert!(can_compile(&expr));
        let prog = compile(&expr).unwrap();
        let res = execute(&prog, &[], |_, _| unreachable!()).unwrap();
        assert_eq!(res, Value::Int(90));
    }

    #[test]
    fn test_vm_comparisons() {
        let expr = Expr::Bin(
            Box::new(Expr::Lit(Value::Int(15))),
            BinOp::Gt,
            Box::new(Expr::Lit(Value::Int(10))),
        );
        let prog = compile(&expr).unwrap();
        let res = execute(&prog, &[], |_, _| unreachable!()).unwrap();
        assert_eq!(res, Value::Bool(true));
    }

    #[test]
    fn test_vm_boolean_short_circuit() {
        // false AND (10 > 5) -> deve avaliar para false
        let expr = Expr::Bin(
            Box::new(Expr::Lit(Value::Bool(false))),
            BinOp::And,
            Box::new(Expr::Bin(
                Box::new(Expr::Lit(Value::Int(10))),
                BinOp::Gt,
                Box::new(Expr::Lit(Value::Int(5))),
            )),
        );
        let prog = compile(&expr).unwrap();
        let res = execute(&prog, &[], |_, _| unreachable!()).unwrap();
        assert_eq!(res, Value::Bool(false));

        // true OR (5 > 10) -> deve avaliar para true
        let expr_or = Expr::Bin(
            Box::new(Expr::Lit(Value::Bool(true))),
            BinOp::Or,
            Box::new(Expr::Lit(Value::Bool(false))),
        );
        let prog_or = compile(&expr_or).unwrap();
        let res_or = execute(&prog_or, &[], |_, _| unreachable!()).unwrap();
        assert_eq!(res_or, Value::Bool(true));
    }

    #[test]
    fn test_vm_three_valued_logic() {
        // NULL AND true -> NULL
        let expr = Expr::Bin(
            Box::new(Expr::Lit(Value::Null)),
            BinOp::And,
            Box::new(Expr::Lit(Value::Bool(true))),
        );
        let prog = compile(&expr).unwrap();
        let res = execute(&prog, &[], |_, _| unreachable!()).unwrap();
        assert_eq!(res, Value::Null);

        // NULL OR true -> true
        let expr_or = Expr::Bin(
            Box::new(Expr::Lit(Value::Null)),
            BinOp::Or,
            Box::new(Expr::Lit(Value::Bool(true))),
        );
        let prog_or = compile(&expr_or).unwrap();
        let res_or = execute(&prog_or, &[], |_, _| unreachable!()).unwrap();
        assert_eq!(res_or, Value::Bool(true));
    }

    #[test]
    fn test_vm_between_and_in() {
        // 5 BETWEEN 1 AND 10 -> true
        let expr_between = Expr::Between(
            Box::new(Expr::Lit(Value::Int(5))),
            Box::new(Expr::Lit(Value::Int(1))),
            Box::new(Expr::Lit(Value::Int(10))),
            false,
        );
        let prog = compile(&expr_between).unwrap();
        let res = execute(&prog, &[], |_, _| unreachable!()).unwrap();
        assert_eq!(res, Value::Bool(true));

        // 7 IN (1, 3, 7, 9) -> true
        let expr_in = Expr::In(
            Box::new(Expr::Lit(Value::Int(7))),
            vec![
                Expr::Lit(Value::Int(1)),
                Expr::Lit(Value::Int(3)),
                Expr::Lit(Value::Int(7)),
                Expr::Lit(Value::Int(9)),
            ],
            false,
        );
        let prog_in = compile(&expr_in).unwrap();
        let res_in = execute(&prog_in, &[], |_, _| unreachable!()).unwrap();
        assert_eq!(res_in, Value::Bool(true));
    }

    #[test]
    fn test_vm_params_and_cols() {
        // $1 + u.val
        let expr = Expr::Bin(
            Box::new(Expr::Param(0)),
            BinOp::Add,
            Box::new(Expr::Col(Some("u".into()), "val".into())),
        );
        let prog = compile(&expr).unwrap();
        let params = [Value::Int(100)];
        let res = execute(&prog, &params, |tbl, col| {
            assert_eq!(tbl, Some("u"));
            assert_eq!(col, "val");
            Ok(Value::Int(42))
        })
        .unwrap();
        assert_eq!(res, Value::Int(142));
    }
}