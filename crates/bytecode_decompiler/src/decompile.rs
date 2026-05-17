use std::collections::{HashMap, HashSet};

use crate::bytecode::{
    format_constant, format_lua_string, reg_name, resolve_import, resolve_import_aux, upval_name,
    Chunk, Constant, Instruction, Proto,
};
use crate::opcode::{insn_a, insn_b, insn_c, insn_d, jump_target, Opcode};

#[derive(Clone)]
enum Expr {
    Nil,
    Bool(bool),
    Number(f64),
    String(String),
    Local(String),
    Global(String),
    Upvalue(String),
    Import(String),
    Unary { op: &'static str, arg: Box<Expr> },
    Binary { op: &'static str, left: Box<Expr>, right: Box<Expr> },
    Index { table: Box<Expr>, key: Box<Expr> },
    Call { func: Box<Expr>, args: Vec<Expr> },
    Varargs,
    Unknown(String),
}

impl Expr {
    fn render(&self) -> String {
        match self {
            Expr::Nil => "nil".into(),
            Expr::Bool(b) => b.to_string(),
            Expr::Number(n) => {
                if n.fract() == 0.0 && n.abs() < 1e15 {
                    format!("{n:.0}")
                } else {
                    n.to_string()
                }
            }
            Expr::String(s) => format_lua_string(s),
            Expr::Local(s) | Expr::Global(s) | Expr::Upvalue(s) | Expr::Import(s) => s.clone(),
            Expr::Unary { op, arg } => format!("({op}{})", arg.render()),
            Expr::Varargs => "...".into(),
            Expr::Binary { op, left, right } => format!("({} {op} {})", left.render(), right.render()),
            Expr::Index { table, key } => {
                if let Expr::String(s) = key.as_ref() {
                    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                        && !s.is_empty()
                        && !s.chars().next().unwrap().is_numeric()
                    {
                        return format!("{}.{}", table.render(), s);
                    }
                }
                format!("{}[{}]", table.render(), key.render())
            }
            Expr::Call { func, args } => {
                let args = args.iter().map(Expr::render).collect::<Vec<_>>().join(", ");
                format!("{}({args})", func.render())
            }
            Expr::Unknown(s) => s.clone(),
        }
    }
}

struct FunctionDecompiler<'a> {
    chunk: &'a Chunk,
    proto: &'a Proto,
    proto_index: usize,
    regs: HashMap<u8, Expr>,
    emitted: HashSet<usize>,
    blocks: Vec<BasicBlock>,
}

#[derive(Clone)]
struct BasicBlock {
    start: usize,
    end: usize,
    successors: Vec<usize>,
    predecessors: Vec<usize>,
}

pub struct Decompiler;

impl Decompiler {
    pub fn decompile_chunk(chunk: &Chunk) -> String {
        let mut out = String::from("-- Decompiled Luau bytecode\n");
        out.push_str(&Self::decompile_proto(chunk, chunk.main_index, 0));
        out
    }

    fn decompile_proto(chunk: &Chunk, index: usize, depth: usize) -> String {
        let proto = &chunk.protos[index];
        let mut d = FunctionDecompiler::new(chunk, proto, index);
        d.build_cfg();
        d.decompile(depth)
    }
}

impl<'a> FunctionDecompiler<'a> {
    fn new(chunk: &'a Chunk, proto: &'a Proto, proto_index: usize) -> Self {
        Self {
            chunk,
            proto,
            proto_index,
            regs: HashMap::new(),
            emitted: HashSet::new(),
            blocks: Vec::new(),
        }
    }

    fn build_cfg(&mut self) {
        let n = self.proto.instructions.len();
        if n == 0 {
            self.blocks.push(BasicBlock {
                start: 0,
                end: 0,
                successors: vec![],
                predecessors: vec![],
            });
            return;
        }

        let mut leaders = HashSet::new();
        leaders.insert(0);
        for (pc, inst) in self.proto.instructions.iter().enumerate() {
            if let Some(tgt) = jump_target(pc, inst.raw, inst.opcode) {
                if tgt < n {
                    leaders.insert(tgt);
                }
            }
            if inst.opcode.terminates_block() && pc + 1 < n {
                leaders.insert(pc + 1);
            }
            if matches!(inst.opcode, Opcode::JumpIf | Opcode::JumpIfNot) {
                if pc + 1 < n {
                    leaders.insert(pc + 1);
                }
            }
        }

        let mut starts: Vec<usize> = leaders.into_iter().collect();
        starts.sort_unstable();

        for i in 0..starts.len() {
            let start = starts[i];
            let end = starts.get(i + 1).copied().unwrap_or(n);
            self.blocks.push(BasicBlock {
                start,
                end,
                successors: vec![],
                predecessors: vec![],
            });
        }

        for bi in 0..self.blocks.len() {
            let end_pc = self.blocks[bi].end.saturating_sub(1);
            if end_pc >= n {
                continue;
            }
            let inst = &self.proto.instructions[end_pc];
            match inst.opcode {
                Opcode::Jump | Opcode::JumpBack | Opcode::JumpX => {
                    if let Some(tgt) = jump_target(end_pc, inst.raw, inst.opcode) {
                        let t = Self::block_index_at(&self.blocks, tgt);
                        self.blocks[bi].successors.push(t);
                        self.blocks[t].predecessors.push(bi);
                    }
                }
                Opcode::JumpIf | Opcode::JumpIfNot => {
                    if let Some(tgt) = jump_target(end_pc, inst.raw, inst.opcode) {
                        let t = Self::block_index_at(&self.blocks, tgt);
                        self.blocks[bi].successors.push(t);
                        self.blocks[t].predecessors.push(bi);
                    }
                    if bi + 1 < self.blocks.len() {
                        self.blocks[bi].successors.push(bi + 1);
                        self.blocks[bi + 1].predecessors.push(bi);
                    }
                }
                Opcode::ForNPrep | Opcode::ForGPrep | Opcode::ForGPrepInext | Opcode::ForGPrepNext => {
                    if let Some(tgt) = jump_target(end_pc, inst.raw, inst.opcode) {
                        let t = Self::block_index_at(&self.blocks, tgt);
                        self.blocks[bi].successors.push(t);
                        self.blocks[t].predecessors.push(bi);
                    }
                }
                Opcode::Return => {}
                _ => {
                    if bi + 1 < self.blocks.len() {
                        self.blocks[bi].successors.push(bi + 1);
                        self.blocks[bi + 1].predecessors.push(bi);
                    }
                }
            }
        }
    }

    fn decompile(&mut self, depth: usize) -> String {
        let indent = "    ".repeat(depth);
        let name = self
            .proto
            .debug_name
            .clone()
            .unwrap_or_else(|| "anonymous".into());

        let mut params = Vec::new();
        for i in 0..self.proto.num_params {
            params.push(reg_name(self.proto, i, 0));
        }
        if self.proto.is_vararg {
            params.push("...".into());
        }
        let params = params.join(", ");

        let mut out = format!("{indent}function {name}({params})\n");
        let body = self.emit_block(0, &indent);
        out.push_str(&body);
        out.push_str(&format!("{indent}end\n"));

        for &child in &self.proto.child_indices {
            let child = child as usize;
            if child < self.chunk.protos.len() {
                out.push('\n');
                out.push_str(&Decompiler::decompile_proto(self.chunk, child, depth));
            }
        }
        out
    }

    fn emit_block(&mut self, block_idx: usize, indent: &str) -> String {
        if block_idx >= self.blocks.len() {
            return String::new();
        }
        let block = self.blocks[block_idx].clone();
        if self.emitted.contains(&block.start) {
            return format!("{indent}-- block {} (merged)\n", block.start);
        }
        self.emitted.insert(block.start);

        let mut out = String::new();
        let mut pc = block.start;
        while pc < block.end {
            let inst = self.proto.instructions[pc].clone();
            if let Some(s) = self.emit_instruction(pc, &inst, indent, block_idx) {
                out.push_str(&s);
            }
            pc += 1;
        }

        if block.end > block.start {
            let last = &self.proto.instructions[block.end - 1];
            match last.opcode {
                Opcode::JumpIf => {
                    let reg = insn_a(last.raw);
                    let cond = self.reg(reg, block.end - 1);
                    if let Some(fall) = block.successors.iter().find(|&&s| s != block_idx) {
                        if let Some(taken) = jump_target(block.end - 1, last.raw, last.opcode) {
                            let taken_block = self.block_index(taken);
                            out.push_str(&format!("{indent}if {} then\n", cond.render()));
                            out.push_str(&self.emit_block(taken_block, &format!("{indent}    ")));
                            out.push_str(&format!("{indent}end\n"));
                            if *fall != taken_block {
                                out.push_str(&self.emit_block(*fall, indent));
                            }
                            return out;
                        }
                    }
                }
                Opcode::JumpIfNot => {
                    let reg = insn_a(last.raw);
                    let cond = self.reg(reg, block.end - 1);
                    if let Some(fall) = block.successors.iter().find(|&&s| s != block_idx) {
                        if let Some(taken) = jump_target(block.end - 1, last.raw, last.opcode) {
                            let taken_block = self.block_index(taken);
                            out.push_str(&format!("{indent}if not {} then\n", cond.render()));
                            out.push_str(&self.emit_block(taken_block, &format!("{indent}    ")));
                            out.push_str(&format!("{indent}end\n"));
                            if *fall != taken_block {
                                out.push_str(&self.emit_block(*fall, indent));
                            }
                            return out;
                        }
                    }
                }
                Opcode::ForNPrep => {
                    let base = insn_a(last.raw);
                    let r = |o: u8| reg_name(self.proto, base + o, block.end - 1);
                    if let Some(body_block) = block.successors.first().copied() {
                        out.push_str(&format!(
                            "{indent}for {} = {}, {}, {} do\n",
                            r(3),
                            self.reg(base + 2, block.end - 1).render(),
                            self.reg(base, block.end - 1).render(),
                            self.reg(base + 1, block.end - 1).render(),
                        ));
                        out.push_str(&self.emit_block(body_block, &format!("{indent}    ")));
                        out.push_str(&format!("{indent}end\n"));
                        return out;
                    }
                }
                Opcode::Jump | Opcode::JumpBack | Opcode::JumpX => {
                    if let Some(tgt) = jump_target(block.end - 1, last.raw, last.opcode) {
                        let tb = self.block_index(tgt);
                        if !self.emitted.contains(&self.blocks[tb].start) {
                            out.push_str(&format!("{indent}-- goto block {}\n", tgt));
                            out.push_str(&self.emit_block(tb, indent));
                        }
                    }
                    return out;
                }
                Opcode::Return => return out,
                _ => {}
            }
        }

        for succ in &block.successors {
            if !self.emitted.contains(&self.blocks[*succ].start) {
                out.push_str(&self.emit_block(*succ, indent));
            }
        }
        out
    }

    fn block_index(&self, pc: usize) -> usize {
        Self::block_index_at(&self.blocks, pc)
    }

    fn block_index_at(blocks: &[BasicBlock], pc: usize) -> usize {
        blocks
            .iter()
            .position(|b| pc >= b.start && pc < b.end)
            .unwrap_or(0)
    }

    fn emit_instruction(&mut self, pc: usize, inst: &Instruction, indent: &str, block_idx: usize) -> Option<String> {
        let a = insn_a(inst.raw);
        let b = insn_b(inst.raw);
        let c = insn_c(inst.raw);
        let d = insn_d(inst.raw);

        match inst.opcode {
            Opcode::LoadNil => {
                self.set_reg(a, Expr::Nil, pc);
                None
            }
            Opcode::LoadB => {
                self.set_reg(a, Expr::Bool(b != 0), pc);
                None
            }
            Opcode::LoadN => {
                self.set_reg(a, Expr::Number(d as f64), pc);
                None
            }
            Opcode::LoadK => {
                self.set_reg(a, self.const_expr(d as u16), pc);
                None
            }
            Opcode::LoadKx => {
                self.set_reg(a, self.const_expr(inst.aux.unwrap_or(0) as u16), pc);
                None
            }
            Opcode::Move => {
                let v = self.reg(b, pc);
                self.set_reg(a, v, pc);
                None
            }
            Opcode::GetGlobal => {
                let name = self.const_string(inst.aux.unwrap_or(0) as u16);
                self.set_reg(a, Expr::Global(name), pc);
                None
            }
            Opcode::SetGlobal => {
                let name = self.const_string(inst.aux.unwrap_or(0) as u16);
                let val = self.reg(a, pc);
                Some(format!("{indent}{name} = {}\n", val.render()))
            }
            Opcode::GetUpval => {
                self.set_reg(a, Expr::Upvalue(upval_name(self.proto, b)), pc);
                None
            }
            Opcode::Setupval => {
                let name = upval_name(self.proto, b);
                let val = self.reg(a, pc);
                Some(format!("{indent}{name} = {}\n", val.render()))
            }
            Opcode::GetImport => {
                let path = if let Some(aux) = inst.aux {
                    resolve_import_aux(aux, &self.proto.constants)
                } else if let Some(Constant::Import(id)) = self.proto.constants.get(d as usize) {
                    resolve_import(*id, &self.proto.constants)
                } else {
                    format!("import_{d}")
                };
                self.set_reg(a, Expr::Import(path), pc);
                None
            }
            Opcode::GetTable => {
                let tbl = self.reg(b, pc);
                let key = self.reg(c, pc);
                self.set_reg(a, Expr::Index { table: Box::new(tbl), key: Box::new(key) }, pc);
                None
            }
            Opcode::GetTableKs => {
                let tbl = self.reg(b, pc);
                let key = Expr::String(self.const_string(inst.aux.unwrap_or(0) as u16));
                self.set_reg(a, Expr::Index { table: Box::new(tbl), key: Box::new(key) }, pc);
                None
            }
            Opcode::GetTableN => {
                let tbl = self.reg(b, pc);
                let key = Expr::Number((c as u32 + 1) as f64);
                self.set_reg(a, Expr::Index { table: Box::new(tbl), key: Box::new(key) }, pc);
                None
            }
            Opcode::SetTable => {
                let val = self.reg(a, pc);
                let tbl = self.reg(b, pc);
                let key = self.reg(c, pc);
                Some(format!(
                    "{indent}{}[{}] = {}\n",
                    tbl.render(),
                    key.render(),
                    val.render()
                ))
            }
            Opcode::SetTableKs => {
                let val = self.reg(a, pc);
                let tbl = self.reg(b, pc);
                let key = self.const_string(inst.aux.unwrap_or(0) as u16);
                Some(format!(
                    "{indent}{}.{} = {}\n",
                    tbl.render(),
                    key,
                    val.render()
                ))
            }
            Opcode::SetTableN => {
                let val = self.reg(a, pc);
                let tbl = self.reg(b, pc);
                Some(format!(
                    "{indent}{}[{}] = {}\n",
                    tbl.render(),
                    c as u32 + 1,
                    val.render()
                ))
            }
            Opcode::Add => self.binop(a, b, c, pc, "+"),
            Opcode::Sub => self.binop(a, b, c, pc, "-"),
            Opcode::Mul => self.binop(a, b, c, pc, "*"),
            Opcode::Div => self.binop(a, b, c, pc, "/"),
            Opcode::Mod => self.binop(a, b, c, pc, "%"),
            Opcode::Pow => self.binop(a, b, c, pc, "^"),
            Opcode::AddK => self.binop_k(a, b, c, pc, "+"),
            Opcode::SubK => self.binop_k(a, b, c, pc, "-"),
            Opcode::MulK => self.binop_k(a, b, c, pc, "*"),
            Opcode::DivK => self.binop_k(a, b, c, pc, "/"),
            Opcode::ModK => self.binop_k(a, b, c, pc, "%"),
            Opcode::PowK => self.binop_k(a, b, c, pc, "^"),
            Opcode::SubRk => {
                let left = self.const_expr(b as u16);
                let right = self.reg(c, pc);
                self.set_reg(
                    a,
                    Expr::Binary {
                        op: "-",
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    pc,
                );
                None
            }
            Opcode::DivRk => {
                let left = self.const_expr(b as u16);
                let right = self.reg(c, pc);
                self.set_reg(
                    a,
                    Expr::Binary {
                        op: "/",
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    pc,
                );
                None
            }
            Opcode::Not => {
                let v = self.reg(b, pc);
                self.set_reg(a, Expr::Unary { op: "not ", arg: Box::new(v) }, pc);
                None
            }
            Opcode::Minus => {
                let v = self.reg(b, pc);
                self.set_reg(a, Expr::Unary { op: "-", arg: Box::new(v) }, pc);
                None
            }
            Opcode::Length => {
                let v = self.reg(b, pc);
                self.set_reg(a, Expr::Unary { op: "#", arg: Box::new(v) }, pc);
                None
            }
            Opcode::Concat => {
                let mut parts = Vec::new();
                for r in b..=c {
                    parts.push(self.reg(r, pc));
                }
                let mut expr = parts[0].clone();
                for p in parts.into_iter().skip(1) {
                    expr = Expr::Binary {
                        op: "..",
                        left: Box::new(expr),
                        right: Box::new(p),
                    };
                }
                self.set_reg(a, expr, pc);
                None
            }
            Opcode::NewTable => {
                self.set_reg(a, Expr::Unknown("{}".into()), pc);
                None
            }
            Opcode::DupTable => {
                let template = self.const_expr(d as u16);
                self.set_reg(a, template, pc);
                None
            }
            Opcode::GetVarargs => {
                self.set_reg(a, Expr::Varargs, pc);
                None
            }
            Opcode::Call => {
                let func = self.reg(a, pc);
                let argc = if b == 0 { 0 } else { b as usize - 1 };
                let mut args = Vec::new();
                for i in 0..argc {
                    args.push(self.reg(a + 1 + i as u8, pc));
                }
                let call = Expr::Call {
                    func: Box::new(func.clone()),
                    args,
                };
                let nret = if c == 0 { 1 } else { c as usize - 1 };
                if nret == 0 {
                    Some(format!("{indent}{}\n", call.render()))
                } else if nret == 1 {
                    self.set_reg(a, call, pc);
                    None
                } else {
                    let rendered = call.render();
                    for i in 0..nret {
                        self.set_reg(
                            a + i as u8,
                            Expr::Unknown(format!("({rendered})[{i}]")),
                            pc,
                        );
                    }
                    Some(format!("{indent}local _ = {rendered}\n"))
                }
            }
            Opcode::Return => {
                let count = if b == 0 {
                    (self.proto.max_stack as usize).saturating_sub(a as usize)
                } else {
                    b as usize - 1
                };
                let vals: Vec<_> = (0..count)
                    .map(|i| self.reg(a + i as u8, pc).render())
                    .collect();
                Some(format!("{indent}return {}\n", vals.join(", ")))
            }
            Opcode::NewClosure => {
                let child = d as usize;
                let child_name = self
                    .chunk
                    .protos
                    .get(child)
                    .and_then(|p| p.debug_name.clone())
                    .unwrap_or_else(|| format!("proto_{child}"));
                self.set_reg(a, Expr::Unknown(format!("function --[[{child_name}]] ... end")), pc);
                None
            }
            Opcode::NameCall => {
                let obj = self.reg(b, pc);
                let method = self.const_string(inst.aux.unwrap_or(0) as u16);
                self.set_reg(
                    a,
                    Expr::Index {
                        table: Box::new(obj.clone()),
                        key: Box::new(Expr::String(method.clone())),
                    },
                    pc,
                );
                self.set_reg(a + 1, obj, pc);
                None
            }
            Opcode::JumpIf | Opcode::JumpIfNot | Opcode::ForNPrep => None,
            Opcode::ForNLoop => {
                if let Some(succ) = self.blocks.get(block_idx).and_then(|b| b.successors.first()) {
                    return Some(self.emit_block(*succ, indent));
                }
                None
            }
            Opcode::Capture | Opcode::CloseUpvals | Opcode::Nop | Opcode::Break | Opcode::PrepVarargs => None,
            Opcode::FastCall | Opcode::FastCall1 | Opcode::FastCall2 | Opcode::FastCall2K | Opcode::FastCall3 => None,
            Opcode::NativeCall | Opcode::Coverage | Opcode::DupClosure => None,
            Opcode::Jump | Opcode::JumpBack | Opcode::JumpX => None,
            Opcode::ForGLoop | Opcode::ForGPrep | Opcode::ForGPrepInext | Opcode::ForGPrepNext => None,
            Opcode::SetList => None,
            Opcode::JumpIfEq
            | Opcode::JumpIfLe
            | Opcode::JumpIfLt
            | Opcode::JumpIfNeq
            | Opcode::JumpIfNotLe
            | Opcode::JumpIfNotLt
            | Opcode::JumpXEqNil
            | Opcode::JumpXEqKb
            | Opcode::JumpXEqKn
            | Opcode::JumpXEqKs
            | Opcode::Idiv
            | Opcode::IdivK
            | Opcode::And
            | Opcode::Or
            | Opcode::AndK
            | Opcode::OrK
            | Opcode::Unknown(_) => {
                Some(format!(
                    "{indent}-- {} pc={} a={a} b={b} c={c} d={d}\n",
                    inst.opcode.name(),
                    inst.pc + 1
                ))
            }
        }
    }

    fn binop(&mut self, a: u8, b: u8, c: u8, pc: usize, op: &'static str) -> Option<String> {
        let left = self.reg(b, pc);
        let right = self.reg(c, pc);
        self.set_reg(
            a,
            Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            },
            pc,
        );
        None
    }

    fn binop_k(&mut self, a: u8, b: u8, k: u8, pc: usize, op: &'static str) -> Option<String> {
        let left = self.reg(b, pc);
        let right = self.const_expr(k as u16);
        self.set_reg(
            a,
            Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            },
            pc,
        );
        None
    }

    fn reg(&self, r: u8, pc: usize) -> Expr {
        self.regs.get(&r).cloned().unwrap_or_else(|| Expr::Local(reg_name(self.proto, r, pc)))
    }

    fn set_reg(&mut self, r: u8, expr: Expr, pc: usize) {
        let name = reg_name(self.proto, r, pc);
        let expr = match expr {
            Expr::Local(ref s) if s == &name => expr,
            other => other,
        };
        self.regs.insert(r, expr);
    }

    fn const_expr(&self, idx: u16) -> Expr {
        match self.proto.constants.get(idx as usize) {
            Some(Constant::Nil) => Expr::Nil,
            Some(Constant::Boolean(b)) => Expr::Bool(*b),
            Some(Constant::Number(n)) => Expr::Number(*n),
            Some(Constant::Integer(n)) => Expr::Number(*n as f64),
            Some(Constant::String(s)) => Expr::String(s.clone()),
            Some(Constant::Import(id)) => Expr::Import(resolve_import(*id, &self.proto.constants)),
            Some(Constant::Table(keys)) => {
                let parts = keys.iter().map(|k| format_lua_string(k)).collect::<Vec<_>>().join(", ");
                Expr::Unknown(format!("{{{parts}}}"))
            }
            Some(Constant::Closure(idx)) => Expr::Unknown(format!("<closure:{idx}>")),
            Some(Constant::Vector(v)) => Expr::Unknown(format!(
                "vector.create({}, {}, {})",
                v[0], v[1], v[2]
            )),
            None => Expr::Unknown(format!("K{idx}")),
        }
    }

    fn const_string(&self, idx: u16) -> String {
        match self.proto.constants.get(idx as usize) {
            Some(Constant::String(s)) => s.clone(),
            Some(other) => format_constant(other),
            None => format!("K{idx}"),
        }
    }
}
