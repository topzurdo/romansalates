use std::collections::{HashMap, HashSet};

use crate::bytecode::{
    format_constant, format_lua_string, reg_name, resolve_import, resolve_import_aux, upval_name,
    Chunk, Constant, Instruction, Proto,
};
use crate::opcode::{aux_kb, aux_kv, aux_not, insn_a, insn_b, insn_c, insn_d, jump_target, Opcode};

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
    MethodCall {
        object: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },
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
            Expr::Local(s) | Expr::Global(s) | Expr::Upvalue(s) => s.clone(),
            Expr::Import(s) => render_import_path(s),
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
                if let Expr::Import(msg) = func.as_ref() {
                    if is_roblox_error_template(msg) {
                        let rendered_args = args.iter().map(Expr::render).collect::<Vec<_>>().join(", ");
                        if rendered_args.is_empty() {
                            return format!("error({})", format_lua_string(msg));
                        }
                        return format!("error({msg_fmt}, {rendered_args})", msg_fmt = format_lua_string(msg));
                    }
                }
                let args = args.iter().map(Expr::render).collect::<Vec<_>>().join(", ");
                format!("{}({args})", func.render())
            }
            Expr::MethodCall { object, method, args } => {
                let obj = object.render();
                let args = args.iter().map(Expr::render).collect::<Vec<_>>().join(", ");
                if is_valid_lua_ident(method) {
                    if args.is_empty() {
                        format!("{obj}:{method}")
                    } else {
                        format!("{obj}:{method}({args})")
                    }
                } else if args.is_empty() {
                    format!("{obj}[{m}]", m = format_lua_string(method))
                } else {
                    format!("{obj}[{m}]({args})", m = format_lua_string(method))
                }
            }
            Expr::Unknown(s) => s.clone(),
        }
    }
}

struct FunctionDecompiler<'a> {
    chunk: &'a Chunk,
    proto: &'a Proto,
    regs: HashMap<u8, Expr>,
    pending_namecall: HashMap<u8, (String, Expr)>,
    emitted_blocks: HashSet<usize>,
    blocks: Vec<BasicBlock>,
    newtable_serial: usize,
}

enum WorkItem {
    Block { idx: usize, indent: String },
    CloseIf { indent: String },
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
        Self::decompile_proto_body(chunk, chunk.main_index)
    }

    fn decompile_proto_body(chunk: &Chunk, index: usize) -> String {
        let proto = &chunk.protos[index];
        let mut d = FunctionDecompiler::new(chunk, proto);
        d.build_cfg();
        d.decompile(index, index == chunk.main_index)
    }
}

fn is_roblox_error_template(s: &str) -> bool {
    s.contains("%*")
        || s.starts_with("Unknown ")
        || s.starts_with("Tried to ")
        || s.contains("DropTable")
        || s.contains("Directory %*")
}

fn render_import_path(path: &str) -> String {
    if is_roblox_error_template(path) {
        return format_lua_string(path);
    }
    if path.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') && !path.is_empty() {
        return path.to_string();
    }
    format_lua_string(path)
}

fn is_valid_lua_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.chars().next().unwrap().is_numeric()
}

fn fold_member(base: Expr, key: &str) -> Expr {
    if !is_valid_lua_ident(key) {
        return Expr::Index {
            table: Box::new(base),
            key: Box::new(Expr::String(key.to_string())),
        };
    }
    match base {
        Expr::Import(path) => {
            if path.is_empty() {
                Expr::Import(key.to_string())
            } else {
                Expr::Import(format!("{path}.{key}"))
            }
        }
        Expr::Global(path) => {
            if path.is_empty() {
                Expr::Global(key.to_string())
            } else {
                Expr::Global(format!("{path}.{key}"))
            }
        }
        Expr::Index { table, key: idx } => {
            if let Expr::String(seg) = idx.as_ref() {
                if let Expr::Import(path) = table.as_ref() {
                    return Expr::Import(format!("{path}.{seg}.{key}"));
                }
            }
            Expr::Index {
                table,
                key: Box::new(Expr::String(key.to_string())),
            }
        }
        other => Expr::Index {
            table: Box::new(other),
            key: Box::new(Expr::String(key.to_string())),
        },
    }
}

fn luau_builtin_name(id: u8) -> &'static str {
    match id {
        1 => "assert",
        2 => "math.abs",
        3 => "math.acos",
        4 => "math.asin",
        5 => "math.atan2",
        6 => "math.atan",
        7 => "math.ceil",
        8 => "math.cosh",
        9 => "math.cos",
        10 => "math.deg",
        11 => "math.exp",
        12 => "math.floor",
        13 => "math.fmod",
        14 => "math.frexp",
        15 => "math.ldexp",
        16 => "math.log10",
        17 => "math.log",
        18 => "math.max",
        19 => "math.min",
        20 => "math.modf",
        21 => "math.pow",
        22 => "math.rad",
        23 => "math.sinh",
        24 => "math.sin",
        25 => "math.sqrt",
        26 => "math.tanh",
        27 => "math.tan",
        28 => "bit32.arshift",
        29 => "bit32.band",
        30 => "bit32.bnot",
        31 => "bit32.bor",
        32 => "bit32.bxor",
        33 => "bit32.btest",
        34 => "bit32.extract",
        35 => "bit32.lrotate",
        36 => "bit32.lshift",
        37 => "bit32.replace",
        38 => "bit32.rrotate",
        39 => "bit32.rshift",
        40 => "type",
        41 => "string.byte",
        42 => "string.char",
        43 => "string.len",
        44 => "typeof",
        45 => "string.sub",
        46 => "math.clamp",
        47 => "math.sign",
        48 => "math.round",
        49 => "rawset",
        50 => "rawget",
        51 => "rawequal",
        52 => "table.insert",
        53 => "table.unpack",
        54 => "vector.create",
        55 => "bit32.countlz",
        56 => "bit32.countrz",
        57 => "select",
        58 => "rawlen",
        59 => "bit32.extract",
        60 => "getmetatable",
        61 => "setmetatable",
        62 => "tonumber",
        63 => "tostring",
        _ => "builtin",
    }
}

impl<'a> FunctionDecompiler<'a> {
    fn new(chunk: &'a Chunk, proto: &'a Proto) -> Self {
        Self {
            chunk,
            proto,
            regs: HashMap::new(),
            pending_namecall: HashMap::new(),
            emitted_blocks: HashSet::new(),
            blocks: Vec::new(),
            newtable_serial: 0,
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
            if matches!(
                inst.opcode,
                Opcode::JumpIf | Opcode::JumpIfNot | Opcode::JumpXEqNil | Opcode::JumpXEqKb
                    | Opcode::JumpXEqKn | Opcode::JumpXEqKs
            ) {
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
                Opcode::JumpIf | Opcode::JumpIfNot | Opcode::JumpXEqNil | Opcode::JumpXEqKb
                | Opcode::JumpXEqKn | Opcode::JumpXEqKs => {
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
                Opcode::ForNPrep => {
                    if let Some(tgt) = jump_target(end_pc, inst.raw, inst.opcode) {
                        let t = Self::block_index_at(&self.blocks, tgt);
                        self.blocks[bi].successors.push(t);
                        self.blocks[t].predecessors.push(bi);
                    }
                }
                Opcode::ForGPrep | Opcode::ForGPrepInext | Opcode::ForGPrepNext => {
                    if end_pc + 1 < n {
                        let next = Self::block_index_at(&self.blocks, end_pc + 1);
                        if !self.blocks[bi].successors.contains(&next) {
                            self.blocks[bi].successors.push(next);
                            self.blocks[next].predecessors.push(bi);
                        }
                    }
                    if let Some(tgt) = jump_target(end_pc, inst.raw, inst.opcode) {
                        let t = Self::block_index_at(&self.blocks, tgt);
                        if !self.blocks[bi].successors.contains(&t) {
                            self.blocks[bi].successors.push(t);
                            self.blocks[t].predecessors.push(bi);
                        }
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

    fn decompile(&mut self, proto_index: usize, is_main: bool) -> String {
        let base_name = self
            .proto
            .debug_name
            .clone()
            .unwrap_or_else(|| "anonymous".into());
        let name = if is_main {
            if base_name == "anonymous" || base_name == "<anonymous>" {
                "main".into()
            } else {
                base_name
            }
        } else if base_name == "anonymous" || base_name == "<anonymous>" {
            format!("proto_{proto_index}")
        } else {
            format!("{base_name}__p{proto_index}")
        };

        let mut params = Vec::new();
        for i in 0..self.proto.num_params {
            params.push(reg_name(self.proto, i, 0));
        }
        if self.proto.is_vararg {
            params.push("...".into());
        }
        let params = params.join(", ");

        let mut out = format!("function {name}({params})\n");
        out.push_str(&self.emit_body());
        out.push_str("end\n\n");
        out
    }

    /// Iterative CFG walk — avoids stack overflow on long JUMPIFNOT chains (Roblox modules).
    fn emit_body(&mut self) -> String {
        let mut out = String::new();
        let mut work = vec![WorkItem::Block {
            idx: 0,
            indent: "    ".into(),
        }];

        while let Some(item) = work.pop() {
            match item {
                WorkItem::CloseIf { indent } => {
                    out.push_str(&format!("{indent}end\n"));
                }
                WorkItem::Block { idx: block_idx, indent } => {
                    if block_idx >= self.blocks.len() {
                        continue;
                    }
                    if !self.emitted_blocks.insert(block_idx) {
                        continue;
                    }

                    let block = self.blocks[block_idx].clone();
                    let mut pc = block.start;
                    while pc < block.end {
                        let inst = self.proto.instructions[pc].clone();
                        if let Some(s) = self.emit_instruction(pc, &inst, &indent, block_idx) {
                            out.push_str(&s);
                        }
                        pc += 1;
                    }

                    if block.end <= block.start {
                        continue;
                    }

                    let last_pc = block.end - 1;
                    let last = self.proto.instructions[last_pc].clone();
                    let jump_succ = jump_target(last_pc, last.raw, last.opcode)
                        .map(|t| self.block_index(t));
                    let fall = block
                        .successors
                        .iter()
                        .copied()
                        .find(|s| Some(*s) != jump_succ);

                    match last.opcode {
                        Opcode::Return => {}
                        Opcode::JumpIf => {
                            let reg = insn_a(last.raw);
                            let cond = self.reg(reg, last_pc);
                            if let Some(taken_block) = jump_succ {
                                out.push_str(&format!("{indent}if {} then\n", cond.render()));
                                if let Some(fb) = fall {
                                    work.push(WorkItem::Block {
                                        idx: fb,
                                        indent: indent.clone(),
                                    });
                                }
                                work.push(WorkItem::CloseIf {
                                    indent: indent.clone(),
                                });
                                work.push(WorkItem::Block {
                                    idx: taken_block,
                                    indent: format!("{indent}    "),
                                });
                            } else if let Some(fb) = fall {
                                work.push(WorkItem::Block {
                                    idx: fb,
                                    indent,
                                });
                            }
                        }
                        Opcode::JumpIfNot => {
                            let reg = insn_a(last.raw);
                            let cond = self.reg(reg, last_pc);
                            if let Some(taken_block) = jump_succ {
                                out.push_str(&format!("{indent}if not {} then\n", cond.render()));
                                if let Some(fb) = fall {
                                    work.push(WorkItem::Block {
                                        idx: fb,
                                        indent: indent.clone(),
                                    });
                                }
                                work.push(WorkItem::CloseIf {
                                    indent: indent.clone(),
                                });
                                work.push(WorkItem::Block {
                                    idx: taken_block,
                                    indent: format!("{indent}    "),
                                });
                            } else if let Some(fb) = fall {
                                work.push(WorkItem::Block {
                                    idx: fb,
                                    indent,
                                });
                            }
                        }
                        Opcode::JumpXEqNil | Opcode::JumpXEqKb | Opcode::JumpXEqKn | Opcode::JumpXEqKs => {
                            let cond = self.jump_x_eq_condition(&last, last_pc);
                            if let Some(taken_block) = jump_succ {
                                out.push_str(&format!("{indent}if not ({cond}) then\n"));
                                if let Some(fb) = fall {
                                    work.push(WorkItem::Block {
                                        idx: fb,
                                        indent: indent.clone(),
                                    });
                                }
                                work.push(WorkItem::CloseIf {
                                    indent: indent.clone(),
                                });
                                work.push(WorkItem::Block {
                                    idx: taken_block,
                                    indent: format!("{indent}    "),
                                });
                            } else if let Some(fb) = fall {
                                work.push(WorkItem::Block {
                                    idx: fb,
                                    indent,
                                });
                            }
                        }
                        Opcode::ForNPrep => {
                            let base = insn_a(last.raw);
                            let r = |o: u8| reg_name(self.proto, base + o, last_pc);
                            if let Some(body_block) = block.successors.first().copied() {
                                out.push_str(&format!(
                                    "{indent}for {} = {}, {}, {} do\n",
                                    r(3),
                                    self.reg(base + 2, last_pc).render(),
                                    self.reg(base, last_pc).render(),
                                    self.reg(base + 1, last_pc).render(),
                                ));
                                work.push(WorkItem::CloseIf {
                                    indent: indent.clone(),
                                });
                                work.push(WorkItem::Block {
                                    idx: body_block,
                                    indent: format!("{indent}    "),
                                });
                            }
                        }
                        Opcode::ForGPrep | Opcode::ForGPrepInext | Opcode::ForGPrepNext => {
                            let base = insn_a(last.raw);
                            let vars = reg_name(self.proto, base + 3, last_pc);
                            let iter = reg_name(self.proto, base, last_pc);
                            let body_block = self.block_index(last_pc + 1);
                            out.push_str(&format!("{indent}for {vars} in {iter} do\n"));
                            work.push(WorkItem::CloseIf {
                                indent: indent.clone(),
                            });
                            work.push(WorkItem::Block {
                                idx: body_block,
                                indent: format!("{indent}    "),
                            });
                        }
                        Opcode::ForGLoop => {
                            for succ in block.successors.iter().rev() {
                                if !self.emitted_blocks.contains(succ) {
                                    work.push(WorkItem::Block {
                                        idx: *succ,
                                        indent: indent.clone(),
                                    });
                                }
                            }
                        }
                        Opcode::Jump | Opcode::JumpBack | Opcode::JumpX => {
                            if let Some(tgt) = jump_target(last_pc, last.raw, last.opcode) {
                                let tb = self.block_index(tgt);
                                if self.emitted_blocks.contains(&tb) {
                                    out.push_str(&format!("{indent}-- goto pc {tgt}\n"));
                                } else {
                                    work.push(WorkItem::Block {
                                        idx: tb,
                                        indent: indent.clone(),
                                    });
                                }
                            }
                        }
                        _ => {
                            for succ in block.successors.iter().rev() {
                                if !self.emitted_blocks.contains(succ) {
                                    work.push(WorkItem::Block {
                                        idx: *succ,
                                        indent: indent.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
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

    fn emit_instruction(&mut self, pc: usize, inst: &Instruction, indent: &str, _block_idx: usize) -> Option<String> {
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
            Opcode::DupClosure => {
                let expr = if let Some(Constant::Closure(child)) = self.proto.constants.get(d as usize) {
                    self.closure_expr(*child as usize)
                } else {
                    self.closure_expr(d as usize)
                };
                self.set_reg(a, expr, pc);
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
                let key = self.const_string(inst.aux.unwrap_or(0) as u16);
                self.set_reg(a, fold_member(tbl, &key), pc);
                None
            }
            Opcode::GetUdataKs => {
                let tbl = self.reg(b, pc);
                let key = self.const_string(inst.aux.unwrap_or(0) as u16);
                self.set_reg(a, fold_member(tbl, &key), pc);
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
            Opcode::SetUdataKs => {
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
                let name = if self.newtable_serial == 0 {
                    self.proto
                        .debug_name
                        .as_deref()
                        .filter(|n| *n != "anonymous" && *n != "<anonymous>")
                        .map(|n| format!("{n}_tbl"))
                        .unwrap_or_else(|| "module".into())
                } else {
                    format!("t{}", self.newtable_serial)
                };
                self.newtable_serial += 1;
                self.set_reg(a, Expr::Local(name), pc);
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
            Opcode::Call | Opcode::CallFb => {
                let nret = if c == 0 { 1 } else { c as usize - 1 };
                let call = if let Some((method, object)) = self.pending_namecall.remove(&a) {
                    let user_argc = b.saturating_sub(2) as usize;
                    let mut args = Vec::new();
                    for i in 0..user_argc {
                        args.push(self.reg(a + 2 + i as u8, pc));
                    }
                    Expr::MethodCall {
                        object: Box::new(object),
                        method,
                        args,
                    }
                } else {
                    let func = self.reg(a, pc);
                    let argc = if b == 0 { 0 } else { b as usize - 1 };
                    let mut args = Vec::new();
                    for i in 0..argc {
                        args.push(self.reg(a + 1 + i as u8, pc));
                    }
                    self.build_call_expr(func, args)
                };
                if nret == 0 {
                    Some(format!("{indent}{}\n", call.render()))
                } else if nret == 1 {
                    self.set_reg(a, call, pc);
                    None
                } else {
                    self.set_reg(a, call, pc);
                    Some(format!(
                        "{indent}-- call returns {nret} values (R{a}..)\n",
                    ))
                }
            }
            Opcode::Return => {
                let count = if b == 0 {
                    if self.proto.is_vararg {
                        (self.proto.max_stack as usize).saturating_sub(a as usize).max(1)
                    } else {
                        1
                    }
                } else {
                    b as usize - 1
                };
                let vals: Vec<_> = (0..count)
                    .map(|i| self.reg(a + i as u8, pc).render())
                    .collect();
                Some(format!("{indent}return {}\n", vals.join(", ")))
            }
            Opcode::NewClosure => {
                self.set_reg(a, self.closure_expr(d as usize), pc);
                None
            }
            Opcode::NameCall | Opcode::NameCallUdata => {
                let obj = self.reg(b, pc);
                let method = self.const_string(inst.aux.unwrap_or(0) as u16);
                self.pending_namecall.insert(a, (method, obj.clone()));
                self.set_reg(a + 1, obj, pc);
                None
            }
            Opcode::JumpIf | Opcode::JumpIfNot | Opcode::JumpIfEq | Opcode::JumpIfLe | Opcode::JumpIfLt
            | Opcode::JumpIfNeq | Opcode::JumpIfNotLe | Opcode::JumpIfNotLt
            | Opcode::JumpXEqNil | Opcode::JumpXEqKb | Opcode::JumpXEqKn | Opcode::JumpXEqKs
            | Opcode::ForNPrep => None,
            Opcode::ForNLoop => None,
            Opcode::SetList => {
                let tbl = self.reg(a, pc);
                let start_reg = b;
                let count = if c == 0 { 0 } else { c as usize - 1 };
                let base = inst.aux.unwrap_or(0) as usize;
                let mut s = String::new();
                for i in 0..count {
                    let key = (base + 1 + i) as u32;
                    let val = self.reg(start_reg.wrapping_add(i as u8), pc);
                    s.push_str(&format!(
                        "{indent}{}[{key}] = {}\n",
                        tbl.render(),
                        val.render()
                    ));
                }
                if s.is_empty() { None } else { Some(s) }
            }
            Opcode::Capture | Opcode::CloseUpvals | Opcode::Nop | Opcode::Break | Opcode::PrepVarargs => None,
            Opcode::FastCall | Opcode::FastCall1 | Opcode::FastCall2 | Opcode::FastCall2K | Opcode::FastCall3 => {
                self.emit_fast_call(pc, inst.opcode, a, b, c, inst.aux);
                None
            }
            Opcode::NativeCall | Opcode::Coverage => None,
            Opcode::NewClassMember => {
                let member = self.const_string(inst.aux.unwrap_or(0) as u16);
                let val = self.reg(c, pc);
                Some(format!(
                    "{indent}-- class member {member} = {}\n",
                    val.render()
                ))
            }
            Opcode::Jump | Opcode::JumpBack | Opcode::JumpX => None,
            Opcode::ForGLoop | Opcode::ForGPrep | Opcode::ForGPrepInext | Opcode::ForGPrepNext => None,
            Opcode::And => self.binop(a, b, c, pc, "and"),
            Opcode::Or => self.binop(a, b, c, pc, "or"),
            Opcode::AndK => self.binop_k(a, b, c, pc, "and"),
            Opcode::OrK => self.binop_k(a, b, c, pc, "or"),
            Opcode::Idiv => self.binop(a, b, c, pc, "//"),
            Opcode::IdivK => self.binop_k(a, b, c, pc, "//"),
            Opcode::Unknown(v) => {
                Some(format!(
                    "{indent}-- UNKNOWN op={v} wire=0x{:02X} ({}) pc={} a={a} b={b} c={c} d={d}\n",
                    inst.wire_opcode,
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

    fn emit_fast_call(
        &mut self,
        pc: usize,
        op: Opcode,
        builtin_id: u8,
        arg_b: u8,
        arg_c: u8,
        aux: Option<u32>,
    ) {
        let name = luau_builtin_name(builtin_id);
        let mut args = Vec::new();
        let result_reg = match op {
            Opcode::FastCall1 => {
                args.push(self.reg(arg_b, pc));
                arg_b
            }
            Opcode::FastCall2 => {
                args.push(self.reg(arg_b, pc));
                let r2 = aux.map(|v| (v & 0xff) as u8).unwrap_or(arg_c);
                args.push(self.reg(r2, pc));
                arg_b
            }
            Opcode::FastCall2K => {
                args.push(self.reg(arg_b, pc));
                args.push(self.const_expr(aux.unwrap_or(0) as u16));
                arg_b
            }
            Opcode::FastCall3 => {
                args.push(self.reg(arg_b, pc));
                let auxv = aux.unwrap_or(0);
                args.push(self.reg((auxv & 0xff) as u8, pc));
                args.push(self.reg(((auxv >> 8) & 0xff) as u8, pc));
                arg_b
            }
            _ => arg_b,
        };
        let call = self.build_call_expr(Expr::Import(name.to_string()), args);
        if let Some(next) = self.proto.instructions.get(pc + 1) {
            if matches!(next.opcode, Opcode::Call) {
                let base = insn_a(next.raw);
                let nret = if insn_c(next.raw) == 0 {
                    1
                } else {
                    insn_c(next.raw) as usize - 1
                };
                if nret == 1 {
                    self.set_reg(base, call, pc);
                    return;
                }
            }
        }
        self.set_reg(result_reg, call, pc);
    }

    fn jump_x_eq_condition(&self, inst: &Instruction, pc: usize) -> String {
        let reg = insn_a(inst.raw);
        let left = self.reg(reg, pc);
        let aux = inst.aux.unwrap_or(0);
        let mut cond = match inst.opcode {
            Opcode::JumpXEqNil => format!("{} == nil", left.render()),
            Opcode::JumpXEqKb => {
                let kb = aux_kb(aux);
                format!("{} == {}", left.render(), kb)
            }
            Opcode::JumpXEqKn => {
                let kn = self.const_expr(aux_kv(aux));
                format!("{} == {}", left.render(), kn.render())
            }
            Opcode::JumpXEqKs => {
                let ks = format_lua_string(&self.const_string(aux_kv(aux)));
                format!("{} == {ks}", left.render())
            }
            _ => left.render(),
        };
        if aux_not(aux) {
            cond = format!("not ({cond})");
        }
        cond
    }

    fn build_call_expr(&self, func: Expr, args: Vec<Expr>) -> Expr {
        if let Expr::Import(ref path) = func {
            if path == "game" && args.len() == 1 {
                return fold_game_path(&args[0]);
            }
        }
        if let Expr::Index { table, key } = &func {
            if let Expr::String(method) = key.as_ref() {
                if method == "__index" {
                    if let Expr::String(prop) = table.as_ref() {
                        if is_roblox_error_template(prop) {
                            return Expr::Call {
                                func: Box::new(Expr::Import("error".into())),
                                args: std::iter::once(Expr::String(prop.clone()))
                                    .chain(args)
                                    .collect(),
                            };
                        }
                    }
                }
            }
        }
        Expr::Call {
            func: Box::new(func),
            args,
        }
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
            Some(Constant::Unknown { tag }) => Expr::Unknown(format!("<const:{tag:02X}>")),
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

    fn closure_expr(&self, child: usize) -> Expr {
        let proto = match self.chunk.protos.get(child) {
            Some(p) => p,
            None => {
                return Expr::Unknown(format!("function() -- missing proto {child}\nend"));
            }
        };
        let mut params = Vec::new();
        for i in 0..proto.num_params {
            params.push(reg_name(proto, i, 0));
        }
        if proto.is_vararg {
            params.push("...".into());
        }
        let params = params.join(", ");
        let mut inner = FunctionDecompiler::new(self.chunk, proto);
        inner.build_cfg();
        let body = inner.emit_body();
        Expr::Unknown(format!("function({params})\n{body}end"))
    }
}

fn fold_game_path(arg: &Expr) -> Expr {
    match arg {
        Expr::Import(path) => Expr::Import(format!("game.{path}")),
        Expr::Global(path) => Expr::Import(format!("game.{path}")),
        Expr::Index { table, key } => {
            if let Expr::Import(prefix) = table.as_ref() {
                if let Expr::String(seg) = key.as_ref() {
                    return Expr::Import(format!("{prefix}.{seg}"));
                }
            }
            if let Expr::String(seg) = key.as_ref() {
                return Expr::Import(format!("game.{seg}"));
            }
            Expr::Index {
                table: Box::new(Expr::Import("game".into())),
                key: key.clone(),
            }
        }
        other => Expr::Call {
            func: Box::new(Expr::Import("game".into())),
            args: vec![other.clone()],
        },
    }
}
