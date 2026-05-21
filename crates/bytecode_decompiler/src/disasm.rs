use crate::bytecode::{format_constant, resolve_import, resolve_import_aux, Chunk, Constant, Instruction, Proto};
use crate::opcode::{insn_a, insn_b, insn_c, insn_d, Opcode};

pub struct Disassembler;

impl Disassembler {
    pub fn disassemble_chunk(chunk: &Chunk) -> String {
        let mut out = String::new();
        out.push_str(&format!("; Luau bytecode v{}\n", chunk.version));
        out.push_str(&format!("; main proto: {}\n\n", chunk.main_index));

        for (i, proto) in chunk.protos.iter().enumerate() {
            out.push_str(&Self::disassemble_proto(i, proto, chunk));
            out.push('\n');
        }
        out
    }

    pub fn disassemble_proto(index: usize, proto: &Proto, chunk: &Chunk) -> String {
        let mut out = String::new();
        let name = proto
            .debug_name
            .as_deref()
            .unwrap_or("<anonymous>");
        out.push_str(&format!(
            "; function {} (proto {}, line {}, params {}, upvals {})\n",
            name, index, proto.line_defined, proto.num_params, proto.num_upvalues
        ));

        for inst in &proto.instructions {
            let line = if inst.line > 0 {
                format!(" [{:>4}]", inst.line)
            } else {
                String::new()
            };
            out.push_str(&format!(
                "{:04}{line} {}\n",
                inst.pc + 1,
                format_instruction(inst, proto, chunk)
            ));
        }
        out
    }
}

pub fn format_instruction(inst: &Instruction, proto: &Proto, _chunk: &Chunk) -> String {
    let a = insn_a(inst.raw);
    let b = insn_b(inst.raw);
    let c = insn_c(inst.raw);
    let d = insn_d(inst.raw);

    match inst.opcode {
        Opcode::LoadNil => format!("LOADNIL R{a}"),
        Opcode::LoadB => format!("LOADB R{a} {b} +{c}"),
        Opcode::LoadN => format!("LOADN R{a} {d}"),
        Opcode::LoadK => format!("LOADK R{a} {}", const_at(proto, d as u16)),
        Opcode::LoadKx => format!(
            "LOADKX R{a} {}",
            const_at(proto, inst.aux.unwrap_or(0) as u16)
        ),
        Opcode::Move => format!("MOVE R{a} R{b}"),
        Opcode::GetGlobal => format!(
            "GETGLOBAL R{a} {}",
            const_at(proto, inst.aux.unwrap_or(0) as u16)
        ),
        Opcode::SetGlobal => format!(
            "SETGLOBAL R{a} {}",
            const_at(proto, inst.aux.unwrap_or(0) as u16)
        ),
        Opcode::GetUpval => format!("GETUPVAL R{a} U{b}"),
        Opcode::Setupval => format!("SETUPVAL R{a} U{b}"),
        Opcode::CloseUpvals => format!("CLOSEUPVALS R{a}"),
        Opcode::GetImport => format!(
            "GETIMPORT R{a} {}",
            import_at(proto, d as i32, inst.aux)
        ),
        Opcode::GetTable => format!("GETTABLE R{a} R{b} R{c}"),
        Opcode::SetTable => format!("SETTABLE R{a} R{b} R{c}"),
        Opcode::GetTableKs => format!(
            "GETTABLEKS R{a} R{b} {}",
            const_at(proto, inst.aux.unwrap_or(0) as u16)
        ),
        Opcode::SetTableKs => format!(
            "SETTABLEKS R{a} R{b} {}",
            const_at(proto, inst.aux.unwrap_or(0) as u16)
        ),
        Opcode::GetTableN => format!("GETTABLEN R{a} R{b} {}", c as u32 + 1),
        Opcode::SetTableN => format!("SETTABLEN R{a} R{b} {}", c as u32 + 1),
        Opcode::NewClosure => format!("NEWCLOSURE R{a} P{d}"),
        Opcode::NameCall => format!(
            "NAMECALL R{a} R{b} {}",
            const_at(proto, inst.aux.unwrap_or(0) as u16)
        ),
        Opcode::Call => format!("CALL R{a} {b} {c}"),
        Opcode::Return => format!("RETURN R{a} {b}"),
        Opcode::Jump => format!("JUMP {d:+}"),
        Opcode::JumpBack => format!("JUMPBACK {d:+}"),
        Opcode::JumpIf => format!("JUMPIF R{a} {d:+}"),
        Opcode::JumpIfNot => format!("JUMPIFNOT R{a} {d:+}"),
        Opcode::JumpIfEq => format!("JUMPIFEQ R{a} R{} {d:+}", reg_aux(inst)),
        Opcode::JumpIfLe => format!("JUMPIFLE R{a} R{} {d:+}", reg_aux(inst)),
        Opcode::JumpIfLt => format!("JUMPIFLT R{a} R{} {d:+}", reg_aux(inst)),
        Opcode::JumpIfNeq => format!("JUMPIFNOTEQ R{a} R{} {d:+}", reg_aux(inst)),
        Opcode::JumpIfNotLe => format!("JUMPIFNOTLE R{a} R{} {d:+}", reg_aux(inst)),
        Opcode::JumpIfNotLt => format!("JUMPIFNOTLT R{a} R{} {d:+}", reg_aux(inst)),
        Opcode::Add => format!("ADD R{a} R{b} R{c}"),
        Opcode::Sub => format!("SUB R{a} R{b} R{c}"),
        Opcode::Mul => format!("MUL R{a} R{b} R{c}"),
        Opcode::Div => format!("DIV R{a} R{b} R{c}"),
        Opcode::Mod => format!("MOD R{a} R{b} R{c}"),
        Opcode::Pow => format!("POW R{a} R{b} R{c}"),
        Opcode::AddK => format!("ADDK R{a} R{b} {}", const_at(proto, c as u16)),
        Opcode::SubK => format!("SUBK R{a} R{b} {}", const_at(proto, c as u16)),
        Opcode::MulK => format!("MULK R{a} R{b} {}", const_at(proto, c as u16)),
        Opcode::DivK => format!("DIVK R{a} R{b} {}", const_at(proto, c as u16)),
        Opcode::ModK => format!("MODK R{a} R{b} {}", const_at(proto, c as u16)),
        Opcode::PowK => format!("POWK R{a} R{b} {}", const_at(proto, c as u16)),
        Opcode::And => format!("AND R{a} R{b} R{c}"),
        Opcode::Or => format!("OR R{a} R{b} R{c}"),
        Opcode::AndK => format!("ANDK R{a} R{b} {}", const_at(proto, c as u16)),
        Opcode::OrK => format!("ORK R{a} R{b} {}", const_at(proto, c as u16)),
        Opcode::Concat => format!("CONCAT R{a} R{b} R{c}"),
        Opcode::Not => format!("NOT R{a} R{b}"),
        Opcode::Minus => format!("MINUS R{a} R{b}"),
        Opcode::Length => format!("LENGTH R{a} R{b}"),
        Opcode::NewTable => format!("NEWTABLE R{a} {b}"),
        Opcode::DupTable => format!("DUPTABLE R{a} {}", const_at(proto, d as u16)),
        Opcode::SetList => format!("SETLIST R{a} R{b} {c}"),
        Opcode::ForNPrep => format!("FORNPREP R{a} {d:+}"),
        Opcode::ForNLoop => format!("FORNLOOP R{a} {d:+}"),
        Opcode::ForGLoop => format!("FORGLOOP R{a} {d:+}"),
        Opcode::ForGPrep => format!("FORGPREP R{a} {d:+}"),
        Opcode::ForGPrepInext => format!("FORGPREP_INEXT R{a} {d:+}"),
        Opcode::ForGPrepNext => format!("FORGPREP_NEXT R{a} {d:+}"),
        Opcode::FastCall2 => format!("FASTCALL2 {a} R{b} +{c}"),
        Opcode::FastCall2K => format!("FASTCALL2K {a} R{b}"),
        Opcode::FastCall3 => format!("FASTCALL3 {a} R{b} +{c}"),
        Opcode::JumpX => format!("JUMPX {d:+}"),
        Opcode::JumpXEqNil => format!("JUMPXEQNIL R{a} {d:+}"),
        Opcode::JumpXEqKb => format!("JUMPXEQKB R{a} {d:+}"),
        Opcode::JumpXEqKn => format!("JUMPXEQKN R{a} {d:+}"),
        Opcode::JumpXEqKs => format!("JUMPXEQKS R{a} {d:+}"),
        Opcode::NameCallUdata => format!(
            "NAMECALLUDATA R{a} R{b} {}",
            const_at(proto, inst.aux.unwrap_or(0) as u16)
        ),
        Opcode::DupClosure => format!("DUPCLOSURE R{a} {}", const_at(proto, d as u16)),
        Opcode::CallFb => format!("CALLFB R{a} {b} {c}"),
        Opcode::Capture => format!("CAPTURE {} R{b}", capture_kind(a)),
        Opcode::GetVarargs => format!("GETVARARGS R{a} {b}"),
        Opcode::PrepVarargs => format!("PREPVARARGS {a}"),
        Opcode::FastCall => format!("FASTCALL {a} +{c}"),
        Opcode::FastCall1 => format!("FASTCALL1 {a} R{b} +{c}"),
        Opcode::Nop | Opcode::Break => format!("{}", inst.opcode.name()),
        Opcode::Unknown(v) => format!("OP_{v:02X} {a} {b} {c}"),
        other => format!("{} R{a} R{b} R{c} D{d}", other.name()),
    }
}

fn reg_aux(inst: &Instruction) -> u8 {
    insn_a(inst.aux.unwrap_or(0))
}

fn capture_kind(a: u8) -> &'static str {
    match a {
        0 => "VAL",
        1 => "REF",
        2 => "UPVAL",
        _ => "CAP",
    }
}

fn const_at(proto: &Proto, idx: u16) -> String {
    match proto.constants.get(idx as usize) {
        Some(c) => format_constant(c),
        None => format!("K{idx}"),
    }
}

fn import_at(proto: &Proto, d: i32, aux: Option<u32>) -> String {
    if let Some(aux) = aux {
        return resolve_import_aux(aux, &proto.constants);
    }
    if d >= 0 {
        if let Some(Constant::Import(id)) = proto.constants.get(d as usize) {
            return resolve_import(*id, &proto.constants);
        }
    }
    format!("import({d})")
}
