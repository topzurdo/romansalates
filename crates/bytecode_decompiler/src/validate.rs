use crate::bytecode::{Chunk, Proto};
use crate::error::{DecompileError, Result};
use crate::opcode::{insn_b, insn_c, insn_d, jump_target, Opcode};

#[derive(Debug, Clone, Copy)]
pub struct ValidateOptions {
    /// Unknown opcodes and version mismatches become warnings instead of hard errors.
    pub lenient: bool,
}

impl Default for ValidateOptions {
    fn default() -> Self {
        Self { lenient: true }
    }
}

pub fn validate_chunk(chunk: &Chunk) -> Result<()> {
    let mut warnings = Vec::new();
    validate_chunk_with_options(chunk, ValidateOptions::default(), &mut warnings)
}

pub fn validate_chunk_with_options(
    chunk: &Chunk,
    options: ValidateOptions,
    warnings: &mut Vec<String>,
) -> Result<()> {
    for (i, proto) in chunk.protos.iter().enumerate() {
        validate_proto_with_options(i, proto, chunk.protos.len(), chunk.version, options, warnings)?;
    }
    if chunk.main_index >= chunk.protos.len() && !chunk.protos.is_empty() {
        return Err(DecompileError::Message(format!(
            "main_index {} out of range (proto count {})",
            chunk.main_index,
            chunk.protos.len()
        )));
    }
    Ok(())
}

pub fn validate_proto(index: usize, proto: &Proto, proto_count: usize) -> Result<()> {
    let mut warnings = Vec::new();
    validate_proto_with_options(index, proto, proto_count, LBC_VERSION_ASSUME, ValidateOptions::default(), &mut warnings)
}

const LBC_VERSION_ASSUME: u8 = 11;

pub fn validate_proto_with_options(
    index: usize,
    proto: &Proto,
    proto_count: usize,
    bytecode_version: u8,
    options: ValidateOptions,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let n = proto.instructions.len();
    let word_len: usize = proto.instructions.iter().map(|i| i.opcode.word_len()).sum();
    if word_len == 0 && n > 0 {
        return Err(DecompileError::Message(format!(
            "proto {index}: empty instruction word accounting"
        )));
    }

    for (pc, inst) in proto.instructions.iter().enumerate() {
        if let Opcode::Unknown(v) = inst.opcode {
            let msg = format!(
                "proto {index} pc {pc}: unknown opcode 0x{v:02X} (wire 0x{:02X})",
                inst.wire_opcode
            );
            if options.lenient {
                warnings.push(msg);
            } else {
                return Err(DecompileError::Message(msg));
            }
            continue;
        }

        let min_v = inst.opcode.min_bytecode_version();
        if bytecode_version < min_v {
            let msg = format!(
                "proto {index} pc {pc}: opcode {} requires bytecode v{min_v}, blob is v{bytecode_version}",
                inst.opcode.name()
            );
            if options.lenient {
                warnings.push(msg);
            } else {
                return Err(DecompileError::Message(msg));
            }
        }

        if let Some(target) = jump_target(pc, inst.raw, inst.opcode) {
            if target > n {
                let msg = format!(
                    "proto {index} pc {pc}: jump target {target} past end ({n} instructions)"
                );
                if options.lenient {
                    warnings.push(msg);
                } else {
                    return Err(DecompileError::Message(msg));
                }
            }
        }

        check_constant_refs(index, pc, inst, proto, proto_count)?;
    }

    for &child in &proto.child_indices {
        if child as usize >= proto_count {
            let msg = format!("proto {index}: child index {child} out of range (proto count {proto_count})");
            if options.lenient {
                warnings.push(msg);
            } else {
                return Err(DecompileError::Message(msg));
            }
        }
    }
    Ok(())
}

fn check_constant_refs(
    index: usize,
    pc: usize,
    inst: &crate::bytecode::Instruction,
    proto: &Proto,
    proto_count: usize,
) -> Result<()> {
    let n = proto.constants.len();
    let check = |idx: usize| -> Result<()> {
        if idx >= n {
            Err(DecompileError::Message(format!(
                "proto {index} pc {pc}: constant index {idx} out of range (len {n})"
            )))
        } else {
            Ok(())
        }
    };

    let d = insn_d(inst.raw);
    match inst.opcode {
        Opcode::NewClosure => {
            if d >= 0 {
                let child = d as usize;
                if child >= proto_count {
                    return Err(DecompileError::Message(format!(
                        "proto {index} pc {pc}: child proto index {child} out of range (proto count {proto_count})"
                    )));
                }
            }
        }
        Opcode::LoadK | Opcode::DupTable => check(d as usize)?,
        Opcode::LoadKx => {
            if let Some(aux) = inst.aux {
                check(aux_kv_idx(aux))?;
            }
        }
        Opcode::GetGlobal | Opcode::SetGlobal | Opcode::GetTableKs | Opcode::SetTableKs
        | Opcode::GetUdataKs | Opcode::SetUdataKs | Opcode::NameCall | Opcode::NameCallUdata
        | Opcode::NewClassMember => {
            if let Some(aux) = inst.aux {
                check(aux_kv_idx(aux))?;
            }
        }
        Opcode::GetImport => {
            if let Some(aux) = inst.aux {
                for idx in import_aux_indices(aux) {
                    check(idx)?;
                }
            } else if d >= 0 {
                check(d as usize)?;
            }
        }
        Opcode::JumpXEqKn | Opcode::JumpXEqKs => {
            if let Some(aux) = inst.aux {
                check(aux_kv_idx(aux))?;
            }
        }
        Opcode::AddK | Opcode::SubK | Opcode::MulK | Opcode::DivK | Opcode::ModK | Opcode::PowK
        | Opcode::AndK | Opcode::OrK | Opcode::IdivK => check(insn_c(inst.raw) as usize)?,
        Opcode::SubRk | Opcode::DivRk => check(insn_b(inst.raw) as usize)?,
        Opcode::DupClosure => {
            if d >= 0 {
                check(d as usize)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn aux_kv_idx(aux: u32) -> usize {
    (aux & 0xffffff) as usize
}

fn import_aux_indices(aux: u32) -> Vec<usize> {
    let count = (aux >> 30) as usize;
    let mut out = Vec::new();
    if count > 0 {
        out.push(((aux >> 20) & 0x3ff) as usize);
    }
    if count > 1 {
        out.push(((aux >> 10) & 0x3ff) as usize);
    }
    if count > 2 {
        out.push((aux & 0x3ff) as usize);
    }
    out
}
