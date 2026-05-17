use crate::error::{DecompileError, Result};
use crate::opcode::{detect_wire_format, Opcode, WireFormat};
use crate::utils::{
    read_bytes, read_f32, read_f64, read_i32_le, read_u8, read_u32_le, read_varint, read_varint64,
};
use crate::validate::{validate_chunk_with_options, ValidateOptions};

#[derive(Debug, Clone, Copy)]
pub struct BytecodeOptions {
    pub wire: WireFormat,
    pub lenient: bool,
}

impl Default for BytecodeOptions {
    fn default() -> Self {
        Self {
            wire: WireFormat::Auto,
            lenient: true,
        }
    }
}

impl BytecodeOptions {
    pub fn roblox_strict() -> Self {
        Self {
            wire: WireFormat::Roblox227,
            lenient: false,
        }
    }
}

pub const LBC_VERSION_MIN: u8 = 3;
pub const LBC_VERSION_MAX: u8 = 11;

pub const TAG_NIL: u8 = 0;
pub const TAG_BOOL: u8 = 1;
pub const TAG_NUMBER: u8 = 2;
pub const TAG_STRING: u8 = 3;
pub const TAG_IMPORT: u8 = 4;
pub const TAG_TABLE: u8 = 5;
pub const TAG_CLOSURE: u8 = 6;
pub const TAG_VECTOR: u8 = 7;
pub const TAG_TABLE_CONST: u8 = 8;
pub const TAG_INTEGER: u8 = 9;
pub const TAG_CLASS_SHAPE: u8 = 10;

#[derive(Debug, Clone)]
pub struct Chunk {
    pub version: u8,
    pub types_version: u8,
    pub strings: Vec<String>,
    pub protos: Vec<Proto>,
    pub main_index: usize,
    pub wire_format: WireFormat,
    pub warnings: Vec<String>,
    /// Filled during parse, drained when instructions are decoded (not part of public API).
    raw_instruction_words: Vec<Vec<u32>>,
}

#[derive(Debug, Clone)]
pub struct Proto {
    pub max_stack: u8,
    pub num_params: u8,
    pub num_upvalues: u8,
    pub is_vararg: bool,
    pub flags: u8,
    pub instructions: Vec<Instruction>,
    pub constants: Vec<Constant>,
    pub child_indices: Vec<u32>,
    pub line_defined: u32,
    pub debug_name: Option<String>,
    pub debug_locals: Vec<DebugLocal>,
    pub debug_upvals: Vec<String>,
    line_map: Vec<i32>,
}

#[derive(Debug, Clone)]
pub struct DebugLocal {
    pub name: String,
    pub start_pc: u32,
    pub end_pc: u32,
    pub reg: u8,
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub pc: usize,
    pub line: i32,
    pub opcode: Opcode,
    /// Low byte of the instruction word as stored in the blob (before ×227 decode).
    pub wire_opcode: u8,
    pub raw: u32,
    pub aux: Option<u32>,
}

#[derive(Debug, Clone)]
pub enum Constant {
    Nil,
    Boolean(bool),
    Number(f64),
    Integer(i64),
    String(String),
    Import(u32),
    Table(Vec<String>),
    Closure(u32),
    Vector([f32; 4]),
    Unknown { tag: u8 },
}

pub struct BytecodeReader;

impl BytecodeReader {
    pub fn read(bytes: &[u8]) -> Result<Chunk> {
        Self::read_with_options(bytes, BytecodeOptions::default())
    }

    pub fn read_with_options(bytes: &[u8], options: BytecodeOptions) -> Result<Chunk> {
        let mut chunk = Self::read_unparsed(bytes)?;
        let wire = match options.wire {
            WireFormat::Auto => {
                let slices: Vec<&[u32]> = chunk
                    .raw_instruction_words
                    .iter()
                    .map(|v| v.as_slice())
                    .collect();
                detect_wire_format(&slices)
            }
            other => other,
        };
        let line_maps: Vec<Vec<i32>> = chunk.protos.iter().map(|p| p.line_map.clone()).collect();
        for ((proto, raw), lines) in chunk
            .protos
            .iter_mut()
            .zip(chunk.raw_instruction_words.drain(..))
            .zip(line_maps)
        {
            proto.instructions = parse_instruction_words(&raw, wire)?;
            let mut word_idx = 0usize;
            for inst in &mut proto.instructions {
                inst.line = *lines.get(word_idx).unwrap_or(&0);
                word_idx += inst.opcode.word_len();
            }
            proto.line_map.clear();
        }
        chunk.wire_format = wire;
        let mut warnings = Vec::new();
        validate_chunk_with_options(
            &chunk,
            ValidateOptions {
                lenient: options.lenient,
            },
            &mut warnings,
        )?;
        chunk.warnings = warnings;
        Ok(chunk)
    }

    fn read_unparsed(bytes: &[u8]) -> Result<Chunk> {
        let mut offset = 0;
        if bytes.is_empty() {
            return Err(DecompileError::UnexpectedEof);
        }

        let version = read_u8(bytes, &mut offset).ok_or(DecompileError::UnexpectedEof)?;
        if version == 0 {
            return Err(DecompileError::Malformed("error bytecode marker"));
        }
        if !(LBC_VERSION_MIN..=LBC_VERSION_MAX).contains(&version) {
            return Err(DecompileError::UnsupportedVersion(version));
        }

        let types_version = if version >= 4 {
            read_u8(bytes, &mut offset).ok_or(DecompileError::UnexpectedEof)?
        } else {
            0
        };
        let strings = Self::read_string_table(bytes, &mut offset)?;
        Self::skip_userdata_type_map(bytes, &mut offset, version)?;

        let func_count = read_varint(bytes, &mut offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let mut protos = Vec::with_capacity(func_count);
        let mut raw_instruction_words = Vec::with_capacity(func_count);
        for i in 0..func_count {
            let (proto, raw) = Self::read_proto_at(bytes, &mut offset, &strings, version, types_version)
                .map_err(|e| match e {
                    DecompileError::Malformed(msg) => {
                        DecompileError::Message(format!("proto {i}: {msg}"))
                    }
                    other => other,
                })?;
            raw_instruction_words.push(raw);
            protos.push(proto);
        }

        let main_index = match read_varint(bytes, &mut offset) {
            Some(idx) => idx as usize,
            None => 0,
        };
        let main_index = if protos.is_empty() {
            0
        } else if main_index >= protos.len() {
            protos.len() - 1
        } else {
            main_index
        };

        Ok(Chunk {
            version,
            types_version,
            strings,
            protos,
            main_index,
            wire_format: WireFormat::Auto,
            warnings: Vec::new(),
            raw_instruction_words,
        })
    }

    fn read_proto_at(
        bytes: &[u8],
        offset: &mut usize,
        strings: &[String],
        version: u8,
        types_version: u8,
    ) -> Result<(Proto, Vec<u32>)> {
        Self::read_proto_inner(bytes, offset, strings, version, types_version)
    }

    fn read_string_table(bytes: &[u8], offset: &mut usize) -> Result<Vec<String>> {
        let count = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let mut strings = Vec::with_capacity(count);
        for _ in 0..count {
            let len = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
            let raw = read_bytes(bytes, offset, len).ok_or(DecompileError::UnexpectedEof)?;
            strings.push(String::from_utf8_lossy(raw).into_owned());
        }
        Ok(strings)
    }

    fn skip_userdata_type_map(bytes: &[u8], offset: &mut usize, version: u8) -> Result<()> {
        if version <= 5 {
            return Ok(());
        }
        loop {
            let tag = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
            if tag == 0 {
                break;
            }
            read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
        }
        Ok(())
    }

    fn read_proto_inner(
        bytes: &[u8],
        offset: &mut usize,
        strings: &[String],
        version: u8,
        types_version: u8,
    ) -> Result<(Proto, Vec<u32>)> {
        let max_stack = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
        let num_params = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
        let num_upvalues = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
        let is_vararg = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)? != 0;
        let flags = if version >= 4 {
            read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)?
        } else {
            0
        };

        let typeinfo_size = if version >= 4 {
            read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize
        } else {
            0
        };
        if typeinfo_size > 0 {
            let blob = read_bytes(bytes, offset, typeinfo_size).ok_or(DecompileError::UnexpectedEof)?;
            let mut sub_off = 0usize;
            if types_version > 1 {
                let _ = read_varint(blob, &mut sub_off);
                let _ = read_varint(blob, &mut sub_off);
                let _ = read_varint(blob, &mut sub_off);
            }
        }

        let word_count = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let mut raw_words = Vec::with_capacity(word_count);
        for _ in 0..word_count {
            raw_words.push(read_u32_le(bytes, offset).ok_or(DecompileError::UnexpectedEof)?);
        }

        let const_count = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let mut constants = Vec::with_capacity(const_count);
        for _ in 0..const_count {
            constants.push(Self::read_constant(bytes, offset, strings, version)?);
        }

        let child_count = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let mut child_indices = Vec::with_capacity(child_count);
        for _ in 0..child_count {
            child_indices.push(read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?);
        }

        let line_defined = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
        let debug_name_idx = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
        let debug_name = resolve_string_index(strings, debug_name_idx);

        let has_lines = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)? != 0;
        let word_lines = if has_lines {
            Self::read_line_info(bytes, offset, word_count)?
        } else {
            vec![0; word_count]
        };

        let has_debug = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)? != 0;
        let (debug_locals, debug_upvals) = if has_debug {
            Self::read_debug_info(bytes, offset, strings)?
        } else {
            (Vec::new(), Vec::new())
        };

        if version >= 11 {
            Self::skip_feedback_vector(bytes, offset)?;
        }

        Ok((
            Proto {
                max_stack,
                num_params,
                num_upvalues,
                is_vararg,
                flags,
                instructions: Vec::new(),
                constants,
                child_indices,
                line_defined,
                debug_name,
                debug_locals,
                debug_upvals,
                line_map: word_lines,
            },
            raw_words,
        ))
    }

    fn read_constant(bytes: &[u8], offset: &mut usize, strings: &[String], version: u8) -> Result<Constant> {
        let tag = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
        match tag {
            TAG_NIL => Ok(Constant::Nil),
            TAG_BOOL => {
                let v = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                Ok(Constant::Boolean(v != 0))
            }
            TAG_NUMBER => Ok(Constant::Number(read_f64(bytes, offset).ok_or(DecompileError::UnexpectedEof)?)),
            TAG_STRING => {
                let idx = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                Ok(Constant::String(
                    resolve_string_index(strings, idx).unwrap_or_default(),
                ))
            }
            TAG_IMPORT => {
                let ids = read_u32_le(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                Ok(Constant::Import(ids))
            }
            TAG_TABLE => {
                let len = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
                let mut keys = Vec::with_capacity(len);
                for _ in 0..len {
                    let k = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                    keys.push(format!("k{k}"));
                }
                Ok(Constant::Table(keys))
            }
            TAG_CLOSURE => {
                let idx = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                Ok(Constant::Closure(idx))
            }
            TAG_VECTOR => {
                let x = read_f32(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                let y = read_f32(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                let z = read_f32(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                let w = read_f32(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                Ok(Constant::Vector([x, y, z, w]))
            }
            TAG_TABLE_CONST if version >= 7 => {
                let key_count = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
                let mut keys = Vec::with_capacity(key_count);
                for _ in 0..key_count {
                    let key_k = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                    let _value_k = read_i32_le(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                    keys.push(format!("k{key_k}"));
                }
                Ok(Constant::Table(keys))
            }
            TAG_INTEGER if version >= 8 => {
                let negative = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)? != 0;
                let magnitude = read_varint64(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                let value = if negative {
                    -(magnitude as i64)
                } else {
                    magnitude as i64
                };
                Ok(Constant::Integer(value))
            }
            TAG_CLASS_SHAPE if version >= 10 => {
                let _class_name_k =
                    read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                let num_properties =
                    read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
                let num_methods =
                    read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
                let member_count = num_properties.saturating_add(num_methods);
                for _ in 0..member_count {
                    read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                }
                Ok(Constant::String("<class_shape>".into()))
            }
            _ => Ok(Constant::Unknown { tag }),
        }
    }

    fn read_line_info(bytes: &[u8], offset: &mut usize, word_count: usize) -> Result<Vec<i32>> {
        let line_gap_log2 = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as u32;
        let intervals = ((word_count.saturating_sub(1)) >> line_gap_log2) + 1;

        let mut line_deltas = Vec::with_capacity(word_count);
        let mut last_offset = 0u32;
        for _ in 0..word_count {
            last_offset += read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as u32;
            line_deltas.push(last_offset);
        }

        let mut abs_lines = Vec::with_capacity(intervals);
        let mut last_line = 0u32;
        for _ in 0..intervals {
            last_line = last_line.wrapping_add(read_u32_le(bytes, offset).ok_or(DecompileError::UnexpectedEof)?);
            abs_lines.push(last_line);
        }

        let mut lines = vec![0i32; word_count];
        for (i, line) in lines.iter_mut().enumerate() {
            let abs_index = (i >> line_gap_log2).min(abs_lines.len().saturating_sub(1));
            let baseline = abs_lines.get(abs_index).copied().unwrap_or(0);
            *line = (baseline + line_deltas[i]) as i32;
        }
        Ok(lines)
    }

    fn skip_feedback_vector(bytes: &[u8], offset: &mut usize) -> Result<()> {
        let count = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        for _ in 0..count {
            read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
            read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
        }
        Ok(())
    }

    fn read_debug_info(
        bytes: &[u8],
        offset: &mut usize,
        strings: &[String],
    ) -> Result<(Vec<DebugLocal>, Vec<String>)> {
        let local_count = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let mut debug_locals = Vec::with_capacity(local_count);
        for _ in 0..local_count {
            let name_idx = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
            let start_pc = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
            let end_pc = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
            let reg = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
            debug_locals.push(DebugLocal {
                name: resolve_string_index(strings, name_idx)
                    .unwrap_or_else(|| format!("local_{reg}")),
                start_pc,
                end_pc,
                reg,
            });
        }

        let upval_count = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let mut debug_upvals = Vec::with_capacity(upval_count);
        for _ in 0..upval_count {
            let name_idx = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
            debug_upvals.push(
                resolve_string_index(strings, name_idx)
                    .unwrap_or_else(|| format!("upval_{}", debug_upvals.len())),
            );
        }

        Ok((debug_locals, debug_upvals))
    }
}

/// Decode a proto instruction stream (Roblox-encoded opcodes in the low byte of each word).
#[cfg(test)]
mod instruction_tests {
    use super::parse_instruction_words;
    use crate::opcode::{Opcode, WireFormat};

    fn word(op: u8, a: u8, b: u8, c: u8) -> u32 {
        let op = Opcode::encode_u8(op);
        u32::from(op) | (u32::from(a) << 8) | (u32::from(b) << 16) | (u32::from(c) << 24)
    }

    #[test]
    fn callfb_and_new_class_member_consume_aux_word() {
        let raw = [
            word(87, 0, 2, 1),
            5,
            word(86, 1, 0, 2),
            3,
            word(22, 0, 1, 0),
        ];
        let inst = parse_instruction_words(&raw, WireFormat::Roblox227).expect("parse");
        assert_eq!(inst.len(), 3);
        assert_eq!(inst[0].opcode, Opcode::CallFb);
        assert_eq!(inst[0].aux, Some(5));
        assert_eq!(inst[1].opcode, Opcode::NewClassMember);
        assert_eq!(inst[1].aux, Some(3));
        assert_eq!(inst[2].opcode, Opcode::Return);
    }

    #[test]
    fn rejects_stream_without_required_aux() {
        let raw = [word(87, 0, 2, 1)];
        assert!(parse_instruction_words(&raw, WireFormat::Roblox227).is_err());
    }
}

/// Luau string table indices are 1-based; 0 means empty / absent.
fn resolve_string_index(strings: &[String], index: u32) -> Option<String> {
    if index == 0 {
        return None;
    }
    strings.get((index - 1) as usize).cloned()
}

pub fn parse_instruction_words(raw_words: &[u32], wire: WireFormat) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    let mut idx = 0usize;
    let mut pc = 0usize;
    while idx < raw_words.len() {
        let raw = raw_words[idx];
        let wire_opcode = (raw & 0xff) as u8;
        let op = Opcode::from_wire_byte(wire_opcode, wire);
        let aux = if op.has_aux() {
            idx += 1;
            if idx >= raw_words.len() {
                return Err(DecompileError::Malformed(
                    "instruction stream ended before AUX word",
                ));
            }
            Some(raw_words[idx])
        } else {
            None
        };
        instructions.push(Instruction {
            pc,
            line: 0,
            opcode: op,
            wire_opcode,
            raw,
            aux,
        });
        pc += 1;
        idx += 1;
    }
    let consumed: usize = instructions.iter().map(|i| i.opcode.word_len()).sum();
    if consumed != raw_words.len() {
        return Err(DecompileError::Malformed(
            "instruction word count does not match decoded instruction lengths",
        ));
    }
    Ok(instructions)
}

pub fn resolve_import(ids: u32, constants: &[Constant]) -> String {
    let count = (ids >> 30) as usize;
    let indices = [
        if count > 0 { Some(((ids >> 20) & 0x3ff) as usize) } else { None },
        if count > 1 { Some(((ids >> 10) & 0x3ff) as usize) } else { None },
        if count > 2 { Some((ids & 0x3ff) as usize) } else { None },
    ];
    indices
        .into_iter()
        .flatten()
        .filter_map(|i| constants.get(i))
        .map(|c| match c {
            Constant::String(s) => s.clone(),
            other => format_constant(other),
        })
        .collect::<Vec<_>>()
        .join(".")
}

pub fn resolve_import_aux(aux: u32, constants: &[Constant]) -> String {
    let count = (aux >> 30) as usize;
    let indices = [
        if count > 0 { Some(((aux >> 20) & 0x3ff) as usize) } else { None },
        if count > 1 { Some(((aux >> 10) & 0x3ff) as usize) } else { None },
        if count > 2 { Some((aux & 0x3ff) as usize) } else { None },
    ];
    let path: String = indices
        .into_iter()
        .flatten()
        .filter_map(|i| constants.get(i))
        .map(|c| match c {
            Constant::String(s) => s.clone(),
            other => format_constant(other),
        })
        .collect::<Vec<_>>()
        .join(".");
    if !path.is_empty() {
        return path;
    }
    if let Some(Constant::Import(id)) = constants.get((aux & 0x3ff) as usize) {
        return resolve_import(*id, constants);
    }
    if let Some(Constant::String(s)) = constants.get((aux & 0x3ff) as usize) {
        return s.clone();
    }
    format!("import_{aux:08X}")
}

pub fn format_constant(c: &Constant) -> String {
    match c {
        Constant::Nil => "nil".into(),
        Constant::Boolean(b) => b.to_string(),
        Constant::Number(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{n:.0}")
            } else {
                n.to_string()
            }
        }
        Constant::Integer(n) => n.to_string(),
        Constant::String(s) => format_lua_string(s),
        Constant::Import(_) => "<import>".into(),
        Constant::Table(keys) => format!(
            "{{{}}}",
            keys.iter()
                .map(|k| format_lua_string(k))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Constant::Closure(idx) => format!("<closure:{idx}>"),
        Constant::Vector(v) => format!("vector.create({}, {}, {})", v[0], v[1], v[2]),
        Constant::Unknown { tag } => format!("<const:{tag:02X}>"),
    }
}

pub fn format_lua_string(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !s.is_empty() && !s.chars().next().unwrap().is_numeric() {
        return s.to_string();
    }
    let mut out = String::from('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_ascii() => out.push(c),
            c => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
        }
    }
    out.push('"');
    out
}

pub fn reg_name(proto: &Proto, reg: u8, pc: usize) -> String {
    for loc in &proto.debug_locals {
        if loc.reg == reg && (pc as u32) >= loc.start_pc && (pc as u32) < loc.end_pc {
            return loc.name.clone();
        }
    }
    if (reg as usize) < proto.num_params as usize {
        return format!("arg{}", reg + 1);
    }
    format!("r{reg}")
}

pub fn upval_name(proto: &Proto, idx: u8) -> String {
    proto
        .debug_upvals
        .get(idx as usize)
        .cloned()
        .unwrap_or_else(|| format!("upval_{idx}"))
}
