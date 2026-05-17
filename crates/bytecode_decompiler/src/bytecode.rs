use crate::error::{DecompileError, Result};
use crate::opcode::Opcode;
use crate::utils::{read_bytes, read_f32, read_f64, read_u8, read_u32_le, read_varint};

pub const LBC_VERSION_MIN: u8 = 3;
pub const LBC_VERSION_MAX: u8 = 8;

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

#[derive(Debug, Clone)]
pub struct Chunk {
    pub version: u8,
    pub types_version: u8,
    pub strings: Vec<String>,
    pub protos: Vec<Proto>,
    pub main_index: usize,
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
}

pub struct BytecodeReader;

impl BytecodeReader {
    pub fn read(bytes: &[u8]) -> Result<Chunk> {
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

        let types_version = read_u8(bytes, &mut offset).ok_or(DecompileError::UnexpectedEof)?;
        let strings = Self::read_string_table(bytes, &mut offset)?;
        Self::skip_userdata_type_map(bytes, &mut offset, version)?;

        let func_count = read_varint(bytes, &mut offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let mut protos = Vec::with_capacity(func_count);
        for _ in 0..func_count {
            protos.push(Self::read_proto_at(bytes, &mut offset, &strings, version, types_version)?);
        }

        let main_index = read_varint(bytes, &mut offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        if main_index >= func_count {
            return Err(DecompileError::Malformed("main proto index out of range"));
        }

        Ok(Chunk {
            version,
            types_version,
            strings,
            protos,
            main_index,
        })
    }

    fn read_proto_at(
        bytes: &[u8],
        offset: &mut usize,
        strings: &[String],
        version: u8,
        types_version: u8,
    ) -> Result<Proto> {
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
    ) -> Result<Proto> {
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

        let mut instructions = Vec::new();
        let mut idx = 0usize;
        let mut pc = 0usize;
        while idx < raw_words.len() {
            let word_idx = idx;
            let raw = raw_words[idx];
            let op = Opcode::from_u8((raw & 0xff) as u8);
            let aux = if op.has_aux() {
                idx += 1;
                if idx >= raw_words.len() {
                    return Err(DecompileError::Malformed("missing aux word"));
                }
                Some(raw_words[idx])
            } else {
                None
            };
            instructions.push(Instruction {
                pc,
                line: 0,
                opcode: op,
                raw,
                aux,
            });
            pc += 1;
            idx += 1;
            let _ = word_idx;
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
        let debug_name_idx = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let debug_name = strings.get(debug_name_idx).cloned();

        let has_lines = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)? != 0;
        let word_lines = if has_lines {
            Self::read_line_info(bytes, offset, word_count)?
        } else {
            vec![0; word_count]
        };

        let mut word_idx = 0usize;
        for inst in &mut instructions {
            inst.line = *word_lines.get(word_idx).unwrap_or(&0);
            word_idx += inst.opcode.word_len();
        }

        let has_debug = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)? != 0;
        let (debug_locals, debug_upvals) = if has_debug {
            Self::read_debug_info(bytes, offset, strings)?
        } else {
            (Vec::new(), Vec::new())
        };

        Ok(Proto {
            max_stack,
            num_params,
            num_upvalues,
            is_vararg,
            flags,
            instructions,
            constants,
            child_indices,
            line_defined,
            debug_name,
            debug_locals,
            debug_upvals,
        })
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
                let idx = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
                Ok(Constant::String(strings.get(idx).cloned().unwrap_or_default()))
            }
            TAG_IMPORT => {
                let ids = read_u32_le(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                Ok(Constant::Import(ids))
            }
            TAG_TABLE => {
                let len = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
                let mut keys = Vec::with_capacity(len);
                for _ in 0..len {
                    let k = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
                    keys.push(strings.get(k).cloned().unwrap_or_default());
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
                let _len = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
                Ok(Constant::Table(Vec::new()))
            }
            TAG_INTEGER if version >= 8 => {
                let lo = read_u32_le(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as u64;
                let hi = read_u32_le(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as u64;
                Ok(Constant::Integer(((hi << 32) | lo) as i64))
            }
            _ => Err(DecompileError::Malformed("unknown constant tag")),
        }
    }

    fn read_line_info(bytes: &[u8], offset: &mut usize, word_count: usize) -> Result<Vec<i32>> {
        let line_gap_log2 = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as u32;
        let baseline_size = ((word_count.saturating_sub(1)) >> line_gap_log2) + 1;

        let mut small = Vec::with_capacity(word_count);
        let mut last_offset = 0i32;
        for _ in 0..word_count {
            let byte = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as i8 as i32;
            last_offset += byte;
            small.push(last_offset);
        }

        let mut abs = Vec::with_capacity(baseline_size);
        let mut last_line = 0i32;
        for _ in 0..baseline_size {
            let delta = read_u32_le(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as i32;
            last_line += delta;
            abs.push(last_line);
        }

        let mut lines = vec![0i32; word_count];
        for (i, line) in lines.iter_mut().enumerate() {
            let abs_index = (i as u32) >> line_gap_log2;
            let mut result = small[i] + abs[abs_index as usize];
            if line_gap_log2 <= 1 && -small[i] == abs[abs_index as usize] {
                if let Some(next) = abs.get(abs_index as usize + 1) {
                    result += *next;
                }
            }
            if result <= 0 {
                result += 0x100;
            }
            *line = result;
        }
        Ok(lines)
    }

    fn read_debug_info(
        bytes: &[u8],
        offset: &mut usize,
        strings: &[String],
    ) -> Result<(Vec<DebugLocal>, Vec<String>)> {
        let local_count = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let mut debug_locals = Vec::with_capacity(local_count);
        for _ in 0..local_count {
            let name_idx = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
            let start_pc = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
            let end_pc = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
            let reg = read_u8(bytes, offset).ok_or(DecompileError::UnexpectedEof)?;
            debug_locals.push(DebugLocal {
                name: strings.get(name_idx).cloned().unwrap_or_else(|| format!("local_{reg}")),
                start_pc,
                end_pc,
                reg,
            });
        }

        let upval_count = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
        let mut debug_upvals = Vec::with_capacity(upval_count);
        for _ in 0..upval_count {
            let name_idx = read_varint(bytes, offset).ok_or(DecompileError::UnexpectedEof)? as usize;
            debug_upvals.push(
                strings
                    .get(name_idx)
                    .cloned()
                    .unwrap_or_else(|| format!("upval_{}", debug_upvals.len())),
            );
        }

        Ok((debug_locals, debug_upvals))
    }
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
