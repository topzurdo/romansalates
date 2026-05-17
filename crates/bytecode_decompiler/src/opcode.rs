use crate::opcode_table::{meta_for_index, OP_META};

/// How the low byte of each instruction word maps to a logical Luau opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WireFormat {
    /// Pick Roblox×227 vs plain by scoring parse quality on the blob.
    #[default]
    Auto,
    /// Roblox: `logical = (wire * 203) & 0xFF` (inverse of ×227).
    Roblox227,
    /// Upstream Luau / Fiu: low byte is the opcode index directly.
    Plain,
}

impl WireFormat {
    pub fn decode_wire_byte(self, wire: u8) -> u8 {
        match self {
            WireFormat::Roblox227 => ((wire as u16).wrapping_mul(203) & 0xff) as u8,
            WireFormat::Plain => wire,
            WireFormat::Auto => wire,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Nop = 0,
    Break,
    LoadNil,
    LoadB,
    LoadN,
    LoadK,
    Move,
    GetGlobal,
    SetGlobal,
    GetUpval,
    Setupval,
    CloseUpvals,
    GetImport,
    GetTable,
    SetTable,
    GetTableKs,
    SetTableKs,
    GetTableN,
    SetTableN,
    NewClosure,
    NameCall,
    Call,
    Return,
    Jump,
    JumpBack,
    JumpIf,
    JumpIfNot,
    JumpIfEq,
    JumpIfLe,
    JumpIfLt,
    JumpIfNeq,
    JumpIfNotLe,
    JumpIfNotLt,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    AddK,
    SubK,
    MulK,
    DivK,
    ModK,
    PowK,
    And,
    Or,
    AndK,
    OrK,
    Concat,
    Not,
    Minus,
    Length,
    NewTable,
    DupTable,
    SetList,
    ForNPrep,
    ForNLoop,
    ForGLoop,
    ForGPrepInext,
    FastCall3,
    ForGPrepNext,
    NativeCall,
    GetVarargs,
    DupClosure,
    PrepVarargs,
    LoadKx,
    JumpX,
    FastCall,
    Coverage,
    Capture,
    SubRk,
    DivRk,
    FastCall1,
    FastCall2,
    FastCall2K,
    ForGPrep,
    JumpXEqNil,
    JumpXEqKb,
    JumpXEqKn,
    JumpXEqKs,
    Idiv,
    IdivK,
    GetUdataKs,
    SetUdataKs,
    NameCallUdata,
    NewClassMember,
    CallFb,
    Unknown(u8),
}

impl Opcode {
    pub const COUNT: u8 = 88;

    /// Encode a logical opcode for the low byte of an instruction word (Roblox Luau).
    pub fn encode_u8(op: u8) -> u8 {
        ((op as u16).wrapping_mul(227) & 0xff) as u8
    }

    pub fn from_wire_byte(wire: u8, format: WireFormat) -> Self {
        Self::from_u8_raw(format.decode_wire_byte(wire))
    }

    /// Roblox-scrambled wire byte → logical opcode (default for legacy call sites).
    pub fn from_u8(v: u8) -> Self {
        Self::from_wire_byte(v, WireFormat::Roblox227)
    }

    pub fn index(self) -> u8 {
        match self {
            Self::Nop => 0,
            Self::Break => 1,
            Self::LoadNil => 2,
            Self::LoadB => 3,
            Self::LoadN => 4,
            Self::LoadK => 5,
            Self::Move => 6,
            Self::GetGlobal => 7,
            Self::SetGlobal => 8,
            Self::GetUpval => 9,
            Self::Setupval => 10,
            Self::CloseUpvals => 11,
            Self::GetImport => 12,
            Self::GetTable => 13,
            Self::SetTable => 14,
            Self::GetTableKs => 15,
            Self::SetTableKs => 16,
            Self::GetTableN => 17,
            Self::SetTableN => 18,
            Self::NewClosure => 19,
            Self::NameCall => 20,
            Self::Call => 21,
            Self::Return => 22,
            Self::Jump => 23,
            Self::JumpBack => 24,
            Self::JumpIf => 25,
            Self::JumpIfNot => 26,
            Self::JumpIfEq => 27,
            Self::JumpIfLe => 28,
            Self::JumpIfLt => 29,
            Self::JumpIfNeq => 30,
            Self::JumpIfNotLe => 31,
            Self::JumpIfNotLt => 32,
            Self::Add => 33,
            Self::Sub => 34,
            Self::Mul => 35,
            Self::Div => 36,
            Self::Mod => 37,
            Self::Pow => 38,
            Self::AddK => 39,
            Self::SubK => 40,
            Self::MulK => 41,
            Self::DivK => 42,
            Self::ModK => 43,
            Self::PowK => 44,
            Self::And => 45,
            Self::Or => 46,
            Self::AndK => 47,
            Self::OrK => 48,
            Self::Concat => 49,
            Self::Not => 50,
            Self::Minus => 51,
            Self::Length => 52,
            Self::NewTable => 53,
            Self::DupTable => 54,
            Self::SetList => 55,
            Self::ForNPrep => 56,
            Self::ForNLoop => 57,
            Self::ForGLoop => 58,
            Self::ForGPrepInext => 59,
            Self::FastCall3 => 60,
            Self::ForGPrepNext => 61,
            Self::NativeCall => 62,
            Self::GetVarargs => 63,
            Self::DupClosure => 64,
            Self::PrepVarargs => 65,
            Self::LoadKx => 66,
            Self::JumpX => 67,
            Self::FastCall => 68,
            Self::Coverage => 69,
            Self::Capture => 70,
            Self::SubRk => 71,
            Self::DivRk => 72,
            Self::FastCall1 => 73,
            Self::FastCall2 => 74,
            Self::FastCall2K => 75,
            Self::ForGPrep => 76,
            Self::JumpXEqNil => 77,
            Self::JumpXEqKb => 78,
            Self::JumpXEqKn => 79,
            Self::JumpXEqKs => 80,
            Self::Idiv => 81,
            Self::IdivK => 82,
            Self::GetUdataKs => 83,
            Self::SetUdataKs => 84,
            Self::NameCallUdata => 85,
            Self::NewClassMember => 86,
            Self::CallFb => 87,
            Self::Unknown(v) => v,
        }
    }

    pub fn min_bytecode_version(self) -> u8 {
        meta_for_index(self.index())
            .map(|m| m.min_version)
            .unwrap_or(255)
    }

    pub fn from_u8_raw(v: u8) -> Self {
        match v {
            0 => Self::Nop,
            1 => Self::Break,
            2 => Self::LoadNil,
            3 => Self::LoadB,
            4 => Self::LoadN,
            5 => Self::LoadK,
            6 => Self::Move,
            7 => Self::GetGlobal,
            8 => Self::SetGlobal,
            9 => Self::GetUpval,
            10 => Self::Setupval,
            11 => Self::CloseUpvals,
            12 => Self::GetImport,
            13 => Self::GetTable,
            14 => Self::SetTable,
            15 => Self::GetTableKs,
            16 => Self::SetTableKs,
            17 => Self::GetTableN,
            18 => Self::SetTableN,
            19 => Self::NewClosure,
            20 => Self::NameCall,
            21 => Self::Call,
            22 => Self::Return,
            23 => Self::Jump,
            24 => Self::JumpBack,
            25 => Self::JumpIf,
            26 => Self::JumpIfNot,
            27 => Self::JumpIfEq,
            28 => Self::JumpIfLe,
            29 => Self::JumpIfLt,
            30 => Self::JumpIfNeq,
            31 => Self::JumpIfNotLe,
            32 => Self::JumpIfNotLt,
            33 => Self::Add,
            34 => Self::Sub,
            35 => Self::Mul,
            36 => Self::Div,
            37 => Self::Mod,
            38 => Self::Pow,
            39 => Self::AddK,
            40 => Self::SubK,
            41 => Self::MulK,
            42 => Self::DivK,
            43 => Self::ModK,
            44 => Self::PowK,
            45 => Self::And,
            46 => Self::Or,
            47 => Self::AndK,
            48 => Self::OrK,
            49 => Self::Concat,
            50 => Self::Not,
            51 => Self::Minus,
            52 => Self::Length,
            53 => Self::NewTable,
            54 => Self::DupTable,
            55 => Self::SetList,
            56 => Self::ForNPrep,
            57 => Self::ForNLoop,
            58 => Self::ForGLoop,
            59 => Self::ForGPrepInext,
            60 => Self::FastCall3,
            61 => Self::ForGPrepNext,
            62 => Self::NativeCall,
            63 => Self::GetVarargs,
            64 => Self::DupClosure,
            65 => Self::PrepVarargs,
            66 => Self::LoadKx,
            67 => Self::JumpX,
            68 => Self::FastCall,
            69 => Self::Coverage,
            70 => Self::Capture,
            71 => Self::SubRk,
            72 => Self::DivRk,
            73 => Self::FastCall1,
            74 => Self::FastCall2,
            75 => Self::FastCall2K,
            76 => Self::ForGPrep,
            77 => Self::JumpXEqNil,
            78 => Self::JumpXEqKb,
            79 => Self::JumpXEqKn,
            80 => Self::JumpXEqKs,
            81 => Self::Idiv,
            82 => Self::IdivK,
            83 => Self::GetUdataKs,
            84 => Self::SetUdataKs,
            85 => Self::NameCallUdata,
            86 => Self::NewClassMember,
            87 => Self::CallFb,
            other => Self::Unknown(other),
        }
    }

    pub fn name(self) -> &'static str {
        meta_for_index(self.index())
            .map(|m| m.name)
            .unwrap_or("UNKNOWN")
    }

    pub fn word_len(self) -> usize {
        if self.has_aux() { 2 } else { 1 }
    }

    pub fn has_aux(self) -> bool {
        meta_for_index(self.index())
            .map(|m| m.has_aux)
            .unwrap_or(false)
    }

    pub fn is_branch(self) -> bool {
        if meta_for_index(self.index()).is_some_and(|m| m.is_branch) {
            return true;
        }
        matches!(self, Self::LoadB)
    }

    pub fn is_jump_x_eq(self) -> bool {
        matches!(
            self,
            Self::JumpXEqNil | Self::JumpXEqKb | Self::JumpXEqKn | Self::JumpXEqKs
        )
    }

    pub fn is_jump_d(self) -> bool {
        matches!(
            self,
            Self::Jump
                | Self::JumpIf
                | Self::JumpIfNot
                | Self::JumpIfEq
                | Self::JumpIfLe
                | Self::JumpIfLt
                | Self::JumpIfNeq
                | Self::JumpIfNotLe
                | Self::JumpIfNotLt
                | Self::ForNPrep
                | Self::ForNLoop
                | Self::ForGLoop
                | Self::ForGPrep
                | Self::ForGPrepInext
                | Self::ForGPrepNext
                | Self::JumpBack
                | Self::JumpXEqNil
                | Self::JumpXEqKb
                | Self::JumpXEqKn
                | Self::JumpXEqKs
        )
    }

    pub fn terminates_block(self) -> bool {
        meta_for_index(self.index())
            .is_some_and(|m| m.terminates)
    }
}

/// Score how well `format` decodes a raw instruction word stream (higher = better).
pub fn score_instruction_words(raw_words: &[u32], format: WireFormat) -> i32 {
    if format == WireFormat::Auto {
        return i32::MIN;
    }
    let mut idx = 0usize;
    let mut score = 0i32;
    while idx < raw_words.len() {
        let raw = raw_words[idx];
        let op = Opcode::from_wire_byte((raw & 0xff) as u8, format);
        score += match op {
            Opcode::Unknown(_) => -12,
            _ if (op.index() as usize) < OP_META.len() => 3,
            _ => -4,
        };
        if op.has_aux() {
            idx += 1;
            if idx >= raw_words.len() {
                return i32::MIN / 4;
            }
        }
        idx += 1;
    }
    let consumed: usize = {
        let mut i = 0usize;
        let mut words = 0usize;
        while i < raw_words.len() {
            let op = Opcode::from_wire_byte((raw_words[i] & 0xff) as u8, format);
            words += op.word_len();
            i += op.word_len();
        }
        words
    };
    if consumed != raw_words.len() {
        score -= 500;
    }
    score
}

pub fn detect_wire_format(all_proto_words: &[&[u32]]) -> WireFormat {
    let mut best = WireFormat::Roblox227;
    let mut best_score = i32::MIN;
    for format in [WireFormat::Roblox227, WireFormat::Plain] {
        let score: i32 = all_proto_words
            .iter()
            .map(|words| score_instruction_words(words, format))
            .sum();
        if score > best_score {
            best_score = score;
            best = format;
        }
    }
    best
}

pub fn insn_a(raw: u32) -> u8 {
    ((raw >> 8) & 0xff) as u8
}

pub fn insn_b(raw: u32) -> u8 {
    ((raw >> 16) & 0xff) as u8
}

pub fn insn_c(raw: u32) -> u8 {
    ((raw >> 24) & 0xff) as u8
}

pub fn insn_d(raw: u32) -> i32 {
    (raw as i32) >> 16
}

pub fn insn_e(raw: u32) -> i32 {
    (raw as i32) >> 8
}

pub fn jump_target(pc: usize, raw: u32, op: Opcode) -> Option<usize> {
    if op.is_jump_d() {
        let d = insn_d(raw);
        Some((pc as i32 + d + 1) as usize)
    } else if matches!(op, Opcode::JumpX) {
        let e = insn_e(raw);
        Some((pc as i32 + e + 1) as usize)
    } else if matches!(op, Opcode::LoadB) {
        let c = insn_c(raw);
        if c != 0 {
            Some(pc + c as usize + 1)
        } else {
            None
        }
    } else {
        None
    }
}

pub fn aux_kv(aux: u32) -> u16 {
    (aux & 0xffffff) as u16
}

pub fn aux_not(aux: u32) -> bool {
    (aux >> 31) != 0
}

pub fn aux_kb(aux: u32) -> bool {
    (aux & 1) != 0
}
