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
    Unknown(u8),
}

impl Opcode {
    pub fn from_u8(v: u8) -> Self {
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
            other => Self::Unknown(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Nop => "NOP",
            Self::Break => "BREAK",
            Self::LoadNil => "LOADNIL",
            Self::LoadB => "LOADB",
            Self::LoadN => "LOADN",
            Self::LoadK => "LOADK",
            Self::Move => "MOVE",
            Self::GetGlobal => "GETGLOBAL",
            Self::SetGlobal => "SETGLOBAL",
            Self::GetUpval => "GETUPVAL",
            Self::Setupval => "SETUPVAL",
            Self::CloseUpvals => "CLOSEUPVALS",
            Self::GetImport => "GETIMPORT",
            Self::GetTable => "GETTABLE",
            Self::SetTable => "SETTABLE",
            Self::GetTableKs => "GETTABLEKS",
            Self::SetTableKs => "SETTABLEKS",
            Self::GetTableN => "GETTABLEN",
            Self::SetTableN => "SETTABLEN",
            Self::NewClosure => "NEWCLOSURE",
            Self::NameCall => "NAMECALL",
            Self::Call => "CALL",
            Self::Return => "RETURN",
            Self::Jump => "JUMP",
            Self::JumpBack => "JUMPBACK",
            Self::JumpIf => "JUMPIF",
            Self::JumpIfNot => "JUMPIFNOT",
            Self::JumpIfEq => "JUMPIFEQ",
            Self::JumpIfLe => "JUMPIFLE",
            Self::JumpIfLt => "JUMPIFLT",
            Self::JumpIfNeq => "JUMPIFNOTEQ",
            Self::JumpIfNotLe => "JUMPIFNOTLE",
            Self::JumpIfNotLt => "JUMPIFNOTLT",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Div => "DIV",
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::AddK => "ADDK",
            Self::SubK => "SUBK",
            Self::MulK => "MULK",
            Self::DivK => "DIVK",
            Self::ModK => "MODK",
            Self::PowK => "POWK",
            Self::And => "AND",
            Self::Or => "OR",
            Self::AndK => "ANDK",
            Self::OrK => "ORK",
            Self::Concat => "CONCAT",
            Self::Not => "NOT",
            Self::Minus => "MINUS",
            Self::Length => "LENGTH",
            Self::NewTable => "NEWTABLE",
            Self::DupTable => "DUPTABLE",
            Self::SetList => "SETLIST",
            Self::ForNPrep => "FORNPREP",
            Self::ForNLoop => "FORNLOOP",
            Self::ForGLoop => "FORGLOOP",
            Self::ForGPrepInext => "FORGPREP_INEXT",
            Self::FastCall3 => "FASTCALL3",
            Self::ForGPrepNext => "FORGPREP_NEXT",
            Self::NativeCall => "NATIVECALL",
            Self::GetVarargs => "GETVARARGS",
            Self::DupClosure => "DUPCLOSURE",
            Self::PrepVarargs => "PREPVARARGS",
            Self::LoadKx => "LOADKX",
            Self::JumpX => "JUMPX",
            Self::FastCall => "FASTCALL",
            Self::Coverage => "COVERAGE",
            Self::Capture => "CAPTURE",
            Self::SubRk => "SUBRK",
            Self::DivRk => "DIVRK",
            Self::FastCall1 => "FASTCALL1",
            Self::FastCall2 => "FASTCALL2",
            Self::FastCall2K => "FASTCALL2K",
            Self::ForGPrep => "FORGPREP",
            Self::JumpXEqNil => "JUMPXEQKNIL",
            Self::JumpXEqKb => "JUMPXEQKB",
            Self::JumpXEqKn => "JUMPXEQKN",
            Self::JumpXEqKs => "JUMPXEQKS",
            Self::Idiv => "IDIV",
            Self::IdivK => "IDIVK",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    pub fn word_len(self) -> usize {
        if self.has_aux() { 2 } else { 1 }
    }

    pub fn has_aux(self) -> bool {
        matches!(
            self,
            Self::GetGlobal
                | Self::SetGlobal
                | Self::GetImport
                | Self::GetTableKs
                | Self::SetTableKs
                | Self::NameCall
                | Self::JumpIfEq
                | Self::JumpIfLe
                | Self::JumpIfLt
                | Self::JumpIfNeq
                | Self::JumpIfNotLe
                | Self::JumpIfNotLt
                | Self::NewTable
                | Self::SetList
                | Self::ForGLoop
                | Self::LoadKx
                | Self::FastCall2
                | Self::FastCall2K
                | Self::FastCall3
                | Self::JumpXEqNil
                | Self::JumpXEqKb
                | Self::JumpXEqKn
                | Self::JumpXEqKs
        )
    }

    pub fn is_branch(self) -> bool {
        matches!(
            self,
            Self::Jump
                | Self::JumpBack
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
                | Self::JumpX
                | Self::JumpXEqNil
                | Self::JumpXEqKb
                | Self::JumpXEqKn
                | Self::JumpXEqKs
                | Self::LoadB
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
        matches!(self, Self::Return | Self::Jump | Self::JumpBack | Self::JumpX)
    }
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
