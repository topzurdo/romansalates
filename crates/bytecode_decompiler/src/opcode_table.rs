//! Fiu-style opcode metadata (Luau VM / Roblox Luau).
//! Single source for AUX sizing, bytecode version gates, and control-flow hints.

/// Instruction operand layout (Fiu `OP_MODE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InsnMode {
    None = 0,
    A = 1,
    Ab = 2,
    Abc = 3,
    Ad = 4,
    Ae = 5,
}

#[derive(Clone, Copy, Debug)]
pub struct OpcodeMeta {
    pub name: &'static str,
    pub mode: InsnMode,
    pub has_aux: bool,
    /// Minimum `Chunk::version` that may legally emit this opcode (Luau LBC version).
    pub min_version: u8,
    pub is_branch: bool,
    pub terminates: bool,
}

/// Luau opcodes 0..=87 (`LOP__COUNT` = 88). Order matches `LuauOpcode` / Fiu `opList`.
pub const OP_META: [OpcodeMeta; 88] = [
    meta("NOP", InsnMode::None, false, 1, false, false),
    meta("BREAK", InsnMode::None, false, 1, false, false),
    meta("LOADNIL", InsnMode::A, false, 1, false, false),
    meta("LOADB", InsnMode::Abc, false, 1, true, true),
    meta("LOADN", InsnMode::Ad, false, 1, false, false),
    meta("LOADK", InsnMode::Ad, false, 1, false, false),
    meta("MOVE", InsnMode::Ab, false, 1, false, false),
    meta("GETGLOBAL", InsnMode::A, true, 1, false, false),
    meta("SETGLOBAL", InsnMode::A, true, 1, false, false),
    meta("GETUPVAL", InsnMode::Ab, false, 1, false, false),
    meta("SETUPVAL", InsnMode::Ab, false, 1, false, false),
    meta("CLOSEUPVALS", InsnMode::A, false, 1, false, false),
    meta("GETIMPORT", InsnMode::Ad, true, 1, false, false),
    meta("GETTABLE", InsnMode::Abc, false, 1, false, false),
    meta("SETTABLE", InsnMode::Abc, false, 1, false, false),
    meta("GETTABLEKS", InsnMode::Abc, true, 1, false, false),
    meta("SETTABLEKS", InsnMode::Abc, true, 1, false, false),
    meta("GETTABLEN", InsnMode::Abc, false, 1, false, false),
    meta("SETTABLEN", InsnMode::Abc, false, 1, false, false),
    meta("NEWCLOSURE", InsnMode::Ad, false, 1, false, false),
    meta("NAMECALL", InsnMode::Abc, true, 1, false, false),
    meta("CALL", InsnMode::Abc, false, 1, false, false),
    meta("RETURN", InsnMode::Ab, false, 1, false, true),
    meta("JUMP", InsnMode::Ad, false, 1, true, true),
    meta("JUMPBACK", InsnMode::Ad, false, 1, true, true),
    meta("JUMPIF", InsnMode::Ad, false, 1, true, true),
    meta("JUMPIFNOT", InsnMode::Ad, false, 1, true, true),
    meta("JUMPIFEQ", InsnMode::Ad, true, 1, true, true),
    meta("JUMPIFLE", InsnMode::Ad, true, 1, true, true),
    meta("JUMPIFLT", InsnMode::Ad, true, 1, true, true),
    meta("JUMPIFNOTEQ", InsnMode::Ad, true, 1, true, true),
    meta("JUMPIFNOTLE", InsnMode::Ad, true, 1, true, true),
    meta("JUMPIFNOTLT", InsnMode::Ad, true, 1, true, true),
    meta("ADD", InsnMode::Abc, false, 1, false, false),
    meta("SUB", InsnMode::Abc, false, 1, false, false),
    meta("MUL", InsnMode::Abc, false, 1, false, false),
    meta("DIV", InsnMode::Abc, false, 1, false, false),
    meta("MOD", InsnMode::Abc, false, 1, false, false),
    meta("POW", InsnMode::Abc, false, 1, false, false),
    meta("ADDK", InsnMode::Abc, false, 1, false, false),
    meta("SUBK", InsnMode::Abc, false, 1, false, false),
    meta("MULK", InsnMode::Abc, false, 1, false, false),
    meta("DIVK", InsnMode::Abc, false, 1, false, false),
    meta("MODK", InsnMode::Abc, false, 1, false, false),
    meta("POWK", InsnMode::Abc, false, 1, false, false),
    meta("AND", InsnMode::Abc, false, 1, false, false),
    meta("OR", InsnMode::Abc, false, 1, false, false),
    meta("ANDK", InsnMode::Abc, false, 1, false, false),
    meta("ORK", InsnMode::Abc, false, 1, false, false),
    meta("CONCAT", InsnMode::Abc, false, 1, false, false),
    meta("NOT", InsnMode::Ab, false, 1, false, false),
    meta("MINUS", InsnMode::Ab, false, 1, false, false),
    meta("LENGTH", InsnMode::Ab, false, 1, false, false),
    meta("NEWTABLE", InsnMode::Ab, true, 1, false, false),
    meta("DUPTABLE", InsnMode::Ad, false, 1, false, false),
    meta("SETLIST", InsnMode::Abc, true, 1, false, false),
    meta("FORNPREP", InsnMode::Ad, false, 1, true, true),
    meta("FORNLOOP", InsnMode::Ad, false, 1, true, true),
    meta("FORGLOOP", InsnMode::Ad, true, 3, true, true),
    meta("FORGPREP_INEXT", InsnMode::Ad, false, 3, true, true),
    meta("FASTCALL3", InsnMode::Abc, true, 6, false, false),
    meta("FORGPREP_NEXT", InsnMode::Ad, false, 3, true, true),
    meta("NATIVECALL", InsnMode::None, false, 3, false, false),
    meta("GETVARARGS", InsnMode::Ab, false, 1, false, false),
    meta("DUPCLOSURE", InsnMode::Ad, false, 1, false, false),
    meta("PREPVARARGS", InsnMode::A, false, 1, false, false),
    meta("LOADKX", InsnMode::A, true, 1, false, false),
    meta("JUMPX", InsnMode::Ae, false, 3, true, true),
    meta("FASTCALL", InsnMode::Abc, false, 1, false, false),
    meta("COVERAGE", InsnMode::Ae, false, 1, false, false),
    meta("CAPTURE", InsnMode::Ab, false, 1, false, false),
    meta("SUBRK", InsnMode::Abc, false, 5, false, false),
    meta("DIVRK", InsnMode::Abc, false, 5, false, false),
    meta("FASTCALL1", InsnMode::Abc, false, 1, false, false),
    meta("FASTCALL2", InsnMode::Abc, true, 1, false, false),
    meta("FASTCALL2K", InsnMode::Abc, true, 1, false, false),
    meta("FORGPREP", InsnMode::Ad, false, 3, true, true),
    meta("JUMPXEQKNIL", InsnMode::Ad, true, 3, true, true),
    meta("JUMPXEQKB", InsnMode::Ad, true, 3, true, true),
    meta("JUMPXEQKN", InsnMode::Ad, true, 3, true, true),
    meta("JUMPXEQKS", InsnMode::Ad, true, 3, true, true),
    meta("IDIV", InsnMode::Abc, false, 4, false, false),
    meta("IDIVK", InsnMode::Abc, false, 4, false, false),
    meta("GETUDATAKS", InsnMode::Abc, true, 9, false, false),
    meta("SETUDATAKS", InsnMode::Abc, true, 9, false, false),
    meta("NAMECALLUDATA", InsnMode::Abc, true, 9, false, false),
    meta("NEWCLASSMEMBER", InsnMode::Abc, true, 10, false, false),
    meta("CALLFB", InsnMode::Abc, true, 11, false, false),
];

const fn meta(
    name: &'static str,
    mode: InsnMode,
    has_aux: bool,
    min_version: u8,
    is_branch: bool,
    terminates: bool,
) -> OpcodeMeta {
    OpcodeMeta {
        name,
        mode,
        has_aux,
        min_version,
        is_branch,
        terminates,
    }
}

pub fn meta_for_index(index: u8) -> Option<&'static OpcodeMeta> {
    OP_META.get(index as usize)
}
