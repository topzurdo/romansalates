//! Synthetic Roblox v9 bytecode samples for parse/validate regression.

mod builder {
    pub fn write_varint(out: &mut Vec<u8>, mut v: u32) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }

    pub fn insn(op: u8, a: u8, b: u8, c: u8) -> u32 {
        let op = bytecode_decompiler::opcode::Opcode::encode_u8(op);
        u32::from(op) | (u32::from(a) << 8) | (u32::from(b) << 16) | (u32::from(c) << 24)
    }

    pub fn minimal_chunk(words: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(9); // Roblox v9
        out.push(0); // types_version
        write_varint(&mut out, 1);
        write_varint(&mut out, 0); // empty debug name string
        out.push(0); // end userdata type map

        write_varint(&mut out, 1); // one proto
        out.extend_from_slice(&encode_proto(words));

        write_varint(&mut out, 0); // main = proto 0
        out
    }

    fn encode_proto(words: &[u32]) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(8); // max_stack
        p.push(0); // num_params
        p.push(0); // num_upvalues
        p.push(0); // is_vararg
        p.push(0); // flags
        write_varint(&mut p, 0); // typeinfo size
        write_varint(&mut p, words.len() as u32);
        for &w in words {
            p.extend_from_slice(&w.to_le_bytes());
        }
        write_varint(&mut p, 0); // constants
        write_varint(&mut p, 0); // children
        write_varint(&mut p, 0); // line_defined
        write_varint(&mut p, 0); // debug_name -> strings[0]
        p.push(0); // no line info
        p.push(0); // no debug
        p
    }
}

use bytecode_decompiler::bytecode::BytecodeOptions;
use bytecode_decompiler::opcode::{Opcode, WireFormat};
use bytecode_decompiler::{validate_chunk, BytecodeReader};

#[test]
fn auto_wire_detects_roblox_on_v9_blob() {
    let words = [
        builder::insn(87, 0, 2, 1),
        42,
        builder::insn(22, 0, 1, 0),
    ];
    let bytes = builder::minimal_chunk(&words);
    let chunk = BytecodeReader::read_with_options(
        &bytes,
        BytecodeOptions {
            wire: WireFormat::Auto,
            lenient: true,
        },
    )
    .expect("parse with auto wire");
    assert_eq!(chunk.wire_format, WireFormat::Roblox227);
}

#[test]
fn v9_minimal_callfb_parses_and_validates() {
    let words = [
        builder::insn(87, 0, 2, 1),
        42,
        builder::insn(22, 0, 1, 0),
    ];
    let bytes = builder::minimal_chunk(&words);
    let chunk = BytecodeReader::read(&bytes).expect("parse minimal v9 chunk");
    assert_eq!(chunk.version, 9);
    validate_chunk(&chunk).expect("validate");
    let proto = &chunk.protos[0];
    assert_eq!(proto.instructions.len(), 2);
    assert!(proto
        .instructions
        .iter()
        .all(|i| !matches!(i.opcode, Opcode::Unknown(_))));
}

#[test]
fn v9_return_only_decompiles_without_panic() {
    let words = [
        builder::insn(2, 0, 0, 0), // LOADNIL A
        builder::insn(22, 0, 2, 0), // RETURN
    ];
    let bytes = builder::minimal_chunk(&words);
    let chunk = BytecodeReader::read(&bytes).unwrap();
    validate_chunk(&chunk).unwrap();
    let lua = bytecode_decompiler::Decompiler::decompile_chunk(&chunk);
    assert!(lua.contains("return"));
}
