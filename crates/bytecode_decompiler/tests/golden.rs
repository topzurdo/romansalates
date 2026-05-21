//! Decompiler golden / pattern tests on synthetic Roblox-shaped bytecode.

mod builder {
    use bytecode_decompiler::opcode::Opcode;

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
        let op = Opcode::encode_u8(op);
        u32::from(op) | (u32::from(a) << 8) | (u32::from(b) << 16) | (u32::from(c) << 24)
    }

    pub fn insn_d(op: u8, a: u8, d: i16) -> u32 {
        let op = Opcode::encode_u8(op);
        u32::from(op) | (u32::from(a) << 8) | ((d as u32) << 16)
    }

    pub fn aux_reg(reg: u8) -> u32 {
        u32::from(reg) << 8
    }

    pub struct ProtoSpec {
        pub words: Vec<u32>,
        pub constants: Vec<Vec<u8>>,
        pub child_indices: Vec<u32>,
        pub debug_locals: Vec<(u8, u32, u32, u32)>, // reg, name_idx, start, end
        pub debug_name_idx: u32,
        pub is_vararg: bool,
    }

    impl ProtoSpec {
        pub fn simple(words: &[u32]) -> Self {
            Self {
                words: words.to_vec(),
                constants: Vec::new(),
                child_indices: Vec::new(),
                debug_locals: Vec::new(),
                debug_name_idx: 0,
                is_vararg: false,
            }
        }
    }

    fn encode_proto(spec: &ProtoSpec) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(8); // max_stack
        p.push(0); // num_params
        p.push(0); // num_upvalues
        p.push(u8::from(spec.is_vararg));
        p.push(0); // flags
        write_varint(&mut p, 0); // typeinfo size
        write_varint(&mut p, spec.words.len() as u32);
        for &w in &spec.words {
            p.extend_from_slice(&w.to_le_bytes());
        }
        write_varint(&mut p, spec.constants.len() as u32);
        for c in &spec.constants {
            p.extend_from_slice(c);
        }
        write_varint(&mut p, spec.child_indices.len() as u32);
        for &child in &spec.child_indices {
            write_varint(&mut p, child);
        }
        write_varint(&mut p, 0); // line_defined
        write_varint(&mut p, spec.debug_name_idx); // debug_name (1-based string table)
        p.push(0); // no line info
        if spec.debug_locals.is_empty() {
            p.push(0); // no debug
        } else {
            p.push(1);
            write_varint(&mut p, spec.debug_locals.len() as u32);
            for (reg, name_idx, start, end) in &spec.debug_locals {
                write_varint(&mut p, *name_idx);
                write_varint(&mut p, *start);
                write_varint(&mut p, *end);
                p.push(*reg);
            }
            write_varint(&mut p, 0); // upval debug names
        }
        p
    }

    pub fn chunk(protos: &[ProtoSpec], main: u32) -> Vec<u8> {
        chunk_with_strings(protos, main, &["", "result"])
    }

    pub fn chunk_with_strings(protos: &[ProtoSpec], main: u32, strings: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(9); // Roblox v9
        out.push(0); // types_version
        write_varint(&mut out, strings.len() as u32);
        for s in strings {
            write_varint(&mut out, s.len() as u32);
            out.extend_from_slice(s.as_bytes());
        }
        out.push(0); // end userdata type map

        write_varint(&mut out, protos.len() as u32);
        for spec in protos {
            out.extend_from_slice(&encode_proto(spec));
        }
        write_varint(&mut out, main);
        out
    }

    /// TAG_STRING constant pointing at string table index (1-based).
    pub fn string_constant(string_table_index: u32) -> Vec<u8> {
        let mut c = vec![3u8];
        write_varint(&mut c, string_table_index);
        c
    }

    /// TAG_TABLE constant: each entry is a 1-based string table index (DupTable template keys).
    pub fn table_constant(string_table_indices: &[u32]) -> Vec<u8> {
        let mut c = vec![5u8];
        write_varint(&mut c, string_table_indices.len() as u32);
        for &idx in string_table_indices {
            write_varint(&mut c, idx);
        }
        c
    }
}

use bytecode_decompiler::bytecode::BytecodeOptions;
use bytecode_decompiler::opcode::WireFormat;
use bytecode_decompiler::BytecodeReader;
use bytecode_decompiler::Decompiler;

fn decompile_bytes(bytes: &[u8]) -> String {
    let chunk = BytecodeReader::read_with_options(
        bytes,
        BytecodeOptions {
            wire: WireFormat::Auto,
            lenient: true,
        },
    )
    .expect("parse synthetic chunk");
    Decompiler::decompile_chunk(&chunk)
}

fn count_matches(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

fn count_empty_if_blocks(lua: &str) -> usize {
    let lines: Vec<&str> = lua.lines().collect();
    let mut count = 0usize;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !(trimmed.starts_with("if ") && trimmed.ends_with(" then")) {
            continue;
        }
        let next = lines
            .get(i + 1)
            .map(|l| l.trim())
            .unwrap_or("end");
        if next == "else" || next == "elseif" || next == "end" {
            count += 1;
        }
    }
    count
}

fn assert_corpus_common(name: &str, lua: &str) {
    assert!(
        lua.contains("function"),
        "{name} should decompile to pseudo-Lua, got:\n{}",
        &lua[..lua.len().min(500)]
    );
    assert!(
        !lua.contains("k27 = nil"),
        "{name} should resolve DupTable keys, got:\n{}",
        &lua[..lua.len().min(500)]
    );
    assert!(
        !lua.contains("-- goto pc"),
        "{name} should not emit goto comments, got:\n{}",
        &lua[..lua.len().min(500)]
    );
    assert!(
        !lua.contains("upval_"),
        "{name} should not emit raw upval_N names, got:\n{}",
        &lua[..lua.len().min(800)]
    );
    assert!(
        !lua.contains("-- captures:"),
        "{name} should not emit capture stubs, got:\n{}",
        &lua[..lua.len().min(800)]
    );
}

#[test]
fn jump_if_eq_emits_comparison_if() {
    let words = [
        builder::insn_d(4, 0, 1),
        builder::insn_d(4, 1, 1),
        builder::insn_d(27, 0, 1),
        builder::aux_reg(1),
        builder::insn_d(4, 0, 0),
        builder::insn(22, 0, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("if 1 == 1 then"),
        "expected comparison if, got:\n{lua}"
    );
}

#[test]
fn for_n_prep_emits_numeric_for_loop() {
    let words = [
        builder::insn_d(4, 0, 0),
        builder::insn_d(4, 1, 10),
        builder::insn_d(4, 2, 1),
        builder::insn_d(4, 3, 0),
        builder::insn_d(56, 0, 2),
        builder::insn(22, 0, 1, 0),
        builder::insn(22, 0, 1, 0),
        builder::insn_d(57, 0, -3),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("for r3 = "),
        "expected numeric for loop, got:\n{lua}"
    );
}

#[test]
fn fastcall_skips_fallback_bytecode() {
    let words = [
        builder::insn(2, 1, 0, 0),
        builder::insn(73, 44, 1, 3),
        builder::insn(12, 0, 0, 0),
        0u32,
        builder::insn(6, 0, 1, 0),
        builder::insn(6, 1, 0, 0),
        builder::insn(21, 1, 2, 2),
        builder::insn(22, 1, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(lua.contains("typeof"), "expected typeof fastcall, got:\n{lua}");
    assert!(
        !lua.contains("import_0"),
        "fallback import should be skipped, got:\n{lua}"
    );
}

fn min_line_indent_after(haystack: &str, needle: &str) -> Option<usize> {
    let mut after = false;
    for line in haystack.lines() {
        if after {
            if line.trim().is_empty() {
                continue;
            }
            return Some(line.find(|c: char| !c.is_whitespace()).unwrap_or(0));
        }
        if line.contains(needle) {
            after = true;
        }
    }
    None
}

#[test]
fn nested_closure_indents() {
    let child = builder::ProtoSpec {
        words: vec![
            builder::insn_d(25, 0, 3),
            builder::insn(22, 0, 1, 0),
            builder::insn_d(4, 0, 1),
            builder::insn(22, 0, 1, 0),
        ],
        constants: Vec::new(),
        child_indices: Vec::new(),
        debug_locals: Vec::new(),
        debug_name_idx: 3,
        is_vararg: false,
    };
    let parent = builder::ProtoSpec {
        words: vec![
            builder::insn(19, 0, 0, 0),
            builder::insn(22, 0, 2, 0),
        ],
        constants: Vec::new(),
        child_indices: vec![1],
        debug_locals: Vec::new(),
        debug_name_idx: 0,
        is_vararg: false,
    };
    let bytes = builder::chunk_with_strings(&[parent, child], 0, &["", "result", "WaitForModule"]);
    let lua = decompile_bytes(&bytes);
    let inner_indent = min_line_indent_after(&lua, "local WaitForModule = function")
        .unwrap_or(0);
    assert!(
        inner_indent >= 8,
        "nested closure body should be indented >= 8 spaces, got {inner_indent} in:\n{lua}"
    );
}

fn assert_duplicate_operands_spilled(bytes: &[u8]) {
    let lua = decompile_bytes(bytes);
    assert!(
        !lua.contains("r0 - r0") || lua.contains("local r0"),
        "duplicate call operands (e.g. os.clock() - os.clock()) should spill, got:\n{lua}"
    );
}

#[test]
fn clock_delta_not_zero() {
    let words = [
        builder::insn_d(4, 0, 0),
        builder::insn_d(4, 1, 0),
        builder::insn(6, 2, 0, 1),
        builder::insn(26, 3, 2, 1),
        builder::insn(22, 3, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    assert_duplicate_operands_spilled(&bytes);
}

#[test]
fn sub_spills_duplicate_rendered_operands() {
    let words = [
        builder::insn_d(4, 0, 0),
        builder::insn_d(4, 1, 0),
        builder::insn(6, 2, 0, 1),
        builder::insn(26, 3, 2, 1),
        builder::insn(22, 3, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    assert_duplicate_operands_spilled(&bytes);
}

#[test]
fn named_closure_hoisted_from_debug_name() {
    let child = builder::ProtoSpec {
        words: vec![
            builder::insn(2, 0, 0, 0),
            builder::insn(22, 0, 2, 0),
        ],
        constants: Vec::new(),
        child_indices: Vec::new(),
        debug_locals: Vec::new(),
        debug_name_idx: 3,
        is_vararg: false,
    };
    let parent = builder::ProtoSpec {
        words: vec![
            builder::insn(19, 0, 0, 0),
            builder::insn(22, 0, 2, 0),
        ],
        constants: Vec::new(),
        child_indices: vec![1],
        debug_locals: Vec::new(),
        debug_name_idx: 0,
        is_vararg: false,
    };
    let bytes = builder::chunk_with_strings(&[parent, child], 0, &["", "result", "UpdateInventory"]);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("local UpdateInventory = function"),
        "expected hoisted named closure, got:\n{lua}"
    );
}

#[test]
fn newclosure_uses_child_indices() {
    let child = builder::ProtoSpec::simple(&[
        builder::insn(2, 0, 0, 0),
        builder::insn(22, 0, 2, 0),
    ]);
    let parent = builder::ProtoSpec {
        words: vec![
            builder::insn(19, 0, 0, 0),
            builder::insn(22, 0, 2, 0),
        ],
        constants: Vec::new(),
        child_indices: vec![1],
        debug_locals: Vec::new(),
        debug_name_idx: 0,
        is_vararg: false,
    };
    let bytes = builder::chunk(&[parent, child], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("function()") && !lua.contains("missing proto"),
        "expected inline child closure, got:\n{lua}"
    );
}

#[test]
fn debug_local_emits_local_declaration_on_call() {
    let mut spec = builder::ProtoSpec::simple(&[
        builder::insn(2, 1, 0, 0),
        builder::insn(6, 0, 1, 0),
        builder::insn(22, 0, 2, 0),
    ]);
    spec.debug_locals.push((0, 2, 0, 10));
    let bytes = builder::chunk(&[spec], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("local result = "),
        "expected local declaration from debug info, got:\n{lua}"
    );
}

#[test]
fn capture_insn_is_silent_in_output() {
    let words = [
        builder::insn(2, 0, 0, 0),
        builder::insn(70, 0, 0, 0),
        builder::insn(22, 0, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        !lua.contains("-- capture"),
        "capture ops should be absorbed, not emitted as comments, got:\n{lua}"
    );
}

#[test]
fn namecall_call_emits_colon_syntax() {
    let spec = builder::ProtoSpec {
        words: vec![
            builder::insn(2, 1, 0, 0),
            builder::insn(2, 2, 0, 0),
            builder::insn(20, 0, 1, 0),
            0u32,
            builder::insn(21, 0, 3, 2),
            builder::insn(22, 0, 2, 0),
        ],
        constants: vec![builder::string_constant(2)],
        child_indices: Vec::new(),
        debug_locals: Vec::new(),
        debug_name_idx: 0,
        is_vararg: false,
    };
    let bytes = builder::chunk_with_strings(&[spec], 0, &["", "WaitForChild"]);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains(":WaitForChild("),
        "expected method call syntax, got:\n{lua}"
    );
    assert!(
        !lua.contains(".WaitForChild("),
        "expected colon call, got:\n{lua}"
    );
}

#[test]
fn if_branch_register_snapshot_isolates_taken_and_fall() {
    let words = [
        builder::insn_d(4, 0, 1),
        builder::insn_d(4, 1, 10),
        builder::insn_d(25, 0, 2),
        builder::insn_d(4, 1, 20),
        builder::insn(22, 1, 2, 0),
        builder::insn(22, 1, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(lua.contains("return 10"), "taken branch should keep R1=10, got:\n{lua}");
    assert!(
        !lua.contains("if 1 then\n        return 20"),
        "fall-path assignment must not leak into taken branch, got:\n{lua}"
    );
}

#[test]
fn jump_past_end_does_not_panic() {
    let words = [
        builder::insn_d(4, 0, 1),
        builder::insn_d(25, 0, 100),
        builder::insn(22, 0, 1, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(lua.contains("function main"), "expected output, got:\n{lua}");
}

#[test]
fn while_loop_from_jumpifnot_jumpback() {
    let mut spec = builder::ProtoSpec::simple(&[
        builder::insn_d(4, 0, 1),
        builder::insn_d(26, 0, 2),
        builder::insn_d(4, 1, 42),
        builder::insn_d(24, 0, -3),
        builder::insn(22, 1, 2, 0),
    ]);
    spec.debug_locals.push((1, 2, 2, 5));
    let bytes = builder::chunk_with_strings(&[spec], 0, &["", "value"]);
    let lua = decompile_bytes(&bytes);
    assert!(lua.contains("while 1 do"), "expected while loop, got:\n{lua}");
    assert!(
        lua.contains("local value = 42"),
        "while body should emit debug local, got:\n{lua}"
    );
    assert!(
        !lua.contains("-- goto pc"),
        "JumpBack should not emit goto inside while, got:\n{lua}"
    );
}

#[test]
fn join_block_decompiles_if_else() {
    let words = [
        builder::insn_d(4, 0, 1),
        builder::insn_d(25, 0, 1),
        builder::insn_d(4, 1, 20),
        builder::insn_d(23, 0, 0),
        builder::insn_d(4, 1, 10),
        builder::insn(22, 1, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(lua.contains("return 10") || lua.contains("return 20"));
}

#[test]
fn vararg_wrapper_emits_ellipsis_return() {
    let words = [
        builder::insn(68, 1, 0, 0),
        builder::insn(67, 0, 0, 0),
        builder::insn(21, 0, 2, 0),
        builder::insn(22, 0, 0, 0),
    ];
    let mut spec = builder::ProtoSpec::simple(&words);
    spec.is_vararg = true;
    let bytes = builder::chunk(&[spec], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("return ..."),
        "expected vararg return ellipsis, got:\n{lua}"
    );
}

#[test]
fn corpus_fixtures_decompile_without_panic() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut found = 0usize;
    for entry in std::fs::read_dir(&dir).expect("read fixtures dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("corpus_") || !name.ends_with(".bin") {
            continue;
        }
        found += 1;
        let bytes = std::fs::read(&path).expect("read corpus fixture");
        assert!(bytes.len() >= 8, "{name} too small");
        let lua = decompile_bytes(&bytes);
        assert_corpus_common(name, &lua);

        match name {
            "corpus_queue_script.bin" => {
                assert!(
                    lua.contains("MultiboxFramework") || lua.contains(":WaitForChild(\"MultiboxFramework\")"),
                    "expected MultiboxFramework require path in queue script, got:\n{}",
                    &lua[..lua.len().min(800)]
                );
                assert!(
                    lua.contains("\"QueueLeaderChanged\"") || lua.contains("'QueueLeaderChanged'"),
                    "event name should be quoted, got:\n{}",
                    &lua[..lua.len().min(800)]
                );
                assert!(
                    !lua.contains("SetLiftCanCollide = SetLiftCanCollide"),
                    "self-assignment should be stripped, got:\n{}",
                    &lua[..lua.len().min(800)]
                );
                assert!(
                    lua.contains("SetLiftCanCollide") && !lua.contains("Connect(\"SetLiftCanCollide\")"),
                    "SetLiftCanCollide should connect by reference, got:\n{}",
                    &lua[..lua.len().min(800)]
                );
                assert!(
                    lua.contains("MapName") || lua.contains("string.format") || lua.contains("Voter"),
                    "queue handler should include UI update path, got:\n{}",
                    &lua[..lua.len().min(2000)]
                );
                assert!(
                    !lua.contains("return\n    r4 = arg1.queueId"),
                    "UI update should not appear as dead code after bare return, got:\n{}",
                    &lua[..lua.len().min(1500)]
                );
            }
            "corpus_troop_item.bin" => {
                assert!(
                    lua.contains("WaitForModule(\"TroopBuilder\")"),
                    "expected TroopBuilder module load, got:\n{}",
                    &lua[..lua.len().min(1200)]
                );
                assert!(
                    lua.contains("local TroopBuilder = ")
                        || (lua.contains(".new()") && lua.contains(".setTroopModel(")),
                    "expected hoisted or spilled TroopBuilder chain, got:\n{}",
                    &lua[..lua.len().min(1200)]
                );
                assert!(
                    !lua.contains("WaitForModule(\"TroopBuilder\").new().set"),
                    "builder methods should not repeat full inline chain, got:\n{}",
                    &lua[..lua.len().min(1200)]
                );
                assert!(
                    lua.contains("\"Exclusive\"") || lua.contains("'Exclusive'"),
                    "enum string constants should be quoted, got:\n{}",
                    &lua[..lua.len().min(1200)]
                );
                assert!(
                    lua.contains("\"Damage\"") || lua.contains("'Damage'"),
                    "stat name constants should be quoted in table, got:\n{}",
                    &lua[..lua.len().min(1200)]
                );
            }
            "corpus_clans_permissions.bin" => {
                assert!(
                    lua.contains("ChangeRank") && lua.contains("DisbandClan"),
                    "expected permission table keys, got:\n{}",
                    &lua[..lua.len().min(800)]
                );
            }
            "corpus_cmdr_argument.bin" => {
                assert!(
                    lua.len() > 100,
                    "cmdr argument module should produce non-trivial output, got:\n{lua}"
                );
            }
            "corpus_teleport_handler.bin" => {
                assert!(
                    lua.contains("require") || lua.contains("Teleport"),
                    "teleport handler should mention teleport/require, got:\n{}",
                    &lua[..lua.len().min(800)]
                );
            }
            "corpus_base_camera.bin" => {
                assert!(lua.len() > 200, "{name} should produce substantial output");
                assert!(
                    count_empty_if_blocks(&lua) <= 4,
                    "{name} has too many empty if blocks ({})",
                    count_empty_if_blocks(&lua)
                );
            }
            "corpus_camera_popper.bin" => {
                assert!(lua.contains("Popper") || lua.contains("Raycast"), "{name} missing camera terms");
                assert!(
                    count_matches(&lua, "for ") <= 4,
                    "{name} should not emit many empty for loops"
                );
                assert!(
                    lua.contains("if ") && (lua.contains("repeat") || lua.contains("while ")),
                    "{name} should emit structured control flow, got:\n{}",
                    &lua[..lua.len().min(800)]
                );
                assert!(
                    count_matches(&lua, "Connect(\"") <= 6,
                    "{name} should prefer Connect(handler) over Connect(\"handler\"), got {} quoted",
                    count_matches(&lua, "Connect(\"")
                );
                assert!(
                    count_matches(&lua, "nil:Connect") <= 4,
                    "{name} should resolve connect objects (got {} nil:Connect)",
                    count_matches(&lua, "nil:Connect")
                );
            }
            "corpus_classic_camera.bin" => {
                assert!(lua.len() > 30, "{name} too short");
            }
            "corpus_click_to_move.bin" => {
                assert!(lua.len() > 400, "{name} should be large module output");
                assert!(
                    count_empty_if_blocks(&lua) <= 4,
                    "{name} has too many empty if blocks ({})",
                    count_empty_if_blocks(&lua)
                );
            }
            "corpus_cmdr_util.bin" => {
                assert!(lua.len() > 150, "{name} too short");
            }
            "corpus_cmdr_window.bin" => {
                assert!(lua.len() > 80, "{name} too short");
            }
            "corpus_control_module.bin" => {
                assert!(lua.len() > 150, "{name} too short");
            }
            "corpus_rbx_character_sounds.bin" => {
                assert!(
                    lua.contains("Humanoid") || lua.contains("Sound") || lua.len() > 80,
                    "{name} expected character sound patterns"
                );
            }
            _ => {}
        }
    }
    assert!(
        found >= 13,
        "expected at least 13 corpus_*.bin fixtures, found {found}"
    );
}

fn assert_user_sample_quality(name: &str, lua: &str, markers: &[&str]) {
    assert_corpus_common(name, lua);
    assert!(
        count_empty_if_blocks(lua) <= 4,
        "{name} has too many empty if blocks ({})",
        count_empty_if_blocks(lua)
    );
    assert!(
        !lua.contains("os.clock() - os.clock()"),
        "{name} should not emit identical os.clock delta, got:\n{}",
        &lua[..lua.len().min(800)]
    );
    assert!(
        markers.iter().any(|m| lua.contains(m)),
        "{name} missing expected markers {markers:?}, got:\n{}",
        &lua[..lua.len().min(1200)]
    );
}

#[test]
fn user_framework_fixture_decompiles_when_present() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus_framework_loader.bin");
    if !path.exists() {
        return;
    }
    let bytes = std::fs::read(&path).expect("read framework loader fixture");
    let lua = decompile_bytes(&bytes);
    assert_user_sample_quality(
        "corpus_framework_loader.bin",
        &lua,
        &["WaitForModule", "LoadFramework", "coroutine.yield"],
    );
}

#[test]
fn user_post_office_fixture_decompiles_when_present() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus_post_office.bin");
    if !path.exists() {
        return;
    }
    let bytes = std::fs::read(&path).expect("read post office fixture");
    let lua = decompile_bytes(&bytes);
    assert_user_sample_quality(
        "corpus_post_office.bin",
        &lua,
        &["UpdateInventory", "inboxUpdated", "switchMenu"],
    );
}

#[test]
fn user_cmdr_client_fixture_decompiles_when_present() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus_cmdr_client.bin");
    if !path.exists() {
        return;
    }
    let bytes = std::fs::read(&path).expect("read cmdr client fixture");
    let lua = decompile_bytes(&bytes);
    assert_user_sample_quality(
        "corpus_cmdr_client.bin",
        &lua,
        &["SetActivationKeys", "Registry", "Dispatcher"],
    );
}

#[test]
fn postoffice_fixture_decompiles_when_present() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/postoffice.bin");
    if !path.exists() {
        return;
    }
    let bytes = std::fs::read(&path).expect("read postoffice fixture");
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("CanOpen") || lua.contains("PostOffice") || lua.contains("function main"),
        "expected PostOffice-like decompile output, got:\n{}",
        &lua[..lua.len().min(2000)]
    );
    assert!(
        !lua.contains("k27 = nil"),
        "DupTable keys should be resolved, got:\n{}",
        &lua[..lua.len().min(2000)]
    );
}

#[test]
fn real_module_loader_patterns() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/module_loader.bin");
    if !path.exists() {
        return;
    }
    let bytes = std::fs::read(&path).expect("read fixture");
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains(":WaitForChild(") || lua.contains("WaitForChild"),
        "expected Roblox namecall patterns, got:\n{lua}"
    );
}

#[test]
fn repeat_until_from_jumpif_jumpback() {
    let words = [
        builder::insn_d(4, 0, 42),
        builder::insn_d(4, 1, 0),
        builder::insn_d(25, 1, 1),
        builder::insn_d(24, 0, -4),
        builder::insn(22, 0, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("repeat") && lua.contains("until r1"),
        "expected repeat-until loop, got:\n{lua}"
    );
}

#[test]
fn dup_table_resolves_string_keys_and_settableks() {
    let spec = builder::ProtoSpec {
        words: vec![
            builder::insn_d(54, 0, 0), // DupTable R0 K0
            builder::insn_d(4, 1, 99), // LOADN R1 99
            builder::insn(16, 1, 0, 0), // SetTableKs R1 -> R0.CanOpen
            1u32,                       // aux: constant index 1 (CanOpen string)
            builder::insn(22, 0, 2, 0),  // RETURN R0
        ],
        constants: vec![
            builder::table_constant(&[2, 3, 4, 5]),
            builder::string_constant(2),
        ],
        child_indices: Vec::new(),
        debug_locals: Vec::new(),
        debug_name_idx: 0,
        is_vararg: false,
    };
    let bytes = builder::chunk_with_strings(
        &[spec],
        0,
        &[
            "",
            "CanOpen",
            "OpenCallback",
            "CanClose",
            "CloseCallback",
        ],
    );
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("CanOpen") && !lua.contains("k2"),
        "expected resolved DupTable keys, got:\n{lua}"
    );
    assert!(
        lua.contains("CanOpen = 99") || lua.contains("CanOpen = r"),
        "expected SetTableKs assignment, got:\n{lua}"
    );
}

#[test]
fn newtable_setlist_emits_table_literal() {
    let words = [
        builder::insn(53, 0, 0, 0),
        0u32,
        builder::insn_d(4, 1, 10),
        builder::insn_d(4, 2, 20),
        builder::insn(55, 0, 1, 3),
        0u32,
        builder::insn(22, 0, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(lua.contains("{10, 20}"), "expected table literal, got:\n{lua}");
}

#[test]
fn newclosure_capture_emits_capture_header() {
    let child = builder::ProtoSpec::simple(&[
        builder::insn(2, 0, 0, 0),
        builder::insn(22, 0, 2, 0),
    ]);
    let parent = builder::ProtoSpec {
        words: vec![
            builder::insn(2, 1, 0, 0),
            builder::insn(19, 0, 0, 0),
            builder::insn(70, 0, 1, 0),
            builder::insn(22, 0, 2, 0),
        ],
        constants: Vec::new(),
        child_indices: vec![1],
        debug_locals: Vec::new(),
        debug_name_idx: 0,
        is_vararg: false,
    };
    let bytes = builder::chunk(&[parent, child], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("return nil") || lua.contains("-- captures: val r1"),
        "expected closure body or capture header, got:\n{lua}"
    );
    assert!(
        !lua.contains("-- capture val"),
        "capture insn should be absorbed into header, got:\n{lua}"
    );
}

#[test]
fn jump_if_skips_empty_then_without_end() {
    let words = [
        builder::insn_d(4, 0, 1),
        builder::insn_d(4, 1, 42),
        builder::insn_d(25, 0, 1),
        builder::insn_d(23, 0, 1),
        builder::insn(22, 1, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        !lua.contains("then\n    end\n"),
        "empty taken branch should not emit empty if-then-end, got:\n{lua}"
    );
    assert!(
        lua.contains("return 42") || lua.contains("return r1"),
        "true path should return, got:\n{lua}"
    );
}

#[test]
fn and_opcode_emits_binary_and() {
    let words = [
        builder::insn_d(4, 1, 1),
        builder::insn_d(4, 2, 2),
        builder::insn(45, 0, 1, 2),
        builder::insn(22, 0, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(lua.contains("and"), "expected and expression, got:\n{lua}");
}

#[test]
fn jump_x_eq_kb_taken_block_matches_true_branch() {
    let words = [
        builder::insn_d(3, 0, 1), // LOADB R0 true
        builder::insn_d(78, 0, 3), // JUMPXEQKB R0 +3 when true
        1u32,                      // aux: kb = true
        builder::insn_d(4, 1, 0),  // false path: R1 = 0
        builder::insn(22, 1, 2, 0),
        builder::insn_d(4, 1, 1), // true path: R1 = 1
        builder::insn(22, 1, 2, 0),
    ];
    let bytes = builder::chunk(&[builder::ProtoSpec::simple(&words)], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("return 1") && lua.contains("return 0"),
        "expected both branch returns, got:\n{lua}"
    );
    assert!(
        lua.contains("if ") && lua.contains("else") && lua.contains("end"),
        "expected if/else/end for both branches, got:\n{lua}"
    );
    assert!(
        lua.find("return 1").unwrap() < lua.find("return 0").unwrap(),
        "true branch (return 1) should appear before false branch, got:\n{lua}"
    );
}

#[test]
fn call_b_zero_uses_next_register_as_arg() {
    let spec = builder::ProtoSpec {
        words: vec![
            builder::insn_d(4, 0, 99), // R0 = callable placeholder
            builder::insn_d(4, 1, 99), // R1 = arg
            builder::insn(21, 0, 0, 2),
            builder::insn(22, 0, 2, 0),
        ],
        constants: Vec::new(),
        child_indices: Vec::new(),
        debug_locals: Vec::new(),
        debug_name_idx: 0,
        is_vararg: false,
    };
    let bytes = builder::chunk(&[spec], 0);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains("(99)"),
        "CALL with B=0 should pass the next register as an argument, got:\n{lua}"
    );
    assert!(
        !lua.contains("r0()") && !lua.contains("require()"),
        "CALL with B=0 must not drop the argument, got:\n{lua}"
    );
}

#[test]
fn loadk_string_used_as_method_arg_is_quoted() {
    let spec = builder::ProtoSpec {
        words: vec![
            builder::insn(2, 1, 0, 0),
            builder::insn_d(5, 2, 1),
            builder::insn(20, 0, 1, 0),
            0u32,
            builder::insn(21, 0, 3, 2),
            builder::insn(22, 0, 2, 0),
        ],
        constants: vec![
            builder::string_constant(3),
            builder::string_constant(2),
        ],
        child_indices: Vec::new(),
        debug_locals: Vec::new(),
        debug_name_idx: 0,
        is_vararg: false,
    };
    let bytes = builder::chunk_with_strings(&[spec], 0, &["", "ChildPart", "WaitForChild"]);
    let lua = decompile_bytes(&bytes);
    assert!(
        lua.contains(":WaitForChild(\"ChildPart\")"),
        "expected quoted WaitForChild argument, got:\n{lua}"
    );
}
