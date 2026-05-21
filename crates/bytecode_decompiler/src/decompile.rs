use std::collections::{HashMap, HashSet};

use crate::bytecode::{
    format_constant, format_lua_string, format_lua_string_quoted, reg_name, resolve_import,
    resolve_import_aux, upval_name,
    Chunk, Constant, Instruction, Proto,
};
use crate::opcode::{
    aux_kb, aux_kv, aux_not, insn_a, insn_b, insn_c, insn_d, instruction_word_starts,
    jump_target_with_starts, total_instruction_words, Opcode,
};

fn reg_aux(inst: &Instruction) -> u8 {
    insn_a(inst.aux.unwrap_or(0))
}

fn is_two_way_branch(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::JumpIf
            | Opcode::JumpIfNot
            | Opcode::JumpIfEq
            | Opcode::JumpIfLe
            | Opcode::JumpIfLt
            | Opcode::JumpIfNeq
            | Opcode::JumpIfNotLe
            | Opcode::JumpIfNotLt
            | Opcode::JumpXEqNil
            | Opcode::JumpXEqKb
            | Opcode::JumpXEqKn
            | Opcode::JumpXEqKs
    )
}

#[derive(Clone, PartialEq)]
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
    TableLiteral {
        array: Vec<(usize, Expr)>,
        hash: Vec<(String, Expr)>,
    },
    Unknown(String),
    /// Register value merged from multiple CFG predecessors (SSA phi).
    Phi { reg: u8, arms: Vec<Expr> },
}

#[derive(Clone, Default)]
struct TableBuild {
    array: HashMap<usize, Expr>,
    hash: HashMap<String, Expr>,
    template_keys: Option<Vec<String>>,
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
            Expr::String(s) => format_lua_string_quoted(s),
            Expr::Global(s) => render_global_name(s),
            Expr::Local(s) | Expr::Upvalue(s) => s.clone(),
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
                let args = args.iter().map(|a| render_value_expr(a)).collect::<Vec<_>>().join(", ");
                format!("{}({args})", func.render())
            }
            Expr::MethodCall { object, method, args } => {
                let obj = object.render();
                let args = args
                    .iter()
                    .map(|arg| render_method_arg(method, arg))
                    .collect::<Vec<_>>()
                    .join(", ");
                if is_valid_lua_ident(method) {
                    if args.is_empty() {
                        format!("{obj}:{method}()")
                    } else {
                        format!("{obj}:{method}({args})")
                    }
                } else if args.is_empty() {
                    format!("{obj}[{m}]", m = format_lua_string(method))
                } else {
                    format!("{obj}[{m}]({args})", m = format_lua_string(method))
                }
            }
            Expr::TableLiteral { array, hash } => render_table_literal(array, hash),
            Expr::Unknown(s) => s.clone(),
            Expr::Phi { arms, .. } => pick_phi_variant(arms).render(),
        }
    }
}

fn render_table_literal(array: &[(usize, Expr)], hash: &[(String, Expr)]) -> String {
    let mut parts = Vec::new();
    let mut last_idx = 0usize;
    for (idx, val) in array {
        if *idx != last_idx + 1 && !parts.is_empty() {
            parts.push(format!("[{idx}] = {}", render_value_expr(val)));
        } else {
            parts.push(render_value_expr(val));
        }
        last_idx = *idx;
    }
    let mut hash_sorted: Vec<_> = hash.iter().collect();
    hash_sorted.sort_by_key(|(k, _)| k.as_str());
    for (key, val) in hash_sorted {
        if is_valid_lua_ident(key) {
            parts.push(format!("{key} = {}", render_value_expr(val)));
        } else {
            parts.push(format!("[{}] = {}", format_lua_string(key), render_value_expr(val)));
        }
    }
    format!("{{{}}}", parts.join(", "))
}

struct FunctionDecompiler<'a> {
    chunk: &'a Chunk,
    proto: &'a Proto,
    regs: HashMap<u8, Expr>,
    pending_namecall: HashMap<u8, (String, Expr)>,
    emitted_blocks: HashSet<usize>,
    skipped_pcs: HashSet<usize>,
    declared_regs: HashSet<u8>,
    blocks: Vec<BasicBlock>,
    word_starts: Vec<usize>,
    total_words: usize,
    exit_block: usize,
    newtable_serial: usize,
    join_contributions: HashMap<usize, Vec<(usize, HashMap<u8, Expr>, HashMap<u8, (String, Expr)>)>>,
    loop_headers: HashSet<usize>,
    while_headers: HashSet<usize>,
    repeat_headers: HashSet<usize>,
    repeat_until: HashMap<usize, String>,
    repeat_until_pc: HashMap<usize, usize>,
    repeat_open_headers: HashSet<usize>,
    handled_repeat_jumpif_blocks: HashSet<usize>,
    repeat_tail_blocks: HashSet<usize>,
    table_builds: HashMap<u8, TableBuild>,
    closure_captures: HashMap<usize, Vec<String>>,
    generic_for_latches: HashSet<usize>,
    hoisted_closures: HashMap<usize, String>,
    hoisted_closure_names: HashSet<String>,
    loop_body_blocks: HashSet<usize>,
    require_entries: HashMap<String, (Expr, usize)>,
    hoisted_requires: Vec<(String, Expr)>,
    closure_upval_names: HashMap<usize, Vec<String>>,
    upval_override_names: HashMap<u8, String>,
    reg_upval_slots: HashMap<u8, u8>,
    reg_import_paths: HashMap<u8, String>,
}

enum WorkItem {
    Block {
        idx: usize,
        indent: String,
        regs: HashMap<u8, Expr>,
        pending_namecall: HashMap<u8, (String, Expr)>,
    },
    CloseBlock { indent: String },
    /// Deferred source line (e.g. `else`) so branch bodies emit before it on the work stack.
    EmitLine(String),
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

fn merge_reg_maps(maps: &[HashMap<u8, Expr>]) -> HashMap<u8, Expr> {
    if maps.is_empty() {
        return HashMap::new();
    }
    if maps.len() == 1 {
        return maps[0].clone();
    }
    let mut all_regs = HashSet::new();
    for m in maps {
        all_regs.extend(m.keys().copied());
    }
    let mut merged = HashMap::new();
    for r in all_regs {
        let values: Vec<&Expr> = maps.iter().filter_map(|m| m.get(&r)).collect();
        if values.is_empty() {
            continue;
        }
        let first = values[0];
        if values.iter().all(|v| *v == first) {
            merged.insert(r, first.clone());
        } else {
            merged.insert(
                r,
                Expr::Phi {
                    reg: r,
                    arms: values.iter().map(|v| (*v).clone()).collect(),
                },
            );
        }
    }
    merged
}

fn merge_pending_maps(
    maps: &[HashMap<u8, (String, Expr)>],
) -> HashMap<u8, (String, Expr)> {
    if maps.is_empty() {
        return HashMap::new();
    }
    let mut merged = maps[0].clone();
    for m in &maps[1..] {
        for (r, v) in m {
            merged.entry(*r).or_insert_with(|| v.clone());
        }
    }
    merged
}

const INDENT_STEP: &str = "    ";

fn indent_add(base: &str) -> String {
    format!("{base}{INDENT_STEP}")
}

fn opcode_emits_statement(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::SetGlobal
            | Opcode::Setupval
            | Opcode::SetTable
            | Opcode::SetTableKs
            | Opcode::SetUdataKs
            | Opcode::SetTableN
            | Opcode::Call
            | Opcode::CallFb
            | Opcode::Return
            | Opcode::FastCall
            | Opcode::FastCall1
            | Opcode::FastCall2
            | Opcode::FastCall2K
            | Opcode::FastCall3
    )
}

fn is_roblox_error_template(s: &str) -> bool {
    s.contains("%*")
        || s.starts_with("Unknown ")
        || s.starts_with("Tried to ")
        || s.contains("DropTable")
        || s.contains("Directory %*")
}

fn expr_from_import_path(path: &str) -> Expr {
    if path.contains('.') {
        Expr::Import(path.to_string())
    } else if is_valid_lua_ident(path) {
        Expr::Local(path.to_string())
    } else {
        Expr::Import(path.to_string())
    }
}

fn collect_hoisted_function_names(body: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("local ") {
            if let Some((name, _)) = rest.split_once(" = function") {
                let name = name.trim();
                if is_valid_lua_ident(name) {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

fn rewrite_connect_handler_refs(body: &str) -> String {
    let names = collect_hoisted_function_names(body);
    if names.is_empty() {
        return body.to_string();
    }
    let mut out = body.to_string();
    for name in names {
        let q = format_lua_string_quoted(&name);
        for sep in [":Connect(", ".Connect("] {
            out = out.replace(&format!("{sep}{q})"), &format!("{sep}{name})"));
            out = out.replace(&format!("{sep}{q}, "), &format!("{sep}{name}, "));
        }
        out = out.replace(&format!(", {q})"), &format!(", {name})"));
    }
    out
}

fn simplify_emitted_if_conditions(body: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("if ") {
            if let Some(cond) = rest.strip_suffix(" then") {
                let simplified = simplify_condition(cond);
                if simplified != cond {
                    let indent = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
                    out.push(format!("{}if {} then", &line[..indent], simplified));
                    continue;
                }
            } else if let Some(rest) = trimmed.strip_prefix("elseif ") {
                if let Some(cond) = rest.strip_suffix(" then") {
                    let simplified = simplify_condition(cond);
                    if simplified != cond {
                        let indent = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
                        out.push(format!("{}elseif {} then", &line[..indent], simplified));
                        continue;
                    }
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("while ") {
            if let Some(cond) = rest.strip_suffix(" do") {
                let simplified = simplify_condition(cond);
                if simplified != cond {
                    let indent = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
                    out.push(format!("{}while {} do", &line[..indent], simplified));
                    continue;
                }
            }
        }
        out.push(line.to_string());
    }
    let mut joined = out.join("\n");
    if body.ends_with('\n') {
        joined.push('\n');
    }
    joined
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

fn is_builtin_global(name: &str) -> bool {
    matches!(
        name,
        "true"
            | "false"
            | "nil"
            | "and"
            | "or"
            | "not"
            | "game"
            | "workspace"
            | "script"
            | "shared"
            | "Enum"
            | "Vector3"
            | "Vector2"
            | "CFrame"
            | "Color3"
            | "UDim2"
            | "TweenInfo"
            | "Instance"
            | "Math"
            | "table"
            | "string"
            | "debug"
            | "coroutine"
            | "typeof"
            | "unpack"
            | "select"
            | "error"
            | "assert"
            | "pcall"
            | "xpcall"
            | "require"
            | "setmetatable"
            | "getmetatable"
            | "tick"
            | "wait"
            | "delay"
            | "spawn"
    )
}

fn global_looks_like_const(name: &str) -> bool {
    is_valid_lua_ident(name)
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
        && !is_builtin_global(name)
}

fn render_global_name(name: &str) -> String {
    if global_looks_like_const(name) {
        format_lua_string(name)
    } else {
        name.to_string()
    }
}

fn render_value_expr(expr: &Expr) -> String {
    match expr {
        Expr::Global(s) => render_global_name(s),
        Expr::String(s) => format_lua_string_quoted(s),
        other => other.render(),
    }
}

fn simplify_condition(cond: &str) -> String {
    let mut c = cond.trim().to_string();
    loop {
        let trimmed = c.trim();
        if let Some(inner) = trimmed.strip_prefix("not (").and_then(|s| s.strip_suffix(')')) {
            if let Some(inner2) = inner.strip_prefix("not (").and_then(|s| s.strip_suffix(')')) {
                c = inner2.to_string();
                continue;
            }
            if let Some(inner2) = inner.strip_prefix("not ").filter(|s| !s.contains('(')) {
                c = inner2.to_string();
                continue;
            }
        }
        break;
    }
    if let Some(v) = c.strip_suffix(" == false") {
        return format!("not ({})", v.trim());
    }
    if let Some(v) = c.strip_suffix(" == true") {
        return v.trim().to_string();
    }
    if let Some(v) = c.strip_prefix("not (").and_then(|s| s.strip_suffix(" == false)")) {
        return v.trim().to_string();
    }
    if let Some(v) = c.strip_prefix("not (").and_then(|s| s.strip_suffix(" == nil)")) {
        return format!("{v} ~= nil");
    }
    c
}

fn is_register_placeholder(s: &str) -> bool {
    (s.starts_with('r') && s.len() > 1 && s[1..].chars().all(|c| c.is_ascii_digit()))
        || s.starts_with("arg")
        || s.starts_with("upval_")
}

fn trim_return_values(vals: Vec<String>) -> Vec<String> {
    if vals.len() <= 1 {
        return vals;
    }
    let first = vals[0].clone();
    if first.contains('(') || first.contains(':') {
        let junk_tail = vals[1..].iter().all(|v| {
            v == &first
                || v == "true"
                || v == "false"
                || v == "nil"
                || is_register_placeholder(v)
        });
        if junk_tail {
            return vec![first];
        }
    }
    let mut out = Vec::new();
    for v in vals {
        if is_register_placeholder(&v) {
            continue;
        }
        if out.last() == Some(&v) {
            continue;
        }
        out.push(v);
    }
    if out.is_empty() {
        vec![first]
    } else {
        out
    }
}

fn call_is_side_effect_only(call: &Expr) -> bool {
    match call {
        Expr::MethodCall { method, .. } => matches!(
            method.as_str(),
            "Connect"
                | "Once"
                | "Wait"
                | "Play"
                | "Stop"
                | "Destroy"
                | "Fire"
                | "Invoke"
                | "GiveTask"
                | "Defer"
                | "Delay"
                | "Cancel"
                | "Disconnect"
                | "Pause"
                | "Resume"
        ),
        _ => false,
    }
}

fn expr_quality_score(expr: &Expr) -> i32 {
    match expr {
        Expr::Unknown(s) if s.starts_with('r') && s.len() > 1 => 0,
        Expr::Unknown(s) if s.starts_with("arg") => 1,
        Expr::Unknown(_) => 2,
        Expr::Nil | Expr::Bool(_) | Expr::Number(_) => 3,
        Expr::String(_) => 4,
        Expr::Varargs => 5,
        Expr::Upvalue(_) => 8,
        Expr::Global(_) => 10,
        Expr::Import(_) => 12,
        Expr::Local(_) => 14,
        Expr::TableLiteral { .. } => 16,
        Expr::Call { .. } => 18,
        Expr::Index { .. } => 22,
        Expr::MethodCall { .. } => 26,
        Expr::Binary { left, right, .. } => expr_quality_score(left) + expr_quality_score(right),
        Expr::Unary { arg, .. } => expr_quality_score(arg),
        Expr::Phi { arms, .. } => arms.iter().map(expr_quality_score).max().unwrap_or(0),
    }
}

fn pick_phi_variant(arms: &[Expr]) -> Expr {
    if arms.is_empty() {
        return Expr::Nil;
    }
    if arms.len() == 1 {
        return arms[0].clone();
    }
    let best_score = arms.iter().map(expr_quality_score).max().unwrap_or(0);
    let top: Vec<&Expr> = arms
        .iter()
        .filter(|a| expr_quality_score(a) >= best_score.saturating_sub(4))
        .collect();
    top.into_iter()
        .max_by_key(|a| a.render().len())
        .cloned()
        .unwrap_or_else(|| arms[0].clone())
}

fn is_require_call(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Call {
            func,
            ..
        } if matches!(func.as_ref(), Expr::Global(g) if g == "require")
            || matches!(func.as_ref(), Expr::Local(g) if g == "require")
    )
}

fn infer_require_local_name(call: &Expr) -> String {
    let Some(arg) = (match call {
        Expr::Call { args, .. } => args.first(),
        _ => None,
    }) else {
        return "module".into();
    };
    if let Some(name) = extract_wait_for_child_name(arg) {
        return name;
    }
    if let Expr::Import(path) = arg {
        let seg = path.rsplit('.').next().unwrap_or(path);
        if is_valid_lua_ident(seg) {
            return seg.to_string();
        }
    }
    "module".into()
}

fn extract_wait_for_child_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall { method, args, .. } if method == "WaitForChild" => {
            args.first().and_then(expr_to_string_lit)
        }
        _ => None,
    }
}

fn require_call_key(call: &Expr) -> Option<String> {
    if !is_require_call(call) {
        return None;
    }
    Some(call.render())
}

fn strip_empty_control_blocks(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();
        let is_if_not = trimmed.starts_with("if not ") && trimmed.ends_with(" then");
        let is_if_then_else_fixup =
            trimmed.starts_with("if ") && !is_if_not && trimmed.ends_with(" then");
        let is_empty_block_start = is_if_not
            || (trimmed.starts_with("while ") && trimmed.ends_with(" do"))
            || (trimmed.starts_with("for ") && trimmed.ends_with(" do"))
            || trimmed == "repeat";
        if is_empty_block_start || is_if_then_else_fixup {
            let base_indent = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
            let mut j = i + 1;
            let mut inner: Vec<&str> = Vec::new();
            let mut skip = false;
            let mut empty_then_else_body = false;
            while j < lines.len() {
                let t = lines[j].trim();
                let indent = lines[j].find(|c: char| !c.is_whitespace()).unwrap_or(0);
                if t == "else" && inner.iter().all(|l| l.trim().is_empty()) {
                    inner.clear();
                    empty_then_else_body = true;
                    j += 1;
                    continue;
                }
                if (t == "end" || t.starts_with("until")) && indent <= base_indent {
                    if inner.iter().all(|l| l.trim().is_empty()) {
                        if trimmed == "repeat" && t.starts_with("until") {
                            out.push(line.to_string());
                            out.push(lines[j].to_string());
                        } else if trimmed.starts_with("for ") && !empty_then_else_body {
                            out.push(line.to_string());
                            out.push(lines[j].to_string());
                        } else if !is_if_then_else_fixup
                            && !trimmed.starts_with("for ")
                            && trimmed != "repeat"
                        {
                            // Skip wholly empty if-not / while.
                        } else if trimmed.starts_with("for ") {
                            // Skip empty for loops in corpus output.
                        }
                        i = j + 1;
                        skip = true;
                        break;
                    }
                    if empty_then_else_body {
                        for l in inner {
                            out.push(l.to_string());
                        }
                        i = j + 1;
                        skip = true;
                        break;
                    }
                    out.push(line.to_string());
                    for l in inner {
                        out.push(l.to_string());
                    }
                    out.push(lines[j].to_string());
                    i = j + 1;
                    skip = true;
                    break;
                }
                inner.push(lines[j]);
                j += 1;
            }
            if skip {
                continue;
            }
        }
        out.push(line.to_string());
        i += 1;
    }
    let mut joined = out.join("\n");
    if body.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

fn infer_builder_local_name(chain: &str) -> String {
    if chain.contains("WaitForModule(") {
        if let Some(start) = chain.find("WaitForModule(") {
            let rest = &chain[start + "WaitForModule(".len()..];
            if let Some(end) = rest.find(')') {
                let inner = rest[..end].trim().trim_matches('"').trim_matches('\'');
                if !inner.is_empty() {
                    let base = inner.rsplit('.').next().unwrap_or(inner).trim();
                    if is_valid_lua_ident(base) {
                        if base.ends_with("Builder") {
                            return base.to_string();
                        }
                        return format!("{base}Builder");
                    }
                }
            }
        }
        return "builder".into();
    }
    "obj".into()
}

fn hoist_repeated_builder_chains(body: &str) -> (String, Vec<(String, String)>) {
    let marker = ".new()";
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut pos = 0usize;
    while pos < body.len() {
        let Some(rel) = body[pos..].find(marker) else {
            break;
        };
        let end = pos + rel + marker.len();
        let mut start = pos + rel;
        while start > 0 {
            let b = body.as_bytes()[start - 1];
            if b.is_ascii_alphanumeric()
                || b == b'_'
                || b == b')'
                || b == b']'
                || b == b'"'
                || b == b'\''
                || b == b'('
            {
                start -= 1;
            } else if b == b':' {
                start -= 1;
                while start > 0 {
                    let c = body.as_bytes()[start - 1];
                    if c.is_ascii_alphanumeric() || c == b'_' {
                        start -= 1;
                    } else {
                        break;
                    }
                }
                break;
            } else if b == b'.' {
                break;
            } else {
                break;
            }
        }
        while start < body.len() && (body.as_bytes()[start] == b' ' || body.as_bytes()[start] == b'\t') {
            start += 1;
        }
        let chain = body[start..end].trim().to_string();
        if chain.contains(':') && chain.len() > 8 {
            *counts.entry(chain).or_insert(0) += 1;
        }
        pos = end;
    }
    let mut preludes = Vec::new();
    let mut out = body.to_string();
    for (chain, count) in counts {
        if count < 3 {
            continue;
        }
        let name = infer_builder_local_name(&chain);
        if preludes.iter().any(|(n, _)| n == &name) {
            continue;
        }
        preludes.push((name.clone(), chain.clone()));
        out = out.replace(&chain, &name);
    }
    (out, preludes)
}

fn infer_chain_local_name(chain: &str) -> String {
    if chain.contains("RaycastParams.new()") {
        return "rayParams".into();
    }
    if chain.contains("WaitForChild(") && chain.contains(":Clone()") {
        if let Some(start) = chain.find("WaitForChild(") {
            let rest = &chain[start + "WaitForChild(".len()..];
            if let Some(end) = rest.find(')') {
                let inner = rest[..end].trim().trim_matches('"').trim_matches('\'');
                if !inner.is_empty() {
                    return format!("{}Clone", inner.trim_matches('"'));
                }
            }
        }
        return "clone".into();
    }
    if chain.contains(".new()") {
        return infer_builder_local_name(chain);
    }
    "tmp".into()
}

fn hoist_repeated_expr_chains(body: &str) -> (String, Vec<(String, String)>) {
    let markers = [".new()", ":Clone()"];
    let mut counts: HashMap<String, usize> = HashMap::new();
    for marker in markers {
        let mut pos = 0usize;
        while pos < body.len() {
            let Some(rel) = body[pos..].find(marker) else {
                break;
            };
            let end = pos + rel + marker.len();
            let mut start = pos + rel;
            while start > 0 {
                let b = body.as_bytes()[start - 1];
                if b.is_ascii_alphanumeric()
                    || b == b'_'
                    || b == b')'
                    || b == b']'
                    || b == b'"'
                    || b == b'\''
                    || b == b'('
                    || b == b'.'
                    || b == b':'
                {
                    start -= 1;
                } else {
                    break;
                }
            }
            while start < body.len() && (body.as_bytes()[start] == b' ' || body.as_bytes()[start] == b'\t') {
                start += 1;
            }
            let chain = body[start..end].trim().to_string();
            if chain.len() > 6 {
                *counts.entry(chain).or_insert(0) += 1;
            }
            pos = end;
        }
    }
    let mut preludes = Vec::new();
    let mut out = body.to_string();
    for (chain, count) in counts {
        if count < 2 {
            continue;
        }
        let name = infer_chain_local_name(&chain);
        if preludes.iter().any(|(n, _)| n == &name) {
            continue;
        }
        preludes.push((name.clone(), chain.clone()));
        out = out.replace(&chain, &name);
    }
    (out, preludes)
}

fn finalize_emitted_body(raw: &str) -> (String, Vec<(String, String)>, Vec<(String, String)>) {
    finalize_emitted_body_opts(raw, true, true)
}

fn finalize_emitted_body_opts(
    raw: &str,
    strip_empty: bool,
    trim_dead_return: bool,
) -> (String, Vec<(String, String)>, Vec<(String, String)>) {
    let body = polish_emitted_lua(raw, strip_empty, trim_dead_return);
    let (body, text_hoists) = hoist_duplicate_requires(&body);
    let (body, builder_hoists) = hoist_repeated_builder_chains(&body);
    let (mut body, expr_hoists) = hoist_repeated_expr_chains(&body);
    let mut all_hoists = builder_hoists;
    for h in expr_hoists {
        if !all_hoists.iter().any(|(n, _)| n == &h.0) {
            all_hoists.push(h);
        }
    }
    for (name, chain) in &all_hoists {
        if chain.contains(':') && !chain.contains("RaycastParams") {
            let dot = format!("{name}.");
            let colon = format!("{name}:");
            body = body.replace(&dot, &colon);
        }
    }
    (body, text_hoists, all_hoists)
}

fn builder_hoist_prelude(indent: &str, hoists: &[(String, String)]) -> String {
    hoists
        .iter()
        .map(|(name, chain)| format!("{indent}local {name} = {chain}\n"))
        .collect()
}

fn polish_emitted_lua(body: &str, strip_empty: bool, trim_dead_return: bool) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut out: Vec<String> = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            if out.last().map(|s| s.trim()) == Some(trimmed) {
                continue;
            }
        }
        out.push(line.to_string());
    }
    let mut joined = out.join("\n");
    if body.ends_with('\n') {
        joined.push('\n');
    }
    if strip_empty {
        joined = strip_empty_control_blocks(&joined);
        joined = strip_empty_if_then_end(&joined);
    }
    joined = strip_self_assignments(&joined);
    joined = simplify_emitted_if_conditions(&joined);
    if strip_empty && trim_dead_return {
        joined = trim_unreachable_after_return(&joined);
        joined = trim_unreachable_main_tail(&joined);
    }
    joined
}

/// Drop statements emitted after bare `return` in the main function body only.
fn trim_unreachable_after_return(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut out: Vec<String> = Vec::new();
    let mut skip_from_indent: Option<usize> = None;
    let mut fn_depth = 0i32;

    for line in lines {
        let indent = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
        let trimmed = line.trim();

        if trimmed.contains("function(")
            || trimmed.starts_with("function(")
            || trimmed.starts_with("function ")
            || trimmed.contains(" = function(")
        {
            fn_depth += 1;
        }

        if let Some(cut) = skip_from_indent {
            if indent < cut {
                skip_from_indent = None;
            } else if indent == cut {
                if trimmed == "end"
                    || trimmed == "else"
                    || trimmed.starts_with("elseif")
                    || trimmed.starts_with("until")
                {
                    skip_from_indent = None;
                    out.push(line.to_string());
                    if trimmed == "end" && fn_depth > 1 {
                        fn_depth -= 1;
                    }
                    continue;
                }
                continue;
            }
        }

        out.push(line.to_string());
        if trimmed == "return" && fn_depth == 0 {
            skip_from_indent = Some(indent);
        }
        if trimmed == "end" || trimmed == "end)" {
            if fn_depth > 0 {
                fn_depth -= 1;
            }
        }
    }

    let mut joined = out.join("\n");
    if body.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

/// Remove `if cond then` / `while cond do` blocks whose body is only blank lines before `end`.
fn strip_empty_if_then_end(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();
        let is_if = trimmed.starts_with("if ") && trimmed.ends_with(" then");
        let is_while = trimmed.starts_with("while ") && trimmed.ends_with(" do");
        if is_if || is_while {
            let base_indent = line.find(|c: char| !c.is_whitespace()).unwrap_or(0);
            let mut j = i + 1;
            let mut inner: Vec<&str> = Vec::new();
            let mut handled = false;
            while j < lines.len() {
                let t = lines[j].trim();
                let indent = lines[j].find(|c: char| !c.is_whitespace()).unwrap_or(0);
                if t == "else" || t.starts_with("elseif") {
                    break;
                }
                if t == "end" && indent <= base_indent {
                    if inner.iter().all(|l| l.trim().is_empty()) {
                        i = j + 1;
                    } else {
                        out.push(line.to_string());
                        for l in inner {
                            out.push(l.to_string());
                        }
                        out.push(lines[j].to_string());
                        i = j + 1;
                    }
                    handled = true;
                    break;
                }
                inner.push(lines[j]);
                j += 1;
            }
            if handled {
                continue;
            }
        }
        out.push(line.to_string());
        i += 1;
    }
    let mut joined = out.join("\n");
    if body.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

fn strip_self_assignments(body: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some((lhs, rhs)) = trimmed.split_once(" = ") {
            if !lhs.is_empty() && lhs == rhs {
                continue;
            }
        }
        out.push(line.to_string());
    }
    let mut joined = out.join("\n");
    if body.ends_with('\n') {
        joined.push('\n');
    }
    joined
}

/// Drop CFG-scheduling artifacts: trailing init calls (e.g. Heartbeat:Wait) after the real return.
fn trim_unreachable_main_tail(body: &str) -> String {
    let mut lines: Vec<&str> = body.lines().collect();
    loop {
        let Some(last) = lines.last() else {
            break;
        };
        let t = last.trim();
        if t.is_empty() {
            lines.pop();
            continue;
        }
        if (t.contains("Heartbeat") && t.contains("Wait"))
            || (t.contains("RunService") && t.contains("GetService"))
        {
            lines.pop();
            continue;
        }
        break;
    }
    let mut out = lines.join("\n");
    if body.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn find_balanced_close(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn infer_name_from_require_expr(require_expr: &str) -> String {
    if let Some(idx) = require_expr.find("WaitForChild(") {
        let rest = &require_expr[idx + "WaitForChild(".len()..];
        if let Some(end) = rest.find(')') {
            let inner = rest[..end].trim();
            let name = inner.trim_matches('"').trim_matches('\'');
            if is_valid_lua_ident(name) {
                return name.to_string();
            }
        }
    }
    "module".into()
}

fn hoist_duplicate_requires(body: &str) -> (String, Vec<(String, String)>) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut pos = 0usize;
    while pos < body.len() {
        let Some(rel) = body[pos..].find("require(") else {
            break;
        };
        let start = pos + rel;
        let slice = &body[start..];
        let Some(end) = find_balanced_close(slice) else {
            pos = start + 8;
            continue;
        };
        let expr = slice[..end].to_string();
        *counts.entry(expr).or_insert(0) += 1;
        pos = start + end;
    }

    let mut preludes = Vec::new();
    let mut out = body.to_string();
    for (require_expr, count) in counts {
        if count < 2 {
            continue;
        }
        let name = infer_name_from_require_expr(&require_expr);
        preludes.push((name.clone(), require_expr.clone()));
        out = out.replace(&require_expr, &name);
    }
    (out, preludes)
}

fn expr_to_string_lit(expr: &Expr) -> Option<String> {
    match expr {
        Expr::String(s) => Some(s.clone()),
        Expr::Import(s) | Expr::Global(s) | Expr::Local(s) if is_valid_lua_ident(s) => Some(s.clone()),
        _ => None,
    }
}

fn methods_with_quoted_string_args(method: &str) -> bool {
    matches!(
        method,
        "GetService"
            | "WaitForChild"
            | "WaitForModule"
            | "FindFirstChild"
            | "FindFirstChildOfClass"
            | "IsA"
            | "GetFastFlag"
            | "WaitForManager"
            | "GetPropertyChangedSignal"
            | "profilebegin"
            | "profileend"
            | "Fire"
            | "Fired"
            | "Invoke"
            | "Connect"
            | "WaitForEvent"
    )
}

fn render_method_arg(method: &str, arg: &Expr) -> String {
    if methods_with_quoted_string_args(method) {
        if let Some(s) = expr_to_string_lit(arg) {
            return format_lua_string_quoted(&s);
        }
    }
    if matches!(
        method,
        "IsA" | "FindFirstChildOfClass" | "addTag" | "newAbility" | "setRarity" | "setStatsShowing"
    ) {
        if let Expr::Global(s) = arg {
            if global_looks_like_const(s) {
                return format_lua_string_quoted(s);
            }
        }
        if let Expr::String(s) = arg {
            if global_looks_like_const(s) {
                return format_lua_string_quoted(s);
            }
        }
    }
    render_value_expr(arg)
}

fn normalize_method_call(call: Expr) -> Expr {
    let Expr::MethodCall { object, method, mut args } = call else {
        return call;
    };
    if methods_with_quoted_string_args(&method) {
        args = args
            .into_iter()
            .map(|arg| {
                if let Some(s) = expr_to_string_lit(&arg) {
                    Expr::String(s)
                } else {
                    arg
                }
            })
            .collect();
    }
    Expr::MethodCall {
        object,
        method,
        args,
    }
}

fn builtin_expr(name: &str) -> Expr {
    if name.contains('.') || name == "assert" || name == "type" || name == "typeof" {
        Expr::Global(name.to_string())
    } else {
        Expr::Global(name.to_string())
    }
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
        let mut declared_regs = HashSet::new();
        for i in 0..proto.num_params {
            declared_regs.insert(i);
        }
        let word_starts = instruction_word_starts(&proto.instructions);
        let total_words = total_instruction_words(&proto.instructions);
        Self {
            chunk,
            proto,
            regs: HashMap::new(),
            pending_namecall: HashMap::new(),
            emitted_blocks: HashSet::new(),
            skipped_pcs: HashSet::new(),
            declared_regs,
            blocks: Vec::new(),
            word_starts,
            total_words,
            exit_block: 0,
            newtable_serial: 0,
            join_contributions: HashMap::new(),
            loop_headers: HashSet::new(),
            while_headers: HashSet::new(),
            repeat_headers: HashSet::new(),
            repeat_until: HashMap::new(),
            repeat_until_pc: HashMap::new(),
            repeat_open_headers: HashSet::new(),
            handled_repeat_jumpif_blocks: HashSet::new(),
            repeat_tail_blocks: HashSet::new(),
            table_builds: HashMap::new(),
            closure_captures: HashMap::new(),
            generic_for_latches: HashSet::new(),
            hoisted_closures: HashMap::new(),
            hoisted_closure_names: HashSet::new(),
            loop_body_blocks: HashSet::new(),
            require_entries: HashMap::new(),
            hoisted_requires: Vec::new(),
            closure_upval_names: HashMap::new(),
            upval_override_names: HashMap::new(),
            reg_upval_slots: HashMap::new(),
            reg_import_paths: HashMap::new(),
        }
    }

    fn infer_reg_provenance(&mut self) {
        self.reg_upval_slots.clear();
        self.reg_import_paths.clear();
        for inst in &self.proto.instructions {
            match inst.opcode {
                Opcode::GetUpval => {
                    self.reg_upval_slots.insert(insn_a(inst.raw), insn_b(inst.raw));
                }
                Opcode::GetImport => {
                    let reg = insn_a(inst.raw);
                    let path = if let Some(aux) = inst.aux {
                        resolve_import_aux(aux, &self.proto.constants)
                    } else {
                        let d = insn_d(inst.raw) as usize;
                        if let Some(Constant::Import(id)) = self.proto.constants.get(d) {
                            resolve_import(*id, &self.proto.constants)
                        } else {
                            format!("import_{d}")
                        }
                    };
                    self.reg_import_paths.insert(reg, path);
                }
                _ => {}
            }
        }
    }

    fn resolve_method_object(&self, reg: u8, expr: &Expr) -> Expr {
        if let Some(&uv) = self.reg_upval_slots.get(&reg) {
            return self.upval_expr(uv);
        }
        let rendered = expr.render();
        if rendered != "nil" {
            return expr.clone();
        }
        if let Some(path) = self.reg_import_paths.get(&reg) {
            if !path.starts_with("import_") && !path.contains('.') {
                return expr_from_import_path(path);
            }
        }
        if let Expr::Phi { arms, .. } = expr {
            for arm in arms {
                let r = arm.render();
                if r != "nil" && !r.is_empty() {
                    return arm.clone();
                }
            }
        }
        expr.clone()
    }

    fn infer_upval_names(&mut self) {
        let mut reg_import: HashMap<u8, String> = HashMap::new();
        for (pc, inst) in self.proto.instructions.iter().enumerate() {
            if inst.opcode == Opcode::GetImport {
                let reg = insn_a(inst.raw);
                let path = if let Some(aux) = inst.aux {
                    resolve_import_aux(aux, &self.proto.constants)
                } else {
                    let d = insn_d(inst.raw) as usize;
                    if let Some(Constant::Import(id)) = self.proto.constants.get(d) {
                        resolve_import(*id, &self.proto.constants)
                    } else {
                        format!("import_{d}")
                    }
                };
                reg_import.insert(reg, path);
            }
            if inst.opcode == Opcode::Move {
                let dst = insn_a(inst.raw);
                let src = insn_b(inst.raw);
                if let Some(path) = reg_import.get(&src) {
                    reg_import.insert(dst, path.clone());
                }
            }
            if inst.opcode == Opcode::Setupval {
                let idx = insn_b(inst.raw);
                let src = insn_a(inst.raw);
                if let Some(path) = reg_import.get(&src) {
                    let name = path.rsplit('.').next().unwrap_or(path.as_str());
                    let friendly = if name.is_empty() {
                        format!("upval_{idx}")
                    } else if is_valid_lua_ident(name) {
                        name.to_string()
                    } else {
                        format!("upval_{idx}")
                    };
                    self.upval_override_names.insert(idx, friendly);
                } else {
                    self.upval_override_names.entry(idx).or_insert_with(|| {
                        reg_name(self.proto, src, pc)
                    });
                }
            }
        }
        for (i, name) in self.proto.debug_upvals.iter().enumerate() {
            if !name.is_empty() && !name.starts_with("upval_") {
                self.upval_override_names
                    .entry(i as u8)
                    .or_insert_with(|| name.clone());
            }
        }
    }

    fn upval_display_name(&self, idx: u8) -> String {
        self.upval_override_names
            .get(&idx)
            .cloned()
            .unwrap_or_else(|| upval_name(self.proto, idx))
    }

    fn emit_linear_body(&mut self, base_indent: &str) -> String {
        let indent = base_indent;
        let mut out = String::new();
        for pc in 0..self.proto.instructions.len() {
            if self.skipped_pcs.contains(&pc) {
                continue;
            }
            let inst = self.proto.instructions[pc].clone();
            if matches!(
                inst.opcode,
                Opcode::Jump
                    | Opcode::JumpBack
                    | Opcode::JumpIf
                    | Opcode::JumpIfNot
                    | Opcode::JumpX
                    | Opcode::ForNPrep
                    | Opcode::ForNLoop
                    | Opcode::ForGPrep
                    | Opcode::ForGPrepInext
                    | Opcode::ForGPrepNext
                    | Opcode::ForGLoop
            ) {
                continue;
            }
            if let Some(s) = self.emit_instruction(pc, &inst, indent, 0) {
                out.push_str(&s);
            }
        }
        out
    }

    fn upval_expr(&self, idx: u8) -> Expr {
        let name = self.upval_display_name(idx);
        if name.starts_with("upval_") {
            Expr::Upvalue(name)
        } else {
            Expr::Local(name)
        }
    }

    fn should_use_linear_fallback(&self, cfg: &str) -> bool {
        if self.proto.instructions.len() > 200 && self.proto.num_params == 0 {
            return false;
        }
        (cfg.trim().is_empty() && self.count_emittable_ops() > 0)
            || self.cfg_truncated_after_early_return(cfg)
            || self.cfg_missing_expected_strings(cfg)
    }

    fn emit_function_body(&mut self, base_indent: &str) -> String {
        let cfg = self.emit_body(base_indent);
        if self.should_use_linear_fallback(&cfg) {
            self.emitted_blocks.clear();
            self.join_contributions.clear();
            self.emit_linear_body(base_indent)
        } else {
            cfg
        }
    }

    fn cfg_missing_expected_strings(&self, cfg: &str) -> bool {
        if self.proto.num_params != 1 {
            return false;
        }
        self.proto.constants.iter().any(|c| {
            matches!(
                c,
                Constant::String(s) if s == "MapName" && !cfg.contains("MapName")
            )
        })
    }

    /// CFG sometimes emits only an early-return path and drops merge blocks (queue handlers).
    fn cfg_truncated_after_early_return(&self, cfg: &str) -> bool {
        if self.proto.num_params != 1 {
            return false;
        }
        let Some(ret_pc) = self
            .proto
            .instructions
            .iter()
            .position(|i| i.opcode == Opcode::Return)
        else {
            return false;
        };
        if ret_pc + 1 >= self.proto.instructions.len() {
            return false;
        }
        let tail_ops = self.proto.instructions[ret_pc + 1..]
            .iter()
            .filter(|i| opcode_emits_statement(i.opcode))
            .count();
        let cfg_lines = cfg.lines().filter(|l| !l.trim().is_empty()).count();
        tail_ops >= 5 && cfg_lines < 30
    }

    fn count_emittable_ops(&self) -> usize {
        self.proto
            .instructions
            .iter()
            .filter(|i| opcode_emits_statement(i.opcode))
            .count()
    }

    fn materialize_require(&mut self, call: Expr) -> Expr {
        let Some(key) = require_call_key(&call) else {
            return call;
        };
        let entry = self
            .require_entries
            .entry(key.clone())
            .or_insert_with(|| (call.clone(), 0));
        entry.1 += 1;
        if let Some((existing_name, _)) = self
            .hoisted_requires
            .iter()
            .find(|(_, expr)| require_call_key(expr).as_deref() == Some(key.as_str()))
        {
            return Expr::Local(existing_name.clone());
        }
        let name = infer_require_local_name(&entry.0);
        if entry.1 == 1 && name == "module" {
            return call;
        }
        self.hoisted_requires
            .push((name.clone(), entry.0.clone()));
        Expr::Local(name)
    }

    fn hoist_require_subexpr(&mut self, expr: Expr) -> Expr {
        if is_require_call(&expr) {
            return self.materialize_require(expr);
        }
        match expr {
            Expr::MethodCall { object, method, args } => Expr::MethodCall {
                object: Box::new(self.hoist_require_subexpr(*object)),
                method,
                args: args
                    .into_iter()
                    .map(|a| self.hoist_require_subexpr(a))
                    .collect(),
            },
            Expr::Call { func, args } => {
                let rebuilt = Expr::Call {
                    func: Box::new(self.hoist_require_subexpr(*func)),
                    args: args
                        .into_iter()
                        .map(|a| self.hoist_require_subexpr(a))
                        .collect(),
                };
                if is_require_call(&rebuilt) {
                    self.materialize_require(rebuilt)
                } else {
                    rebuilt
                }
            }
            Expr::Index { table, key } => Expr::Index {
                table: Box::new(self.hoist_require_subexpr(*table)),
                key: Box::new(self.hoist_require_subexpr(*key)),
            },
            Expr::Unary { op, arg } => Expr::Unary {
                op,
                arg: Box::new(self.hoist_require_subexpr(*arg)),
            },
            Expr::Binary { op, left, right } => Expr::Binary {
                op,
                left: Box::new(self.hoist_require_subexpr(*left)),
                right: Box::new(self.hoist_require_subexpr(*right)),
            },
            other => other,
        }
    }

    fn jump_target_pc(&self, inst_pc: usize, raw: u32, op: Opcode) -> Option<usize> {
        jump_target_with_starts(
            inst_pc,
            &self.word_starts,
            self.total_words,
            raw,
            op,
        )
    }

    fn resolve_child_proto(&self, d: i32) -> usize {
        self.proto
            .child_indices
            .get(d as usize)
            .copied()
            .unwrap_or(d as u32) as usize
    }

    fn is_named_local(&self, reg: u8, pc: usize) -> bool {
        self.proto.debug_locals.iter().any(|loc| {
            loc.reg == reg && (pc as u32) >= loc.start_pc && (pc as u32) < loc.end_pc
        })
    }

    fn fork_state(&self) -> (HashMap<u8, Expr>, HashMap<u8, (String, Expr)>) {
        (self.regs.clone(), self.pending_namecall.clone())
    }

    fn restore_state(
        &mut self,
        regs: HashMap<u8, Expr>,
        pending_namecall: HashMap<u8, (String, Expr)>,
    ) {
        self.regs = regs;
        self.pending_namecall = pending_namecall;
    }

    fn schedule_block(
        work: &mut Vec<WorkItem>,
        idx: usize,
        indent: String,
        regs: HashMap<u8, Expr>,
        pending_namecall: HashMap<u8, (String, Expr)>,
    ) {
        work.push(WorkItem::Block {
            idx,
            indent,
            regs,
            pending_namecall,
        });
    }

    fn block_is_effectively_empty(&self, block_idx: usize) -> bool {
        if block_idx >= self.blocks.len() {
            return true;
        }
        let b = &self.blocks[block_idx];
        for pc in b.start..b.end {
            if self.skipped_pcs.contains(&pc) {
                continue;
            }
            let op = self.proto.instructions[pc].opcode;
            if opcode_emits_statement(op) {
                return false;
            }
            if matches!(
                op,
                Opcode::NameCall
                    | Opcode::NameCallUdata
                    | Opcode::Call
                    | Opcode::CallFb
                    | Opcode::FastCall
                    | Opcode::FastCall1
                    | Opcode::FastCall2
                    | Opcode::FastCall2K
                    | Opcode::FastCall3
                    | Opcode::SetTable
                    | Opcode::SetTableKs
                    | Opcode::SetTableN
                    | Opcode::SetUdataKs
                    | Opcode::NewTable
                    | Opcode::SetList
            ) {
                return false;
            }
            if op == Opcode::Move {
                let inst = &self.proto.instructions[pc];
                let reg = insn_a(inst.raw);
                if self.is_named_local(reg, pc) && !self.declared_regs.contains(&reg) {
                    return false;
                }
            }
            if matches!(op, Opcode::LoadK | Opcode::LoadKx | Opcode::LoadN) {
                let inst = &self.proto.instructions[pc];
                let reg = insn_a(inst.raw);
                if self.is_named_local(reg, pc) && !self.declared_regs.contains(&reg) {
                    return false;
                }
            }
        }
        true
    }

    /// Walk past aux-only glue blocks (e.g. after `JUMPXEQ*`) to the real branch body.
    fn effective_branch_target(&self, mut block_idx: usize) -> usize {
        for _ in 0..8 {
            if block_idx >= self.blocks.len() {
                return block_idx;
            }
            if !self.block_is_effectively_empty(block_idx) {
                return block_idx;
            }
            let b = &self.blocks[block_idx];
            let linear = b.successors.iter().find(|&&s| {
                s != self.exit_block && self.blocks[s].start == b.end
            });
            match linear {
                Some(&next) => block_idx = next,
                None => return block_idx,
            }
        }
        block_idx
    }

    fn linear_successor(&self, block_idx: usize) -> Option<usize> {
        if block_idx >= self.blocks.len() {
            return None;
        }
        let b = &self.blocks[block_idx];
        b.successors.iter().copied().find(|&s| {
            s != self.exit_block
                && s < self.blocks.len()
                && self.blocks[s].start == b.end
        })
    }

    fn blocks_through_glue(&self, start: usize, end: usize) -> Vec<usize> {
        if start >= self.blocks.len() {
            return Vec::new();
        }
        if end >= self.blocks.len() {
            return vec![start];
        }
        let (from, to) = if self.blocks[start].start <= self.blocks[end].start {
            (start, end)
        } else {
            (end, start)
        };
        let mut out = Vec::new();
        let mut bi = from;
        for _ in 0..4096 {
            out.push(bi);
            if bi == to {
                break;
            }
            let Some(next) = self.linear_successor(bi) else {
                break;
            };
            if self.blocks[next].start > self.blocks[to].start {
                break;
            }
            bi = next;
        }
        out
    }

    fn block_has_table_build_ops(&self, block_idx: usize) -> bool {
        if block_idx >= self.blocks.len() {
            return false;
        }
        let b = &self.blocks[block_idx];
        for pc in b.start..b.end {
            if self.skipped_pcs.contains(&pc) {
                continue;
            }
            if matches!(
                self.proto.instructions[pc].opcode,
                Opcode::SetTableKs
                    | Opcode::SetTable
                    | Opcode::NewTable
                    | Opcode::DupTable
                    | Opcode::GetTableKs
            ) {
                return true;
            }
        }
        false
    }

    fn should_schedule_branch_from_start(&self, start: usize, end: usize) -> bool {
        if start >= self.blocks.len() || end >= self.blocks.len() || start == end {
            return false;
        }
        if self.emitted_blocks.contains(&start) {
            return false;
        }
        self.blocks_through_glue(start, end)
            .iter()
            .filter(|bi| self.block_has_table_build_ops(**bi))
            .count()
            >= 3
    }

    fn contribute_branch_chain(
        &mut self,
        work: &mut Vec<WorkItem>,
        start: usize,
        end: usize,
        from_block: usize,
        indent: String,
        regs: HashMap<u8, Expr>,
        pending_namecall: HashMap<u8, (String, Expr)>,
    ) {
        let target = if self.should_schedule_branch_from_start(start, end) {
            start
        } else {
            end
        };
        self.contribute_block(
            work,
            target,
            from_block,
            indent,
            regs,
            pending_namecall,
        );
    }

    fn contribute_block(
        &mut self,
        work: &mut Vec<WorkItem>,
        target: usize,
        from_block: usize,
        indent: String,
        regs: HashMap<u8, Expr>,
        pending_namecall: HashMap<u8, (String, Expr)>,
    ) {
        if target >= self.blocks.len() {
            return;
        }
        let pred_count = self.blocks[target].predecessors.len();
        if pred_count <= 1 || self.loop_headers.contains(&target) {
            Self::schedule_block(work, target, indent, regs, pending_namecall);
            return;
        }
        let entry = self.join_contributions.entry(target).or_default();
        if entry.iter().any(|(p, _, _)| *p == from_block) {
            return;
        }
        entry.push((from_block, regs, pending_namecall));
        if entry.len() >= pred_count {
            let reg_maps: Vec<_> = entry.iter().map(|(_, r, _)| r.clone()).collect();
            let pend_maps: Vec<_> = entry.iter().map(|(_, _, p)| p.clone()).collect();
            let merged_regs = merge_reg_maps(&reg_maps);
            let merged_pending = merge_pending_maps(&pend_maps);
            self.join_contributions.remove(&target);
            Self::schedule_block(work, target, indent, merged_regs, merged_pending);
        }
    }

    fn is_repeat_exit_jump(&self, fall: Option<usize>, jump_succ: Option<usize>) -> bool {
        fall.map(|b| self.repeat_tail_blocks.contains(&b))
            .unwrap_or(false)
            || jump_succ
                .map(|b| self.repeat_tail_blocks.contains(&b))
                .unwrap_or(false)
    }

    fn emit_if_then(
        &mut self,
        work: &mut Vec<WorkItem>,
        out: &mut String,
        indent: &str,
        block_idx: usize,
        cond: &str,
        taken_block: usize,
        fall: Option<usize>,
        fork_regs: HashMap<u8, Expr>,
        fork_pending: HashMap<u8, (String, Expr)>,
    ) {
        let taken_start = taken_block;
        let fall_start = fall;
        let taken_end = self.effective_branch_target(taken_block);
        let fall_end = fall.map(|fb| self.effective_branch_target(fb));
        if fall_end == Some(taken_end) {
            self.contribute_branch_chain(
                work,
                taken_start,
                taken_end,
                block_idx,
                indent.to_string(),
                fork_regs,
                fork_pending,
            );
            return;
        }
        let taken_empty = self.block_is_effectively_empty(taken_end);
        let fall_empty = fall_end
            .map(|b| self.block_is_effectively_empty(b))
            .unwrap_or(true);

        if taken_empty && fall_empty {
            return;
        }
        if taken_empty && !fall_empty {
            out.push_str(&format!("{indent}if not ({cond}) then\n"));
            work.push(WorkItem::CloseBlock {
                indent: indent.to_string(),
            });
            self.contribute_branch_chain(
                work,
                fall_start.unwrap(),
                fall_end.unwrap(),
                block_idx,
                format!("{indent}    "),
                fork_regs,
                fork_pending,
            );
            return;
        }
        if fall_empty && !taken_empty {
            out.push_str(&format!("{indent}if {cond} then\n"));
            work.push(WorkItem::CloseBlock {
                indent: indent.to_string(),
            });
            self.contribute_branch_chain(
                work,
                taken_start,
                taken_end,
                block_idx,
                format!("{indent}    "),
                fork_regs,
                fork_pending,
            );
            return;
        }
        // Stack is LIFO: push else/fall before taken so taken emits under `if`, then else, then fall.
        out.push_str(&format!("{indent}if {cond} then\n"));
        work.push(WorkItem::CloseBlock {
            indent: indent.to_string(),
        });
        if let (Some(fs), Some(fe)) = (fall_start, fall_end) {
            self.contribute_branch_chain(
                work,
                fs,
                fe,
                block_idx,
                format!("{indent}    "),
                fork_regs.clone(),
                fork_pending.clone(),
            );
            work.push(WorkItem::EmitLine(format!("{indent}else\n")));
        }
        self.contribute_branch_chain(
            work,
            taken_start,
            taken_end,
            block_idx,
            format!("{indent}    "),
            fork_regs,
            fork_pending,
        );
    }

    fn repeat_until_condition(proto: &Proto, inst: &Instruction, pc: usize) -> String {
        match inst.opcode {
            Opcode::JumpIf => reg_name(proto, insn_a(inst.raw), pc),
            Opcode::JumpIfNot => format!("not ({})", reg_name(proto, insn_a(inst.raw), pc)),
            Opcode::JumpIfEq => format!(
                "{} == {}",
                reg_name(proto, insn_a(inst.raw), pc),
                reg_name(proto, reg_aux(inst), pc)
            ),
            Opcode::JumpIfNeq => format!(
                "{} ~= {}",
                reg_name(proto, insn_a(inst.raw), pc),
                reg_name(proto, reg_aux(inst), pc)
            ),
            Opcode::JumpIfLe => format!(
                "{} <= {}",
                reg_name(proto, insn_a(inst.raw), pc),
                reg_name(proto, reg_aux(inst), pc)
            ),
            Opcode::JumpIfLt => format!(
                "{} < {}",
                reg_name(proto, insn_a(inst.raw), pc),
                reg_name(proto, reg_aux(inst), pc)
            ),
            Opcode::JumpIfNotLe => format!(
                "{} > {}",
                reg_name(proto, insn_a(inst.raw), pc),
                reg_name(proto, reg_aux(inst), pc)
            ),
            Opcode::JumpIfNotLt => format!(
                "{} >= {}",
                reg_name(proto, insn_a(inst.raw), pc),
                reg_name(proto, reg_aux(inst), pc)
            ),
            _ => reg_name(proto, insn_a(inst.raw), pc),
        }
    }

    fn render_repeat_until_cond(&mut self, pc: usize) -> String {
        let inst = self.proto.instructions[pc].clone();
        let mut symbolic_reg = |reg: u8| {
            let name = reg_name(self.proto, reg, pc);
            let rendered = self.reg(reg, pc).render();
            if name.starts_with('r')
                && (rendered.parse::<f64>().is_ok()
                    || rendered == "true"
                    || rendered == "false"
                    || rendered == "nil")
            {
                name
            } else {
                rendered
            }
        };
        match inst.opcode {
            Opcode::JumpIf => simplify_condition(&symbolic_reg(insn_a(inst.raw))),
            Opcode::JumpIfNot => {
                format!("not ({})", simplify_condition(&symbolic_reg(insn_a(inst.raw))))
            }
            Opcode::JumpIfEq | Opcode::JumpIfNeq | Opcode::JumpIfLe | Opcode::JumpIfLt
            | Opcode::JumpIfNotLe | Opcode::JumpIfNotLt => {
                simplify_condition(&self.jump_compare_condition(&inst, pc))
            }
            _ => Self::repeat_until_condition(self.proto, &inst, pc),
        }
    }

    fn repeat_header_for_tail(&self, tail_bi: usize) -> Option<usize> {
        if tail_bi >= self.blocks.len() {
            return None;
        }
        let b = &self.blocks[tail_bi];
        if b.end <= b.start {
            return None;
        }
        let last_pc = b.end - 1;
        let inst = &self.proto.instructions[last_pc];
        if inst.opcode != Opcode::JumpBack {
            return None;
        }
        self.jump_target_pc(last_pc, inst.raw, inst.opcode)
            .map(|t| self.block_index(t))
    }

    fn emit_repeat_until_from_jumpif(
        &mut self,
        work: &mut Vec<WorkItem>,
        out: &mut String,
        indent: &str,
        block_idx: usize,
        jumpif_block: usize,
        body_block: usize,
        exit_block: Option<usize>,
        fork_regs: HashMap<u8, Expr>,
        fork_pending: HashMap<u8, (String, Expr)>,
    ) {
        self.handled_repeat_jumpif_blocks.insert(jumpif_block);
        out.push_str(&format!("{indent}repeat\n"));
        let body_start = self
            .repeat_header_for_tail(body_block)
            .unwrap_or(body_block);
        if let Some(header) = self.repeat_header_for_tail(body_block) {
            self.repeat_open_headers.insert(header);
        }
        if let Some(exit) = exit_block {
            self.contribute_branch_chain(
                work,
                exit,
                self.effective_branch_target(exit),
                block_idx,
                indent.to_string(),
                fork_regs.clone(),
                fork_pending.clone(),
            );
        }
        self.contribute_branch_chain(
            work,
            body_start,
            self.effective_branch_target(body_block),
            block_idx,
            format!("{indent}    "),
            fork_regs,
            fork_pending,
        );
    }

    fn analyze_loops(&mut self) {
        self.loop_headers.clear();
        self.while_headers.clear();
        self.repeat_headers.clear();
        self.repeat_until.clear();
        self.repeat_until_pc.clear();
        self.repeat_open_headers.clear();
        self.handled_repeat_jumpif_blocks.clear();
        self.repeat_tail_blocks.clear();
        let n = self.proto.instructions.len();
        for bi in 0..self.blocks.len() {
            let end_pc = self.blocks[bi].end.saturating_sub(1);
            if end_pc >= n {
                continue;
            }
            let inst = &self.proto.instructions[end_pc];
            if !matches!(inst.opcode, Opcode::JumpBack) {
                continue;
            }
            let Some(tgt) = self.jump_target_pc(end_pc, inst.raw, inst.opcode) else {
                continue;
            };
            let header = self.block_index(tgt);
            self.loop_headers.insert(header);

            if self.blocks[bi].end >= 2 {
                let prev_pc = self.blocks[bi].end - 2;
                let prev = &self.proto.instructions[prev_pc];
                if is_two_way_branch(prev.opcode) && !self.is_while_header(header) {
                    self.repeat_headers.insert(header);
                    self.repeat_tail_blocks.insert(bi);
                    let until_cond = Self::repeat_until_condition(self.proto, prev, prev_pc);
                    self.repeat_until.insert(header, until_cond);
                    self.repeat_until_pc.insert(header, prev_pc);
                }
            }
        }
        for header in self.loop_headers.clone() {
            if self.is_while_header(header) {
                self.while_headers.insert(header);
            }
        }
    }

    fn is_while_header(&self, block_idx: usize) -> bool {
        let block = &self.blocks[block_idx];
        if block.end <= block.start {
            return false;
        }
        let last_pc = block.end - 1;
        if last_pc >= self.proto.instructions.len() {
            return false;
        }
        let last = &self.proto.instructions[last_pc];
        if last.opcode != Opcode::JumpIfNot {
            return false;
        }
        let jump_succ = self
            .jump_target_pc(last_pc, last.raw, last.opcode)
            .map(|t| self.block_index(t));
        block.successors.iter().any(|s| Some(*s) != jump_succ) && jump_succ.is_some()
    }

    fn scan_closure_captures(&mut self) {
        self.closure_captures.clear();
        let n = self.proto.instructions.len();
        let mut pc = 0usize;
        while pc < n {
            let inst = &self.proto.instructions[pc];
            if matches!(inst.opcode, Opcode::NewClosure | Opcode::DupClosure) {
                let child = if inst.opcode == Opcode::DupClosure {
                    if let Some(Constant::Closure(idx)) = self.proto.constants.get(insn_d(inst.raw) as usize)
                    {
                        *idx as usize
                    } else {
                        self.resolve_child_proto(insn_d(inst.raw))
                    }
                } else {
                    self.resolve_child_proto(insn_d(inst.raw))
                };
                let mut caps = Vec::new();
                let mut cap_names = Vec::new();
                let mut q = pc + 1;
                while q < n && self.proto.instructions[q].opcode == Opcode::Capture {
                    let cap = &self.proto.instructions[q];
                    let kind = match insn_a(cap.raw) {
                        0 => "val",
                        1 => "ref",
                        2 => "upval",
                        _ => "cap",
                    };
                    let src = insn_b(cap.raw);
                    let name = if kind == "upval" {
                        self.upval_display_name(src)
                    } else {
                        reg_name(self.proto, src, q)
                    };
                    cap_names.push(name.clone());
                    caps.push(format!("{kind} {name}"));
                    self.skipped_pcs.insert(q);
                    q += 1;
                }
                if !caps.is_empty() {
                    self.closure_captures.insert(child, caps);
                    self.closure_upval_names.insert(child, cap_names);
                }
            }
            pc += 1;
        }
    }

    fn start_table(&mut self, reg: u8, template_keys: Option<Vec<String>>) {
        self.table_builds.insert(
            reg,
            TableBuild {
                array: HashMap::new(),
                hash: HashMap::new(),
                template_keys,
            },
        );
    }

    fn table_add_array(&mut self, reg: u8, base: usize, start_reg: u8, count: usize, pc: usize) {
        if !self.table_builds.contains_key(&reg) {
            return;
        }
        let vals: Vec<Expr> = (0..count)
            .map(|i| self.reg(start_reg.wrapping_add(i as u8), pc))
            .collect();
        if let Some(build) = self.table_builds.get_mut(&reg) {
            for (i, val) in vals.into_iter().enumerate() {
                build.array.insert(base + 1 + i, val);
            }
        }
    }

    fn table_add_hash(&mut self, reg: u8, key: String, val: Expr) {
        if let Some(build) = self.table_builds.get_mut(&reg) {
            build.hash.insert(key, val);
        }
    }

    fn finalize_table_reg(&mut self, reg: u8) -> Option<Expr> {
        let build = self.table_builds.remove(&reg)?;
        let mut array: Vec<(usize, Expr)> = build.array.into_iter().collect();
        array.sort_by_key(|(idx, _)| *idx);
        let mut hash: HashMap<String, Expr> = build.hash;
        if let Some(keys) = build.template_keys {
            for key in keys {
                hash.entry(key).or_insert(Expr::Nil);
            }
        }
        let hash: Vec<(String, Expr)> = hash.into_iter().collect();
        Some(Expr::TableLiteral { array, hash })
    }

    fn materialize_table(&mut self, reg: u8) {
        if let Some(expr) = self.finalize_table_reg(reg) {
            self.regs.insert(reg, expr);
        }
    }

    fn try_short_circuit_and(&mut self, cond_reg: u8, cond_pc: usize, result_reg: u8, false_val: bool) {
        let left = self.reg(cond_reg, cond_pc);
        if let Some(right) = self.regs.get(&result_reg).cloned() {
            if right != Expr::Bool(false_val) {
                self.set_reg(
                    result_reg,
                    Expr::Binary {
                        op: "and",
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    cond_pc,
                );
            }
        }
    }

    fn push_cfg_edge(&mut self, from: usize, to: usize) {
        if from >= self.blocks.len() || to >= self.blocks.len() {
            return;
        }
        if !self.blocks[from].successors.contains(&to) {
            self.blocks[from].successors.push(to);
        }
        if !self.blocks[to].predecessors.contains(&from) {
            self.blocks[to].predecessors.push(from);
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
            self.exit_block = 0;
            return;
        }

        let mut leaders = HashSet::new();
        leaders.insert(0);
        leaders.insert(n);
        for (pc, inst) in self.proto.instructions.iter().enumerate() {
            if let Some(tgt) = self.jump_target_pc(pc, inst.raw, inst.opcode) {
                leaders.insert(tgt);
            }
            if inst.opcode.terminates_block() && pc + 1 < n {
                leaders.insert(pc + 1);
            }
            if is_two_way_branch(inst.opcode) {
                if pc + 1 < n {
                    leaders.insert(pc + 1);
                }
            }
            if matches!(
                inst.opcode,
                Opcode::ForNPrep | Opcode::ForGPrep | Opcode::ForGPrepInext | Opcode::ForGPrepNext
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
        self.exit_block = self
            .blocks
            .iter()
            .position(|b| b.start == n && b.end == n)
            .unwrap_or_else(|| {
                let idx = self.blocks.len();
                self.blocks.push(BasicBlock {
                    start: n,
                    end: n,
                    successors: vec![],
                    predecessors: vec![],
                });
                idx
            });

        for bi in 0..self.blocks.len() {
            let end_pc = self.blocks[bi].end.saturating_sub(1);
            if end_pc >= n {
                continue;
            }
            let inst = &self.proto.instructions[end_pc];
            match inst.opcode {
                Opcode::Jump | Opcode::JumpBack | Opcode::JumpX => {
                    let t = self.resolve_jump_block(end_pc, inst.raw, inst.opcode);
                    self.push_cfg_edge(bi, t);
                }
                Opcode::ForNLoop | Opcode::ForGLoop => {
                    let t = self.resolve_jump_block(end_pc, inst.raw, inst.opcode);
                    self.push_cfg_edge(bi, t);
                    if bi + 1 < self.blocks.len() {
                        self.push_cfg_edge(bi, bi + 1);
                    }
                }
                _ if is_two_way_branch(inst.opcode) => {
                    let t = self.resolve_jump_block(end_pc, inst.raw, inst.opcode);
                    self.push_cfg_edge(bi, t);
                    if bi + 1 < self.blocks.len() {
                        self.push_cfg_edge(bi, bi + 1);
                    }
                }
                Opcode::ForNPrep => {
                    if bi + 1 < self.blocks.len() {
                        self.push_cfg_edge(bi, bi + 1);
                    }
                    let t = self.resolve_jump_block(end_pc, inst.raw, inst.opcode);
                    self.push_cfg_edge(bi, t);
                }
                Opcode::ForGPrep | Opcode::ForGPrepInext | Opcode::ForGPrepNext => {
                    if end_pc + 1 < n {
                        let next = self.block_index(end_pc + 1);
                        self.push_cfg_edge(bi, next);
                    }
                    let t = self.resolve_jump_block(end_pc, inst.raw, inst.opcode);
                    self.push_cfg_edge(bi, t);
                }
                Opcode::LoadB if insn_c(inst.raw) != 0 => {
                    let t = self.resolve_jump_block(end_pc, inst.raw, inst.opcode);
                    self.push_cfg_edge(bi, t);
                }
                Opcode::Return => {}
                _ => {
                    if bi + 1 < self.blocks.len() {
                        self.push_cfg_edge(bi, bi + 1);
                    }
                }
            }
        }
        self.analyze_loops();
        self.analyze_generic_fors();
        self.analyze_loop_bodies();
        self.infer_upval_names();
        self.infer_reg_provenance();
        self.scan_closure_captures();
    }

    fn analyze_loop_bodies(&mut self) {
        self.loop_body_blocks.clear();
        for &header in &self.loop_headers {
            let mut stack = vec![header];
            let mut seen = HashSet::new();
            while let Some(bi) = stack.pop() {
                if bi >= self.blocks.len() || !seen.insert(bi) {
                    continue;
                }
                self.loop_body_blocks.insert(bi);
                for &succ in &self.blocks[bi].successors {
                    if succ == self.exit_block {
                        continue;
                    }
                    if succ == header && bi != header {
                        continue;
                    }
                    stack.push(succ);
                }
            }
        }
    }

    fn analyze_generic_fors(&mut self) {
        self.generic_for_latches.clear();
        let n = self.proto.instructions.len();
        for bi in 0..self.blocks.len() {
            let end_pc = self.blocks[bi].end.saturating_sub(1);
            if end_pc >= n {
                continue;
            }
            let inst = &self.proto.instructions[end_pc];
            if !matches!(
                inst.opcode,
                Opcode::ForGPrep | Opcode::ForGPrepInext | Opcode::ForGPrepNext
            ) {
                continue;
            }
            let latch_pc = self.resolve_jump_block(end_pc, inst.raw, inst.opcode);
            let latch_bi = self.block_index(latch_pc);
            self.generic_for_latches.insert(latch_bi);
        }
    }

    fn is_anonymous_proto_name(name: &str) -> bool {
        name.is_empty() || name == "anonymous" || name == "<anonymous>"
    }

    fn resolve_closure_child(&self, inst: &Instruction) -> Option<usize> {
        match inst.opcode {
            Opcode::NewClosure => Some(self.resolve_child_proto(insn_d(inst.raw))),
            Opcode::DupClosure => {
                if let Some(Constant::Closure(idx)) =
                    self.proto.constants.get(insn_d(inst.raw) as usize)
                {
                    Some(*idx as usize)
                } else {
                    Some(self.resolve_child_proto(insn_d(inst.raw)))
                }
            }
            _ => None,
        }
    }

    fn closure_hoist_name(&self, pc: usize) -> Option<(usize, String)> {
        let inst = &self.proto.instructions[pc];
        let child = self.resolve_closure_child(inst)?;
        if let Some(proto) = self.chunk.protos.get(child) {
            if let Some(name) = proto.debug_name.as_ref() {
                if !Self::is_anonymous_proto_name(name) {
                    return Some((child, name.clone()));
                }
            }
        }
        let mut reg = insn_a(inst.raw);
        let mut q = pc + 1;
        let n = self.proto.instructions.len();
        while q < n && self.proto.instructions[q].opcode == Opcode::Capture {
            q += 1;
        }
        if q < n && self.proto.instructions[q].opcode == Opcode::Move {
            let mv = &self.proto.instructions[q];
            if insn_b(mv.raw) == reg {
                reg = insn_a(mv.raw);
            }
        }
        if self.is_named_local(reg, pc) {
            return Some((child, reg_name(self.proto, reg, pc)));
        }
        None
    }

    fn collect_named_closures(&self) -> Vec<(usize, String)> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for pc in 0..self.proto.instructions.len() {
            if !matches!(
                self.proto.instructions[pc].opcode,
                Opcode::NewClosure | Opcode::DupClosure
            ) {
                continue;
            }
            let Some((child, name)) = self.closure_hoist_name(pc) else {
                continue;
            };
            if seen.insert(child) {
                out.push((child, name));
            }
        }
        out
    }

    fn install_hoisted_closures(&mut self, ordered: &[(usize, String)]) {
        self.hoisted_closures = ordered.iter().cloned().collect();
        self.hoisted_closure_names = ordered.iter().map(|(_, name)| name.clone()).collect();
    }

    fn is_hoisted_closure_expr(&self, expr: &Expr) -> bool {
        matches!(expr, Expr::Local(name) if self.hoisted_closure_names.contains(name))
    }

    fn emit_hoisted_closure(&self, child: usize, display_name: &str, parent_indent: &str) -> String {
        let proto = match self.chunk.protos.get(child) {
            Some(p) => p,
            None => return String::new(),
        };
        let body_base = indent_add(parent_indent);
        let mut inner = FunctionDecompiler::new(self.chunk, proto);
        if let Some(names) = self.closure_upval_names.get(&child) {
            for (i, name) in names.iter().enumerate() {
                inner.upval_override_names.insert(i as u8, name.clone());
            }
        }
        inner.build_cfg();
        let ordered = inner.collect_named_closures();
        inner.install_hoisted_closures(&ordered);
        let mut nested = String::new();
        for (idx, name) in &ordered {
            nested.push_str(&inner.emit_hoisted_closure(*idx, name, &body_base));
        }
        let mut params = Vec::new();
        for i in 0..proto.num_params {
            params.push(reg_name(proto, i, 0));
        }
        if proto.is_vararg {
            params.push("...".into());
        }
        let params = params.join(", ");
        let raw_body = inner.emit_function_body(&body_base);
        let (body, _, builder_hoists) = finalize_emitted_body_opts(&raw_body, true, false);
        let hoist_prelude = builder_hoist_prelude(&body_base, &builder_hoists);
        format!(
            "{parent_indent}local {display_name} = function({params})\n{nested}{hoist_prelude}{body}{parent_indent}end\n"
        )
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

        let ordered = self.collect_named_closures();
        self.install_hoisted_closures(&ordered);
        let mut prelude = String::new();
        for (child_idx, hoisted_name) in &ordered {
            prelude.push_str(&self.emit_hoisted_closure(*child_idx, hoisted_name, "    "));
        }

        let (mut body, text_hoists, builder_hoists) = finalize_emitted_body(&self.emit_function_body("    "));

        let mut import_prelude = String::new();
        for (name, expr) in self.hoisted_requires.clone() {
            let rendered = expr.render();
            if body.contains(&rendered) {
                body = body.replace(&rendered, &name);
            }
            import_prelude.push_str(&format!("    local {name} = {rendered}\n"));
        }
        for (name, expr) in text_hoists {
            if !import_prelude.contains(&format!("local {name} =")) {
                import_prelude.push_str(&format!("    local {name} = {expr}\n"));
            }
        }
        import_prelude.push_str(&builder_hoist_prelude("    ", &builder_hoists));

        let mut out = format!("function {name}({params})\n");
        out.push_str(&import_prelude);
        out.push_str(&prelude);
        out.push_str(&body);
        out = rewrite_connect_handler_refs(&out);
        out = strip_empty_control_blocks(&out);
        out = strip_empty_if_then_end(&out);
        out = strip_empty_control_blocks(&out);
        out = strip_empty_if_then_end(&out);
        out.push_str("end\n\n");
        out
    }

    /// Iterative CFG walk — avoids stack overflow on long JUMPIFNOT chains (Roblox modules).
    fn emit_body(&mut self, base_indent: &str) -> String {
        let mut out = String::new();
        let mut work = vec![WorkItem::Block {
            idx: 0,
            indent: base_indent.to_string(),
            regs: HashMap::new(),
            pending_namecall: HashMap::new(),
        }];

        while let Some(item) = work.pop() {
                match item {
                    WorkItem::EmitLine(line) => {
                        out.push_str(&line);
                    }
                    WorkItem::CloseBlock { indent } => {
                        out.push_str(&format!("{indent}end\n"));
                    }
                    WorkItem::Block {
                        idx: block_idx,
                        indent,
                        regs,
                        pending_namecall,
                    } => {
                    if block_idx >= self.blocks.len() {
                        continue;
                    }
                    if self.generic_for_latches.contains(&block_idx) {
                        continue;
                    }
                    if !self.emitted_blocks.insert(block_idx) {
                        continue;
                    }

                    self.restore_state(regs, pending_namecall);

                    if self.repeat_headers.contains(&block_idx)
                        && !self.repeat_open_headers.contains(&block_idx)
                    {
                        out.push_str(&format!("{indent}repeat\n"));
                    }

                    let block = self.blocks[block_idx].clone();
                    let mut pc = block.start;
                    while pc < block.end {
                        let inst = self.proto.instructions[pc].clone();
                        let skip_repeat_tail = self.repeat_tail_blocks.contains(&block_idx)
                            && pc + 2 == block.end
                            && matches!(
                                inst.opcode,
                                Opcode::JumpIf | Opcode::JumpIfNot
                            );
                        if skip_repeat_tail {
                            pc += 1;
                            continue;
                        }
                        if let Some(s) = self.emit_instruction(pc, &inst, &indent, block_idx) {
                            out.push_str(&s);
                            if inst.opcode == Opcode::Return {
                                break;
                            }
                        }
                        pc += 1;
                    }

                    if block.end <= block.start {
                        continue;
                    }

                    let last_pc = block.end - 1;
                    let last = self.proto.instructions[last_pc].clone();
                    let jump_succ = self
                        .jump_target_pc(last_pc, last.raw, last.opcode)
                        .map(|t| self.block_index(t));
                    let fall = block
                        .successors
                        .iter()
                        .copied()
                        .find(|s| Some(*s) != jump_succ);
                    let (fork_regs, fork_pending) = self.fork_state();

                    match last.opcode {
                        Opcode::Return => {}
                        Opcode::JumpIf => {
                            let reg = insn_a(last.raw);
                            let cond = simplify_condition(&self.reg(reg, last_pc).render());
                            if self.handled_repeat_jumpif_blocks.contains(&block_idx) {
                            } else if self.is_repeat_exit_jump(fall, jump_succ) {
                                if fall
                                    .map(|b| self.repeat_tail_blocks.contains(&b))
                                    .unwrap_or(false)
                                {
                                    self.emit_repeat_until_from_jumpif(
                                        &mut work,
                                        &mut out,
                                        &indent,
                                        block_idx,
                                        block_idx,
                                        fall.unwrap(),
                                        jump_succ,
                                        fork_regs,
                                        fork_pending,
                                    );
                                } else if jump_succ
                                    .map(|b| self.repeat_tail_blocks.contains(&b))
                                    .unwrap_or(false)
                                {
                                    self.emit_repeat_until_from_jumpif(
                                        &mut work,
                                        &mut out,
                                        &indent,
                                        block_idx,
                                        block_idx,
                                        jump_succ.unwrap(),
                                        fall,
                                        fork_regs,
                                        fork_pending,
                                    );
                                } else {
                                    if let Some(fb) = fall {
                                        self.contribute_block(
                                            &mut work,
                                            fb,
                                            block_idx,
                                            indent.clone(),
                                            fork_regs.clone(),
                                            fork_pending.clone(),
                                        );
                                    }
                                    if let Some(tb) = jump_succ {
                                        self.contribute_block(
                                            &mut work,
                                            tb,
                                            block_idx,
                                            indent.clone(),
                                            fork_regs,
                                            fork_pending,
                                        );
                                    }
                                }
                            } else if let Some(taken_block) = jump_succ {
                                self.emit_if_then(
                                    &mut work,
                                    &mut out,
                                    &indent,
                                    block_idx,
                                    &cond,
                                    taken_block,
                                    fall,
                                    fork_regs,
                                    fork_pending,
                                );
                            } else if let Some(fb) = fall {
                                self.contribute_block(
                                    &mut work,
                                    fb,
                                    block_idx,
                                    indent,
                                    fork_regs,
                                    fork_pending,
                                );
                            }
                        }
                        Opcode::JumpIfNot => {
                            let reg = insn_a(last.raw);
                            let cond = simplify_condition(&self.reg(reg, last_pc).render());
                            if let (Some(exit_block), Some(body_block)) = (jump_succ, fall) {
                                if self.while_headers.contains(&block_idx) {
                                    out.push_str(&format!("{indent}while {cond} do\n"));
                                    self.contribute_block(
                                        &mut work,
                                        exit_block,
                                        block_idx,
                                        indent.clone(),
                                        fork_regs.clone(),
                                        fork_pending.clone(),
                                    );
                                    work.push(WorkItem::CloseBlock {
                                        indent: indent.clone(),
                                    });
                                    self.contribute_block(
                                        &mut work,
                                        body_block,
                                        block_idx,
                                        format!("{indent}    "),
                                        fork_regs,
                                        fork_pending,
                                    );
                                } else if self.is_repeat_exit_jump(Some(body_block), Some(exit_block)) {
                                    if let Some(fb) = Some(body_block) {
                                        self.contribute_block(
                                            &mut work,
                                            fb,
                                            block_idx,
                                            indent.clone(),
                                            fork_regs.clone(),
                                            fork_pending.clone(),
                                        );
                                    }
                                    self.contribute_block(
                                        &mut work,
                                        exit_block,
                                        block_idx,
                                        indent.clone(),
                                        fork_regs,
                                        fork_pending,
                                    );
                                } else {
                                    self.emit_if_then(
                                        &mut work,
                                        &mut out,
                                        &indent,
                                        block_idx,
                                        &format!("not ({cond})"),
                                        exit_block,
                                        Some(body_block),
                                        fork_regs,
                                        fork_pending,
                                    );
                                }
                            } else if let Some(taken_block) = jump_succ {
                                self.emit_if_then(
                                    &mut work,
                                    &mut out,
                                    &indent,
                                    block_idx,
                                    &format!("not ({cond})"),
                                    taken_block,
                                    fall,
                                    fork_regs,
                                    fork_pending,
                                );
                            } else if let Some(fb) = fall {
                                self.contribute_block(
                                    &mut work,
                                    fb,
                                    block_idx,
                                    indent,
                                    fork_regs,
                                    fork_pending,
                                );
                            }
                        }
                        Opcode::JumpIfEq
                        | Opcode::JumpIfLe
                        | Opcode::JumpIfLt
                        | Opcode::JumpIfNeq
                        | Opcode::JumpIfNotLe
                        | Opcode::JumpIfNotLt => {
                            let cond = simplify_condition(&self.jump_compare_condition(&last, last_pc));
                            if let Some(taken_block) = jump_succ {
                                self.emit_if_then(
                                    &mut work,
                                    &mut out,
                                    &indent,
                                    block_idx,
                                    &cond,
                                    taken_block,
                                    fall,
                                    fork_regs,
                                    fork_pending,
                                );
                            } else if let Some(fb) = fall {
                                self.contribute_block(
                                    &mut work,
                                    fb,
                                    block_idx,
                                    indent,
                                    fork_regs,
                                    fork_pending,
                                );
                            }
                        }
                        Opcode::JumpXEqNil | Opcode::JumpXEqKb | Opcode::JumpXEqKn | Opcode::JumpXEqKs => {
                            let cond = simplify_condition(&self.jump_x_eq_condition(&last, last_pc));
                            if let Some(taken_block) = jump_succ {
                                self.emit_if_then(
                                    &mut work,
                                    &mut out,
                                    &indent,
                                    block_idx,
                                    &cond,
                                    taken_block,
                                    fall,
                                    fork_regs,
                                    fork_pending,
                                );
                            } else if let Some(fb) = fall {
                                self.contribute_block(
                                    &mut work,
                                    fb,
                                    block_idx,
                                    indent,
                                    fork_regs,
                                    fork_pending,
                                );
                            }
                        }
                        Opcode::ForNPrep => {
                            let base = insn_a(last.raw);
                            let r = |o: u8| reg_name(self.proto, base + o, last_pc);
                            if let Some(body_block) = fall {
                                out.push_str(&format!(
                                    "{indent}for {} = {}, {}, {} do\n",
                                    r(3),
                                    self.reg(base + 2, last_pc).render(),
                                    self.reg(base, last_pc).render(),
                                    self.reg(base + 1, last_pc).render(),
                                ));
                                if let Some(exit_block) = jump_succ {
                                    self.contribute_block(
                                        &mut work,
                                        exit_block,
                                        block_idx,
                                        indent.clone(),
                                        fork_regs.clone(),
                                        fork_pending.clone(),
                                    );
                                }
                                work.push(WorkItem::CloseBlock {
                                    indent: indent.clone(),
                                });
                                let (body_regs, body_pending) = self.fork_state();
                                self.contribute_block(
                                    &mut work,
                                    body_block,
                                    block_idx,
                                    format!("{indent}    "),
                                    body_regs,
                                    body_pending,
                                );
                            }
                        }
                        Opcode::ForGPrep | Opcode::ForGPrepInext | Opcode::ForGPrepNext => {
                            let base = insn_a(last.raw);
                            let vars = reg_name(self.proto, base + 3, last_pc);
                            let iter = reg_name(self.proto, base, last_pc);
                            if let Some(body_entry) = fall {
                                let latch_block = jump_succ.unwrap_or(self.exit_block);
                                let latch_start = self.blocks[latch_block].start;
                                let body_start = self.blocks[body_entry].start;
                                out.push_str(&format!("{indent}for {vars} in {iter} do\n"));
                                let (body_regs, body_pending) = self.fork_state();
                                let body_indent = format!("{indent}    ");
                                let mut body_blocks: Vec<usize> = (0..self.blocks.len())
                                    .filter(|&bi| {
                                        bi != block_idx
                                            && bi != latch_block
                                            && bi != self.exit_block
                                            && (self.loop_body_blocks.contains(&bi)
                                                || (self.blocks[bi].start >= body_start
                                                    && self.blocks[bi].start < latch_start))
                                    })
                                    .collect();
                                body_blocks.sort_by_key(|bi| self.blocks[*bi].start);
                                for bi in body_blocks {
                                    self.contribute_block(
                                        &mut work,
                                        bi,
                                        block_idx,
                                        body_indent.clone(),
                                        body_regs.clone(),
                                        body_pending.clone(),
                                    );
                                }
                                work.push(WorkItem::CloseBlock {
                                    indent: indent.clone(),
                                });
                                let exit_block = self.blocks[latch_block]
                                    .successors
                                    .iter()
                                    .copied()
                                    .find(|&s| s != block_idx && s != self.exit_block)
                                    .or_else(|| {
                                        (latch_block + 1 < self.blocks.len())
                                            .then_some(latch_block + 1)
                                    });
                                if let Some(exit) = exit_block {
                                    self.contribute_block(
                                        &mut work,
                                        exit,
                                        block_idx,
                                        indent.clone(),
                                        fork_regs,
                                        fork_pending,
                                    );
                                }
                            }
                        }
                        Opcode::ForNLoop | Opcode::ForGLoop => {
                            if let Some(exit_block) = fall {
                                self.contribute_block(
                                    &mut work,
                                    exit_block,
                                    block_idx,
                                    indent.clone(),
                                    fork_regs,
                                    fork_pending,
                                );
                            }
                        }
                        Opcode::JumpBack => {
                            let tb = self.resolve_jump_block(last_pc, last.raw, last.opcode);
                            let until_cond = self
                                .repeat_until_pc
                                .get(&tb)
                                .map(|&pc| pc)
                                .map(|pc| self.render_repeat_until_cond(pc))
                                .or_else(|| self.repeat_until.get(&tb).cloned());
                            if let Some(until_cond) = until_cond {
                                out.push_str(&format!("{indent}until {until_cond}\n"));
                                if block.end >= 2 {
                                    let prev_pc = block.end - 2;
                                    let prev = &self.proto.instructions[prev_pc];
                                    let exit_block =
                                        self.resolve_jump_block(prev_pc, prev.raw, prev.opcode);
                                    if exit_block != self.exit_block {
                                        self.contribute_block(
                                            &mut work,
                                            exit_block,
                                            block_idx,
                                            indent.clone(),
                                            fork_regs,
                                            fork_pending,
                                        );
                                    }
                                }
                            } else if tb != self.exit_block && !self.emitted_blocks.contains(&tb) {
                                self.contribute_block(
                                    &mut work,
                                    tb,
                                    block_idx,
                                    indent.clone(),
                                    fork_regs,
                                    fork_pending,
                                );
                            }
                        }
                        Opcode::Jump | Opcode::JumpX => {
                            let tb = self.resolve_jump_block(last_pc, last.raw, last.opcode);
                            if tb == self.exit_block {
                                // jump leaves the function
                            } else if self.emitted_blocks.contains(&tb) {
                                out.push_str(&format!(
                                    "{indent}-- goto pc {}\n",
                                    self.blocks[tb].start
                                ));
                            } else {
                                self.contribute_block(
                                    &mut work,
                                    tb,
                                    block_idx,
                                    indent.clone(),
                                    fork_regs,
                                    fork_pending,
                                );
                            }
                        }
        Opcode::LoadB if insn_c(last.raw) != 0 => {
            if let Some(pred) = self.blocks[block_idx].predecessors.first() {
                let pred_block = &self.blocks[*pred];
                if pred_block.end > pred_block.start {
                    let pred_last_pc = pred_block.end - 1;
                    let pred_last = &self.proto.instructions[pred_last_pc];
                    if pred_last.opcode == Opcode::JumpIfNot {
                        let cond_reg = insn_a(pred_last.raw);
                        let result_reg = insn_a(last.raw);
                        let false_val = insn_b(last.raw) != 0;
                        self.try_short_circuit_and(cond_reg, pred_last_pc, result_reg, false_val);
                    }
                }
            }
            if let Some(tgt_block) = jump_succ {
                                self.contribute_block(
                                    &mut work,
                                    tgt_block,
                                    block_idx,
                                    indent.clone(),
                                    fork_regs.clone(),
                                    fork_pending.clone(),
                                );
                            } else if let Some(fb) = fall {
                                self.contribute_block(&mut work, fb, block_idx, indent, fork_regs, fork_pending);
                            }
                        }
                        _ => {
                            let (succ_regs, succ_pending) = self.fork_state();
                            for succ in block.successors.iter().rev() {
                                if !self.emitted_blocks.contains(succ) {
                                    self.contribute_block(
                                        &mut work,
                                        *succ,
                                        block_idx,
                                        indent.clone(),
                                        succ_regs.clone(),
                                        succ_pending.clone(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        for reg in self
            .table_builds
            .keys()
            .copied()
            .collect::<Vec<_>>()
        {
            self.materialize_table(reg);
        }
        out
    }

    fn block_contains(b: &BasicBlock, pc: usize) -> bool {
        if b.start == b.end {
            pc == b.start
        } else {
            pc >= b.start && pc < b.end
        }
    }

    fn block_index_at(blocks: &[BasicBlock], pc: usize) -> Option<usize> {
        blocks.iter().position(|b| Self::block_contains(b, pc))
    }

    fn resolve_jump_block(&self, inst_pc: usize, raw: u32, op: Opcode) -> usize {
        self.jump_target_pc(inst_pc, raw, op)
            .map(|t| self.block_index(t))
            .unwrap_or(self.exit_block)
    }

    fn block_index(&self, pc: usize) -> usize {
        Self::block_index_at(&self.blocks, pc).unwrap_or(self.exit_block)
    }

    fn emit_instruction(&mut self, pc: usize, inst: &Instruction, indent: &str, block_idx: usize) -> Option<String> {
        if self.skipped_pcs.contains(&pc) {
            return None;
        }
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
                let expr = Expr::Number(d as f64);
                if let Some(line) = self.emit_local_assign(a, expr.clone(), pc, indent) {
                    Some(line)
                } else {
                    self.set_reg(a, expr, pc);
                    None
                }
            }
            Opcode::LoadK => {
                let expr = self.const_expr(d as u16);
                if let Some(line) = self.emit_local_assign(a, expr.clone(), pc, indent) {
                    Some(line)
                } else {
                    self.set_reg(a, expr, pc);
                    None
                }
            }
            Opcode::LoadKx => {
                let expr = self.const_expr(inst.aux.unwrap_or(0) as u16);
                if let Some(line) = self.emit_local_assign(a, expr.clone(), pc, indent) {
                    Some(line)
                } else {
                    self.set_reg(a, expr, pc);
                    None
                }
            }
            Opcode::Move => {
                if self.table_builds.contains_key(&b) {
                    self.materialize_table(b);
                }
                self.table_builds.remove(&a);
                let v = self.reg(b, pc);
                if let Some(line) = self.emit_local_assign(a, v.clone(), pc, indent) {
                    Some(line)
                } else {
                    self.set_reg(a, v, pc);
                    None
                }
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
                self.set_reg(a, self.upval_expr(b), pc);
                None
            }
            Opcode::Setupval => {
                let name = self.upval_display_name(b);
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
                let child = if let Some(Constant::Closure(child)) = self.proto.constants.get(d as usize) {
                    *child as usize
                } else {
                    self.resolve_child_proto(insn_d(inst.raw))
                };
                self.set_reg(a, self.closure_expr(child, indent), pc);
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
                if self.table_builds.contains_key(&b) {
                    let key = self.reg(c, pc);
                    let key_str = key.render();
                    self.table_add_hash(b, key_str, val);
                    return None;
                }
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
                let key = self.const_string(inst.aux.unwrap_or(0) as u16);
                if self.table_builds.contains_key(&b) {
                    self.table_add_hash(b, key, val);
                    return None;
                }
                let tbl = self.reg(b, pc);
                Some(format!(
                    "{indent}{}.{} = {}\n",
                    tbl.render(),
                    key,
                    val.render()
                ))
            }
            Opcode::SetUdataKs => {
                let val = self.reg(a, pc);
                let key = self.const_string(inst.aux.unwrap_or(0) as u16);
                if self.table_builds.contains_key(&b) {
                    self.table_add_hash(b, key, val);
                    return None;
                }
                let tbl = self.reg(b, pc);
                Some(format!(
                    "{indent}{}.{} = {}\n",
                    tbl.render(),
                    key,
                    val.render()
                ))
            }
            Opcode::SetTableN => {
                let val = self.reg(a, pc);
                if self.table_builds.contains_key(&b) {
                    let key = (c as u32 + 1).to_string();
                    self.table_add_hash(b, key, val);
                    return None;
                }
                let tbl = self.reg(b, pc);
                Some(format!(
                    "{indent}{}[{}] = {}\n",
                    tbl.render(),
                    c as u32 + 1,
                    val.render()
                ))
            }
            Opcode::Add => self.binop(a, b, c, pc, "+", indent),
            Opcode::Sub => self.binop(a, b, c, pc, "-", indent),
            Opcode::Mul => self.binop(a, b, c, pc, "*", indent),
            Opcode::Div => self.binop(a, b, c, pc, "/", indent),
            Opcode::Mod => self.binop(a, b, c, pc, "%", indent),
            Opcode::Pow => self.binop(a, b, c, pc, "^", indent),
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
                self.start_table(a, None);
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
                let template = match self.proto.constants.get(d as usize) {
                    Some(Constant::Table(keys)) => Some(keys.clone()),
                    _ => None,
                };
                self.start_table(a, template.clone());
                if let Some(keys) = template {
                    let hash: Vec<(String, Expr)> =
                        keys.into_iter().map(|k| (k, Expr::Nil)).collect();
                    self.set_reg(a, Expr::TableLiteral { array: vec![], hash }, pc);
                } else {
                    self.set_reg(a, self.const_expr(d as u16), pc);
                }
                None
            }
            Opcode::GetVarargs => {
                self.set_reg(a, Expr::Varargs, pc);
                None
            }
            Opcode::Call | Opcode::CallFb => {
                let multret = c == 0;
                let nret = if multret { 0 } else { c as usize - 1 };
                let call = if let Some((method, object)) = self.pending_namecall.remove(&a) {
                    let user_argc = if b == 0 {
                        1usize
                    } else {
                        b.saturating_sub(2) as usize
                    };
                    let mut args = Vec::new();
                    for i in 0..user_argc {
                        args.push(self.reg(a + 2 + i as u8, pc));
                    }
                    normalize_method_call(Expr::MethodCall {
                        object: Box::new(object),
                        method,
                        args,
                    })
                } else {
                    let func = self.reg(a, pc);
                    let mut args = Vec::new();
                    if b == 0 {
                        args.push(self.reg(a.wrapping_add(1), pc));
                    } else {
                        let argc = b as usize - 1;
                        for i in 0..argc {
                            args.push(self.reg(a + 1 + i as u8, pc));
                        }
                    }
                    self.build_call_expr(func, args)
                };
                let call = self.hoist_require_subexpr(call);
                if multret {
                    self.set_reg(a, call.clone(), pc);
                    if call_is_side_effect_only(&call) {
                        Some(format!("{indent}{}\n", call.render()))
                    } else {
                        None
                    }
                } else if nret == 0 {
                    Some(format!("{indent}{}\n", call.render()))
                } else if nret == 1 {
                    let is_method = matches!(call, Expr::MethodCall { .. });
                    if self.should_spill_call_result(a, pc, &call) {
                        if let Some(line) = self.emit_forced_local_assign(a, call.clone(), pc, indent) {
                            return Some(line);
                        }
                    }
                    if self.is_named_local(a, pc) && !self.declared_regs.contains(&a) {
                        let line = self.emit_local_assign(a, call.clone(), pc, indent);
                        if let Some(line) = line {
                            Some(line)
                        } else if is_method {
                            self.set_reg(a, call.clone(), pc);
                            Some(format!("{indent}{}\n", call.render()))
                        } else {
                            self.set_reg(a, call, pc);
                            None
                        }
                    } else if is_method {
                        self.set_reg(a, call, pc);
                        None
                    } else {
                        self.set_reg(a, call, pc);
                        None
                    }
                } else {
                    let mut local_names = Vec::new();
                    for i in 0..nret {
                        let reg = a.wrapping_add(i as u8);
                        if self.is_named_local(reg, pc) && !self.declared_regs.contains(&reg) {
                            local_names.push(reg_name(self.proto, reg, pc));
                        }
                    }
                    for i in 0..nret {
                        let reg = a.wrapping_add(i as u8);
                        if i == 0 {
                            self.set_reg(reg, call.clone(), pc);
                        } else {
                            self.set_reg(reg, Expr::Unknown(format!("r{reg}")), pc);
                        }
                    }
                    if local_names.len() >= 2 {
                        for n in &local_names {
                            if let Some(r) = self
                                .proto
                                .debug_locals
                                .iter()
                                .find(|l| l.name == *n)
                                .map(|l| l.reg)
                            {
                                self.declared_regs.insert(r);
                                self.regs.insert(r, Expr::Local(n.clone()));
                            }
                        }
                        Some(format!(
                            "{indent}local {} = {}\n",
                            local_names.join(", "),
                            call.render()
                        ))
                    } else {
                        None
                    }
                }
            }
            Opcode::Return => {
                let count = if b == 0 {
                    if self.proto.is_vararg {
                        0
                    } else {
                        self.proto
                            .max_stack
                            .saturating_sub(a)
                            .max(1) as usize
                    }
                } else {
                    b as usize - 1
                };
                for i in 0..count {
                    let r = a.wrapping_add(i as u8);
                    if self.table_builds.contains_key(&r) {
                        self.materialize_table(r);
                    }
                }
                if b == 0 && self.proto.is_vararg {
                    if self.table_builds.contains_key(&a) {
                        self.materialize_table(a);
                    }
                }
                let vals: Vec<_> = if b == 0 && self.proto.is_vararg {
                    vec!["...".to_string()]
                } else if b == 0 {
                    (0..count)
                        .map(|i| self.reg(a + i as u8, pc).render())
                        .collect()
                } else {
                    (0..count)
                        .map(|i| self.reg(a + i as u8, pc).render())
                        .collect()
                };
                let vals = trim_return_values(vals);
                Some(format!("{indent}return {}\n", vals.join(", ")))
            }
            Opcode::NewClosure => {
                let child = self.resolve_child_proto(d);
                if let Some(hoist_name) = self.hoisted_closures.get(&child).cloned() {
                    if self.is_named_local(a, pc) {
                        let local_name = reg_name(self.proto, a, pc);
                        self.declared_regs.insert(a);
                        self.set_reg(a, Expr::Local(hoist_name.clone()), pc);
                        if local_name == hoist_name {
                            return None;
                        }
                    }
                }
                self.set_reg(a, self.closure_expr(child, indent), pc);
                None
            }
            Opcode::NameCall | Opcode::NameCallUdata => {
                let raw = self.reg(b, pc);
                let obj = self.resolve_method_object(b, &raw);
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
                let start_reg = b;
                let count = if c == 0 { 0 } else { c as usize - 1 };
                let base = inst.aux.unwrap_or(0) as usize;
                if self.table_builds.contains_key(&a) {
                    self.table_add_array(a, base, start_reg, count, pc);
                    return None;
                }
                let tbl = self.reg(a, pc);
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
            Opcode::Capture => None,
            Opcode::CloseUpvals | Opcode::Nop | Opcode::PrepVarargs => None,
            Opcode::Break => {
                if self.loop_body_blocks.contains(&block_idx) {
                    Some(format!("{indent}break\n"))
                } else {
                    None
                }
            }
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
            Opcode::And => self.binop(a, b, c, pc, "and", indent),
            Opcode::Or => self.binop(a, b, c, pc, "or", indent),
            Opcode::AndK => self.binop_k(a, b, c, pc, "and"),
            Opcode::OrK => {
                let left = self.reg(b, pc);
                let right = self.const_expr(c as u16);
                self.set_reg(
                    a,
                    Expr::Binary {
                        op: "or",
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    pc,
                );
                None
            }
            Opcode::Idiv => self.binop(a, b, c, pc, "//", indent),
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

    fn binop(
        &mut self,
        a: u8,
        b: u8,
        c: u8,
        pc: usize,
        op: &'static str,
        indent: &str,
    ) -> Option<String> {
        let mut prefix = String::new();
        let left_expr = self.reg(b, pc);
        let right_expr = self.reg(c, pc);
        if left_expr.render() == right_expr.render() && left_expr.render().contains('(') {
            if let Some(line) = self.emit_forced_local_assign(b, left_expr, pc, indent) {
                prefix.push_str(&line);
            }
        }
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
        if prefix.is_empty() {
            None
        } else {
            Some(prefix)
        }
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
        let call = self.build_call_expr(builtin_expr(name), args);
        let call_pc = pc + arg_c as usize + 1;
        if let Some(next) = self.proto.instructions.get(call_pc) {
            if matches!(next.opcode, Opcode::Call) {
                let base = insn_a(next.raw);
                let call_c = insn_c(next.raw);
                let nret = if call_c == 0 {
                    1
                } else {
                    call_c as usize - 1
                };
                self.mark_fastcall_skip(pc, arg_c);
                if nret <= 1 {
                    self.set_reg(base, call, pc);
                } else {
                    self.set_reg(base, call, pc);
                }
                return;
            }
        }
        self.set_reg(result_reg, call, pc);
    }

    fn mark_fastcall_skip(&mut self, fastcall_pc: usize, jump_c: u8) {
        let call_pc = fastcall_pc + jump_c as usize + 1;
        if call_pc >= self.proto.instructions.len() {
            return;
        }
        for skip in (fastcall_pc + 1)..=call_pc {
            self.skipped_pcs.insert(skip);
        }
    }

    fn emit_forced_local_assign(
        &mut self,
        reg: u8,
        expr: Expr,
        pc: usize,
        indent: &str,
    ) -> Option<String> {
        if self.declared_regs.contains(&reg) {
            return None;
        }
        let name = reg_name(self.proto, reg, pc);
        if self.is_hoisted_closure_expr(&expr) || self.hoisted_closure_names.contains(&name) {
            self.declared_regs.insert(reg);
            self.regs.insert(reg, Expr::Local(name));
            return None;
        }
        self.declared_regs.insert(reg);
        self.regs.insert(reg, Expr::Local(name.clone()));
        Some(format!("{indent}local {name} = {}\n", expr.render()))
    }

    fn instruction_writes_reg(&self, inst: &Instruction, reg: u8) -> bool {
        let a = insn_a(inst.raw);
        match inst.opcode {
            Opcode::Move | Opcode::LoadNil | Opcode::LoadB | Opcode::LoadN | Opcode::LoadK
            | Opcode::LoadKx | Opcode::GetGlobal | Opcode::GetUpval | Opcode::GetImport
            | Opcode::DupClosure | Opcode::NewClosure | Opcode::Not | Opcode::Minus | Opcode::Length => {
                a == reg
            }
            Opcode::Add
            | Opcode::Sub
            | Opcode::Mul
            | Opcode::Div
            | Opcode::Mod
            | Opcode::Pow
            | Opcode::AddK
            | Opcode::SubK
            | Opcode::MulK
            | Opcode::DivK
            | Opcode::ModK
            | Opcode::PowK
            | Opcode::SubRk
            | Opcode::DivRk
            | Opcode::And
            | Opcode::Or
            | Opcode::AndK
            | Opcode::OrK
            | Opcode::Concat
            | Opcode::GetTable
            | Opcode::GetTableKs
            | Opcode::GetTableN
            | Opcode::GetUdataKs => a == reg,
            Opcode::Call | Opcode::CallFb => {
                let c = insn_c(inst.raw);
                let nret = if c == 0 { 1 } else { c as usize - 1 };
                (0..nret).any(|i| a.wrapping_add(i as u8) == reg)
            }
            _ => false,
        }
    }

    fn instruction_reads_reg(&self, inst: &Instruction, reg: u8) -> bool {
        let a = insn_a(inst.raw);
        let b = insn_b(inst.raw);
        let c = insn_c(inst.raw);
        match inst.opcode {
            Opcode::Move => b == reg,
            Opcode::Add
            | Opcode::Sub
            | Opcode::Mul
            | Opcode::Div
            | Opcode::Mod
            | Opcode::Pow
            | Opcode::AddK
            | Opcode::SubK
            | Opcode::MulK
            | Opcode::DivK
            | Opcode::ModK
            | Opcode::PowK
            | Opcode::And
            | Opcode::Or
            | Opcode::AndK
            | Opcode::OrK
            | Opcode::Concat
            | Opcode::GetTable
            | Opcode::SetTable => b == reg || c == reg,
            Opcode::GetTableKs | Opcode::GetTableN | Opcode::GetUdataKs | Opcode::SetTableKs
            | Opcode::SetTableN | Opcode::SetUdataKs => b == reg || a == reg,
            Opcode::SubRk | Opcode::DivRk => c == reg,
            Opcode::JumpIf | Opcode::JumpIfNot => a == reg,
            Opcode::JumpIfEq
            | Opcode::JumpIfLe
            | Opcode::JumpIfLt
            | Opcode::JumpIfNeq
            | Opcode::JumpIfNotLe
            | Opcode::JumpIfNotLt => a == reg || reg_aux(inst) == reg,
            Opcode::JumpXEqNil | Opcode::JumpXEqKb | Opcode::JumpXEqKn | Opcode::JumpXEqKs => {
                a == reg
            }
            Opcode::Call | Opcode::CallFb => {
                let argc = if b == 0 { 1 } else { b as usize - 1 };
                (0..=argc).any(|i| a.wrapping_add(i as u8) == reg)
            }
            Opcode::NameCall | Opcode::NameCallUdata => b == reg || a == reg || a.wrapping_add(1) == reg,
            Opcode::Return => {
                let c = insn_c(inst.raw);
                let nret = if c == 0 { 1 } else { c as usize - 1 };
                (0..nret).any(|i| a.wrapping_add(i as u8) == reg)
            }
            _ => false,
        }
    }

    fn should_spill_call_result(&self, reg: u8, pc: usize, call: &Expr) -> bool {
        if !matches!(call, Expr::Call { .. } | Expr::MethodCall { .. }) {
            return false;
        }
        for future_pc in (pc + 1)..self.proto.instructions.len() {
            let inst = &self.proto.instructions[future_pc];
            if self.instruction_writes_reg(inst, reg) {
                return false;
            }
            if self.instruction_reads_reg(inst, reg) {
                return true;
            }
        }
        false
    }

    fn emit_local_assign(
        &mut self,
        reg: u8,
        expr: Expr,
        pc: usize,
        indent: &str,
    ) -> Option<String> {
        if !self.is_named_local(reg, pc) || self.declared_regs.contains(&reg) {
            return None;
        }
        let name = reg_name(self.proto, reg, pc);
        if self.is_hoisted_closure_expr(&expr) || self.hoisted_closure_names.contains(&name) {
            self.declared_regs.insert(reg);
            self.regs.insert(reg, Expr::Local(name));
            return None;
        }
        self.declared_regs.insert(reg);
        self.regs.insert(reg, Expr::Local(name.clone()));
        Some(format!("{indent}local {name} = {}\n", expr.render()))
    }

    fn jump_compare_condition(&mut self, inst: &Instruction, pc: usize) -> String {
        let left = self.reg(insn_a(inst.raw), pc);
        let right = self.reg(reg_aux(inst), pc);
        match inst.opcode {
            Opcode::JumpIfEq => format!("{} == {}", left.render(), right.render()),
            Opcode::JumpIfNeq => format!("{} ~= {}", left.render(), right.render()),
            Opcode::JumpIfLe => format!("{} <= {}", left.render(), right.render()),
            Opcode::JumpIfLt => format!("{} < {}", left.render(), right.render()),
            Opcode::JumpIfNotLe => format!("{} > {}", left.render(), right.render()),
            Opcode::JumpIfNotLt => format!("{} >= {}", left.render(), right.render()),
            _ => "false".into(),
        }
    }

    fn jump_x_eq_condition(&mut self, inst: &Instruction, pc: usize) -> String {
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
                let ks = format_lua_string_quoted(&self.const_string(aux_kv(aux)));
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
        if let Expr::MethodCall { object, method, args: margs } = &func {
            if method == "GetService" && margs.len() == 1 {
                let obj = object.as_ref();
                let is_game = matches!(
                    obj,
                    Expr::Import(p) if p == "game"
                ) || matches!(obj, Expr::Global(p) if p == "game");
                if is_game {
                    if let Some(svc) = expr_to_string_lit(&margs[0]) {
                        return Expr::MethodCall {
                            object: Box::new(Expr::Import("game".into())),
                            method: "GetService".into(),
                            args: vec![Expr::String(svc)],
                        };
                    }
                }
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

    fn reg(&mut self, r: u8, pc: usize) -> Expr {
        // Do not finalize incremental table literals on every read — that turns SETTABLEKS into
        // `{k1=v1, k2=v2}.k3 = v3` instead of mutating one local table.
        if self.table_builds.contains_key(&r) {
            return self
                .regs
                .get(&r)
                .cloned()
                .unwrap_or_else(|| Expr::Local(reg_name(self.proto, r, pc)));
        }
        self.regs
            .get(&r)
            .cloned()
            .map(|e| match e {
                Expr::Phi { arms, .. } => pick_phi_variant(&arms),
                other => other,
            })
            .map(|e| {
                if e.render() == "nil" {
                    self.resolve_method_object(r, &e)
                } else {
                    e
                }
            })
            .unwrap_or_else(|| {
                if let Some(&uv) = self.reg_upval_slots.get(&r) {
                    return self.upval_expr(uv);
                }
                if let Some(path) = self.reg_import_paths.get(&r) {
                    if !path.starts_with("import_") {
                        return expr_from_import_path(path);
                    }
                }
                Expr::Local(reg_name(self.proto, r, pc))
            })
    }

    fn set_reg(&mut self, r: u8, expr: Expr, pc: usize) {
        let name = reg_name(self.proto, r, pc);
        let expr = self.hoist_require_subexpr(expr);
        let expr = match expr {
            Expr::Local(ref s) if s == &name => expr,
            other => other,
        };
        let keep_provenance = matches!(
            &expr,
            Expr::Import(path) if path == "require" || path.ends_with(".require")
        ) || matches!(&expr, Expr::Global(g) if g == "require");
        if !keep_provenance {
            self.reg_import_paths.remove(&r);
            self.reg_upval_slots.remove(&r);
        }
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
                let hash: Vec<(String, Expr)> =
                    keys.iter().cloned().map(|k| (k, Expr::Nil)).collect();
                Expr::TableLiteral {
                    array: vec![],
                    hash,
                }
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

    fn closure_expr(&self, child: usize, parent_indent: &str) -> Expr {
        if let Some(name) = self.hoisted_closures.get(&child) {
            return Expr::Local(name.clone());
        }
        let proto = match self.chunk.protos.get(child) {
            Some(p) => p,
            None => {
                return Expr::Unknown(format!("function() -- missing proto {child}\nend"));
            }
        };
        let body_base = indent_add(parent_indent);
        let mut params = Vec::new();
        for i in 0..proto.num_params {
            params.push(reg_name(proto, i, 0));
        }
        if proto.is_vararg {
            params.push("...".into());
        }
        let params = params.join(", ");
        let mut inner = FunctionDecompiler::new(self.chunk, proto);
        if let Some(names) = self.closure_upval_names.get(&child) {
            for (i, name) in names.iter().enumerate() {
                inner.upval_override_names.insert(i as u8, name.clone());
            }
        }
        inner.build_cfg();
        inner.infer_upval_names();
        let ordered = inner.collect_named_closures();
        inner.install_hoisted_closures(&ordered);
        let (body, _, builder_hoists) =
            finalize_emitted_body_opts(&inner.emit_function_body(&body_base), true, false);
        let hoist_prelude = builder_hoist_prelude(&body_base, &builder_hoists);
        let capture_comment = self
            .closure_captures
            .get(&child)
            .filter(|c| !c.is_empty() && body.trim().is_empty())
            .map(|caps| format!("{body_base}-- captures: {}\n", caps.join(", ")))
            .unwrap_or_default();
        Expr::Unknown(format!(
            "function({params})\n{capture_comment}{hoist_prelude}{body}{parent_indent}end"
        ))
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

#[cfg(test)]
mod hoist_tests {
    use super::*;

    #[test]
    fn hoist_repeated_builder_chain() {
        let sample = concat!(
            "    arg1:WaitForModule(\"TroopBuilder\").new().setA()\n",
            "    arg1:WaitForModule(\"TroopBuilder\").new().setB()\n",
            "    arg1:WaitForModule(\"TroopBuilder\").new().setC()\n",
        );
        let (out, hoists) = hoist_repeated_builder_chains(sample);
        assert!(!hoists.is_empty(), "expected hoists, got out={out:?}");
        assert!(out.contains("TroopBuilder.setA") || out.contains("TroopBuilder:setA"), "out={out}");
    }

    #[test]
    fn strip_empty_then_else_unwraps() {
        let sample = concat!(
            "        if arg1.resetCameraAngle then\n",
            "        else\n",
            "            local r2 = arg1:GetEnabled()\n",
            "            return\n",
            "        end\n",
        );
        let out = strip_empty_control_blocks(sample);
        assert!(
            !out.contains("if arg1.resetCameraAngle then"),
            "empty-then else should unwrap, got:\n{out}"
        );
        assert!(out.contains("local r2"), "else body preserved: {out}");
    }

    #[test]
    fn strip_empty_if_and_for() {
        let sample = "    if x then\n    else\n        y = 1\n    end\n    for i = 1, 2 do\n    end\n";
        let out = strip_empty_control_blocks(sample);
        assert!(!out.contains("if x then"), "empty if-then should be unwrapped: {out}");
        assert!(out.contains("y = 1"), "else body should remain: {out}");
        assert!(out.contains("for i = 1, 2 do"), "empty for shell kept: {out}");
    }

    #[test]
    fn strip_empty_then_else_with_misindented_end() {
        let sample = concat!(
            "        if arg3 then\n",
            "        else\n",
            "            if not (r11:FindPartOnRayWithIgnoreList(arg1, {})) then\n",
            "                return nil\n",
            "            else\n",
            "                local r9 = r11:FindPartOnRayWithIgnoreList(arg1, {})\n",
            "    end\n",
        );
        let out = strip_empty_control_blocks(sample);
        assert!(
            !out.contains("if arg3 then"),
            "empty-then else should unwrap even with misindented end, got:\n{out}"
        );
    }

    #[test]
    fn finalize_strips_raycast_empty_then_else() {
        let sample = concat!(
            "        if arg3 then\n",
            "        else\n",
            "            if not (r11:FindPartOnRayWithIgnoreList(arg1, {})) then\n",
            "                return nil\n",
            "            else\n",
            "                local r9 = r11:FindPartOnRayWithIgnoreList(arg1, {})\n",
            "    end\n",
        );
        let (out, _, _) = finalize_emitted_body_opts(sample, true, false);
        assert!(
            !out.contains("if arg3 then"),
            "finalize should strip empty-then else in hoisted closure body, got:\n{out}"
        );
    }

    #[test]
    fn click_to_move_raycast_empty_if_stripped() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/corpus_click_to_move.bin");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(path).expect("read click_to_move fixture");
        let chunk = crate::BytecodeReader::read_with_options(
            &bytes,
            crate::bytecode::BytecodeOptions {
                wire: crate::opcode::WireFormat::Auto,
                lenient: true,
            },
        )
        .expect("parse");
        let lua = Decompiler::decompile_chunk(&chunk);
        assert!(
            !lua.contains("if arg3 then"),
            "Raycast empty-then else should be stripped in full decompile, got excerpt:\n{}",
            lua.lines()
                .skip_while(|l| !l.contains("local Raycast = function"))
                .take(12)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn trim_unreachable_after_return_drops_sibling_statements() {
        let sample = concat!(
            "    return\n",
            "    r4 = 1\n",
            "    x = 2\n",
            "end\n",
        );
        let out = trim_unreachable_after_return(sample);
        assert!(out.contains("return"), "return should remain: {out}");
        assert!(!out.contains("r4 = 1"), "dead store after return should be removed: {out}");
        assert!(!out.contains("x = 2"), "dead store after return should be removed: {out}");
    }

    #[test]
    fn rewrite_connect_uses_hoisted_handler_names() {
        let sample = concat!(
            "    local playerAdded = function(arg1)\n",
            "    end\n",
            "    game:GetService(\"Players\").PlayerAdded:Connect(\"playerAdded\")\n",
        );
        let out = rewrite_connect_handler_refs(sample);
        assert!(
            out.contains(":Connect(playerAdded)"),
            "expected unquoted handler ref, got:\n{out}"
        );
        assert!(
            !out.contains(":Connect(\"playerAdded\")"),
            "should not keep quoted handler, got:\n{out}"
        );
    }

    #[test]
    fn queue_handler_emits_mapname() {
        use crate::bytecode::BytecodeOptions;
        use crate::BytecodeReader;
        use crate::WireFormat;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/corpus_queue_script.bin");
        let bytes = std::fs::read(path).expect("queue fixture");
        let chunk = BytecodeReader::read_with_options(
            &bytes,
            BytecodeOptions {
                wire: WireFormat::Auto,
                lenient: true,
            },
        )
        .expect("parse queue");
        let pi = chunk
            .protos
            .iter()
            .position(|p| {
                p.constants
                    .iter()
                    .any(|c| matches!(c, Constant::String(s) if s == "MapName"))
            })
            .expect("queue handler proto");
        let main = &chunk.protos[chunk.main_index];
        let handler = main
            .child_indices
            .first()
            .copied()
            .expect("main child") as usize;
        assert_eq!(handler, pi, "main child index should match MapName proto");
        let proto = &chunk.protos[pi];
        let mut d = FunctionDecompiler::new(&chunk, proto);
        d.build_cfg();
        let ordered = d.collect_named_closures();
        d.install_hoisted_closures(&ordered);
        let body = d.emit_function_body("    ");
        assert!(
            body.contains("MapName"),
            "proto {pi} should include MapName UI path, got:\n{body}"
        );

        let mut main_d = FunctionDecompiler::new(&chunk, main);
        main_d.build_cfg();
        let rendered = main_d.closure_expr(handler, "    ").render();
        assert!(
            rendered.contains("MapName"),
            "closure_expr from main should include MapName, got:\n{rendered}"
        );
    }

    #[test]
    fn trim_unreachable_preserves_nested_function_after_return() {
        let sample = concat!(
            "function main(...)\n",
            "    Connect(function(arg1)\n",
            "    return\n",
            "    r4 = arg1.queueId\n",
            "end)\n",
            "end\n",
        );
        let out = trim_unreachable_after_return(sample);
        assert!(out.contains("r4 = arg1.queueId"), "nested closure body preserved: {out}");
    }
}
