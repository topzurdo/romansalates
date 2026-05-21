# romansalates

Infinite Yield fork with local Luau bytecode decompiler and custom DEX.

## Load in Roblox

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/topzurdo/romansalates/main/Iy.lua"))()
```

## Decompiler (PC)

1. Run `bytecode_decompiler.exe` (or build with `cargo build --release`).
2. In-game: `decompile` or open DEX via `explorer` / `dex`.

DEX and IY load from this repo by default; local `readfile` copies override when present.

## Build

```bash
cargo build --release
```

Copy `target/release/bytecode_decompiler.exe` to the project root if needed.

## CLI flags

| Flag | Description |
|------|-------------|
| `--serve` | HTTP server for IY/DEX on `:31337` |
| `--diag` | Diagnostic disassembly to **stderr** on each request |
| `--wire auto\|roblox\|plain` | Opcode wire encoding (default: auto) |
| `--strict` | Fail on unknown opcodes / version mismatch |
| `--mode decompile\|disassembly\|raw` | Output mode |

HTTP `POST /decompile` JSON body accepts optional `"wire"` and `"strict"` fields.

## Decompiler limitations

Pseudo-Lua output — not round-trippable source.

**Executor limits:** `getscriptbytecode` only works for client-replicated LocalScripts and ModuleScripts. Server Scripts and many large core modules fail before bytecode reaches the decompiler (`[bytecode_unavailable]`).

**Phase 3 (done):** `repeat`/`until`, table literals (`NewTable`/`SetList`/`DupTable`), closure capture headers, `while`/`JumpIfNot`, join merge, MULTRET, extended disasm.

**Recent improvements:** DupTable key names from string table, generic `for ... in` body recovery, SSA-lite register merge at joins, named nested functions from debug symbols, HTTP `warnings` in JSON responses.

**Still rough:** import/require hoisting, full multi-return destructuring, real-module fixtures (add `.bin` under `crates/bytecode_decompiler/tests/fixtures/`).

**Debug:** run `bytecode_decompiler.exe --serve --diag` and inspect stderr disassembly when output looks wrong.
