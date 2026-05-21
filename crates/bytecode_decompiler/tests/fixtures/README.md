# Bytecode fixtures

Place real Roblox Luau bytecode samples here for regression tests. Tests in `golden.rs` load `*.bin` when present.

## Recommended fixtures

| File | Source | Notes |
|------|--------|-------|
| `corpus_*.bin` | Curated export (see `manifest.json`) | Real-game regression set |
| `postoffice.bin` | PostOffice LocalScript (client UI) | Large v9 blob (~30 KB); good CFG/for/table coverage |
| `module_loader.bin` | MultiboxFramework ModuleLoader | Core loader patterns |
| `directory_loader.bin` | DirectoryLoader module | |
| `randoms.bin` | Randoms handle module | |

## Export from in-game

### Bulk export (10–20 random scripts)

Run in executor console (after joining a game):

```lua
loadstring(readfile("bytecodeveryop/scripts/export_bytecode_fixtures.lua"))()
```

Or paste `scripts/export_bytecode_fixtures.lua` into the console.

Writes to `bytecodeveryop/fixtures/export_<timestamp>/` in the executor workspace:

- `fixture_01.bin` … `fixture_N.bin` (short names)
- `manifest.json` (full Roblox paths + quality scores)

The script **filters out** PlayerGui clones, UI templates (`RowTemplate`), tiny handlers (<1.8 KB), and repetitive `InventoryItems` spam. It prefers `ReplicatedStorage`, `StarterGui`, and `PlayerScripts` modules.

Copy good exports as `corpus_<name>.bin` into this folder (see existing `corpus_*.bin` + `manifest.json`).

### Manual export

1. Run `bytecode_decompiler.exe --serve --diag` on PC.
2. In Roblox with IY/DEX: decompile the script or use `getscriptbytecode` + save.
3. Base64-decode the request body field `bytecode`, or write raw bytes with a small script.

Server Scripts and non-replicated modules **cannot** be read via `getscriptbytecode` on the client — that is an executor/Roblox limitation, not a decompiler bug.

Synthetic v9 blobs are built inline in `golden.rs` / `corpus.rs`.
