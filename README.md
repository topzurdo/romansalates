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
