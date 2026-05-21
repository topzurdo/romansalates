use std::{collections::HashSet, fs, net::SocketAddr, panic, path::PathBuf};

use anyhow::Context;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use crate::{
    bytecode::{BytecodeOptions, BytecodeReader},
    decompile::Decompiler,
    disasm::Disassembler,
    opcode::{Opcode, WireFormat},
};

#[derive(Parser, Debug)]
#[command(name = "bytecode_decompiler", version, about = "Luau bytecode decompiler")]
pub struct Args {
    #[arg(long)]
    serve: bool,

    #[arg(long, default_value = "127.0.0.1:31337")]
    bind: SocketAddr,

    #[arg(value_name = "INPUT")]
    input: Option<PathBuf>,

    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long, value_enum, default_value_t = OutputMode::Decompile)]
    mode: OutputMode,

    #[arg(long, help = "Print diagnostic disassembly to stderr on every request")]
    diag: bool,

    #[arg(long, value_enum, default_value_t = WireArg::Auto, help = "Opcode wire encoding")]
    wire: WireArg,

    #[arg(long, help = "Strict validation (fail on unknown opcodes / version mismatch)")]
    strict: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum WireArg {
    Auto,
    Roblox,
    Plain,
}

impl From<WireArg> for WireFormat {
    fn from(v: WireArg) -> Self {
        match v {
            WireArg::Auto => WireFormat::Auto,
            WireArg::Roblox => WireFormat::Roblox227,
            WireArg::Plain => WireFormat::Plain,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputMode {
    Decompile,
    Disassembly,
    RawDump,
}

#[derive(Debug, Deserialize)]
pub struct DecompileRequest {
    pub bytecode: String,
    pub mode: Option<String>,
    /// `auto`, `roblox`, or `plain`
    pub wire: Option<String>,
    /// When true, fail on unknown opcodes / version mismatches
    pub strict: Option<bool>,
}

#[derive(Clone)]
struct ServerState {
    diag: bool,
    wire: WireFormat,
    strict: bool,
}

#[derive(Debug, Serialize)]
pub struct DecompileResponse {
    pub ok: bool,
    pub code: String,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

pub fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    let filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .init();

    // Double-click / no args: run HTTP server for IY `decompile` (window stays open).
    if args.serve || args.input.is_none() {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async move {
            let state = ServerState {
                diag: args.diag,
                wire: args.wire.into(),
                strict: args.strict,
            };
            let app = Router::new()
                .route("/decompile", post(decompile_handler))
                .with_state(state);

            let listener = tokio::net::TcpListener::bind(args.bind).await?;
            eprintln!("Luau bytecode decompiler — server mode");
            eprintln!("Listening on http://{}/decompile", args.bind);
            eprintln!("Keep this window open while using IY: decompile");
            eprintln!("Press Ctrl+C to stop.\n");
            tracing::info!("listening on {}", args.bind);
            axum::serve(listener, app).await.map_err(Into::into)
        })
    } else {
        let input = args.input.unwrap();
        let bytes = fs::read(input.as_path())
            .with_context(|| format!("failed to read input file {}", input.display()))?;
        let (code, _warnings) = decompile_bytes(&bytes, args.mode, args.wire.into(), args.strict)?;

        if let Some(path) = args.output {
            fs::write(&path, &code)
                .with_context(|| format!("failed to write output file {}", path.display()))?;
        } else {
            print!("{code}");
        }
        Ok(())
    }
}

async fn decompile_handler(
    State(state): State<ServerState>,
    Json(req): Json<DecompileRequest>,
) -> impl IntoResponse {
    let mode = match req.mode.as_deref() {
        Some("disassembly") | Some("disasm") => OutputMode::Disassembly,
        Some("raw") | Some("dump") => OutputMode::RawDump,
        _ => OutputMode::Decompile,
    };
    let wire = match req.wire.as_deref() {
        Some("roblox") => WireFormat::Roblox227,
        Some("plain") => WireFormat::Plain,
        Some("auto") | None => state.wire,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(DecompileResponse {
                    ok: false,
                    code: String::new(),
                    error: Some(format!(
                        "invalid wire {other:?}; use auto, roblox, or plain"
                    )),
                    warnings: None,
                }),
            );
        }
    };
    let strict = req.strict.unwrap_or(state.strict);

    let b64_len = req.bytecode.len();
    eprintln!(
        "Request: bytecode_size={b64_len}, mode={mode:?}, wire={wire:?}, strict={strict}",
    );

    match STANDARD.decode(req.bytecode) {
        Ok(bytes) => {
            eprintln!(
                "Decoded bytecode: {} bytes (base64 input {b64_len} chars)",
                bytes.len(),
            );
            if bytes.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(DecompileResponse {
                        ok: false,
                        code: String::new(),
                        error: Some(
                            "[bytecode_unavailable] decoded bytecode is empty — executor may have failed getscriptbytecode"
                                .into(),
                        ),
                        warnings: None,
                    }),
                );
            }
            if state.diag {
                match BytecodeReader::read_with_options(
                    &bytes,
                    BytecodeOptions {
                        wire,
                        lenient: !strict,
                    },
                ) {
                    Ok(chunk) => {
                        eprintln!(
                            "Bytecode version: {}  wire: {:?}",
                            chunk.version, chunk.wire_format
                        );
                        for w in &chunk.warnings {
                            eprintln!("WARNING: {w}");
                        }
                        let disasm = Disassembler::disassemble_chunk(&chunk);
                        eprintln!("=== DIAGNOSTIC DISASSEMBLY ===\n{disasm}\n=== END DIAGNOSTIC ===");
                        let mut unknowns = HashSet::new();
                        for proto in &chunk.protos {
                            for inst in &proto.instructions {
                                if let Opcode::Unknown(v) = inst.opcode {
                                    unknowns.insert(v);
                                }
                            }
                        }
                        if !unknowns.is_empty() {
                            let mut list: Vec<_> = unknowns.into_iter().collect();
                            list.sort_unstable();
                            eprintln!(
                                "UNKNOWN OPCODES: {}",
                                list.iter()
                                    .map(|v| format!("{:02X}", v))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            );
                        }
                    }
                    Err(e) => eprintln!("DIAG parse error: {e}"),
                }
            }
            match panic::catch_unwind(|| decompile_bytes(&bytes, mode, wire, strict)) {
                Ok(Ok((code, warnings))) => {
                    eprintln!("Decompile OK: {} chars output", code.len());
                    if !warnings.is_empty() {
                        eprintln!("Warnings: {}", warnings.len());
                    }
                    (
                        StatusCode::OK,
                        Json(DecompileResponse {
                            ok: true,
                            code,
                            error: None,
                            warnings: if warnings.is_empty() {
                                None
                            } else {
                                Some(warnings)
                            },
                        }),
                    )
                }
                Ok(Err(err)) => {
                    eprintln!("Decompile error: {err}");
                    (
                    StatusCode::BAD_REQUEST,
                    Json(DecompileResponse {
                        ok: false,
                        code: String::new(),
                        error: Some(err.to_string()),
                        warnings: None,
                    }),
                    )
                }
                Err(payload) => {
                    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                        (*s).to_string()
                    } else if let Some(s) = payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "internal panic during decompile".to_string()
                    };
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(DecompileResponse {
                            ok: false,
                            code: String::new(),
                            error: Some(msg),
                            warnings: None,
                        }),
                    )
                }
            }
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(DecompileResponse {
                ok: false,
                code: String::new(),
                error: Some(format!("[invalid_base64] {err}")),
                warnings: None,
            }),
        ),
    }
}

fn decompile_bytes(
    bytes: &[u8],
    mode: OutputMode,
    wire: WireFormat,
    strict: bool,
) -> anyhow::Result<(String, Vec<String>)> {
    let options = BytecodeOptions {
        wire,
        lenient: !strict,
    };
    let chunk = BytecodeReader::read_with_options(bytes, options).map_err(|e| {
        anyhow::anyhow!(
            "[parse_failed] {e}. Try --mode disassembly or raw, or run the server with --diag."
        )
    })?;
    if !chunk.warnings.is_empty() {
        for w in &chunk.warnings {
            eprintln!("bytecode warning: {w}");
        }
    }
    let warnings = chunk.warnings.clone();
    let out = match mode {
        OutputMode::RawDump => format!("{chunk:#?}"),
        OutputMode::Disassembly => {
            let mut s = format!(
                "-- wire: {:?}  version: {}\n",
                chunk.wire_format, chunk.version
            );
            s.push_str(&Disassembler::disassemble_chunk(&chunk));
            s
        }
        OutputMode::Decompile => {
            let mut lua = Decompiler::decompile_chunk(&chunk);
            if !warnings.is_empty() {
                let header: String = warnings
                    .iter()
                    .map(|w| format!("-- warning: {w}\n"))
                    .collect();
                lua = format!("{header}{lua}");
            }
            lua
        }
    };
    Ok((out, warnings))
}
