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
}

#[derive(Debug, Serialize)]
pub struct DecompileResponse {
    pub ok: bool,
    pub code: String,
    pub error: Option<String>,
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
            let app = Router::new()
                .route("/decompile", post(decompile_handler))
                .with_state(args.diag);

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
        let code = decompile_bytes(&bytes, args.mode, args.wire.into(), args.strict)?;

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
    State(diag): State<bool>,
    Json(req): Json<DecompileRequest>,
) -> impl IntoResponse {
    let mode = match req.mode.as_deref() {
        Some("disassembly") | Some("disasm") => OutputMode::Disassembly,
        Some("raw") | Some("dump") => OutputMode::RawDump,
        _ => OutputMode::Decompile,
    };

    eprintln!("Request: bytecode_size={}, mode={:?}", req.bytecode.len(), mode);
    println!("Request: bytecode_size={}, mode={:?}", req.bytecode.len(), mode);

    match STANDARD.decode(req.bytecode) {
        Ok(bytes) => {
            if diag {
                match BytecodeReader::read_with_options(
                    &bytes,
                    BytecodeOptions {
                        wire: WireFormat::Auto,
                        lenient: true,
                    },
                ) {
                    Ok(chunk) => {
                        eprintln!(
                            "Bytecode version: {}  wire: {:?}",
                            chunk.version, chunk.wire_format
                        );
                        println!(
                            "Bytecode version: {}  wire: {:?}",
                            chunk.version, chunk.wire_format
                        );
                        for w in &chunk.warnings {
                            eprintln!("WARNING: {w}");
                            println!("WARNING: {w}");
                        }
                        let disasm = Disassembler::disassemble_chunk(&chunk);
                        eprintln!("=== DIAGNOSTIC DISASSEMBLY ===\n{disasm}\n=== END DIAGNOSTIC ===");
                        println!("=== DIAGNOSTIC DISASSEMBLY ===\n{disasm}\n=== END DIAGNOSTIC ===");
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
                            println!(
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
            match panic::catch_unwind(|| {
                decompile_bytes(&bytes, mode, WireFormat::Auto, false)
            }) {
                Ok(Ok(code)) => (
                    StatusCode::OK,
                    Json(DecompileResponse {
                        ok: true,
                        code,
                        error: None,
                    }),
                ),
                Ok(Err(err)) => (
                    StatusCode::BAD_REQUEST,
                    Json(DecompileResponse {
                        ok: false,
                        code: String::new(),
                        error: Some(err.to_string()),
                    }),
                ),
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
                error: Some(err.to_string()),
            }),
        ),
    }
}

fn decompile_bytes(
    bytes: &[u8],
    mode: OutputMode,
    wire: WireFormat,
    strict: bool,
) -> anyhow::Result<String> {
    let options = BytecodeOptions {
        wire,
        lenient: !strict,
    };
    let chunk = BytecodeReader::read_with_options(bytes, options).map_err(|e| {
        anyhow::anyhow!("parse failed: {e}. Try raw dump or disassembly mode for recovery.")
    })?;
    if !chunk.warnings.is_empty() {
        for w in &chunk.warnings {
            eprintln!("bytecode warning: {w}");
        }
    }
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
            if !chunk.warnings.is_empty() {
                let header: String = chunk
                    .warnings
                    .iter()
                    .map(|w| format!("-- warning: {w}\n"))
                    .collect();
                lua = format!("{header}{lua}");
            }
            lua
        }
    };
    Ok(out)
}
