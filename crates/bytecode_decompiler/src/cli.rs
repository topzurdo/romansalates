use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::Context;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use crate::{bytecode::BytecodeReader, decompile::Decompiler, disasm::Disassembler};

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
                .with_state(());

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
        let code = decompile_bytes(&bytes, args.mode)?;

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
    State(()): State<()>,
    Json(req): Json<DecompileRequest>,
) -> impl IntoResponse {
    let mode = match req.mode.as_deref() {
        Some("disassembly") | Some("disasm") => OutputMode::Disassembly,
        Some("raw") | Some("dump") => OutputMode::RawDump,
        _ => OutputMode::Decompile,
    };

    match STANDARD.decode(req.bytecode) {
        Ok(bytes) => match decompile_bytes(&bytes, mode) {
            Ok(code) => (
                StatusCode::OK,
                Json(DecompileResponse {
                    ok: true,
                    code,
                    error: None,
                }),
            ),
            Err(err) => (
                StatusCode::BAD_REQUEST,
                Json(DecompileResponse {
                    ok: false,
                    code: String::new(),
                    error: Some(err.to_string()),
                }),
            ),
        },
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

fn decompile_bytes(bytes: &[u8], mode: OutputMode) -> anyhow::Result<String> {
    let chunk = BytecodeReader::read(bytes)?;
    Ok(match mode {
        OutputMode::RawDump => format!("{chunk:#?}"),
        OutputMode::Disassembly => Disassembler::disassemble_chunk(&chunk),
        OutputMode::Decompile => Decompiler::decompile_chunk(&chunk),
    })
}
