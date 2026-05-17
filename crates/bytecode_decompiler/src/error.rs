use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecompileError {
    #[error("input too short")]
    UnexpectedEof,
    #[error("invalid bytecode signature")]
    InvalidSignature,
    #[error("unsupported bytecode version {0}")]
    UnsupportedVersion(u8),
    #[error("malformed bytecode: {0}")]
    Malformed(&'static str),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Message(String),
}

pub type Result<T> = std::result::Result<T, DecompileError>;
