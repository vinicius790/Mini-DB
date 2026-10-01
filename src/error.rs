//! Erros do motor Mini-DB.

use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    CorruptPage(u32),
    CorruptWal(u64),
    KeyTooLarge(usize, usize),
    ValueTooLarge(usize, usize),
    PageFull,
    Closed,
    Cli(String),
    Sql(String),
    TxnOpen,
    TxnNotOpen,
    BadChecksum(u32),
    UnknownTable(String),
    UnknownIndex(String),
    Server(String),
    /// Entrada rejeitada por validação (mapeada para HTTP 400).
    InvalidInput(String),
    /// Conflito de escrita entre transações MVCC concorrentes (repetir).
    Conflict(String),
    /// Escrita recusada: o banco é uma réplica somente leitura.
    ReadOnly,
    /// Temporariamente indisponível (réplica em ressincronização): HTTP 503.
    Unavailable(String),
    /// Credencial ausente ou inválida (token HTTP/TCP): HTTP 401.
    Unauthorized,
    /// Autenticado, mas sem privilégio para o comando: HTTP 403.
    Forbidden(String),
    /// Violação de restrição do SQL relacional (NOT NULL, UNIQUE, PK, tipo).
    Constraint(String),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::CorruptPage(id) => {
                write!(f, "página corrompida ou magic inválido (page_id={id})")
            }
            Self::CorruptWal(off) => {
                write!(f, "WAL corrompido ou registro truncado em offset {off}")
            }
            Self::KeyTooLarge(n, max) => write!(f, "chave muito longa ({n} bytes; máx {max})"),
            Self::ValueTooLarge(n, max) => write!(f, "valor muito longo ({n} bytes; máx {max})"),
            Self::PageFull => write!(f, "página cheia demais para acomodar a célula"),
            Self::Closed => write!(f, "banco fechado"),
            Self::Cli(s) => write!(f, "comando CLI inválido: {s}"),
            Self::Sql(s) => write!(f, "SQL inválido: {s}"),
            Self::TxnOpen => write!(f, "transação já aberta"),
            Self::TxnNotOpen => write!(f, "nenhuma transação aberta"),
            Self::BadChecksum(id) => write!(f, "checksum de página inválido (page_id={id})"),
            Self::UnknownTable(t) => write!(f, "tabela desconhecida: {t}"),
            Self::UnknownIndex(t) => write!(f, "índice desconhecido: {t}"),
            Self::Server(s) => write!(f, "servidor: {s}"),
            Self::InvalidInput(s) => write!(f, "entrada inválida: {s}"),
            Self::Conflict(s) => write!(f, "conflito de escrita (repita a transação): {s}"),
            Self::ReadOnly => write!(f, "banco somente leitura (réplica)"),
            Self::Unavailable(s) => write!(f, "indisponível no momento: {s}"),
            Self::Unauthorized => write!(f, "não autorizado: credencial ausente ou inválida"),
            Self::Forbidden(s) => write!(f, "permissão negada: {s}"),
            Self::Constraint(s) => write!(f, "restrição violada: {s}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl Error {
    /// `true` quando a culpa é da requisição (dados/estado), não do servidor.
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::KeyTooLarge(..)
                | Self::ValueTooLarge(..)
                | Self::InvalidInput(_)
                | Self::Cli(_)
                | Self::Sql(_)
                | Self::TxnOpen
                | Self::TxnNotOpen
                | Self::UnknownTable(_)
                | Self::UnknownIndex(_)
                | Self::Conflict(_)
                | Self::ReadOnly
                | Self::Constraint(_)
                | Self::Unauthorized
                | Self::Forbidden(_)
        )
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
