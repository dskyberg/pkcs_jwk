//! Enumerates all possible errors returned by this library.
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// Represents a failure to read from input.
    #[error("File input error")]
    ReadFileError(std::io::Error),

    /// Represents a failure to write to output.
    #[error("File output error")]
    WriteFileError(std::io::Error),

    /// Represents all other cases of `std::io::Error` when reading.
    #[error("Stream read error")]
    IOEReadError(std::io::Error),

    /// Represents all other cases of `std::io::Error` when writing.
    #[error("Stream write error")]
    IOEWriteError(std::io::Error),

    #[error("JWK error")]
    JWKError(josekit::JoseError),

    /// Represents unknown file type error`.
    #[error("Uknown file type")]
    FileTypeError,

    /// Represents unknown file type error`.
    #[error("Uknown file type")]
    EncodingError,

    /// Represents unknown file type error`.
    #[error("Uknown algorithm")]
    AlgError,

    /// Represents unknown file type error`.
    #[error("Uknown key type")]
    KeyTypeError,

    /// Represents a failure to parse a PEM file
    #[error("Bad PEM file")]
    BadPEMFile(openssl::error::ErrorStack),

    #[error("Bad PKCS8 file")]
    BadPKCS8File(pkcs8::Error),

    /// Represents a failure to parse a DER file
    #[error("Bad DER file")]
    BadDERFile(openssl::error::ErrorStack),

    #[error("Input type mismatch")]
    TypeMismatch,

    #[error( "Option is not yet supported")]
    NotSupported,

    #[error("Badly formed password arguement")]
    BadPasswordArg,
}
