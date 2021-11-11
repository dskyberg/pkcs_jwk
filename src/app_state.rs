//! App State is derived from the command line input arguements
//!
use std::str::FromStr;
use std::io::{Read, Write};
use anyhow::{bail, Result};
use crate::errors::PemJwkError;

/// Test string values to match against
/*
pub trait IsValid {
    fn valid(val: &str) -> Result<T>;
}
*/

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    RSA,
    EC,
}

impl FromStr for Alg {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Alg> {
        match s.to_uppercase().as_str() {
            "RSA" => Ok(Alg::RSA),
            "EC" => Ok(Alg::EC),
            _ => bail!(PemJwkError::AlgError),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Public,
    Private,
    KeyPair,
}

impl FromStr for KeyType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<KeyType> {
        match s.to_uppercase().as_str() {
            "PUBLIC" => Ok(KeyType::Public),
            "PRIVATE" => Ok(KeyType::Private),
            "KEYPAIR" => Ok(KeyType::KeyPair),
            _ => bail!(PemJwkError::KeyTypeError),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PKCS {
    PKCS1,
    PKCS8,
}

impl FromStr for PKCS {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<PKCS> {
       match s.to_uppercase().as_str() {
            "PKCS8" => Ok(PKCS::PKCS8),
            "PKCS1" => Ok(PKCS::PKCS1),
            _ => bail!(PemJwkError::AlgError),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    PEM,
    DER,
    JWK,
}

impl FromStr for Encoding {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Encoding> {
       match s.to_uppercase().as_str() {
            "PEM" => Ok(Encoding::PEM),
            "DER" => Ok(Encoding::DER),
            "JWK" => Ok(Encoding::JWK),
            _ => bail!(PemJwkError::EncodingError),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Params {
    pub key_type: KeyType,
    pub file: Option<String>,
    pub encoding: Encoding,
    pub pkcs: PKCS,
    pub encrypted: bool,
}

pub struct AppState {
    pub in_params: Params,
    pub out_params: Params,
    pub in_stream: Box<dyn Read>,
    pub out_stream: Box<dyn Write>,
    pub key_id: Option<String>,
    pub alg: Alg,
}

impl AppState {
    /// Create an AppState with default settings
    pub fn new() -> Self {
        Self {
            in_params: Params {
                key_type: KeyType::Private,
                file: None,
                encoding: Encoding::PEM,
                pkcs: PKCS::PKCS8,
                encrypted: false,
            },
            out_params: Params {
                key_type: KeyType::Private,
                file: None,
                encoding: Encoding::JWK,
                pkcs: PKCS::PKCS1,
                encrypted: false,
            },
            in_stream: Box::new(std::io::stdin()),
            out_stream: Box::new(std::io::stdout()),
            key_id: None,
            alg: Alg::RSA,
        }
    }

    pub fn read_stream(&mut self) -> Result<Vec<u8>> {
        let mut bytes = Vec::<u8>::new();
        let _cnt = self
            .in_stream
            .read_to_end(&mut bytes)
            .map_err(|e| PemJwkError::IOEReadError(e));
        Ok(bytes)
    }

    pub fn write_stream(&mut self, bytes: &[u8]) -> Result<()> {
        let _ = self
            .out_stream
            .write_all(bytes)
            .map_err(|e| PemJwkError::IOEWriteError(e));
        Ok(())
    }
}
