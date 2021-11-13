//! Convert PEM and JWK files
//!
//! This app is designed to ingest a key encoded in one format and produce a
//! key in the other.  That's all!  It is written in Rust and leverages the
//! josekit crate (which depends internally on the openssl crate).
//!
//! I created this program for 2 reasons:
//! * I could not find a solution that didn't involve Node or Python
//! * I wanted to learn Rust
//!
//! # File Formats
//! The following file formats are supported for both reading and writing files.
//!
//! ## PEM
//! The PEM format is the default format when generating keys with Openssl.  It
//! is a Base64 encoded PKCS8 or PKCS1 file with header and footer, like this,
//! for PKCS8:
//!
//! ````
//! -----BEGIN PRIVATE KEY-----
//! <base64 encoded content
//! -----END PRIVATE KEY-----
//! ````
//!
//! Or like this for PKCS1
//!
//! ````
//! -----BEGIN RSA PRIVATE KEY-----
//! <base64 encoded content
//! -----END RSA PRIVATE KEY-----
//! ````
//!
//! ## DER
//! DER is binary encoding of the raw ASN.1 key in either PKCS8 or PKCS1 format.
//!
//! ## JWK
//! JSON Web Key (JWK) is a standard format used in JSON based protocols, such as
//! OAuth 2 and OpenID Connect (OIDC). It is part of the JOSE family of open standards
//! for encrypting and signing JWT tokens.
//!
//! # Command line Usage
//! To see all the command line args, run `pkcs_jwk -h`.
//!
//! ## Streaming a (PKCS8) PEM RSA Private key to (PKCS1) JWK
//! This is the default mode.  The app will read a PKCS8 stdin and write  (PKCS1) JWK to stdout.
//! Add this at the end of an openssl key generation for JWK output (note: `jq .` for pretty print):
//!
//! ````
//! openssl genrsa -outform DER 2048 | pkcs_jwk | jq .
//! ````
//!
//!
use pkcs8;

use anyhow::{bail, Result};
use josekit::jwk::{alg::rsa::RsaKeyPair, Jwk};
use openssl::{pkey::Private, rsa::Rsa};

use crate::app_state::*;
use crate::errors::Error;

pub mod app_state;
pub mod cli;
pub mod errors;
pub mod file;

/// Create RSA<Private> from PKCS8 PEM buffer
fn pkcs8_pem_to_rsa_private(bytes: &Vec<u8>) -> Result<Rsa<Private>> {
    let key = Rsa::private_key_from_pem(bytes).map_err(|e| Error::BadPEMFile(e))?;
    Ok(key)
}

/// Create RSA<Private> from a password protected PKCS8 PEM buffer
fn pkcs8_encrypted_pem_to_rsa_private(bytes: &Vec<u8>, passphrase: &str) -> Result<Rsa<Private>> {
    let key = Rsa::private_key_from_pem_passphrase(bytes, passphrase.as_bytes())
        .map_err(|e| Error::BadPEMFile(e))?;
    Ok(key)
}

/// Create RSA<Private> from PKCS8 DER buffer
fn pkcs8_der_to_rsa_private(bytes: &Vec<u8>) -> Result<Rsa<Private>> {
    let pkd = pkcs8::PrivateKeyDocument::from_der(&bytes).map_err(|e| Error::BadPKCS8File(e))?;
    let pki = pkd.private_key_info();
    //pkcs1_from_pkcs8_doc(pki.private_key);
    pkcs1_der_to_rsa_private(&pki.private_key.to_vec())
}

/// Create RSA<Private> from password protected PKCS8 DER buffer
fn pkcs8_encrypted_der_to_rsa_private(bytes: &Vec<u8>, passphrase: &str) -> Result<Rsa<Private>> {
    let epkd =
        pkcs8::EncryptedPrivateKeyDocument::from_der(&bytes).map_err(|e| Error::BadPKCS8File(e))?;
    let pkd = epkd
        .decrypt(passphrase.as_bytes())
        .map_err(|e| Error::BadPKCS8File(e))?;
    let pki = pkd.private_key_info();
    //pkcs1_from_pkcs8_doc(pki.private_key);
    pkcs1_der_to_rsa_private(&pki.private_key.to_vec())
}

/// Create RSA<Private> from PKCS8 PEM buffer
fn pkcs1_pem_to_rsa_private(bytes: &Vec<u8>) -> Result<Rsa<Private>> {
    let key = Rsa::private_key_from_pem(bytes).map_err(|e| Error::BadPEMFile(e))?;
    Ok(key)
}

// Create RSA<Private> from DER buffer
fn pkcs1_der_to_rsa_private(bytes: &Vec<u8>) -> Result<Rsa<Private>> {
    let key = Rsa::private_key_from_der(bytes).map_err(|e| Error::BadDERFile(e))?;
    Ok(key)
}

fn pkcs1_jwk_to_rsa_private(bytes: &Vec<u8>) -> Result<Rsa<Private>> {
    // Use the JoseKit utilities to parse the JWK bytes into a Jwk struct
    let key = Jwk::from_bytes(bytes).map_err(|e| Error::JWKError(e))?;
    // Convert the Jwk to an RSA keypair, and get the PKCS8 DER formatted bytes
    let key_pair =
        josekit::jwk::alg::rsa::RsaKeyPair::from_jwk(&key).map_err(|e| Error::JWKError(e))?;
    let pkcs8_der_bytes = key_pair.to_der_private_key();
    // Now just use the defined method.
    pkcs8_der_to_rsa_private(&pkcs8_der_bytes)
}

/// Determines how to read the private key based on whether the key is
/// PKCS1 or PKCS8 and whether the encoding is PEM, DER, or JWK
fn bytes_to_rsa_private(app_state: &mut AppState, bytes: &Vec<u8>) -> Result<Rsa<Private>> {
    match (app_state.in_params.encoding, app_state.in_params.pkcs) {
        (Encoding::DER, PKCS::PKCS8) => match &app_state.in_params.password {
            Some(passphrase) => pkcs8_encrypted_der_to_rsa_private(bytes, passphrase),
            None => pkcs8_der_to_rsa_private(bytes),
        },
        (Encoding::DER, PKCS::PKCS1) => pkcs1_der_to_rsa_private(bytes),
        (Encoding::PEM, PKCS::PKCS8) => match &app_state.in_params.password {
            Some(passphrase) => pkcs8_encrypted_pem_to_rsa_private(bytes, passphrase),
            None => pkcs8_pem_to_rsa_private(bytes),
        },
        (Encoding::PEM, PKCS::PKCS1) => pkcs1_pem_to_rsa_private(bytes),
        (Encoding::JWK, PKCS::PKCS1) => pkcs1_jwk_to_rsa_private(bytes),
        (Encoding::JWK, PKCS::PKCS8) => bail!(Error::TypeMismatch),
    }
}

/// Write RSA<Private> to DER buffer
fn rsa_private_to_pkcs1_der(key: &Rsa<Private>) -> Result<Vec<u8>> {
    let buffer = key.private_key_to_der().map_err(|e| Error::BadPEMFile(e))?;
    Ok(buffer)
}

/// Write RSA<Private> to DER buffer
fn rsa_private_to_pkcs8_der(key: &Rsa<Private>) -> Result<Vec<u8>> {
    let buffer = key.private_key_to_der().map_err(|e| Error::BadPEMFile(e))?;
    Ok(buffer)
}

/// Write RSA<Private> to PEM buffer
fn rsa_private_to_pkcs1_pem(key: &Rsa<Private>) -> Result<Vec<u8>> {
    let buffer = key.private_key_to_pem().map_err(|e| Error::BadPEMFile(e))?;
    Ok(buffer)
}

/// Write RSA<Private> to PEM buffer
fn rsa_private_to_pkcs8_pem(key: &Rsa<Private>) -> Result<Vec<u8>> {
    let buffer = key.private_key_to_pem().map_err(|e| Error::BadPEMFile(e))?;
    Ok(buffer)
}

/// Convert RSA<Private> to JWK
fn rsa_to_jwk(key: &Rsa<Private>, key_id: &Option<String>) -> Result<Jwk> {
    let der = key.private_key_to_der().map_err(|e| Error::BadPEMFile(e))?;
    let mut kp = RsaKeyPair::from_der(&der).map_err(|e| Error::JWKError(e))?;
    kp.set_key_id(key_id.as_ref());
    Ok(kp.to_jwk_private_key())
}

/// Write RSA<Private> to PEM buffer
fn rsa_private_to_pkcs1_jwk(app_state: &mut AppState, key: &Rsa<Private>) -> Result<Vec<u8>> {
    let jwk = rsa_to_jwk(key, &app_state.key_id)?;
    Ok(jwk.to_string().as_bytes().to_vec())
}

fn rsa_private_to_bytes(app_state: &mut AppState, key: &Rsa<Private>) -> Result<Vec<u8>> {
    match (app_state.out_params.encoding, app_state.out_params.pkcs) {
        (Encoding::DER, PKCS::PKCS8) => rsa_private_to_pkcs8_der(key),
        (Encoding::DER, PKCS::PKCS1) => rsa_private_to_pkcs1_der(key),
        (Encoding::PEM, PKCS::PKCS8) => rsa_private_to_pkcs8_pem(key),
        (Encoding::PEM, PKCS::PKCS1) => rsa_private_to_pkcs1_pem(key),
        (Encoding::JWK, PKCS::PKCS1) => rsa_private_to_pkcs1_jwk(app_state, key),
        (Encoding::JWK, PKCS::PKCS8) => bail!(Error::TypeMismatch),
    }
}

fn convert_rsa_private(app_state: &mut AppState) -> Result<()> {
    // Read the input to a buffer
    let in_bytes = app_state.read_stream()?;
    let rsa = bytes_to_rsa_private(app_state, &in_bytes)?;
    let out_bytes = rsa_private_to_bytes(app_state, &rsa)?;
    app_state.write_stream(&out_bytes)?;

    // Output the file to the desired type
    Ok(())
}

/// Consume the AppState to convert the input file.
///
/// This is the main engine of the app. It processes the AppState to queue up
/// the working functions.
/// Note:  Only RSA Private keys are supported.  Elliptic Curve and Public keys
/// are on the way.
pub fn convert(app_state: &mut AppState) -> Result<()> {
    match (app_state.alg, app_state.in_params.key_type) {
        (Alg::RSA, KeyType::Private) => convert_rsa_private(app_state),
        _ => bail!(Error::NotSupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn try_pkcs8_pem_to_jwk() {
        let bytes = include_bytes!("../tests/pkcs8.pem");
        let result = pkcs8_pem_to_rsa_private(&bytes.to_vec());
        assert!(result.is_ok());
    }

    #[test]
    fn try_pkcs8_der_to_jwk() {
        let bytes = include_bytes!("../tests/pkcs8.der");
        let result = pkcs8_der_to_rsa_private(&bytes.to_vec());
        assert!(result.is_ok());
    }

    #[test]
    fn try_pkcs1_der_to_jwk() {
        let bytes = include_bytes!("../tests/pkcs1.der");
        let result = pkcs1_der_to_rsa_private(&bytes.to_vec());
        assert!(result.is_ok());
    }

    #[test]
    fn try_pkcs1_pem_to_jwk() {
        let bytes = include_bytes!("../tests/pkcs1.pem");
        let result = pkcs1_pem_to_rsa_private(&bytes.to_vec());
        assert!(result.is_ok());
    }

    #[test]
    fn try_rsa_private_to_pkcs8_pem() {
        let der_bytes = include_bytes!("../tests/pkcs8.der");
        let rsa = pkcs8_der_to_rsa_private(&der_bytes.to_vec()).expect("Failed to read RSA DER");
        let result = rsa_private_to_pkcs8_pem(&rsa);
        assert!(result.is_ok());
    }

    #[test]
    fn try_rsa_private_to_pkcs8_der() {
        let der_bytes = include_bytes!("../tests/pkcs8.der");
        let rsa = pkcs8_der_to_rsa_private(&der_bytes.to_vec()).expect("Failed to read RSA DER");
        let result = rsa_private_to_pkcs8_der(&rsa);
        assert!(result.is_ok());
    }

    #[test]
    fn try_rsa_private_to_pkcs1_pem() {
        let der_bytes = include_bytes!("../tests/pkcs8.der");
        let rsa = pkcs8_der_to_rsa_private(&der_bytes.to_vec()).expect("Failed to read RSA DER");
        let result = rsa_private_to_pkcs1_pem(&rsa);
        assert!(result.is_ok());
    }

    #[test]
    fn try_rsa_private_to_pkcs1_der() {
        let der_bytes = include_bytes!("../tests/pkcs8.der");
        let rsa = pkcs8_der_to_rsa_private(&der_bytes.to_vec()).expect("Failed to read RSA DER");
        let result = rsa_private_to_pkcs1_der(&rsa);
        assert!(result.is_ok());
    }
}
