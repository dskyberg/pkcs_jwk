//! Encrypt/Decrypt JWE protected keys
//!
//! This is a highly opinionated and constrained wrapper around josekit jwe. It's only
//! purpose is to encrypt and decrypt JWK's using only the PBE2_HS256_A128 algorithm.
//! If your needs are different, fork the code.

use std::fmt;

use crate::errors::Error;
use anyhow::{bail, Result};
use base64;
use josekit::{jwk::Jwk,jwe::{
    alg::pbes2_hmac_aeskw::*, JweAlgorithm, JweContentEncryption, JweDecrypter, JweEncrypter,
    JweHeader,
}};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// A JWE representation for encrypted JWK keys.
///
/// This format wsa borrowed from the SmallStep CLI format for encrypted JWK keys.
/// It follows [rfc7517](https://datatracker.ietf.org/doc/html/rfc7517) in structure
/// and leverages [josekit](https://docs.rs/josekit) to perform the JWE encryption steps.
///
/// Each component of the struct is Base64 encoded, so that it can be easily streamed
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedJWK {
    pub protected: String,
    pub encrypted_key: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: Option<String>,
}

impl std::fmt::Display for EncryptedJWK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_string(self).expect("this shouldn't fail");
        write!(f, "{}", s)
    }
}

fn b64_decode(input: &str) -> Result<Vec<u8>> {
    let val = base64::decode_config(&input, base64::URL_SAFE_NO_PAD)
        .map_err(|e| Error::Base64Error(e))?;
    Ok(val)
}

fn b64_encode(input: &[u8]) -> Result<String> {
    Ok(base64::encode_config(input, base64::URL_SAFE_NO_PAD))
}

/// Create PBE2  JWK
pub fn pbe2_jwk(key: &[u8]) -> Result<Jwk> {
    let key = base64::encode_config(&key, base64::URL_SAFE_NO_PAD);

    let mut jwk = Jwk::new("oct");
    jwk.set_key_use("enc");
    jwk.set_parameter("k", Some(json!(key)))
        .map_err(|e| Error::JWEError(e))?;
    Ok(jwk)
}

/// JWE wrap the JWK object
pub fn encrypt_content_encryption_key(jwk: &Jwk, key: &[u8]) -> Result<(JweHeader, Vec<u8>)> {
    let enc = josekit::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption::A128cbcHs256;
    let alg = Pbes2HmacAeskwJweAlgorithm::Pbes2Hs256A128kw;

    let mut header = JweHeader::new();
    header.set_content_encryption(enc.name());
    header.set_algorithm(alg.name());
    header.set_content_type("jwk+json");

    let encrypter = alg.encrypter_from_jwk(&jwk)?;
    let mut out_header = header.clone();
    let encrypted_key = encrypter
        .encrypt(key, &header, &mut out_header)
        .map_err(|e| Error::JWEError(e))?
        .unwrap();

    Ok((out_header, encrypted_key))
}

/// JWE wrap the JWK object
pub fn decrypt_content_encryption_key(
    header: &JweHeader,
    jwk: &Jwk,
    encrypted_key: &[u8],
) -> Result<Vec<u8>> {
    let enc = josekit::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption::A128cbcHs256;
    let alg = Pbes2HmacAeskwJweAlgorithm::Pbes2Hs256A128kw;

    let decrypter = alg.decrypter_from_jwk(&jwk)?;
    let cek = decrypter
        .decrypt(Some(encrypted_key), &enc, header)
        .map_err(|e| Error::JWEError(e))?;

    Ok(cek.to_vec())
}

impl EncryptedJWK {
    pub fn encrypt(passphrase: &[u8], in_jwk: &Jwk) -> Result<Self> {
        let enc = josekit::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption::A128cbcHs256;
        let pbe2jwk = pbe2_jwk(passphrase)?;

        let cek = josekit::util::random_bytes(enc.key_len());

        let iv = josekit::util::random_bytes(enc.iv_len());

        // Encrypt the CEK with password based encryption
        let (protected_header, encrypted_cek) = encrypt_content_encryption_key(&pbe2jwk, &cek)?;
        let message_as_str = in_jwk.to_string();
        let message = message_as_str.as_bytes();
        let (ciphertext, otag) = enc
            .encrypt(
                &cek,
                Some(&iv),
                message,
                protected_header.to_string().as_bytes(),
            )
            .map_err(|e| Error::JWEError(e))?;
        // This should never fail
        let tag = otag.unwrap();

        let jwe = Self {
            protected: b64_encode(protected_header.to_string().as_bytes())?,
            encrypted_key: b64_encode(&encrypted_cek)?,
            iv: b64_encode(&iv)?,
            ciphertext: b64_encode(&ciphertext)?,
            tag: Some(b64_encode(&tag)?)
        };

        Ok(jwe)
    }

    pub fn decrypt(&self, passphrase: &[u8]) -> Result<Jwk> {
        let enc = josekit::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption::A128cbcHs256;

        let protected_header = b64_decode(&self.protected)?;
        let encrypted_key = b64_decode(&self.encrypted_key)?;
        let iv = b64_decode(&self.iv)?;
        let ciphertext = b64_decode(&self.ciphertext)?;
        let tag = match &self.tag {
            Some(t) => b64_decode(t)?,
            None => bail!("what happened?"),
        };

        // Decrypt the Content Encryption Key, that is password protected
        let pbe2jwk = pbe2_jwk(passphrase)?;
        let header = JweHeader::from_bytes(&protected_header).map_err(|e| Error::JWEError(e))?;

        let cek = decrypt_content_encryption_key(&header, &pbe2jwk, &encrypted_key)?;

        // Using the cek, decrypt the JWK
        let decrypted_message = enc
            .decrypt(&cek, Some(&iv), &ciphertext, &protected_header, Some(&tag))
            .map_err(|e| Error::JWEError(e))?;

        let jwk = Jwk::from_bytes(&decrypted_message)
            .map_err(|e| Error::JWKError(e))?;
        Ok(jwk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_pb2e() {
        let enc = josekit::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption::A128cbcHs256;
        let cek = josekit::util::random_bytes(enc.key_len());
        let pbe2jwk = pbe2_jwk("password".as_bytes()).expect("failed to make pbe key");

        // Encrypt the CEK with password based encryption
        let (protected_header, encrypted_cek) =
            encrypt_content_encryption_key(&pbe2jwk, &cek).expect("Failed to encrypt");
        let decrypted_key =
            decrypt_content_encryption_key(&protected_header, &pbe2jwk, &encrypted_cek)
                .expect("Failed to decrypt");

        assert_eq!(cek, decrypted_key);
    }

    #[test]
    fn encrypt_and_decrypt() {
        let bytes = include_bytes!("../tests/pkcs1.jwk");
        let jwk = Jwk::from_bytes(&bytes).expect("Could not read JWK");
        let encrypted_jwk =
            EncryptedJWK::encrypt("password".as_bytes(), &jwk).expect("Failed to encrypt JWK");

        let decrypted_jwk = encrypted_jwk
            .decrypt("password".as_bytes())
            .expect("Could not decrypt JWK");

        assert_eq!(jwk, decrypted_jwk);
    }
}
