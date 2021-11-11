//! Manage input and output file types
//!
use std::path::Path;
use std::ffi::OsStr;
use std::str::FromStr;
use anyhow::{anyhow, Result};
use crate::app_state::{Encoding};

/// The support file types

/// Tries to determine the file type from the file name
///
/// If a file name is provided (for input or output), but no to/from type is
/// provided, the type can be determined from the filenames themselves.
///
/// This method is called, once an extension is found by `match_path`.
pub fn match_extension(path: &str) -> Result<Option<Encoding>> {
    match Encoding::from_str(path) {
        Ok(encoding) => Ok(Some(encoding)),
        Err(e) => Err(anyhow!(e)),
    }
}

fn match_path(filename: &str) -> Result<Option<Encoding>> {
    let path = Path::new(filename);
    match path.extension().and_then(OsStr::to_str) {
        Some(ext) => match_extension(ext),
        None => Ok(None),
    }
}


/// Helper function to pull the extension from a filename, and pass it to `match_extension`
pub fn match_filename(o_filename: Option<&str>) -> Result<Option<Encoding>> {
    match o_filename {
        None => Ok(None),
        Some(filename) => match_path(&filename),
    }
}

fn flip_type(ft: Encoding) -> Option<Encoding> {
    match ft {
        Encoding::PEM => Some(Encoding::JWK),
        Encoding::DER => Some(Encoding::JWK),
        Encoding::JWK => Some(Encoding::PEM),
    }
}

pub fn match_or_flip_filename(o_from: Option<Encoding>, o_filename: Option<&str>) -> Result<Option<Encoding>> {
     match match_filename(o_filename)? {
         Some(t) => Ok(Some(t)),
         None => Ok(flip_type(o_from.unwrap())),
     }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_filename() {
        let filename = "key.pem";
        let ft = match_filename(Some(filename)).expect("oops");
        assert_eq!(ft, Some(Encoding::PEM))
    }
}
