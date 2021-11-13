//! Command line processing
//!
//! Processes the arguments on the command line to generate an AppState instance,
//! and execute the program with the provided args.
//!
use std::str::FromStr;
use std::fs::File;
use std::io::Read;
use clap::{ArgMatches};
use anyhow::{bail, Result};
use crate::app_state::*;
use crate::errors::Error;

/// Read a password from a local file
///
/// If the arg to `process_password` is `FILE:<filename>` this method is called
/// to retrieve the password from `<filename>`.
fn read_password_from_file(filename: &str) -> Result<Option<String>> {
    let mut file = File::open(filename).map_err(|e| Error::ReadFileError(e))?;
    let mut buf = String::new();
    let _cnt = file
        .read_to_string(&mut buf)
        .map_err(|e| Error::IOEReadError(e));

    println!("Mode: FILE - Password: {}", &buf);
    Ok(Some(buf))

}

/// Handle password input options similar to openssl
///
/// The password may be of 2 forms:
/// 1. "pass:<value>": The value after the colon represents the actual password
/// 2. "file:<value>": The value after the colon represents a file that contains the password
///
fn process_password(input: Option<&str>) -> Result<Option<String>> {

    match input {
        None => Ok(None),
        Some(s) => {
            let parts = s.split(":").collect::<Vec<&str>>();
            // If there's not enough args, bail
            if parts.len() < 2 {
                bail!(Error::BadPasswordArg);
            }
            let mode = parts[0].to_owned();
            let target;

            // If the password contains a ':', join them
            if parts.len() > 2 {
                match  parts.split_first() {
                    Some((_, remainder)) => {
                        target = remainder.join("");
                    },
                    _ => bail!(Error::BadPasswordArg)
                }
            } else {
                target = parts[1].to_owned();
            }
            match mode.to_lowercase().as_str() {
                "pass" => {
                    println!("Mode: PASS - Password: {}",target);
                    Ok(Some(target))
                },
                "file" => read_password_from_file(&target),
                _ => bail!(Error::BadPasswordArg)
            }
        }
    }
}

/// Processes all CLI arguments into an instance of AppState
pub fn process(matches: &ArgMatches) -> Result<AppState> {
    let mut app_state = AppState::new();

    // Open the input reader.  Bail on error
    if let Some(filename) = matches.value_of("in") {
        app_state.in_params.file = Some(filename.to_string());
        app_state.in_stream =
            Box::new(std::fs::File::open(filename).map_err(|e| Error::ReadFileError(e))?);
        //TODO IF no from arg is provided, see if we can determine from the filename.
        if matches.value_of("from").is_none() {
        }
    }

    if let Some(encoding) = matches.value_of("from") {
        app_state.in_params.encoding = Encoding::from_str(encoding)?;
    }

    if let Some(pkcs) = matches.value_of("inpkcs") {
        app_state.in_params.pkcs = PKCS::from_str(pkcs)?;
    }


    if let Some(keytype) = matches.value_of("inkeytype") {
        app_state.in_params.key_type = KeyType::from_str(keytype)?;
    }

    app_state.in_params.password = process_password(matches.value_of("inpass"))?;


    // Open the output writer.  Bail on error
    if let Some(filename) = matches.value_of("out") {
        app_state.out_params.file = Some(filename.to_string());
        app_state.out_stream =
            Box::new(std::fs::File::create(filename).map_err(|e| Error::ReadFileError(e))?);
        //TODO IF no from arg is provided, see if we can determine from the filename.
        if matches.value_of("to").is_none() {
        }
    }

    if let Some(encoding) = matches.value_of("to") {
        app_state.out_params.encoding = Encoding::from_str(encoding)?;
    }

    if let Some(pkcs) = matches.value_of("outpkcs") {
        app_state.out_params.pkcs = PKCS::from_str(pkcs)?;
    }

    if let Some(keytype) = matches.value_of("outkeytype") {
        app_state.out_params.key_type = KeyType::from_str(keytype)?;
    }

    app_state.out_params.password = process_password(matches.value_of("outpass"))?;

    if let Some(pwd) = matches.value_of("outpass") {
        app_state.out_params.password = Some(pwd.to_owned());
    }

    if let Some(alg) = matches.value_of("alg") {
        app_state.alg = Alg::from_str(alg)?;
    }

    if let Some(kid) = matches.value_of("kid") {
        app_state.key_id = Some(kid.to_owned());
    }

    Ok(app_state)
}