//! Command line processing
//!
//! Processes the arguments on the command line to generate an AppState instance,
//! and execute the program with the provided args.
//!
use std::str::FromStr;
use clap::{ArgMatches};
use anyhow::Result;
use crate::app_state::*;
use crate::errors::Error;

pub fn process(matches: &ArgMatches) -> Result<AppState> {
    let mut app_state = AppState::new();

    if let Some(kid) = matches.value_of("kid") {
        app_state.key_id = Some(kid.to_owned());
    }

    // Open the input reader.  Bail on error
    if let Some(filename) = matches.value_of("in") {
        app_state.in_params.file = Some(filename.to_string());
        app_state.in_stream =
            Box::new(std::fs::File::open(filename).map_err(|e| Error::ReadFileError(e))?);

        //TODO IF no from arg is provided, see if we can determine from the filename.
        if matches.value_of("from").is_none() {
        }
    }

    // Open the output writer.  Bail on error
    if let Some(filename) = matches.value_of("out") {
        app_state.out_params.file = Some(filename.to_string());
        app_state.out_stream =
            Box::new(std::fs::File::create(filename).map_err(|e| Error::ReadFileError(e))?);
        //TODO IF no from arg is provided, see if we can determine from the filename.
        if matches.value_of("to").is_none() {
        }

    }

    if let Some(encoding) = matches.value_of("from") {
        app_state.in_params.encoding = Encoding::from_str(encoding)?;
    }

    if let Some(encoding) = matches.value_of("to") {
        app_state.out_params.encoding = Encoding::from_str(encoding)?;
    }

    if let Some(alg) = matches.value_of("alg") {
        app_state.alg = Alg::from_str(alg)?;
    }

    if let Some(pkcs) = matches.value_of("inpkcs") {
        app_state.in_params.pkcs = PKCS::from_str(pkcs)?;
    }

    if let Some(pkcs) = matches.value_of("outpkcs") {
        app_state.out_params.pkcs = PKCS::from_str(pkcs)?;
    }

    if let Some(keytype) = matches.value_of("inkeytype") {
        app_state.in_params.key_type = KeyType::from_str(keytype)?;
    }

    if let Some(keytype) = matches.value_of("outkeytype") {
        app_state.out_params.key_type = KeyType::from_str(keytype)?;
    }
/*
    // Figure out the input type
     let input_type = match matches.value_of("from") {
        Some(s) => match_extension(s)?,
        None => match match_filename(matches.value_of("in"))? {
            Some(t) => Some(t),
            None => Some(FileType::PEM),
        },
    };

    // Figure out what the output type is, by either evaluating params or
    // by assuming from the input type
    // Figure out the input type
    let output_type = match matches.value_of("to") {
        Some(s) => match_extension(s)?,
        None => match_or_flip_filename(input_type.clone(), matches.value_of("out"))?,
    };
*/
    Ok(app_state)
}