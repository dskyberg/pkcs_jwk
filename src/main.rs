use clap::{App, Arg};
use anyhow::Result;
use pkcs_jwk::{convert, cli::process};

fn main() -> Result<()> {
    // Get the current version from cargo.toml
    const VERSION: &'static str = env!("CARGO_PKG_VERSION");

    let matches = App::new("pkcs_jwk")
        .version(VERSION)
        .about("Convert between PKCS and JWK file formats")
        .arg(
            Arg::with_name("in")
                .long("in")
                .value_name("FILE")
                .help("Sets the input file to use")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("from")
                .long("from")
                .value_name("PEM|DER|JWK")
                .help("Type of input file")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("out")
                .long("out")
                .value_name("FILE")
                .help("Sets the output file to use")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("to")
                .long("to")
                .value_name("PEM|DER|JWK")
                .help("Type of output file")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("kid")
                .long("kid")
                .value_name("NAME")
                .help("Key ID for JWT")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("alg")
                .long("alg")
                .value_name("RSA|EC")
                .help("Key algoritmm")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("inkeytype")
                .long("inkeytype")
                .value_name("PUBLIC|PRIVATE")
                .help("Type of key being input [default is PRIVATE]")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("outkeytype")
                .long("outkeytype")
                .value_name("PUBLIC|PRIVATE")
                .help("Type of key being output [default is PRIVATE")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("inpkcs")
                .long("inpkcs")
                .value_name("PKCS1|PKCS8")
                .help("PKCS format of key being input (default is PKCS8)")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("outpkcs")
                .long("outpkcs")
                .value_name("PKCS1|PKCS8")
                .help("PKCS format of key being input (default is PKCS1)")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("inpass")
                .long("inpass")
                .value_name("PASSWORD")
                .help("password for protected input")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("outpass")
                .long("outpass")
                .value_name("PASSWORD")
                .help("Password protected ouput")
                .required(false)
                .takes_value(true),
        )

        .get_matches();

    let mut app_state = process(&matches)?;

    // Stream the input, convert, and stream the output
    convert(&mut app_state)?;
    Ok(())
}
