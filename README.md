# Convert PEM and JWK files

This app is designed to ingest a key encoded in one format and produce a
key in the other.  That's all!  It is written in Rust and leverages the
josekit crate (which depends internally on the openssl crate).

I created this program for 2 reasons:
* I could not find a solution that didn't involve Node or Python
* I wanted to learn Rust

# File Formats
The following file formats are supported for both reading and writing files.

## PEM
The PEM format is the default format when generating keys with Openssl.  It
is a Base64 encoded PKCS8 or PKCS1 file with header and footer, like this,
for PKCS8:

````
-----BEGIN PRIVATE KEY-----
<base64 encoded content
-----END PRIVATE KEY-----
````

Or like this for PKCS1

````
-----BEGIN RSA PRIVATE KEY-----
<base64 encoded content
-----END RSA PRIVATE KEY-----
````

## DER
DER is binary encoding of the raw ASN.1 key in either PKCS8 or PKCS1 format.

## JWK
JSON Web Key (JWK) is a standard format used in JSON based protocols, such as
OAuth 2 and OpenID Connect (OIDC). It is part of the JOSE family of open standards
for encrypting and signing JWT tokens.

# Command line Usage
To see all the command line args, run `pkcs_jwk -h`.

## Streaming a (PKCS8) PEM RSA Private key to (PKCS1) JWK
This is the default mode.  The app will read a PKCS8 stdin and write  (PKCS1) JWK to stdout.
Add this at the end of an openssl key generation for JWK output (note: `jq .` for pretty print):

````
openssl genrsa -outform DER 2048 | pkcs_jwk | jq .
````

## For more details
Download the repo and run `cargo doc --no-deps --open`