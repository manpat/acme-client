//! Easy to use [Let's Encrypt](https://letsencrypt.org/) compatible
//! Automatic Certificate Management Environment (ACME) client.
//!
//! You can use acme-client library by adding following lines to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! acme-client = "0.5"
//! ```
//!
//! By default `acme-client` will build CLI. You can disable this with:
//!
//! ```toml
//! [dependencies.acme-client]
//! version = "0.5"
//! default-features = false
//! ```
//!
//! See <https://github.com/onur/acme-client> for CLI usage.
//!
//! ## API overview
//!
//! To successfully sign a SSL certificate for a domain name, you need to identify ownership of
//! your domain. You can also identify and sign certificate for multiple domain names and
//! explicitly use your own private keys and certificate signing request (CSR),
//! otherwise this library will generate them. Basic usage of `acme-client`:
//!
//! ```rust,no_run
//! # use acme_client::error::*;
//! # fn main() -> Result<()> {
//! use acme_client::Directory;
//!
//! let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration().register()?;
//!
//! // Create a identifier authorization for example.com
//! let authorization = account.authorization("example.com")?;
//!
//! // Validate ownership of example.com with http challenge
//! let http_challenge = authorization.get_http_challenge().ok_or("HTTP challenge not found".to_err())?;
//! http_challenge.save_key_authorization("/var/www")?;
//! http_challenge.validate()?;
//!
//! let cert = account.certificate_signer(&["example.com"]).sign_certificate()?;
//! cert.save_signed_certificate("certificate.pem")?;
//! cert.save_private_key("certificate.key")?;
//! # Ok(()) }
//! ```
//!
//! `acme-client` supports signing a certificate for multiple domain names with SAN. You need to
//! validate ownership of each domain name:
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::Directory;
//!
//! let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration().register()?;
//!
//! let domains = ["example.com", "example.org"];
//!
//! for domain in domains.iter() {
//!     let authorization = account.authorization(domain)?;
//!     // ...
//! }
//!
//! let cert = account.certificate_signer(&domains).sign_certificate()?;
//! cert.save_signed_certificate("certificate.pem")?;
//! cert.save_private_key("certificate.key")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## Account registration
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::Directory;
//!
//! let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration()
//!                        .email("example@example.org")
//!                        .register()?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! Contact email address is optional. You can also use your own private key during
//! registration. See [AccountRegistration](struct.AccountRegistration.html) helper for more
//! details.
//!
//! If you already registed with your own keys before, you still need to use
//! [`register`](struct.AccountRegistration.html#method.register) method,
//! in this case it will identify your user account instead of creating a new one.
//!
//!
//! ## Identifying ownership of domain name
//!
//! Before sending a certificate signing request to an ACME server, you need to identify ownership
//! of domain names you want to sign a certificate for. To do that you need to create an
//! Authorization object for a domain name and fulfill at least one challenge (http or dns for
//! Let's Encrypt).
//!
//! To create an Authorization object for a domain:
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt().unwrap();
//! # // Use staging directory for doc test
//! # let directory = Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")
//! #   .unwrap();
//! # let account = directory.account_registration().register().unwrap();
//! let authorization = account.authorization("example.com")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! [Authorization](struct.Authorization.html) object will contain challenges created by
//! ACME server. You can create as many Authorization object as you want to verify ownership
//! of the domain names. For example if you want to sign a certificate for
//! `example.com` and `example.org`:
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt().unwrap();
//! # let account = directory.account_registration().register().unwrap();
//! let domains = ["example.com", "example.org"];
//! for domain in domains.iter() {
//!     let authorization = account.authorization(domain)?;
//!     // ...
//! }
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ### Identifier validation challenges
//!
//! When you send authorization request to an ACME server, it will generate
//! identifier validation challenges to provide assurence that an account holder is also
//! the entity that controls an identifier.
//!
//! #### HTTP challenge
//!
//! With HTTP validation, the client in an ACME transaction proves its
//! control over a domain name by proving that it can provision resources
//! on an HTTP server that responds for that domain name.
//!
//! `acme-client` has
//! [`save_key_authorization`](struct.Challenge.html#method.save_key_authorization) method
//! to save vaditation file to a public directory. This directory must be accessible to outside
//! world.
//!
//! ```rust,no_run
//! # use acme_client::error::{Result, ToError};
//! # fn main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! # let account = directory.account_registration()
//! #                        .pkey_from_file("tests/user.key")?  // use test key for doc test
//! #                        .register()?;
//! let authorization = account.authorization("example.com")?;
//! let http_challenge = authorization.get_http_challenge().ok_or("HTTP challenge not found".to_err())?;
//!
//! // This method will save key authorization into
//! // /var/www/.well-known/acme-challenge/ directory.
//! http_challenge.save_key_authorization("/var/www")?;
//!
//! // Validate ownership of example.com with http challenge
//! http_challenge.validate()?;
//! # Ok(()) }
//! ```
//!
//! During validation, ACME server will check
//! `http://example.com/.well-known/acme-challenge/{token}` to identify ownership of domain name.
//! You need to make sure token is publicly accessible.
//!
//! #### DNS challenge:
//!
//! The DNS challenge requires the client to provision a TXT record containing a designated
//! value under a specific validation domain name.
//!
//! `acme-client` can generated this value with
//! [`signature`](struct.Challenge.html#method.signature) method.
//!
//! The user constructs the validation domain name by prepending the label "_acme-challenge"
//! to the domain name being validated, then provisions a TXT record with the digest value under
//! that name. For example, if the domain name being validated is "example.com", then the client
//! would provision the following DNS record:
//!
//! ```text
//! _acme-challenge.example.com: dns_challenge.signature()
//! ```
//!
//! Example validation with DNS challenge:
//!
//! ```rust,no_run
//! # use acme_client::error::*;
//! # fn main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! # let account = directory.account_registration()
//! #                        .pkey_from_file("tests/user.key")?  // use test key for doc test
//! #                        .register()?;
//! let authorization = account.authorization("example.com")?;
//! let dns_challenge = authorization.get_dns_challenge().ok_or("DNS challenge not found".to_err())?;
//! let signature = dns_challenge.signature()?;
//!
//! // User creates a TXT record for _acme-challenge.example.com with the value of signature.
//!
//! // Validate ownership of example.com with DNS challenge
//! dns_challenge.validate()?;
//! # Ok(()) }
//! ```
//!
//! ## Signing a certificate
//!
//! After validating all the domain names you can send a sign certificate request. `acme-client`
//! provides [`CertificateSigner`](struct.CertificateSigner.html) helper for this. You can
//! use your own key and CSR or you can let `CertificateSigner` to generate them for you.
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! # let account = directory.account_registration().register()?;
//! let domains = ["example.com", "example.org"];
//!
//! // ... validate ownership of domain names
//!
//! let certificate_signer = account.certificate_signer(&domains);
//! let cert = certificate_signer.sign_certificate()?;
//! cert.save_signed_certificate("certificate.pem")?;
//! cert.save_private_key("certificate.key")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## Revoking a signed certificate
//!
//! You can use `revoke_certificate` or `revoke_certificate_from_file` methods to revoke a signed
//! certificate. You need to register with the same private key you registered before to
//! successfully revoke a signed certificate. You can also use private key used to generate CSR.
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration()
//!                        .pkey_from_file("user.key")?
//!                        .register()?;
//! account.revoke_certificate_from_file("certificate.pem")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## References
//!
//! * [IETF ACME RFC](https://tools.ietf.org/html/rfc8555)
//! * [Let's Encrypt ACME divergences](https://github.com/letsencrypt/boulder/blob/9c1e8e6764c1de195db6467057e0d148608e411d/docs/acme-divergences.md)

pub extern crate openssl;
#[macro_use] pub extern crate log;
#[macro_use] extern crate failure;
#[macro_use] extern crate hyper;
#[macro_use] extern crate serde_derive;

pub mod types;
pub mod client;

pub use self::client::AcmeClient;
pub use self::types::*;

/// Default Let's Encrypt directory URL to configure client.
pub const LETSENCRYPT_DIRECTORY_URL: &'static str = "https://acme-v02.api.letsencrypt.org/directory";

/// Default Let's Encrypt staging directory URL to configure client.
pub const LETSENCRYPT_STAGING_DIRECTORY_URL: &'static str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Default Let's Encrypt intermediate certificate URL to chain when needed.
pub const LETSENCRYPT_INTERMEDIATE_CERT_URL: &'static str = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem";

/// Default bit length for RSA keys and `X509_REQ`
const BIT_LENGTH: u32 = 2048;


pub type Result<T> = std::result::Result<T, failure::Error>;


#[cfg(test)]
mod tests {
    extern crate env_logger;
    use super::*;

    fn test_acc() -> Result<Account> {
        Directory::lets_encrypt_staging()?
            .account_registration()
            .pkey_from_file("tests/user.key")?
            .register()
    }

    #[test]
    fn test_gen_key() {
        assert!(gen_key().is_ok())
    }

    #[test]
    fn test_b64() {
        assert_eq!(b64(&"foobar".to_string().into_bytes()), "Zm9vYmFy");
    }

    #[test]
    fn test_read_pkey() {
        assert!(read_pkey("tests/user.key").is_ok());
    }

    #[test]
    fn test_gen_csr() {
        let pkey = gen_key().unwrap();
        assert!(gen_csr(&pkey, &["example.com"]).is_ok());
        assert!(gen_csr(&pkey, &["example.com", "sub.example.com"]).is_ok());
    }

    #[test]
    fn test_directory() {
        assert!(Directory::lets_encrypt().is_ok());

        let dir = Directory::lets_encrypt_staging().unwrap();
        assert!(dir.url_for("newNonce").is_some());
        assert!(dir.url_for("newAccount").is_some());
        assert!(dir.url_for("newOrder").is_some());

        assert!(!dir.request_new_nonce().unwrap().is_empty());

        let pkey = gen_key().unwrap();
        assert!(dir.jwk(&pkey).is_ok());
        assert!(dir.jws(&pkey, true, "", None).is_ok());
    }

    #[test]
    fn test_account_registration() {
        let _ = env_logger::init();
        let dir = Directory::lets_encrypt_staging().unwrap();
        dir.account_registration()
            .pkey_from_file("tests/user.key")
            .unwrap()
            .register()
            .unwrap();
    }

    #[test]
    fn test_authorization() {
        let _ = env_logger::init();
        let account = test_acc().unwrap();
        let auth = account.authorization("example.com").unwrap();
        assert!(!auth.0.is_empty());
        assert!(auth.get_challenge("http").is_some());
        assert!(auth.get_http_challenge().is_some());
        assert!(auth.get_dns_challenge().is_some());
        //assert!(auth.get_tls_sni_challenge().is_some());

        for challenge in auth.0 {
            assert!(!challenge.ctype.is_empty());
            assert!(!challenge.url.is_empty());
            assert!(!challenge.token.is_empty());
            assert!(!challenge.key_authorization.is_empty());
        }
    }

    // This test requires properly configured domain name and a http server
    // It will read TEST_DOMAIN and TEST_PUBLIC_DIR environment variables
    #[test]
    #[ignore]
    fn test_sign_certificate() {
        use std::env;
        let _ = env_logger::init();
        let account = test_acc().unwrap();
        let auth = account
            .authorization(&env::var("TEST_DOMAIN").unwrap())
            .unwrap();
        let http_challenge = auth.get_http_challenge().unwrap();
        assert!(http_challenge
                    .save_key_authorization(&env::var("TEST_PUBLIC_DIR").unwrap())
                    .is_ok());
        assert!(http_challenge.validate().is_ok());
        let cert = account
            .certificate_signer(&[&env::var("TEST_DOMAIN").unwrap()])
            .sign_certificate()
            .unwrap();
        account.revoke_certificate(cert.cert()).unwrap();
    }
}
