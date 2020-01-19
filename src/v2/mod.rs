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

// use self::error::*;

pub mod types;
pub mod client;
// pub mod directory;
pub mod account;
// pub mod account_registration;
// pub mod order;

pub use self::client::AcmeClient;
// pub use self::directory::Directory;
pub use self::account::Account;
// pub use self::account_registration::AccountRegistration;
// pub use self::order::Order;
pub use self::types::*;

/// Default Let's Encrypt directory URL to configure client.
pub const LETSENCRYPT_DIRECTORY_URL: &'static str = "https://acme-v02.api.letsencrypt.org/directory";

/// Default Let's Encrypt staging directory URL to configure client.
pub const LETSENCRYPT_STAGING_DIRECTORY_URL: &'static str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Default Let's Encrypt intermediate certificate URL to chain when needed.
pub const LETSENCRYPT_INTERMEDIATE_CERT_URL: &'static str = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem";

/// Default bit length for RSA keys and `X509_REQ`
const BIT_LENGTH: u32 = 2048;



/// The status of an `Order` or `Challenge`
/// See [section-7.1.6](https://tools.ietf.org/html/rfc8555#section-7.1.6)
// pub enum Status {
//     /// The initial state of the object - the server is waiting to a response to a `Challenge`
//     /// or for an `Order`s authorizations to be validated
//     Pending,

//     /// All authorizations in an `Order` are in the `Valid` state and is ready to be "finalized"
//     Ready,

//     /// A `Challenge` transitions to `Processing` when a client responds to a challenge and the server
//     /// begins trying to validate.
//     /// An `Order` transitions to `Processing` when the server receives a finalize request - the server
//     /// is in the cert issuing process
//     Processing,

//     /// Validation has been successful. A `Challenge` was successful or an `Order` has been fulfilled
//     Valid,

//     /// An `Order` or `Challenge` has failed to authorize, or some error has occurred.
//     Invalid,
// }

// impl std::str::FromStr for Status {
//     type Err = failure::Error;

//     fn from_str(s: &str) -> Result<Self> {
//         match s {
//             "pending" => Status::Pending,
//             "ready" => Status::Ready,
//             "processing" => Status::Processing,
//             "valid" => Status::Valid,
//             "invalid" => Status::Invalid,
//         }
//     }
// }





/// Error and result types.
pub mod error {
    pub type Result<T> = std::result::Result<T, failure::Error>;


    pub trait ToError {
        fn to_err(&self) -> failure::Error;
    }

    impl<'a> ToError for &'a str {
        fn to_err(&self) -> failure::Error {
            format_err!("{}", self)
        }
    }


    #[derive(Debug, Fail)]
    pub struct AcmeServerError(pub serde_json::Value);

    impl std::fmt::Display for AcmeServerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Acme server error {}", acme_server_error_description(&self.0))
        }
    }


    fn acme_server_error_description(resp: &serde_json::Value) -> String {
        if let Some(obj) = resp.as_object() {
            let t = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let detail = obj.get("detail").and_then(|d| d.as_str()).unwrap_or("");
            format!("{} {}", t, detail)
        } else {
            String::new()
        }
    }
}


/// Various helper functions.
pub mod helper {

    use std::path::Path;
    use std::fs::File;
    use std::io::Read;
    use openssl;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Req, X509Name};
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::stack::Stack;
    use openssl::hash::MessageDigest;
    use crate::error::{Result, ToError};


    /// Generates new PKey.
    pub fn gen_key() -> Result<PKey<openssl::pkey::Private>> {
        let rsa = Rsa::generate(super::BIT_LENGTH)?;
        let key = PKey::from_rsa(rsa)?;
        Ok(key)
    }


    /// base64 Encoding with URL and Filename Safe Alphabet.
    pub fn b64(data: &[u8]) -> String {
        base64::encode_config(data, base64::URL_SAFE_NO_PAD)
    }


    /// Reads PKey from Path.
    pub fn read_pkey<P: AsRef<Path>>(path: P) -> Result<PKey<openssl::pkey::Private>> {
        let mut file = File::open(path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        let key = PKey::private_key_from_pem(&content)?;
        Ok(key)
    }



    /// Generates X509Req (CSR) from domain names.
    ///
    /// This function will generate a CSR and sign it with PKey.
    ///
    /// Returns X509Req and PKey used to sign X509Req.
    pub fn gen_csr(pkey: &PKey<openssl::pkey::Private>, domains: &[&str]) -> Result<X509Req> {
        if domains.is_empty() {
            return Err("You need to supply at least one or more domain names".to_err());
        }

        let mut builder = X509Req::builder()?;
        let name = {
            let mut name = X509Name::builder()?;
            name.append_entry_by_text("CN", domains[0])?;
            name.build()
        };
        builder.set_subject_name(&name)?;

        // if more than one domain name is supplied
        // add them as SubjectAlternativeName
        if domains.len() > 1 {
            let san_extension = {
                let mut san = SubjectAlternativeName::new();
                for domain in domains.iter() {
                    san.dns(domain);
                }
                san.build(&builder.x509v3_context(None))?
            };
            let mut stack = Stack::new()?;
            stack.push(san_extension)?;
            builder.add_extensions(&stack)?;
        }

        builder.set_pubkey(&pkey)?;
        builder.sign(pkey, MessageDigest::sha256())?;

        Ok(builder.build())
    }
}




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
