
use crate::v2::error::*;
use crate::v2::helper::*;
// use crate::v2::{Directory, Order};

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::io::{Read, Write};

use reqwest::StatusCode;
use openssl::x509::X509;
use openssl::pkey::PKey;

/// Registered account object.
///
/// Every operation requires a registered account. To register an `Account` you can use
/// `Directory::register_account` method.
///
/// See [AccountRegistration](struct.AccountRegistration.html) helper for more details.
pub struct Account {
    // pub(crate) directory: Directory,
    pub(crate) pkey: PKey<openssl::pkey::Private>,
    pub(crate) key_id: String,
}


impl Account {
    /// Creates a new order for `domain`
    // pub fn order(&self, domain: &str) -> Result<Order> {
    //     info!("Sending new order request for {}", domain);

    //     let mut map = HashMap::new();
    //     map.insert("identifiers".to_owned(), {
    //         let mut map = HashMap::new();
    //         map.insert("type".to_owned(), "dns".to_owned());
    //         map.insert("value".to_owned(), domain.to_owned());
    //         vec![map]
    //     });

    //     let (http_status, body, _) = self.directory().request(self.pkey(), "newOrder", map, &self.key_id)?;

    //     if http_status != StatusCode::Created {
    //         return Err(AcmeServerError(body).into());
    //     }

    //     let object = body.as_object().ok_or_else(|| "Malformed response to newOrder request".to_err())?;

    //     let authorizations = object.get("authorizations")
    //     	.and_then(|val| val.as_array())
    //     	.ok_or_else(|| "newOrder response is malformed or missing 'authorizations'".to_err())?
    //     	.iter()
    //     	.filter_map(|val| val.as_str().map(Into::into))
    //     	.collect();

    //     let finalize_uri = object.get("finalize")
    //     	.and_then(|val| val.as_str())
    //     	.map(Into::into)
    //     	.ok_or_else(|| "newOrder response is missing 'finalize' entry".to_err())?;

    //     Ok(Order {
    //     	authorizations,
    //     	finalize_uri
    //     })
    // }

    /// Creates a new `CertificateSigner` helper to sign a certificate for list of domains.
    ///
    /// `domains` must be list of the domain names you want to sign a certificate for.
    /// Currently there is no way to retrieve subject alt names from a X509Req.
    ///
    /// You can additionally use your own private key and CSR.
    /// See [`CertificateSigner`](struct.CertificateSigner.html) for details.
    // pub fn certificate_signer<'a>(&'a self, domains: &'a [&'a str]) -> CertificateSigner<'a> {
    //     CertificateSigner {
    //         account: self,
    //         domains: domains,
    //         pkey: None,
    //         csr: None,
    //     }
    // }

    /// Revokes a signed certificate from pem formatted file
    // pub fn revoke_certificate_from_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
    //     let content = {
    //         let mut file = File::open(path)?;
    //         let mut content = Vec::new();
    //         file.read_to_end(&mut content)?;
    //         content
    //     };
    //     let cert = X509::from_pem(&content)?;
    //     self.revoke_certificate(&cert)
    // }

    /// Revokes a signed certificate
    // pub fn revoke_certificate(&self, cert: &X509) -> Result<()> {
    //     let (status, body, _) = {
    //         let mut map = HashMap::new();
    //         map.insert("certificate".to_owned(), b64(&cert.to_der()?));

    //         self.directory()
    //             .request(self.pkey(), "revokeCert", map, &self.key_id)?
    //     };

    //     match status {
    //         StatusCode::Ok => info!("Certificate successfully revoked"),
    //         StatusCode::Conflict => warn!("Certificate already revoked"),
    //         _ => return Err(AcmeServerError(body).into()),
    //     }

    //     Ok(())
    // }

    /// Writes account private key to a writer
    pub fn write_private_key<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.pkey().private_key_to_pem_pkcs8()?)?)
    }

    /// Saves account private key to a file
    pub fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_private_key(&mut file)
    }

    /// Returns a reference to account private key
    pub fn pkey(&self) -> &PKey<openssl::pkey::Private> {
        &self.pkey
    }

    // /// Returns a reference to directory used to create account
    // pub fn directory(&self) -> &Directory {
    //     &self.directory
    // }
}