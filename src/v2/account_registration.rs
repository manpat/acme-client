use crate::v2::error::*;
use crate::v2::helper::*;

use openssl::pkey::PKey;
use std::path::Path;

/// Helper to register an account.
#[derive(Default)]
pub struct AccountRegistration {
    pub(crate) pkey: Option<PKey<openssl::pkey::Private>>,
    pub(crate) email: Option<String>,
    pub(crate) contact: Option<Vec<String>>,
    pub(crate) agreement: Option<String>,
}


impl AccountRegistration {
    pub fn new() -> Self {
        Default::default()
    }


    /// Sets contact email address
    pub fn email(mut self, email: &str) -> AccountRegistration {
        self.email = Some(email.to_owned());
        self
    }

    /// Sets contact details such as telephone number (Let's Encrypt only supports email address).
    pub fn contact(mut self, contact: &[&str]) -> AccountRegistration {
        self.contact = Some(contact.iter().map(|c| c.to_string()).collect());
        self
    }

    /// Sets agreement url,
    /// [`LETSENCRYPT_AGREEMENT_URL`](constant.LETSENCRYPT_AGREEMENT_URL.html)
    /// will be used during registration if it's not set.
    pub fn agreement(mut self, url: &str) -> AccountRegistration {
        self.agreement = Some(url.to_owned());
        self
    }

    /// Sets account private key. A new key will be generated if it's not set.
    pub fn pkey(mut self, pkey: PKey<openssl::pkey::Private>) -> AccountRegistration {
        self.pkey = Some(pkey);
        self
    }

    /// Sets PKey from a PEM formatted file.
    pub fn pkey_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<AccountRegistration> {
        self.pkey = Some(read_pkey(path)?);
        Ok(self)
    }
}

