
use crate::v2::error::*;
use crate::v2::helper::*;
use crate::v2::{Directory, Account};

use openssl::pkey::PKey;
use reqwest::StatusCode;
use serde_json::to_value;

use std::path::Path;
use std::collections::HashMap;

/// Helper to register an account.
pub struct AccountRegistration {
    pub(crate) directory: Directory,
    pub(crate) pkey: Option<PKey<openssl::pkey::Private>>,
    pub(crate) email: Option<String>,
    pub(crate) contact: Option<Vec<String>>,
    pub(crate) agreement: Option<String>,
}


impl AccountRegistration {
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

    /// Registers an account.
    ///
    /// A PKey will be generated if it doesn't exists.
    pub fn register(self) -> Result<Account> {
        info!("Registering account");
        let mut map = HashMap::new();

        map.insert("termsOfServiceAgreed".to_owned(), to_value(true)?);

        if let Some(mut contact) = self.contact {
            if let Some(email) = self.email {
                contact.push(format!("mailto:{}", email));
            }
            map.insert("contact".to_owned(), to_value(contact)?);

        } else if let Some(email) = self.email {
            map.insert("contact".to_owned(),
                       to_value(vec![format!("mailto:{}", email)])?);
        }

        let pkey = self.pkey.unwrap_or(gen_key()?);
        let (status, body, response) = self.directory.request_unauthorized(&pkey, "newAccount", map)?;

        match status {
            StatusCode::Ok | StatusCode::Created => debug!("User successfully registered"),
            StatusCode::Conflict => debug!("User already registered"),
            _ => return Err(AcmeServerError(body).into()),
        };

        let location = response.headers().get::<reqwest::header::Location>()
            .ok_or_else(|| "Server response to account registration missing Location header".to_err())?;

        Ok(Account {
           directory: self.directory,
           pkey: pkey,
           key_id: location.as_str().to_owned(),
       })
    }
}

