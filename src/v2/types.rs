use crate::error::*;
use crate::helper::*;

// use serde::{Serialize, Deserialize};
use openssl::pkey::PKey;
use std::path::Path;



#[derive(Debug, Clone, Copy)]
pub enum AcmeStatus {
    Pending,
    Processing,
    Invalid,
    Valid,
}



#[derive(Deserialize, Debug, Clone)]
pub struct Order {
    pub authorizations: Vec<AuthorizationUri>,
    
    #[serde(rename="finalize")]
    pub finalize_uri: String,
}


#[derive(Deserialize, Debug, Clone)]
pub struct AuthorizationUri(pub String);


#[derive(Deserialize, Debug, Clone)]
pub struct Authorization {
    pub status: AcmeStatus,
    pub expires: String,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Identifier {
    #[serde(rename="type")]
    pub identifier_type: String,

    #[serde(rename="value")]
    pub uri: String,
}


#[derive(Deserialize, Debug, Clone)]
pub struct Challenge {
    pub status: Option<AcmeStatus>,

    #[serde(rename="type")]
    pub challenge_type: String,
    pub url: String,
    pub token: String,
}




/// Options for registering an account
#[derive(Default)]
pub struct AccountRegistration {
    pub(crate) pkey: Option<PKey<openssl::pkey::Private>>,
    pub(crate) email: Option<String>,
    pub(crate) contact: Option<Vec<String>>,
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



impl<'de> serde::Deserialize<'de> for AcmeStatus {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error> where D: serde::Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "pending" => Ok(AcmeStatus::Pending),
            "processing" => Ok(AcmeStatus::Processing),
            "invalid" => Ok(AcmeStatus::Invalid),
            "valid" => Ok(AcmeStatus::Valid),
            // _ => AcmeStatus::Other(s),
            _ => unimplemented!()
        }
    }
}