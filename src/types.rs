use openssl::pkey::PKey;
use openssl::x509::{X509, X509Req};
use std::path::Path;



#[derive(Debug, Clone, Copy)]
pub enum AcmeStatus {
    Pending,
    Processing,
    Invalid,
    Valid,
    Ready,
}


#[derive(Deserialize, Debug, Clone)]
pub struct OrderUri(pub String);

#[derive(Deserialize, Debug, Clone)]
pub struct AuthorizationUri(pub String);

#[derive(Deserialize, Debug, Clone)]
pub struct CertificateUri(pub String);


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Identifier {
    #[serde(rename="type")]
    pub identifier_type: String,

    #[serde(rename="value")]
    pub uri: String,
}


#[derive(Deserialize)]
pub struct Directory {
    #[serde(rename="newNonce")]
    pub new_nonce_uri: String,

    #[serde(rename="newAccount")]
    pub new_account_uri: String,

    #[serde(rename="newOrder")]
    pub new_order_uri: String,
}


#[derive(Deserialize, Debug, Clone)]
pub struct Order {
    pub status: AcmeStatus,

    pub identifiers: Vec<Identifier>,
    pub authorizations: Vec<AuthorizationUri>,
    #[serde(rename="finalize")]
    pub finalize_uri: String,

    pub expires: Option<String>,
    pub error: Option<String>,
    
    #[serde(rename="certificate")]
    pub certificate_uri: Option<CertificateUri>,
}


#[derive(Deserialize, Debug, Clone)]
pub struct Authorization {
    pub status: AcmeStatus,
    pub expires: String,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
}


#[derive(Deserialize, Debug, Clone)]
pub struct Challenge {
    pub status: Option<AcmeStatus>,

    #[serde(rename="type")]
    pub challenge_type: String,
    pub url: String,
    pub token: String,
}


/// A signed certificate.
pub struct SignedCertificate {
    pub cert: X509,
    pub intermediate_cert: X509,
    pub csr: X509Req,
    pub pkey: PKey<openssl::pkey::Private>,
}



/// Options for registering an account
#[derive(Default)]
pub struct AccountRegistration {
    pub(crate) pkey: Option<PKey<openssl::pkey::Private>>,
    pub(crate) contact: Option<Vec<String>>,
}


impl AccountRegistration {
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets contact email address
    pub fn email(mut self, email: &str) -> AccountRegistration {
        self.contact.get_or_insert_with(Vec::new)
            .push(format!("mailto:{}", email));

        self
    }

    /// Sets contact details such as telephone number (Let's Encrypt only supports email address).
    pub fn contact(mut self, contact: &str) -> AccountRegistration {
        self.contact.get_or_insert_with(Vec::new)
            .push(contact.to_owned());

        self
    }

    /// Sets account private key. A new key will be generated if it's not set.
    pub fn pkey(mut self, pkey: PKey<openssl::pkey::Private>) -> AccountRegistration {
        self.pkey = Some(pkey);
        self
    }

    /// Sets PKey from a PEM formatted file.
    pub fn pkey_from_file<P: AsRef<Path>>(mut self, path: P) -> crate::Result<AccountRegistration> {
        let content = std::fs::read(path)?;
        let key = PKey::private_key_from_pem(&content)?;
        self.pkey = Some(key);

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
            "ready" => Ok(AcmeStatus::Ready),
            _ => unimplemented!()
        }
    }
}