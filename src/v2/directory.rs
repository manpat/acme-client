use crate::v2::*;

/// Directory object to configure client. Main entry point of `acme-client`.
///
/// See [section-6.1.1](https://tools.ietf.org/html/draft-ietf-acme-acme-05#section-6.1.1)
/// for more details.
pub struct Directory {
    /// Base URL of directory
    url: String,
    directory: Value,
}



impl Directory {
    /// Creates a Directory from
    /// [`LETSENCRYPT_DIRECTORY_URL`](constant.LETSENCRYPT_DIRECTORY_URL.html).
    pub fn lets_encrypt() -> Result<Directory> {
        Directory::from_url(LETSENCRYPT_DIRECTORY_URL)
    }

    /// Creates a Directory from
    /// [`LETSENCRYPT_STAGING_DIRECTORY_URL`](constant.LETSENCRYPT_STAGING_DIRECTORY_URL.html).
    pub fn lets_encrypt_staging() -> Result<Directory> {
        Directory::from_url(LETSENCRYPT_STAGING_DIRECTORY_URL)
    }

    /// Creates a Directory from directory URL.
    ///
    /// Example directory for testing `acme-client` crate with staging API:
    ///
    /// ```rust
    /// # use acme_client::error::Result;
    /// # fn try_main() -> Result<()> {
    /// use acme_client::Directory;
    /// let dir = Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")?;
    /// # Ok(()) }
    /// # fn main () { try_main().unwrap(); }
    /// ```
    pub fn from_url(url: &str) -> Result<Directory> {
        let client = Client::new()?;
        let mut res = client.get(url).send()?;
        let mut content = String::new();
        res.read_to_string(&mut content)?;
        Ok(Directory {
           url: url.to_owned(),
           directory: from_str(&content)?,
       })

    }

    /// Returns url for the resource.
    pub(crate) fn url_for(&self, resource: &str) -> Option<&str> {
        self.directory
            .as_object()
            .and_then(|o| o.get(resource))
            .and_then(|k| k.as_str())
    }

    /// Consumes directory and creates new AccountRegistration.
    ///
    /// AccountRegistration is used to register an account.
    ///
    /// ```rust,no_run
    /// # use acme_client::error::Result;
    /// # fn try_main() -> Result<()> {
    /// use acme_client::Directory;
    ///
    /// let directory = Directory::lets_encrypt()?;
    /// let account = directory.account_registration()
    ///                        .email("example@example.org")
    ///                        .register()?;
    /// # Ok(()) }
    /// # fn main () { try_main().unwrap(); }
    /// ```
    pub fn account_registration(self) -> AccountRegistration {
        AccountRegistration {
            directory: self,
            pkey: None,
            email: None,
            contact: None,
            agreement: None,
        }
    }

    /// Gets nonce header from directory.
    ///
    /// This function will try to look for `newNonce` key in directory if it doesn't exists
    /// it will try to get nonce header from directory url.
    pub(crate) fn request_new_nonce(&self) -> Result<String> {
        // let url = self.url_for("newNonce").unwrap_or(&self.url);
        // let client = Client::new()?;
        // let res = client.get(url).send()?;
        // res.headers()
        //     .get::<hyperx::ReplayNonce>()
        //     .ok_or("Replay-Nonce header not found".to_err())
        //     .and_then(|nonce| Ok(nonce.as_str().to_string()))
        Ok(String::new())
    }

    /// Makes a new post request to directory, signs payload with pkey.
    ///
    /// Returns status code and Value object from reply.
    pub(crate) fn request_unauthorized<T: Serialize>(&self,
         pkey: &PKey<openssl::pkey::Private>,
         resource: &str,
         payload: T
    ) -> Result<(StatusCode, Value, reqwest::Response)> {

        use reqwest::{header::ContentType, mime::Mime};
        use std::str::FromStr;

        let mut json = to_value(&payload)?;

        let resource_json: Value = to_value(resource)?;
        json.as_object_mut()
            .and_then(|obj| obj.insert("resource".to_owned(), resource_json));

        let url = self.url_for(resource)
            .ok_or(format_err!("URL for resource: {} not found", resource))?;

        let jws = self.jws(pkey, json, url, None)?;
        let client = Client::new()?;

        let mime_type = Mime::from_str("application/jose+json").unwrap();

        let mut res = client
            .post(url)
            .header(ContentType(mime_type))
            .body(&jws[..])
            .send()?;

        let res_json = {
            let mut res_content = String::new();
            res.read_to_string(&mut res_content)?;
            if !res_content.is_empty() {
                from_str(&res_content)?
            } else {
                to_value(true)?
            }
        };

        Ok((*res.status(), res_json, res))
    }

    /// Makes a new post request to directory, signs payload with pkey.
    ///
    /// Returns status code and Value object from reply.
    pub(crate) fn request<T: Serialize>(&self,
        pkey: &PKey<openssl::pkey::Private>,
        resource: &str,
        payload: T,
        key_id: &str
    ) -> Result<(StatusCode, Value, reqwest::Response)> {

        use reqwest::{header::ContentType, mime::Mime};
        use std::str::FromStr;

        let mut json = to_value(&payload)?;

        let resource_json: Value = to_value(resource)?;
        json.as_object_mut()
            .and_then(|obj| obj.insert("resource".to_owned(), resource_json));

        let url = self.url_for(resource)
            .ok_or(format_err!("URL for resource: {} not found", resource))?;

        let jws = self.jws(pkey, json, url, Some(key_id))?;
        let client = Client::new()?;

        let mime_type = Mime::from_str("application/jose+json").unwrap();

        let mut res = client
            .post(url)
            .header(ContentType(mime_type))
            .body(&jws[..])
            .send()?;

        let res_json = {
            let mut res_content = String::new();
            res.read_to_string(&mut res_content)?;
            if !res_content.is_empty() {
                from_str(&res_content)?
            } else {
                to_value(true)?
            }
        };

        Ok((*res.status(), res_json, res))
    }

    /// Makes a Flattened JSON Web Signature from payload
    pub(crate) fn jws<T: Serialize>(&self, pkey: &PKey<openssl::pkey::Private>, payload: T, url: &str, kid: Option<&str>) -> Result<String> {
        let nonce = self.request_new_nonce()?;
        let mut data: HashMap<String, Value> = HashMap::new();

        // header: 'alg': 'RS256', 'jwk': { e, n, kty }
        let mut header: HashMap<String, Value> = HashMap::new();
        header.insert("alg".to_owned(), to_value("RS256")?);
        header.insert("url".to_owned(), url.into());

        if let Some(kid) = kid {
            header.insert("kid".to_owned(), kid.into());
        } else {
            header.insert("jwk".to_owned(), self.jwk(pkey)?);
        }

        // protected: base64 of header + nonce
        header.insert("nonce".to_owned(), to_value(nonce)?);
        let protected64 = b64(&to_string(&header)?.into_bytes());
        data.insert("protected".to_owned(), to_value(&protected64)?);

        // payload: b64 of payload
        let payload = to_string(&payload)?;
        let payload64 = b64(&payload.into_bytes());
        data.insert("payload".to_owned(), to_value(&payload64)?);

        // signature: b64 of hash of signature of {proctected64}.{payload64}
        data.insert("signature".to_owned(), {
            let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
            signer.update(&format!("{}.{}", protected64, payload64).into_bytes())?;
            to_value(b64(&signer.sign_to_vec()?))?
        });

        Ok(to_string(&data)?)
    }

    /// Returns jwk field of jws header
    pub(crate) fn jwk(&self, pkey: &PKey<openssl::pkey::Private>) -> Result<Value> {
        let rsa = pkey.rsa()?;
        let mut jwk: HashMap<String, String> = HashMap::new();
        jwk.insert("e".to_owned(),
                   b64(&rsa.e().to_vec()));
        jwk.insert("kty".to_owned(), "RSA".to_owned());
        jwk.insert("n".to_owned(),
                   b64(&rsa.n().to_vec()));
        Ok(to_value(jwk)?)
    }
}
