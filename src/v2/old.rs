
/// Helper to sign a certificate.
pub struct CertificateSigner<'a> {
    account: &'a Account,
    domains: &'a [&'a str],
    pkey: Option<PKey<openssl::pkey::Private>>,
    csr: Option<X509Req>,
}


/// A signed certificate.
pub struct SignedCertificate {
    cert: X509,
    csr: X509Req,
    pkey: PKey<openssl::pkey::Private>,
}


/// Identifier authorization object.
pub struct Authorization<'a>(Vec<Challenge<'a>>);


/// A verification challenge.
pub struct Challenge<'a> {
    account: &'a Account,
    /// Type of verification challenge. Usually `http-01`, `dns-01` for letsencrypt.
    ctype: String,
    /// URL to trigger challenge.
    url: String,
    /// Challenge token.
    token: String,
    /// Key authorization.
    key_authorization: String,
}



impl<'a> CertificateSigner<'a> {
    /// Set PKey of CSR
    pub fn pkey(mut self, pkey: PKey<openssl::pkey::Private>) -> CertificateSigner<'a> {
        self.pkey = Some(pkey);
        self
    }

    /// Load PEM formatted PKey from file
    pub fn pkey_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<CertificateSigner<'a>> {
        self.pkey = Some(read_pkey(path)?);
        Ok(self)
    }

    /// Set CSR to sign
    pub fn csr(mut self, csr: X509Req) -> CertificateSigner<'a> {
        self.csr = Some(csr);
        self
    }

    /// Load PKey and CSR from file
    pub fn csr_from_file<P: AsRef<Path>>(mut self,
                                         pkey_path: P,
                                         csr_path: P)
                                         -> Result<CertificateSigner<'a>> {
        self.pkey = Some(read_pkey(pkey_path)?);
        let content = {
            let mut file = File::open(csr_path)?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;
            content
        };
        self.csr = Some(X509Req::from_pem(&content)?);
        Ok(self)
    }


    /// Signs certificate.
    ///
    /// CSR and PKey will be generated if it doesn't set or loaded first.
    pub fn sign_certificate(self) -> Result<SignedCertificate> {
        info!("Signing certificate");
        let pkey = self.pkey.unwrap_or(gen_key()?);
        let csr = self.csr.unwrap_or(gen_csr(&pkey, self.domains)?);
        let mut map = HashMap::new();
        map.insert("resource".to_owned(), "new-cert".to_owned());
        map.insert("csr".to_owned(), b64(&csr.to_der()?));

        // TODO: new-cert doesn't exist - newOrder
        let url = self.account
           .directory()
           .url_for("new-cert")
           .ok_or_else(|| "new-cert url not found".to_err())?;

        let client = Client::new()?;
        let jws = self.account.directory().jws(self.account.pkey(), map, url, Some(&self.account.key_id))?;
        let mut res = client
            .post(url)
            .body(&jws[..])
            .send()?;

        if res.status() != &StatusCode::Created {
            let res_json = {
                let mut res_content = String::new();
                res.read_to_string(&mut res_content)?;
                from_str(&res_content)?
            };
            return Err(AcmeServerError(res_json).into());
        }

        let mut crt_der = Vec::new();
        res.read_to_end(&mut crt_der)?;
        let cert = X509::from_der(&crt_der)?;

        debug!("Certificate successfully signed");
        Ok(SignedCertificate {
               cert: cert,
               csr: csr,
               pkey: pkey,
           })
    }
}


impl SignedCertificate {
    /// Saves signed certificate to a file
    pub fn save_signed_certificate<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_signed_certificate(&mut file)
    }

    /// Saves intermediate certificate to a file
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn save_intermediate_certificate<P: AsRef<Path>>(&self,
                                                         url: Option<&str>,
                                                         path: P)
                                                         -> Result<()> {
        let mut file = File::create(path)?;
        self.write_intermediate_certificate(url, &mut file)
    }

    /// Saves intermediate certificate and signed certificate to a file
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn save_signed_certificate_and_chain<P: AsRef<Path>>(&self,
                                                             url: Option<&str>,
                                                             path: P)
                                                             -> Result<()> {
        let mut file = File::create(path)?;
        self.write_signed_certificate(&mut file)?;
        self.write_intermediate_certificate(url, &mut file)?;
        Ok(())
    }

    /// Saves private key used to sign certificate to a file
    pub fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_private_key(&mut file)
    }

    /// Saves CSR used to sign certificateto to a file
    pub fn save_csr<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_csr(&mut file)
    }

    /// Writes signed certificate to writer.
    pub fn write_signed_certificate<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.cert.to_pem()?)?;
        Ok(())
    }

    /// Writes intermediate certificate to writer.
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn write_intermediate_certificate<W: Write>(&self,
                                                    url: Option<&str>,
                                                    writer: &mut W)
                                                    -> Result<()> {
        let cert = self.get_intermediate_certificate(url)?;
        writer.write_all(&cert.to_pem()?)?;
        Ok(())
    }

    /// Gets intermediate certificate from url.
    ///
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    /// will be used if url is None.
    fn get_intermediate_certificate(&self, url: Option<&str>) -> Result<X509> {
        let client = Client::new()?;
        let mut res = client
            .get(url.unwrap_or(LETSENCRYPT_INTERMEDIATE_CERT_URL))
            .send()?;
        let mut content = Vec::new();
        res.read_to_end(&mut content)?;
        Ok(X509::from_pem(&content)?)
    }

    /// Writes private key used to sign certificate to a writer
    pub fn write_private_key<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.pkey().private_key_to_pem_pkcs8()?)?)
    }

    /// Writes CSR used to sign certificateto a writer
    pub fn write_csr<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.csr().to_pem()?)?)
    }

    /// Returns reference to certificate
    pub fn cert(&self) -> &X509 {
        &self.cert
    }

    /// Returns reference to CSR used to sign certificate
    pub fn csr(&self) -> &X509Req {
        &self.csr
    }

    /// Returns reference to pkey used to sign certificate
    pub fn pkey(&self) -> &PKey<openssl::pkey::Private> {
        &self.pkey
    }
}


impl<'a> Authorization<'a> {
    /// Gets a challenge.
    ///
    /// Pattern is used in `starts_with` for type comparison.
    pub fn get_challenge(&self, pattern: &str) -> Option<&Challenge> {
        for challenge in &self.0 {
            if challenge.ctype().starts_with(pattern) {
                return Some(challenge);
            }
        }
        None
    }

    /// Gets http challenge
    pub fn get_http_challenge(&self) -> Option<&Challenge> {
        self.get_challenge("http")
    }

    /// Gets dns challenge
    pub fn get_dns_challenge(&self) -> Option<&Challenge> {
        self.get_challenge("dns")
    }

    /// Gets tls-sni challenge
    pub fn get_tls_sni_challenge(&self) -> Option<&Challenge> {
        self.get_challenge("tls-sni")
    }
}


impl<'a> Challenge<'a> {
    /// Saves key authorization into `{path}/.well-known/acme-challenge/{token}` for http challenge.
    pub fn save_key_authorization<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use std::fs::create_dir_all;
        let path = path.as_ref().join(".well-known").join("acme-challenge");
        debug!("Saving validation token into: {:?}", &path);
        create_dir_all(&path)?;

        let mut file = File::create(path.join(&self.token))?;
        writeln!(&mut file, "{}", self.key_authorization)?;

        Ok(())
    }

    /// Gets DNS validation signature.
    ///
    /// This value is used for verification of domain over DNS. Signature must be saved
    /// as a TXT record for `_acme_challenge.example.com`.
    pub fn signature(&self) -> Result<String> {
        Ok(b64(&hash(MessageDigest::sha256(),
                     &self.key_authorization.clone().into_bytes())?))
    }

    /// Returns challenge type, usually `http-01` or `dns-01` for Let's Encrypt.
    pub fn ctype(&self) -> &str {
        &self.ctype
    }

    /// Returns challenge token
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns key_authorization
    pub fn key_authorization(&self) -> &str {
        &self.key_authorization
    }

    /// Triggers validation.
    pub fn validate(&self) -> Result<()> {
        info!("Triggering {} validation", self.ctype);
        let payload = {
            let map = {
                let mut map: HashMap<String, Value> = HashMap::new();
                map.insert("type".to_owned(), to_value(&self.ctype)?);
                map.insert("token".to_owned(), to_value(&self.token)?);
                map.insert("resource".to_owned(), to_value("challenge")?);
                map.insert("keyAuthorization".to_owned(),
                           to_value(&self.key_authorization)?);
                map
            };
            self.account.directory().jws(self.account.pkey(), map, &self.url, Some(&self.account.key_id))?
        };

        let client = Client::new()?;
        let mut resp = client.post(&self.url).body(&payload[..]).send()?;

        let mut res_json: Value = {
            let mut res_content = String::new();
            resp.read_to_string(&mut res_content)?;
            from_str(&res_content)?
        };

        if resp.status() != &StatusCode::Accepted {
            return Err(AcmeServerError(res_json).into());
        }

        loop {
            let status = res_json
                .as_object()
                .and_then(|o| o.get("status"))
                .and_then(|s| s.as_str())
                .ok_or_else(|| "Status not found".to_err())?
                .to_owned();

            if status == "pending" {
                debug!("Status is pending, trying again...");
                let mut resp = client.get(&self.url).send()?;
                res_json = {
                    let mut res_content = String::new();
                    resp.read_to_string(&mut res_content)?;
                    from_str(&res_content)?
                };
            } else if status == "valid" {
                return Ok(());
            } else if status == "invalid" {
                return Err(AcmeServerError(res_json).into());
            }

            use std::thread::sleep;
            use std::time::Duration;
            sleep(Duration::from_secs(2));
        }
    }
}
