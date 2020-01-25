
use crate::error::*;
use crate::types::*;
use serde_json::{to_string, from_str, Value, json};
use openssl::pkey::PKey;
use openssl::x509::X509;
use reqwest::StatusCode;

use std::cell::Cell;
use std::io::Read;


pub struct AcmeClient {
	client: reqwest::Client,
	directory: Directory,

	nonce: Cell<String>,
    pkey: PKey<openssl::pkey::Private>,
    account_key_id: String,
}

impl AcmeClient {
	/// Creates an `AcmeClient` with a directory from
	/// [`LETSENCRYPT_DIRECTORY_URL`](constant.LETSENCRYPT_DIRECTORY_URL.html).
	pub fn lets_encrypt(registration: AccountRegistration) -> Result<Self> {
		Self::with_directory(crate::LETSENCRYPT_DIRECTORY_URL, registration)
	}

	/// Creates an `AcmeClient` with a directory from
	/// [`LETSENCRYPT_STAGING_DIRECTORY_URL`](constant.LETSENCRYPT_STAGING_DIRECTORY_URL.html).
	pub fn lets_encrypt_staging(registration: AccountRegistration) -> Result<Self> {
		Self::with_directory(crate::LETSENCRYPT_STAGING_DIRECTORY_URL, registration)
	}

	/// Creates an `AcmeClient` with a directory retrieved from `directory_url`.
	pub fn with_directory(directory_url: &str, registration: AccountRegistration) -> Result<Self> {
		let client = reqwest::Client::new()?;

		let mut response = client.get(directory_url).send()?;
		let directory_content = response_to_string(&mut response)?;
		let directory: Directory = serde_json::from_str(&directory_content)?;

		// Get a nonce for account creation
		let response = client.get(&directory.new_nonce_uri).send()?;
		let nonce = response_nonce(&response)?;

		// Request an account
		let pkey = registration.pkey.unwrap_or(gen_key()?);

		let (nonce, account_key_id) = {
			let payload = json!({
				"resource": "newAccount",
				"termsOfServiceAgreed": true,
				"contact": registration.contact,
			});

			let payload_str = to_string(&payload)?;
			let jws = format_jws(&nonce, &directory.new_account_uri, &pkey, None, &payload_str)?;

			let mut response = client.post(&directory.new_account_uri)
				.header(jose_json_content_type())
				.body(&jws[..])
				.send()?;

			if !response.status().is_success() {
				let body = response_to_string(&mut response)?;
				bail!("Acme request failed: {}", body)
			}

			(response_nonce(&response)?, response_location(&response)?)
		};

		Ok(AcmeClient {
			client,
			directory,

			nonce: Cell::new(nonce),
			pkey,
			account_key_id
		})
	}


	pub fn submit_order(&self, domains: &[&str]) -> Result<(Order, OrderUri)> {
		info!("Sending new order request for {:?}", domains);

		let identifiers = domains.iter()
			.map(|&domain| Identifier {
				identifier_type: "dns".into(),
				uri: domain.into()
			})
			.collect::<Vec<_>>();

		let payload = json!({
			"identifiers": identifiers,
			"resource": "newOrder"
		});

		let (http_status, body, location) = {
			let mut res = self.post_with_account(&self.directory.new_order_uri, &to_string(&payload)?)?;
			let body = response_to_string(&mut res)?;
			(*res.status(), body, response_location(&res)?)
		};

		if http_status != StatusCode::Created {
			bail!("Acme request failed: {}", body)
		}

		let order: Order = from_str(&body)?;
		Ok((order, OrderUri(location)))
	}


	pub fn fetch_order(&self, order: &OrderUri) -> Result<Order> {
		let mut response = self.get_with_account(&order.0)?;

		let body = response_to_string(&mut response)?;
		let order: Order = from_str(&body)?;
		
		Ok(order)
	}


	pub fn fetch_authorization(&self, authorization: &AuthorizationUri) -> Result<Authorization> {
		let mut response = self.get_with_account(&authorization.0)?;

		let body = response_to_string(&mut response)?;
		let authorization: Authorization = from_str(&body)?;
		
		Ok(authorization)
	}


	pub fn fetch_certificate(&self, certificate_uri: &CertificateUri) -> Result<(X509, X509)> {
		let mut response = self.get_with_account(&certificate_uri.0)?;

        let mut body = Vec::new();
        response.read_to_end(&mut body)?;
        let mut certs = X509::stack_from_pem(&body)?;

        let cert = certs.remove(0);
        let intermediate_cert = certs.remove(0);

        Ok((cert, intermediate_cert))
	}


	pub fn signal_challenge_ready(&self, challenge: &Challenge) -> Result<()> {
		self.post_with_account(&challenge.url, "{}").map(|_| ())
	}


	pub fn finalize_order(&self, order: &Order) -> Result<(SignedCertificate, CertificateUri)> {
		let domains = order.identifiers.iter()
			.map(|ident| ident.uri.as_str())
			.collect::<Vec<_>>();

		// Generate a key to sign the certificate request - this key _must_ be different to the key
		// associated with the account, `self.pkey`
        let pkey = gen_key()?;
        let csr = gen_csr(&pkey, &domains)?;
        let csr_b64 = to_base64(csr.to_der()?);

		let payload = to_string(&json!({"csr": csr_b64}))?;

		let mut response = self.post_with_account(&order.finalize_uri, &payload)?;
		let body = response_to_string(&mut response)?;
		let order: Order = from_str(&body)?;

		let certificate_uri = order.certificate_uri.as_ref()
			.ok_or_else(|| format_err!("Failed to get certificate uri"))?;

		let (cert, intermediate_cert) = self.fetch_certificate(certificate_uri)?;

        Ok((SignedCertificate { cert, intermediate_cert, csr, pkey }, certificate_uri.clone()))
	}

    /// Calculate the "key authorization" required to validate a challenge
    /// This is what should go in the 'provisioned resource'
    pub fn calculate_key_authorization(&self, challenge: &crate::types::Challenge) -> Result<String> {
        use openssl::hash::{hash, MessageDigest};

        let jwk = jwk(&self.pkey)?;
        let jwk_bytes = to_string(&jwk)?.into_bytes();

        let jwk_sha = hash(MessageDigest::sha256(), &jwk_bytes)?;
        let jwk_b64 = to_base64(jwk_sha);

        // key-authz = token || '.' || base64url(JWK\_Thumbprint(accountKey))
        let key_authorization = format!("{}.{}",
            challenge.token,
            jwk_b64
        );

        Ok(key_authorization)
    }


    fn take_nonce(&self) -> Result<String> {
    	let nonce = self.nonce.take();

    	if nonce.is_empty() {
			// Request a new nonce if none has been stored
			let res = self.client.get(&self.directory.new_nonce_uri).send()?;
			response_nonce(&res)
    	} else {
	    	Ok(nonce)
    	}
    }

	fn get_with_account(&self, uri: &str) -> Result<reqwest::Response> {
		self.post_with_account(uri, "")
	}

	fn post_with_account(&self, uri: &str, payload: &str) -> Result<reqwest::Response> {
		let jws = format_jws(&self.take_nonce()?, uri, &self.pkey, Some(&self.account_key_id), payload)?;

		let mut res = self.client.post(uri)
			.header(jose_json_content_type())
			.body(&jws[..])
			.send()?;

		// Store nonce so we can use it in the next request
		self.nonce.set(response_nonce(&res)?);

		if !res.status().is_success() {
			let body = response_to_string(&mut res)?;
			bail!("Acme request failed: {}", body)
		}

		Ok(res)
	}
}


fn jose_json_content_type() -> reqwest::header::ContentType {
	use reqwest::{header::ContentType, mime::Mime};
	use std::str::FromStr;
	let mime_type = Mime::from_str("application/jose+json").unwrap();
	ContentType(mime_type)
}


/// Makes a Flattened JSON Web Signature from payload
fn format_jws(nonce: &str, url: &str, pkey: &PKey<openssl::pkey::Private>, kid: Option<&str>, payload: &str) -> Result<String> {
	let header = if let Some(kid) = kid {
		json!({
			"alg": "RS256",
			"url": url,
			"nonce": nonce,
			"kid": kid,
		})
	} else {
		json!({
			"alg": "RS256",
			"url": url,
			"nonce": nonce,
			"jwk": jwk(pkey)?,
		})
	};

	// protected: base64 of header + nonce
	let protected64 = to_base64(to_string(&header)?);

	// payload: b64 of payload
	let payload64 = to_base64(payload);

	// signature: b64 of hash of signature of {proctected64}.{payload64}
	let signature = {
		use openssl::sign::Signer;
		use openssl::hash::MessageDigest;

		let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
		signer.update(format!("{}.{}", protected64, payload64).as_bytes())?;
		to_base64(signer.sign_to_vec()?)
	};

	let data = json!({
		"protected": protected64,
		"payload": payload64,
		"signature": signature,
	});

	Ok(to_string(&data)?)
}


/// Returns jwk field of jws header
fn jwk(pkey: &PKey<openssl::pkey::Private>) -> Result<Value> {
	let rsa = pkey.rsa()?;
	let jwk = json!({
		"e": to_base64(rsa.e().to_vec()),
		"kty": "RSA",
		"n": to_base64(rsa.n().to_vec()),
	});

	Ok(jwk)
}

/// base64 Encoding with URL and Filename Safe Alphabet.
fn to_base64<T: AsRef<[u8]>>(data: T) -> String {
    base64::encode_config(data.as_ref(), base64::URL_SAFE_NO_PAD)
}


fn gen_key() -> Result<PKey<openssl::pkey::Private>> {
    use openssl::rsa::Rsa;

    let rsa = Rsa::generate(super::BIT_LENGTH)?;
    let key = PKey::from_rsa(rsa)?;
    Ok(key)
}


fn gen_csr(pkey: &PKey<openssl::pkey::Private>, domains: &[&str]) -> Result<openssl::x509::X509Req> {
    use openssl::x509::{X509Req, X509Name};
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::stack::Stack;
    use openssl::hash::MessageDigest;

    if domains.is_empty() {
        bail!("You need to supply at least one or more domain names")
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



fn response_to_string(response: &mut reqwest::Response) -> Result<String> {
	let mut res_content = String::new();
	response.read_to_string(&mut res_content)?;
	Ok(res_content)
}

fn response_location(response: &reqwest::Response) -> Result<String> {
	let location = response.headers()
		.get::<reqwest::header::Location>()
		.ok_or_else(|| format_err!("Server response to account registration missing Location header"))?;
	
	Ok(location.as_str().to_owned())
}

fn response_nonce(response: &reqwest::Response) -> Result<String> {
	let nonce = response.headers()
		.get::<hyperx::ReplayNonce>()
		.ok_or_else(|| format_err!("Replay-Nonce header not found"))?;

	Ok(nonce.as_str().to_owned())
}



// header! is making a public struct,
// our custom header is private and only used privately in this module
mod hyperx {
	// ReplayNonce header for hyper
	header! { (ReplayNonce, "Replay-Nonce") => [String] }
}