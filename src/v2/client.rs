
use crate::error::*;
use crate::{AccountRegistration, Account, Order};
use serde_json::{to_value, to_string, from_str, Value, json};
use serde::Serialize;
use openssl::pkey::PKey;
use reqwest::StatusCode;


use std::io::Read;
use std::collections::HashMap;

pub struct Challenge {}


pub struct AcmeClient {
	client: reqwest::Client,

	new_nonce_uri: String,
	new_account_uri: String,
	new_order_uri: String,
}

impl AcmeClient {
	/// Creates an `AcmeClient` with a directory retrieved from `directory_url`.
	pub fn with_directory(directory_url: &str) -> Result<Self> {
		let client = reqwest::Client::new()?;

		let mut res = client.get(directory_url).send()?;
		let mut content = String::new();
		res.read_to_string(&mut content)?;

		let directory: HashMap<String, serde_json::Value> = serde_json::from_str(&content)?;

		let new_nonce_uri = directory.get("newNonce")
			.and_then(|v| v.as_str())
			.map(Into::into)
			.ok_or_else(|| "Directory missing 'newNonce'".to_err())?;

		let new_account_uri = directory.get("newAccount")
			.and_then(|v| v.as_str())
			.map(Into::into)
			.ok_or_else(|| "Directory missing 'newAccount'".to_err())?;

		let new_order_uri = directory.get("newOrder")
			.and_then(|v| v.as_str())
			.map(Into::into)
			.ok_or_else(|| "Directory missing 'newOrder'".to_err())?;

		Ok(AcmeClient {
			client,
			new_nonce_uri,
			new_account_uri,
			new_order_uri,
		})
	}

	/// Creates an `AcmeClient` with a directory from
	/// [`LETSENCRYPT_DIRECTORY_URL`](constant.LETSENCRYPT_DIRECTORY_URL.html).
	pub fn lets_encrypt() -> Result<Self> {
		Self::with_directory(crate::LETSENCRYPT_DIRECTORY_URL)
	}

	/// Creates an `AcmeClient` with a directory from
	/// [`LETSENCRYPT_STAGING_DIRECTORY_URL`](constant.LETSENCRYPT_STAGING_DIRECTORY_URL.html).
	pub fn lets_encrypt_staging() -> Result<Self> {
		Self::with_directory(crate::LETSENCRYPT_STAGING_DIRECTORY_URL)
	}


	pub fn request_new_nonce(&self) -> Result<String> {
		let res = self.client.get(&self.new_nonce_uri).send()?;
		res.headers()
			.get::<hyperx::ReplayNonce>()
			.ok_or("Replay-Nonce header not found".to_err())
			.and_then(|nonce| Ok(nonce.as_str().to_string()))
	}


	/// Registers an account.
	///
	/// A PKey will be generated if it doesn't exist.
	pub fn register_account(&self, registration: AccountRegistration) -> Result<Account> {
		use crate::helper::*;

		info!("Registering account");

		let mut contact_info = registration.contact.unwrap_or(Vec::new());
		if let Some(email) = registration.email {
			contact_info.push(format!("mailto:{}", email));
		}

		let mut payload = json!({
			"resource": "newAccount",
			"termsOfServiceAgreed": true
		});

		if !contact_info.is_empty() {
			payload.as_object_mut().unwrap()
				.insert("contact".to_owned(), to_value(contact_info)?);
		}

		let pkey = registration.pkey.unwrap_or(gen_key()?);

		let (status, mut response) = {
			let mut json = to_string(&payload)?;

			let nonce = self.request_new_nonce()?;
			let jws = format_jws(&nonce, &self.new_account_uri, &pkey, None, &json)?;

			let res = self.client.post(&self.new_account_uri)
				.header(Self::content_type())
				.body(&jws[..])
				.send()?;

			(*res.status(), res)
		};

		match status {
			StatusCode::Ok | StatusCode::Created => debug!("User successfully registered"),
			StatusCode::Conflict => debug!("User already registered"),
			_ => {
				let mut res_content = String::new();
				response.read_to_string(&mut res_content)?;
				return Err(AcmeServerError(from_str(&res_content)?).into())
			},
		};

		let location = response.headers().get::<reqwest::header::Location>()
			.ok_or_else(|| "Server response to account registration missing Location header".to_err())?;

		Ok(Account {
		   pkey: pkey,
		   key_id: location.as_str().to_owned(),
	   })
	}


	pub fn submit_order(&self, account: &Account, domain: &str) -> Result<Order> {
		info!("Sending new order request for {}", domain);

		let mut payload = HashMap::new();
		payload.insert("identifiers".to_owned(), {
			let mut payload = HashMap::new();
			payload.insert("type".to_owned(), "dns".to_owned());
			payload.insert("value".to_owned(), domain.to_owned());
			vec![payload]
		});

		let payload = json!({
			"identifiers": [{"type": "dns", "value": domain}],
			"resource": "newOrder"
		});

		let (http_status, body) = {
			let mut res = self.post_with_account(&self.new_order_uri, &account, &to_string(&payload)?, Some("newOrder"))?;

			let res_json = {
				let mut res_content = String::new();
				res.read_to_string(&mut res_content)?;
				if !res_content.is_empty() {
					from_str(&res_content)?
				} else {
					to_value(true)?
				}
			};

			(*res.status(), res_json)
		};

		if http_status != StatusCode::Created {
			return Err(AcmeServerError(body).into());
		}

		let object = body.as_object().ok_or_else(|| "Malformed response to newOrder request".to_err())?;

		let status = object.get("status")
			.and_then(|val| val.as_str())
			.ok_or_else(|| "newOrder response is missing 'status' entry".to_err())?;

		info!("status {:?}", status);


		let authorizations = object.get("authorizations")
			.and_then(|val| val.as_array())
			.ok_or_else(|| "newOrder response is malformed or missing 'authorizations'".to_err())?
			.iter()
			.filter_map(|val| val.as_str().map(Into::into))
			.collect();

		let finalize_uri = object.get("finalize")
			.and_then(|val| val.as_str())
			.map(Into::into)
			.ok_or_else(|| "newOrder response is missing 'finalize' entry".to_err())?;

		Ok(Order {
			authorizations,
			finalize_uri
		})
	}


	pub fn fetch_challenges(&self, account: &Account, authorization_uri: &str) -> Result<Vec<Challenge>> {
		use crate::helper::*;
		use openssl::hash::{hash, MessageDigest};

		let mut response = self.post_with_account(authorization_uri, &account, "{}", None)?;

		let mut res_content = String::new();
		response.read_to_string(&mut res_content)?;
		let response_json: HashMap<String, Value> = from_str(&res_content)?;

		info!("{:?}", response);

		
		// let mut challenges = Vec::new();
		for challenge in response_json.get("challenges")
				.and_then(|c| c.as_array())
				.ok_or_else(|| "No challenge found".to_err())? {

			let obj = challenge
				.as_object()
				.ok_or_else(|| "Challenge object not found".to_err())?;

			let ctype = obj.get("type")
				.and_then(|t| t.as_str())
				.ok_or_else(|| "Challenge type not found".to_err())?
				.to_owned();
			let uri = obj.get("uri")
				.and_then(|t| t.as_str())
				.ok_or_else(|| "URI not found".to_err())?
				.to_owned();
			let token = obj.get("token")
				.and_then(|t| t.as_str())
				.ok_or_else(|| "Token not found".to_err())?
				.to_owned();

			// This seems really cryptic but it's not
			// https://tools.ietf.org/html/draft-ietf-acme-acme-05#section-7.1
			// key-authz = token || '.' || base64url(JWK\_Thumbprint(accountKey))
			let key_authorization = format!("{}.{}",
											token,
											b64(&hash(MessageDigest::sha256(),
													   &to_string(&jwk(&account.pkey)?)?
																.into_bytes())?));

			info!("{:?}", obj);
			info!("{:?}", ctype);
			info!("{:?}", uri);
			info!("{:?}", token);
			info!("{:?}", key_authorization);

			// let challenge = Challenge {
			// 	account: self,
			// 	ctype: ctype,
			// 	url: uri,
			// 	token: token,
			// 	key_authorization: key_authorization,
			// };
			// challenges.push(challenge);
		}

		Ok(Vec::new())
	}


	fn post_with_account(&self, uri: &str, acct: &Account, payload: &str, resource: Option<&str>) -> Result<reqwest::Response> {
		// let mut json = to_value(&payload)?;
		// if let Some(s) = resource {
		// 	if let Some(obj) = json.as_object_mut() {
		// 		obj.insert("resource".to_owned(), json!(s));
		// 	}
		// }

		info!("{:?}", payload);

		let nonce = self.request_new_nonce()?;
		let jws = format_jws(&nonce, uri, &acct.pkey, Some(&acct.key_id), payload)?;


		let mut res = self.client.post(uri)
			.header(Self::content_type())
			.body(&jws[..])
			.send()?;

		match *res.status() {
			StatusCode::BadRequest => {
				let mut res_content = String::new();
				res.read_to_string(&mut res_content)?;
				return Err(AcmeServerError(from_str(&res_content)?).into())
			}

			_ => {}
		}

		Ok(res)
	}

	
	fn content_type() -> reqwest::header::ContentType {
		use reqwest::{header::ContentType, mime::Mime};
		use std::str::FromStr;
		let mime_type = Mime::from_str("application/jose+json").unwrap();
		ContentType(mime_type)
	}

}



/// Makes a Flattened JSON Web Signature from payload
fn format_jws(nonce: &str, url: &str, pkey: &PKey<openssl::pkey::Private>, kid: Option<&str>, payload: &str) -> Result<String> {
	use openssl::sign::Signer;
	use openssl::hash::{hash, MessageDigest};

	use crate::helper::*;

	let mut data: HashMap<String, Value> = HashMap::new();

	// header: 'alg': 'RS256', 'jwk': { e, n, kty }
	let mut header: HashMap<String, Value> = HashMap::new();
	header.insert("alg".to_owned(), to_value("RS256")?);
	header.insert("url".to_owned(), url.into());
	header.insert("nonce".to_owned(), to_value(nonce)?);

	if let Some(kid) = kid {
		header.insert("kid".to_owned(), kid.into());
	} else {
		header.insert("jwk".to_owned(), jwk(pkey)?);
	}

	// protected: base64 of header + nonce
	let protected64 = b64(&to_string(&header)?.into_bytes());
	data.insert("protected".to_owned(), to_value(&protected64)?);

	// payload: b64 of payload
	// let payload = to_string(&payload)?;
	let payload64 = b64(&payload.as_bytes());
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
fn jwk(pkey: &PKey<openssl::pkey::Private>) -> Result<Value> {
	use crate::helper::*;

	let rsa = pkey.rsa()?;
	let mut jwk: HashMap<String, String> = HashMap::new();
	jwk.insert("e".to_owned(), b64(&rsa.e().to_vec()));
	jwk.insert("kty".to_owned(), "RSA".to_owned());
	jwk.insert("n".to_owned(), b64(&rsa.n().to_vec()));
	Ok(to_value(jwk)?)
}


// header! is making a public struct,
// our custom header is private and only used privately in this module
mod hyperx {
	// ReplayNonce header for hyper
	header! { (ReplayNonce, "Replay-Nonce") => [String] }
}