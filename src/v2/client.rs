
use crate::error::*;
use crate::types::*;
use crate::{AccountRegistration, Account};
use serde_json::{to_value, from_value, to_string, from_str, Value, json};
// use serde::{Serialize, Deserialize};
use openssl::pkey::PKey;
use reqwest::StatusCode;


use std::io::Read;
use std::collections::HashMap;


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
			let nonce = self.request_new_nonce()?;
			let json = to_string(&payload)?;

			let jws = format_jws(&nonce, &self.new_account_uri, &pkey, None, &json)?;

			let res = self.client.post(&self.new_account_uri)
				.header(Self::jose_json_content_type())
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

		let payload = json!({
			"identifiers": [{"type": "dns", "value": domain}],
			"resource": "newOrder"
		});

		let (http_status, body) = {
			let mut res = self.post_with_account(&self.new_order_uri, &account, &to_string(&payload)?)?;
			let body = response_to_string(&mut res)?;
			let res_json = from_str(&body)?;

			(*res.status(), res_json)
		};

		if http_status != StatusCode::Created {
			return Err(AcmeServerError(body).into());
		}

		let order: Order = from_value(body)?;
		Ok(order)
	}


	pub fn fetch_challenges(&self, account: &Account, authorization_uri: &str) -> Result<Vec<Challenge>> {
		let mut response = self.get_with_account(authorization_uri, &account)?;

		let body = response_to_string(&mut response)?;
		let challenges: ChallengeListResponse = from_str(&body)?;
		
		Ok(challenges.challenges)
	}


	fn get_with_account(&self, uri: &str, acct: &Account) -> Result<reqwest::Response> {
		self.post_with_account(uri, acct, "")
	}

	fn post_with_account(&self, uri: &str, acct: &Account, payload: &str) -> Result<reqwest::Response> {
		info!("{:?}", payload);

		let nonce = self.request_new_nonce()?;
		let jws = format_jws(&nonce, uri, &acct.pkey, Some(&acct.key_id), payload)?;

		let mut res = self.client.post(uri)
			.header(Self::jose_json_content_type())
			.body(&jws[..])
			.send()?;

		match *res.status() {
			StatusCode::BadRequest => {
				let body = response_to_string(&mut res)?;
				return Err(AcmeServerError(from_str(&body)?).into())
			}

			_ => {}
		}

		Ok(res)
	}

	
	fn jose_json_content_type() -> reqwest::header::ContentType {
		use reqwest::{header::ContentType, mime::Mime};
		use std::str::FromStr;
		let mime_type = Mime::from_str("application/jose+json").unwrap();
		ContentType(mime_type)
	}

}



/// Makes a Flattened JSON Web Signature from payload
fn format_jws(nonce: &str, url: &str, pkey: &PKey<openssl::pkey::Private>, kid: Option<&str>, payload: &str) -> Result<String> {
	use openssl::sign::Signer;
	use openssl::hash::MessageDigest;

	use crate::helper::*;

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
	let protected64 = b64(&to_string(&header)?.into_bytes());

	// payload: b64 of payload
	let payload64 = b64(&payload.as_bytes());

	// signature: b64 of hash of signature of {proctected64}.{payload64}
	let signature = {
		let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
		signer.update(&format!("{}.{}", protected64, payload64).into_bytes())?;
		b64(&signer.sign_to_vec()?)
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
	use crate::helper::*;

	let rsa = pkey.rsa()?;
	let jwk = json!({
		"e": b64(&rsa.e().to_vec()),
		"kty": "RSA",
		"n": b64(&rsa.n().to_vec()),
	});

	Ok(jwk)
}



fn response_to_string(response: &mut reqwest::Response) -> Result<String> {
	let mut res_content = String::new();
	response.read_to_string(&mut res_content)?;
	Ok(res_content)
}



// header! is making a public struct,
// our custom header is private and only used privately in this module
mod hyperx {
	// ReplayNonce header for hyper
	header! { (ReplayNonce, "Replay-Nonce") => [String] }
}