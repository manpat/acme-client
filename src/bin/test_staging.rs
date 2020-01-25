

use acme_client::*;
use std::io::{Write, Read};
use std::collections::HashMap;

fn main() -> acme_client::error::Result<()> {
	env_logger::init()?;

	let client = AcmeClient::lets_encrypt_staging(AccountRegistration::default())?;
	let (order, order_uri) = client.submit_order(&[
		"testing.join-the-cool.club",
		"testing2.join-the-cool.club"
	])?;

	println!("{:?}", order);

	use std::sync::mpsc::channel;

	enum Msg {
		Challenge(String, String),
		Close
	}

	let (tx, rx) = channel();

	std::thread::spawn(move || -> acme_client::error::Result<()> {
		use std::net::TcpListener;

		let listener = TcpListener::bind("0.0.0.0:8000")?;

		let mut routes = HashMap::new();

		for stream in listener.incoming() {
			for msg in rx.try_iter() {
				match msg {
					Msg::Challenge(token, key_auth) => {
						let uri = format!("/.well-known/acme-challenge/{}", token);
						routes.insert(uri, key_auth);
					}
					Msg::Close => return Ok(())
				}
			}

			let mut stream = stream?;
	
			let mut buffer = [0; 8<<10];
			let read_count = stream.read(&mut buffer)?;
			let request = std::str::from_utf8(&buffer[..read_count])?;

			let key_auth = request.split_whitespace().skip(1).next()
				.and_then(|uri| routes.get(uri));

			if let Some(auth) = key_auth {			
				write!(&mut stream, "HTTP/1.1 200 OK\r\n")?;
				write!(&mut stream, "Content-Type: application/octet-stream\r\n\r\n")?;
				write!(&mut stream, "{}", auth)?;
			} else {
				write!(&mut stream, "HTTP/1.1 404 Not Found\r\n")?;
			}
		}

		Ok(())
	});

	let order = client.fetch_order(&order_uri)?;
	println!("{:?}", order);

	for authorization_uri in order.authorizations.iter() {
		let authorization = client.fetch_authorization(&authorization_uri)?;

		println!("{:?}", authorization);

		let http_challenge = authorization.challenges.into_iter()
			.find(|c| c.challenge_type.starts_with("http"))
			.ok_or_else(|| failure::format_err!("Didn't get any http challenges"))?;

		println!("{:?}", http_challenge);

		let challenge_key_auth = client.calculate_key_authorization(&http_challenge)?; 
		tx.send(Msg::Challenge(http_challenge.token.clone(), challenge_key_auth))?;

		client.signal_challenge_ready(&http_challenge)?;

		// loop {
		// 	std::thread::sleep(std::time::Duration::from_millis(1000));

		// 	let authorization = client.fetch_authorization(&authorization_uri)?;
		// 	println!("STATUS {:?}", authorization);

		// 	match authorization.status {
		// 		AcmeStatus::Pending => {},
		// 		_ => break
		// 	}
		// }

		// tx.send(Msg::Close)?;
	}

	loop {
		std::thread::sleep(std::time::Duration::from_millis(200));

		let order = client.fetch_order(&order_uri)?;
		println!("{:?}", order);

		match order.status {
			// Server is validating
			AcmeStatus::Processing => continue,

			// Ready to finalize
			AcmeStatus::Ready => break,

			// Validation failed
			AcmeStatus::Invalid => {
				println!("Authorization failed! {:?}", order);

				for auth_uri in order.authorizations {
					let auth = client.fetch_authorization(&auth_uri)?;
					println!("  {} -> {:?}", auth_uri.0, auth);
				}

				failure::bail!("Authorization failed!")
			}

			_ => {
				failure::bail!("Unexpected order status? {:?}", order)
			}
		}
	}

	tx.send(Msg::Close)?;

	let (certificate, _cert_location) = client.finalize_order(&order)?;

	std::fs::write("cert.pem", certificate.cert.to_pem()?)?;
	std::fs::write("intermediate_cert.pem", certificate.intermediate_cert.to_pem()?)?;
	println!("hurrah!");

	Ok(())
}
