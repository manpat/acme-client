

use acme_client::*;
use std::io::{Write, Read};

fn main() -> acme_client::error::Result<()> {
	env_logger::init()?;

	let client = AcmeClient::lets_encrypt_staging()?;

	let account = client.register_account(AccountRegistration::new())?;
	let (order, order_uri) = client.submit_order(&account, &[
		"testing.join-the-cool.club",
		"testing2.join-the-cool.club"
	])?;

	println!("{:?}", order);

	use std::sync::mpsc::channel;

	enum Msg {
		Challenge(String),
		Close
	}

	let (tx, rx) = channel();

	std::thread::spawn(move || -> acme_client::error::Result<()> {
		use std::net::TcpListener;

		let listener = TcpListener::bind("0.0.0.0:8000")?;

		let mut challenge_key_auth = String::new();

		for stream in listener.incoming() {
			for msg in rx.try_iter() {
				match msg {
					Msg::Challenge(s) => { challenge_key_auth = s; }
					Msg::Close => return Ok(())
				}
			}

			let mut stream = stream?;
	
			let mut buffer = [0; 8<<10];
			let read_count = stream.read(&mut buffer)?;
			let request = std::str::from_utf8(&buffer[..read_count])?;

			println!("REQUEST({}): {}", read_count, request);
		
			write!(&mut stream, "HTTP/1.1 200 OK\r\n")?;
			write!(&mut stream, "Content-Type: application/octet-stream\r\n\r\n")?;
			write!(&mut stream, "{}", challenge_key_auth)?;
		}

		Ok(())
	});

	let order = client.fetch_order(&account, &order_uri)?;
	println!("{:?}", order);

	for authorization_uri in order.authorizations.iter() {
		let authorization = client.fetch_authorization(&account, &authorization_uri)?;

		println!("{:?}", authorization);

		let http_challenge = authorization.challenges.into_iter()
			.find(|c| c.challenge_type.starts_with("http"))
			.ok_or_else(|| failure::format_err!("Didn't get any http challenges"))?;

		println!("{:?}", http_challenge);

		let challenge_key_auth = account.calculate_key_authorization(&http_challenge)?; 
		tx.send(Msg::Challenge(challenge_key_auth))?;

		client.signal_challenge_ready(&account, &http_challenge)?;

		// loop {
		// 	std::thread::sleep(std::time::Duration::from_millis(1000));

		// 	let authorization = client.fetch_authorization(&account, &authorization_uri)?;
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

		let order = client.fetch_order(&account, &order_uri)?;
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
					let auth = client.fetch_authorization(&account, &auth_uri)?;
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

	let (certificate, _cert_location) = client.finalize_order(&account, &order)?;

	std::fs::write("cert.pem", certificate.cert.to_pem()?)?;
	std::fs::write("intermediate_cert.pem", certificate.intermediate_cert.to_pem()?)?;
	println!("hurrah!");

	Ok(())
}
