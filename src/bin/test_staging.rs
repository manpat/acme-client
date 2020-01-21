

use acme_client::*;
use std::io::{Write, Read};

fn main() -> acme_client::error::Result<()> {
	env_logger::init()?;

	let client = AcmeClient::lets_encrypt_staging()?;

	let account = client.register_account(AccountRegistration::new())?;
	let order = client.submit_order(&account, "testing.join-the-cool.club")?;

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

	for authorization_uri in order.authorizations.iter() {
		let authorization = client.fetch_challenges(&account, &authorization_uri)?;

		println!("{:?}", authorization);

		let http_challenge = authorization.challenges.into_iter()
			.find(|c| c.challenge_type.starts_with("http"))
			.ok_or_else(|| failure::format_err!("Didn't get any http challenges"))?;

		println!("{:?}", http_challenge);

		let challenge_key_auth = account.calculate_key_authorization(&http_challenge)?; 
		tx.send(Msg::Challenge(challenge_key_auth))?;

		client.signal_challenge_ready(&account, &http_challenge)?;

		loop {
			let status = client.fetch_authorization_status(&account, &authorization_uri)?;
			println!("STATUS {:?}", status);

			match status {
				AcmeStatus::Pending => {},
				_ => break
			}

			std::thread::sleep(std::time::Duration::from_millis(500));
		}

		tx.send(Msg::Close)?;
	}

	Ok(())
}
