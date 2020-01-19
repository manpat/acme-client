

use acme_client::*;

fn main() -> acme_client::error::Result<()> {
	env_logger::init()?;

	let client = AcmeClient::lets_encrypt_staging()?;

	let account = client.register_account(AccountRegistration::new())?;
	let order = client.submit_order(&account, "testing.join-the-cool.club")?;

	println!("{:?}", order);

	for authorization in order.authorizations.iter() {
		let challenges = client.fetch_challenges(&account, &authorization)?;
		// println!("{:?}", challenges);
	}

	// let order = account.order("testing.join-the-cool.club")?;

	Ok(())
}