

use acme_client::*;

fn main() -> acme_client::error::Result<()> {
	env_logger::init()?;
	log::set_max_level(log::LevelFilter::Trace);

	let directory = Directory::lets_encrypt_staging()?;

	let account = directory.account_registration().register()?;

	let auth = account.order("patrick-is.cool")?;

	Ok(())
}