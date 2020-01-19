

#[derive(Debug)]
pub struct Order {
	pub authorizations: Vec<String>,
	pub(crate) finalize_uri: String,
}

impl Order {
	// pub fn fetch_challenges(&self, account: &Account) -> Vec<Challenge> {

	// }
}