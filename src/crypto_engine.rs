use crate::application_data::ApplicationData;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use p256::ecdh::SharedSecret;

pub struct CryptoEngine {}

#[allow(clippy::unused_self, clippy::needless_pass_by_value)] // TODO
impl CryptoEngine {
    pub fn new(_group: NamedGroup, _shared: SharedSecret) -> Self {
        Self {}
    }

    pub fn decrypt(&self, _: &ApplicationData) {}
}
