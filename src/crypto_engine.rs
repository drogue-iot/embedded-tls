use crate::application_data::ApplicationData;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use p256::ecdh::SharedSecret;

pub struct CryptoEngine {}

impl CryptoEngine {
    pub fn new(_group: NamedGroup, _shared: SharedSecret) -> Self {
        Self {}
    }

    pub fn decrypt(&self, _: &ApplicationData) {}
}
