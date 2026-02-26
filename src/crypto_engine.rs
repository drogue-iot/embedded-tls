use crate::application_data::ApplicationData;
use crate::extensions::extension_data::supported_groups::NamedGroup;
use p256::ecdh::SharedSecret;

#[allow(dead_code)]
pub struct CryptoEngine {}

#[allow(clippy::unused_self, clippy::needless_pass_by_value, dead_code)] // TODO
impl CryptoEngine {
    pub fn new(_group: NamedGroup, _shared: SharedSecret) -> Self {
        Self {}
    }

    #[allow(dead_code)]
    pub fn decrypt(&self, _: &ApplicationData) {}
}
