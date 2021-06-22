use crate::application_data::ApplicationData;
use crate::named_groups::NamedGroup;
use p256::ecdh::SharedSecret;

pub struct CryptoEngine {
    group: NamedGroup,
    shared: SharedSecret,
}

impl CryptoEngine {
    pub fn new(group: NamedGroup, shared: SharedSecret) -> Self {
        Self { group, shared }
    }

    pub fn decrypt(&self, record: &ApplicationData) {}
}
