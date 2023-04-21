use crate::{
    extension_group,
    extensions::extension_data::{
        key_share::KeyShareServerHello, pre_shared_key::PreSharedKeyServerHello,
        supported_versions::SupportedVersionsServerHello,
    },
};

extension_group! {
    pub enum ServerHelloExtension<'a> {
        KeyShare(KeyShareServerHello<'a>),
        PreSharedKey(PreSharedKeyServerHello),
        SupportedVersions(SupportedVersionsServerHello)
    }
}
