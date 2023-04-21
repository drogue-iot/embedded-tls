use crate::extensions::types::key_share::KeyShare;
use crate::extensions::types::max_fragment_length::MaxFragmentLength;
use crate::extensions::types::pre_shared_key::PreSharedKey;
use crate::extensions::types::psk_key_exchange_modes::PskKeyExchangeModes;
use crate::extensions::types::server_name::ServerNameList;
use crate::extensions::types::signature_algorithms::SignatureAlgorithms;
use crate::extensions::types::signature_algorithms_cert::SignatureAlgorithmsCert;
use crate::extensions::types::status_request::CertificateStatusRequest;
use crate::extensions::types::supported_groups::SupportedGroups;
use crate::extensions::types::supported_versions::SupportedVersions;
use crate::extensions::ExtensionType;

use crate::buffer::*;
use crate::TlsError;

pub enum ClientExtension<'a> {
    ServerName(ServerNameList<'a, 1>),
    SupportedVersions(SupportedVersions<16>),
    SignatureAlgorithms(SignatureAlgorithms<16>),
    SupportedGroups(SupportedGroups<16>),
    KeyShare(KeyShare<'a>),
    PreSharedKey(PreSharedKey<'a, 4>),
    PskKeyExchangeModes(PskKeyExchangeModes<4>),
    SignatureAlgorithmsCert(SignatureAlgorithmsCert<16>),
    MaxFragmentLength(MaxFragmentLength),
    StatusRequest(CertificateStatusRequest),
}

impl ClientExtension<'_> {
    pub fn extension_type(&self) -> ExtensionType {
        match self {
            ClientExtension::ServerName(_) => ExtensionType::ServerName,
            ClientExtension::SupportedVersions(_) => ExtensionType::SupportedVersions,
            ClientExtension::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            ClientExtension::KeyShare(_) => ExtensionType::KeyShare,
            ClientExtension::SupportedGroups(_) => ExtensionType::SupportedGroups,
            ClientExtension::SignatureAlgorithmsCert(_) => ExtensionType::SignatureAlgorithmsCert,
            ClientExtension::PskKeyExchangeModes(_) => ExtensionType::PskKeyExchangeModes,
            ClientExtension::PreSharedKey(_) => ExtensionType::PreSharedKey,
            ClientExtension::MaxFragmentLength(_) => ExtensionType::MaxFragmentLength,
            ClientExtension::StatusRequest(_) => ExtensionType::StatusRequest,
        }
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        trace!("Encoding client extension {:?}", self.extension_type());
        buf.push_u16(self.extension_type() as u16)
            .map_err(|_| TlsError::EncodeError)?;

        buf.with_u16_length(|buf| match self {
            ClientExtension::ServerName(server_name_list) => server_name_list.encode(buf),
            ClientExtension::PskKeyExchangeModes(modes) => modes.encode(buf),
            ClientExtension::SupportedVersions(versions) => versions.encode(buf),
            ClientExtension::SignatureAlgorithms(algorithms) => algorithms.encode(buf),
            ClientExtension::SignatureAlgorithmsCert(cert) => cert.encode(buf),
            ClientExtension::SupportedGroups(supported_groups) => supported_groups.encode(buf),
            ClientExtension::KeyShare(key_share) => key_share.encode(buf),
            ClientExtension::PreSharedKey(psk) => psk.encode(buf),
            ClientExtension::MaxFragmentLength(len) => len.encode(buf),
            ClientExtension::StatusRequest(request) => request.encode(buf),
        })
    }
}
