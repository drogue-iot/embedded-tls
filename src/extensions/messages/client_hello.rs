use crate::{
    buffer::CryptoBuffer,
    extensions::{
        types::{
            application_layer_protocol_negotiation::ApplicationLayerProtocolNegotiation,
            certificate_authorities::CertificateAuthorities,
            certificate_type::{ClientCertTypeRequest, ServerCertTypeRequest},
            cookie::Cookie,
            early_data::EarlyDataIndication,
            heartbeat::Heartbeat,
            key_share::KeyShare,
            max_fragment_length::MaxFragmentLength,
            oid_filters::OidFilters,
            padding::Padding,
            post_handshake_auth::PostHandshakeAuth,
            pre_shared_key::PreSharedKey,
            psk_key_exchange_modes::PskKeyExchangeModes,
            server_name::ServerNameList,
            signature_algorithms::SignatureAlgorithms,
            signature_algorithms_cert::SignatureAlgorithmsCert,
            signed_certificate_timestamp::SignedCertificateTimestampIndication,
            status_request::CertificateStatusRequest,
            supported_groups::SupportedGroups,
            supported_versions::SupportedVersions,
            use_srtp::UseSrtp,
        },
        ExtensionType,
    },
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

// TODO: check if these are the correct types
pub enum ClientHelloExtension<'a> {
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
    UseSrtp(UseSrtp<'a, 4>),
    Heartbeat(Heartbeat),
    ApplicationLayerProtocolNegotiation(ApplicationLayerProtocolNegotiation<'a, 2>),
    SignedCertificateTimestamp(SignedCertificateTimestampIndication),
    ClientCertificateType(ClientCertTypeRequest<2>),
    ServerCertificateType(ServerCertTypeRequest<2>),
    Padding(Padding),
    EarlyData(EarlyDataIndication),
    Cookie(Cookie<'a>),
    CertificateAuthorities(CertificateAuthorities<'a, 4>),
    OidFilters(OidFilters<'a, 4>),
    PostHandshakeAuth(PostHandshakeAuth),
}

impl<'a> ClientHelloExtension<'a> {
    pub fn extension_type(&self) -> ExtensionType {
        match self {
            Self::ServerName(_) => ExtensionType::ServerName,
            Self::PskKeyExchangeModes(_) => ExtensionType::PskKeyExchangeModes,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            Self::SignatureAlgorithmsCert(_) => ExtensionType::SignatureAlgorithmsCert,
            Self::SupportedGroups(_) => ExtensionType::SupportedGroups,
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::PreSharedKey(_) => ExtensionType::PreSharedKey,
            Self::MaxFragmentLength(_) => ExtensionType::MaxFragmentLength,
            Self::StatusRequest(_) => ExtensionType::StatusRequest,
            Self::UseSrtp(_) => ExtensionType::UseSrtp,
            Self::Heartbeat(_) => ExtensionType::Heartbeat,
            Self::ApplicationLayerProtocolNegotiation(_) => {
                ExtensionType::ApplicationLayerProtocolNegotiation
            }
            Self::SignedCertificateTimestamp(_) => ExtensionType::SignedCertificateTimestamp,
            Self::ClientCertificateType(_) => ExtensionType::ClientCertificateType,
            Self::ServerCertificateType(_) => ExtensionType::ServerCertificateType,
            Self::Padding(_) => ExtensionType::Padding,
            Self::EarlyData(_) => ExtensionType::EarlyData,
            Self::Cookie(_) => ExtensionType::Cookie,
            Self::CertificateAuthorities(_) => ExtensionType::CertificateAuthorities,
            Self::OidFilters(_) => ExtensionType::OidFilters,
            Self::PostHandshakeAuth(_) => ExtensionType::PostHandshakeAuth,
        }
    }

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        match ExtensionType::parse(buf)? {
            ExtensionType::ServerName => Ok(Self::ServerName(ServerNameList::parse(buf)?)),
            ExtensionType::MaxFragmentLength => {
                Ok(Self::MaxFragmentLength(MaxFragmentLength::parse(buf)?))
            }
            ExtensionType::StatusRequest => {
                Ok(Self::StatusRequest(CertificateStatusRequest::parse(buf)?))
            }
            ExtensionType::SupportedGroups => {
                Ok(Self::SupportedGroups(SupportedGroups::parse(buf)?))
            }
            ExtensionType::SignatureAlgorithms => {
                Ok(Self::SignatureAlgorithms(SignatureAlgorithms::parse(buf)?))
            }
            ExtensionType::UseSrtp => Ok(Self::UseSrtp(UseSrtp::parse(buf)?)),
            ExtensionType::Heartbeat => Ok(Self::Heartbeat(Heartbeat::parse(buf)?)),
            ExtensionType::ApplicationLayerProtocolNegotiation => {
                Ok(Self::ApplicationLayerProtocolNegotiation(
                    ApplicationLayerProtocolNegotiation::parse(buf)?,
                ))
            }
            ExtensionType::SignedCertificateTimestamp => Ok(Self::SignedCertificateTimestamp(
                SignedCertificateTimestampIndication::parse(buf)?,
            )),
            ExtensionType::ClientCertificateType => Ok(Self::ClientCertificateType(
                ClientCertTypeRequest::parse(buf)?,
            )),
            ExtensionType::ServerCertificateType => Ok(Self::ServerCertificateType(
                ServerCertTypeRequest::parse(buf)?,
            )),
            ExtensionType::Padding => Ok(Self::Padding(Padding::parse(buf)?)),
            ExtensionType::PreSharedKey => Ok(Self::PreSharedKey(PreSharedKey::parse(buf)?)),
            ExtensionType::EarlyData => Ok(Self::EarlyData(EarlyDataIndication::parse(buf)?)),
            ExtensionType::SupportedVersions => {
                Ok(Self::SupportedVersions(SupportedVersions::parse(buf)?))
            }
            ExtensionType::Cookie => Ok(Self::Cookie(Cookie::parse(buf)?)),
            ExtensionType::PskKeyExchangeModes => {
                Ok(Self::PskKeyExchangeModes(PskKeyExchangeModes::parse(buf)?))
            }
            ExtensionType::CertificateAuthorities => Ok(Self::CertificateAuthorities(
                CertificateAuthorities::parse(buf)?,
            )),
            ExtensionType::OidFilters => Ok(Self::OidFilters(OidFilters::parse(buf)?)),
            ExtensionType::PostHandshakeAuth => {
                Ok(Self::PostHandshakeAuth(PostHandshakeAuth::parse(buf)?))
            }
            ExtensionType::SignatureAlgorithmsCert => Ok(Self::SignatureAlgorithmsCert(
                SignatureAlgorithmsCert::parse(buf)?,
            )),
            ExtensionType::KeyShare => Ok(Self::KeyShare(KeyShare::parse(buf)?)),
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.extension_type().encode(buf)?;

        buf.with_u16_length(|buf| match self {
            Self::ServerName(ext) => ext.encode(buf),
            Self::PskKeyExchangeModes(ext) => ext.encode(buf),
            Self::SupportedVersions(ext) => ext.encode(buf),
            Self::SignatureAlgorithms(ext) => ext.encode(buf),
            Self::SignatureAlgorithmsCert(ext) => ext.encode(buf),
            Self::SupportedGroups(ext) => ext.encode(buf),
            Self::KeyShare(ext) => ext.encode(buf),
            Self::PreSharedKey(ext) => ext.encode(buf),
            Self::MaxFragmentLength(ext) => ext.encode(buf),
            Self::StatusRequest(ext) => ext.encode(buf),
            Self::UseSrtp(ext) => ext.encode(buf),
            Self::Heartbeat(ext) => ext.encode(buf),
            Self::ApplicationLayerProtocolNegotiation(ext) => ext.encode(buf),
            Self::SignedCertificateTimestamp(ext) => ext.encode(buf),
            Self::ClientCertificateType(ext) => ext.encode(buf),
            Self::ServerCertificateType(ext) => ext.encode(buf),
            Self::Padding(ext) => ext.encode(buf),
            Self::EarlyData(ext) => ext.encode(buf),
            Self::Cookie(ext) => ext.encode(buf),
            Self::CertificateAuthorities(ext) => ext.encode(buf),
            Self::OidFilters(ext) => ext.encode(buf),
            Self::PostHandshakeAuth(ext) => ext.encode(buf),
        })
    }
}
