use crate::{
    extension_group,
    extensions::extension_data::{
        application_layer_protocol_negotiation::ApplicationLayerProtocolNegotiation,
        certificate_authorities::CertificateAuthorities, certificate_type::CertTypeRequest,
        cookie::Cookie, early_data::EarlyDataIndication, heartbeat::Heartbeat,
        key_share::KeyShareClientHello, max_fragment_length::MaxFragmentLength,
        oid_filters::OidFilters, padding::Padding, post_handshake_auth::PostHandshakeAuth,
        pre_shared_key::PreSharedKeyClientHello, psk_key_exchange_modes::PskKeyExchangeModes,
        server_name::ServerNameList, signature_algorithms::SignatureAlgorithms,
        signature_algorithms_cert::SignatureAlgorithmsCert,
        signed_certificate_timestamp::SignedCertificateTimestampIndication,
        status_request::CertificateStatusRequest, supported_groups::SupportedGroups,
        supported_versions::SupportedVersionsClientHello, use_srtp::UseSrtp,
    },
};

// TODO: check if these are the correct types
extension_group! {
    pub enum ClientHelloExtension<'a> {
        ServerName(ServerNameList<'a, 1>),
        SupportedVersions(SupportedVersionsClientHello<16>),
        SignatureAlgorithms(SignatureAlgorithms<16>),
        SupportedGroups(SupportedGroups<16>),
        KeyShare(KeyShareClientHello<'a, 1>),
        PreSharedKey(PreSharedKeyClientHello<'a, 4>),
        PskKeyExchangeModes(PskKeyExchangeModes<4>),
        SignatureAlgorithmsCert(SignatureAlgorithmsCert<16>),
        MaxFragmentLength(MaxFragmentLength),
        StatusRequest(CertificateStatusRequest),
        UseSrtp(UseSrtp<'a, 4>),
        Heartbeat(Heartbeat),
        ApplicationLayerProtocolNegotiation(ApplicationLayerProtocolNegotiation<'a, 2>),
        SignedCertificateTimestamp(SignedCertificateTimestampIndication),
        ClientCertificateType(CertTypeRequest<2>),
        ServerCertificateType(CertTypeRequest<2>),
        Padding(Padding),
        EarlyData(EarlyDataIndication),
        Cookie(Cookie<'a>),
        CertificateAuthorities(CertificateAuthorities<'a, 4>),
        OidFilters(OidFilters<'a, 4>),
        PostHandshakeAuth(PostHandshakeAuth)
    }
}
