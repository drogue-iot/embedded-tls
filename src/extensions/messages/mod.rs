mod extension_group_macro;

use crate::{
    extension_group,
    extensions::extension_data::{
        application_layer_protocol_negotiation::ApplicationLayerProtocolNegotiation,
        certificate_authorities::CertificateAuthorities,
        certificate_type::{CertTypeRequest, CertTypeResponse},
        cookie::Cookie,
        early_data::EarlyDataIndication,
        heartbeat::Heartbeat,
        key_share::{KeyShareClientHello, KeyShareServerHello},
        max_fragment_length::MaxFragmentLength,
        oid_filters::OidFilters,
        padding::Padding,
        post_handshake_auth::PostHandshakeAuth,
        pre_shared_key::{PreSharedKeyClientHello, PreSharedKeyServerHello},
        psk_key_exchange_modes::PskKeyExchangeModes,
        server_name::ServerNameList,
        signature_algorithms::SignatureAlgorithms,
        signature_algorithms_cert::SignatureAlgorithmsCert,
        signed_certificate_timestamp::SignedCertificateTimestampIndication,
        status_request::CertificateStatusRequest,
        supported_groups::SupportedGroups,
        supported_versions::{SupportedVersionsClientHello, SupportedVersionsServerHello},
        use_srtp::UseSrtp,
    },
};

// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with SH
extension_group! {
    pub enum ServerHelloExtension<'a> {
        KeyShare(KeyShareServerHello<'a>),
        PreSharedKey(PreSharedKeyServerHello),
        SupportedVersions(SupportedVersionsServerHello),
        PostHandshakeAuth(PostHandshakeAuth)
    }
}

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

// TODO: check if these are the correct data types
// Source: https://www.rfc-editor.org/rfc/rfc8446#section-4.2 table, rows marked with EE
extension_group! {
    pub enum EncryptedExtensionsExtension<'a> {
        ServerName(ServerNameList<'a, 1>), // TODO clarify - may be empty or contains a single name - still a list?
        MaxFragmentLength(MaxFragmentLength),
        SupportedGroups(SupportedGroups<1>), // TODO clarify - https://www.rfc-editor.org/rfc/rfc7919#page-8
        // https://www.rfc-editor.org/rfc/rfc5764#page-7
        // The extension_data field MUST contain a UseSRTPData value with a
        // single SRTPProtectionProfile value that the server has chosen for use
        // with this connection.
        UseSrtp(UseSrtp<'a, 1>),
        Heartbeat(Heartbeat),
        // The "extension_data" field of the [..] extension
        // is structured the same as described above for the client
        // "extension_data", except that the "ProtocolNameList" MUST contain
        // exactly one "ProtocolName".
        ApplicationLayerProtocolNegotiation(ApplicationLayerProtocolNegotiation<'a, 1>),
        // Note: RFC 7250 includes the cert types in the Server Hello,
        // but RFC 8446 specifies them for EncryptedExtensions
        ClientCertificateType(CertTypeResponse),
        ServerCertificateType(CertTypeResponse),
        EarlyData(EarlyDataIndication)
    }
}
