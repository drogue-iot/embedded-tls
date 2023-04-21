use crate::{
    extension_group,
    extensions::extension_data::{
        application_layer_protocol_negotiation::ApplicationLayerProtocolNegotiation,
        certificate_type::CertTypeResponse, early_data::EarlyDataIndication, heartbeat::Heartbeat,
        max_fragment_length::MaxFragmentLength, server_name::ServerNameList,
        supported_groups::SupportedGroups, use_srtp::UseSrtp,
    },
};

// TODO: check if these are the correct data types
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
