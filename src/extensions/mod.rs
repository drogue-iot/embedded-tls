pub mod client;
pub mod common;
pub mod server;

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
}

impl ExtensionType {
    pub fn of(num: u16) -> Option<Self> {
        //info!("extension type of {:x}", num);
        match num {
            0 => Some(Self::ServerName),
            1 => Some(Self::MaxFragmentLength),
            5 => Some(Self::StatusRequest),
            10 => Some(Self::SupportedGroups),
            13 => Some(Self::SignatureAlgorithms),
            14 => Some(Self::UseSrtp),
            15 => Some(Self::Heartbeat),
            16 => Some(Self::ApplicationLayerProtocolNegotiation),
            18 => Some(Self::SignedCertificateTimestamp),
            19 => Some(Self::ClientCertificateType),
            20 => Some(Self::ServerCertificateType),
            21 => Some(Self::Padding),
            41 => Some(Self::PreSharedKey),
            42 => Some(Self::EarlyData),
            43 => Some(Self::SupportedVersions),
            44 => Some(Self::Cookie),
            45 => Some(Self::PskKeyExchangeModes),
            47 => Some(Self::CertificateAuthorities),
            48 => Some(Self::OidFilters),
            49 => Some(Self::PostHandshakeAuth),
            50 => Some(Self::SignatureAlgorithmsCert),
            51 => Some(Self::KeyShare),
            _ => None,
        }
    }
}
