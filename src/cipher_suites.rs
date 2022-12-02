#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CipherSuite {
    TlsAes128GcmSha256 = 0x1301,
    TlsAes256GcmSha384 = 0x1302,
    TlsChacha20Poly1305Sha256 = 0x1303,
    TlsAes128CcmSha256 = 0x1304,
    TlsAes128Ccm8Sha256 = 0x1305,
    TlsPskAes128GcmSha256 = 0x00A8,
}

impl CipherSuite {
    pub fn of(num: u16) -> Option<Self> {
        match num {
            0x1301 => Some(Self::TlsAes128GcmSha256),
            0x1302 => Some(Self::TlsAes256GcmSha384),
            0x1303 => Some(Self::TlsChacha20Poly1305Sha256),
            0x1304 => Some(Self::TlsAes128CcmSha256),
            0x1305 => Some(Self::TlsAes128Ccm8Sha256),
            0x00A8 => Some(Self::TlsPskAes128GcmSha256),
            _ => None,
        }
    }
}
