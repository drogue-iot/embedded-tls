use crate::cipher_suites::CipherSuite::{
    TlsAes128Ccm8Sha256, TlsAes128CcmSha256, TlsAes128GcmSha256, TlsAes256GcmSha384,
    TlsChacha20Poly1305Sha256,
};

#[derive(Copy, Clone, Debug)]
pub enum CipherSuite {
    TlsAes128GcmSha256 = 0x1301,
    TlsAes256GcmSha384 = 0x1302,
    TlsChacha20Poly1305Sha256 = 0x1303,
    TlsAes128CcmSha256 = 0x1304,
    TlsAes128Ccm8Sha256 = 0x1305,
}

impl CipherSuite {
    pub fn of(num: u16) -> Option<Self> {
        match num {
            0x1301 => Some(TlsAes128GcmSha256),
            0x1302 => Some(TlsAes256GcmSha384),
            0x1303 => Some(TlsChacha20Poly1305Sha256),
            0x1304 => Some(TlsAes128CcmSha256),
            0x1305 => Some(TlsAes128Ccm8Sha256),
            _ => None,
        }
    }
}
