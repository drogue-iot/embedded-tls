#[derive(Debug)]
pub enum CertificateType {
    X509 = 0,
    RawPublicKey = 2,
}

impl CertificateType {
    pub fn of(num: u8) -> Option<Self> {
        match num {
            0 => Some(Self::X509),
            2 => Some(Self::RawPublicKey),
            _ => None,
        }
    }
}
