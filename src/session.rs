use crate::buffer::CryptoBuffer;
use crate::config::TlsVersion;
use crate::TlsError;

/// Represents a TLS or DTLS session
pub(crate) enum Session {
    TLS,
    DTLS { epoch: u16, seq: u64 },
}

impl Session {
    pub(crate) fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        match self {
            Self::TLS => {}
            Self::DTLS { epoch, seq } => {
                buf.push_u16(*epoch)?;
                buf.push_u48(*seq)?;
            }
        }
        Ok(())
    }

    pub(crate) fn next(&mut self) {
        match self {
            Self::DTLS { epoch, seq } => {
                *seq += 1;
            }
            _ => {}
        }
    }
}

impl From<TlsVersion> for Session {
    fn from(version: TlsVersion) -> Session {
        match version {
            TlsVersion::TLS_1_3 => Session::TLS,
            TlsVersion::DTLS_1_2 => Session::DTLS { epoch: 0, seq: 0 },
        }
    }
}
