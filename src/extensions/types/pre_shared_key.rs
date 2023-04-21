use crate::buffer::CryptoBuffer;
use crate::extensions::ExtensionType;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::TlsError;

use heapless::Vec;

pub struct PreSharedKey<'a, const N: usize> {
    pub identities: Vec<&'a [u8], N>,
    pub hash_size: usize,
}

impl<const N: usize> PreSharedKey<'_, N> {
    pub const EXTENSION_TYPE: ExtensionType = ExtensionType::PreSharedKey;

    fn parse(_buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        unimplemented!()
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for identity in self.identities.iter() {
                buf.with_u16_length(|buf| buf.extend_from_slice(identity))
                    .map_err(|_| TlsError::EncodeError)?;

                // NOTE: No support for ticket age, set to 0 as recommended by RFC
                buf.push_u32(0).map_err(|_| TlsError::EncodeError)?;
            }
            Ok(())
        })
        .map_err(|_| TlsError::EncodeError)?;

        // NOTE: We encode binders later after computing the transcript.
        let binders_len = (1 + self.hash_size) * self.identities.len();
        buf.push_u16(binders_len as u16)
            .map_err(|_| TlsError::EncodeError)?;

        for _ in 0..binders_len {
            buf.push(0).map_err(|_| TlsError::EncodeError)?;
        }

        Ok(())
    }
}
