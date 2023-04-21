use crate::buffer::CryptoBuffer;
use crate::extensions::types::supported_groups::NamedGroup;

use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::TlsError;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShare<'a>(pub(crate) KeyShareEntry<'a>);

impl<'a> KeyShare<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<KeyShare<'a>, ParseError> {
        Ok(KeyShare(KeyShareEntry::parse(buf)?))
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.0.encode(buf)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShareEntry<'a> {
    pub(crate) group: NamedGroup,
    pub(crate) opaque: &'a [u8],
}

impl Clone for KeyShareEntry<'_> {
    fn clone(&self) -> Self {
        Self {
            group: self.group,
            opaque: self.opaque,
        }
    }
}

impl<'a> KeyShareEntry<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<KeyShareEntry<'a>, ParseError> {
        let group = NamedGroup::parse(buf)?;

        let opaque_len = buf.read_u16()?;
        let opaque = buf.slice(opaque_len as usize)?;

        Ok(Self {
            group,
            opaque: opaque.as_slice(),
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            self.group.encode(buf)?;

            buf.with_u16_length(|buf| buf.extend_from_slice(self.opaque))
                .map_err(|_| TlsError::EncodeError)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            env_logger::init();
        });
    }

    #[test]
    fn test_parse_empty() {
        setup();
        let buffer = [
            0x00, 0x017, // Secp256r1
            0x00, 0x00, // key_exchange length = 0 bytes
        ];
        let result = KeyShareEntry::parse(&mut ParseBuffer::new(&buffer)).unwrap();

        assert_eq!(NamedGroup::Secp256r1, result.group);
        assert_eq!(0, result.opaque.as_ref().len());
    }

    #[test]
    fn test_parse() {
        setup();
        let buffer = [
            0x00, 0x017, // Secp256r1
            0x00, 0x02, // key_exchange length = 2 bytes
            0xAA, 0xBB,
        ];
        let result = KeyShareEntry::parse(&mut ParseBuffer::new(&buffer)).unwrap();

        assert_eq!(NamedGroup::Secp256r1, result.group);
        assert_eq!(2, result.opaque.as_ref().len());
        assert_eq!([0xAA, 0xBB], result.opaque);
    }
}
