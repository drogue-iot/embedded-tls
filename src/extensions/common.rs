use crate::named_groups::NamedGroup;
use crate::parse_buffer::{ParseBuffer, ParseError};

#[derive(Debug)]
pub struct KeyShareEntry<'a> {
    pub(crate) group: NamedGroup,
    pub(crate) opaque: &'a [u8],
}

impl Clone for KeyShareEntry<'_> {
    fn clone(&self) -> Self {
        Self {
            group: self.group,
            opaque: self.opaque.clone(),
        }
    }
}

impl<'a> KeyShareEntry<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<KeyShareEntry<'a>, ParseError> {
        let group = NamedGroup::of(buf.read_u16()?).ok_or(ParseError::InvalidData)?;
        let opaque_len = buf.read_u16()?;
        let opaque = buf.slice(opaque_len as usize)?;
        Ok(Self {
            group,
            opaque: opaque.as_slice(),
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::extensions::common::KeyShareEntry;
    use crate::named_groups::NamedGroup;
    use crate::parse_buffer::ParseBuffer;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            env_logger::init();
        });
    }

    // #[test]
    fn test_parse() {
        setup();
        let buffer = [0x00, 0x017, 0xAA, 0xBB];
        let result = KeyShareEntry::parse(&mut ParseBuffer::new(&buffer)).unwrap();

        assert_eq!(NamedGroup::Secp256r1, result.group);
        assert_eq!([0xAA, 0xBB], result.opaque.as_ref());
    }
}
