use crate::named_groups::NamedGroup;
use crate::parse_buffer::{ParseBuffer, ParseError};
use heapless::{consts::*, Vec};

#[derive(Debug)]
pub struct KeyShareEntry {
    pub(crate) group: NamedGroup,
    pub(crate) opaque: Vec<u8, U128>,
}

impl Clone for KeyShareEntry {
    fn clone(&self) -> Self {
        Self {
            group: self.group,
            opaque: self.opaque.clone(),
        }
    }
}

impl KeyShareEntry {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        let group = NamedGroup::of(buf.read_u16()?).ok_or(ParseError::InvalidData)?;
        let mut opaque = Vec::<u8, U128>::new();
        let opaque_len = buf.read_u16()?;
        buf.copy(&mut opaque, opaque_len as usize)?;
        Ok(Self { group, opaque })
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

    #[test]
    fn test_parse() {
        setup();
        let buffer = [0x00, 0x017, 0xAA, 0xBB];
        let result = KeyShareEntry::parse(&mut ParseBuffer::new(&buffer)).unwrap();

        assert_eq!(NamedGroup::Secp256r1, result.group);
        assert_eq!([0xAA, 0xBB], result.opaque.as_ref());
    }
}
