use heapless::Vec;

use crate::{
    buffer::CryptoBuffer,
    parse_buffer::{ParseBuffer, ParseError},
    TlsError,
};

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// uint8 SRTPProtectionProfile[2];
// SRTPProtectionProfile SRTPProtectionProfiles<2..2^16-1>;
pub struct SrtpProtectionProfile(pub u8, pub u8);

impl SrtpProtectionProfile {
    pub const AES128_CM_HMAC_SHA1_80: Self = Self(0x00, 0x01);
    pub const AES128_CM_HMAC_SHA1_32: Self = Self(0x00, 0x02);
    pub const NULL_HMAC_SHA1_80: Self = Self(0x00, 0x05);
    pub const NULL_HMAC_SHA1_32: Self = Self(0x00, 0x06);

    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Ok(Self(buf.read_u8()?, buf.read_u8()?))
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self.0)?;
        buf.push(self.1)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
// struct {
//    SRTPProtectionProfiles SRTPProtectionProfiles;
//    opaque srtp_mki<0..255>;
// } UseSRTPData;
pub struct UseSrtp<'a, const N: usize> {
    pub profiles: Vec<SrtpProtectionProfile, N>,
    pub strp_mki: &'a [u8],
}

impl<'a, const N: usize> UseSrtp<'a, N> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        let profiles_length = buf.read_u16()? as usize;
        let profiles = buf.read_list(profiles_length, SrtpProtectionProfile::parse)?;

        let mki_length = buf.read_u8()? as usize;
        let mki = buf.slice(mki_length)?.as_slice();

        Ok(Self {
            profiles,
            strp_mki: mki,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for profile in self.profiles.iter() {
                profile.encode(buf)?;
            }
            Ok(())
        })?;

        buf.with_u8_length(|buf| buf.extend_from_slice(self.strp_mki))
    }
}
