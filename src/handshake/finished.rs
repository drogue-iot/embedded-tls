use crate::TlsError;
use crate::parse_buffer::ParseBuffer;
use digest::{Output, OutputSizeUser};

#[derive(Clone)]
pub struct Finished<Hash: OutputSizeUser> {
    pub verify: Output<Hash>,
    pub hash: Option<Output<Hash>>,
}

#[cfg(feature = "defmt")]
impl<Hash: OutputSizeUser> defmt::Format for Finished<Hash> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "Finished {{ verify: {:?}, hash: {:?} }}",
            self.verify.as_slice(),
            self.hash.as_ref().map(|h| h.as_slice())
        )
    }
}

impl<Hash: OutputSizeUser> core::fmt::Debug for Finished<Hash> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Finished")
            .field("verify", &self.verify.as_slice())
            .field("hash", &self.hash.as_ref().map(|h| h.as_slice()))
            .finish()
    }
}

impl<Hash: OutputSizeUser> Finished<Hash> {
    pub fn new(verify: Output<Hash>) -> Self {
        Self { verify, hash: None }
    }

    pub fn encode(&self, buf: &mut crate::buffer::CryptoBuffer) -> Result<(), TlsError> {
        buf.extend_from_slice(self.verify.as_slice())
            .map_err(|_| TlsError::EncodeError)
    }

    pub fn parse(buf: &mut ParseBuffer, content_len: u32) -> Result<Self, TlsError> {
        let verify_len = content_len as usize;
        let verify_buf = buf.slice(verify_len).map_err(|_| TlsError::DecodeError)?;
        let verify_slice = verify_buf.as_slice();
        let mut out = Output::<Hash>::default();
        let out_slice: &mut [u8] = out.as_mut();
        out_slice.copy_from_slice(verify_slice);
        Ok(Self::new(out))
    }
}
