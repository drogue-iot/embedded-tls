use crate::parse_buffer::ParseBuffer;
use crate::TlsError;
use heapless::Vec;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CertificateRequestRef<'a> {
    pub(crate) request_context: &'a [u8],
}

impl<'a> CertificateRequestRef<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<CertificateRequestRef<'a>, TlsError> {
        let request_context_len = buf
            .read_u8()
            .map_err(|_| TlsError::InvalidCertificateRequest)?;
        let request_context = buf
            .slice(request_context_len as usize)
            .map_err(|_| TlsError::InvalidCertificateRequest)?;

        let _extensions_length = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidExtensionsLength)?;
        //info!("sh 5 {}", extensions_length);

        buf.slice(_extensions_length as usize)
            .map_err(|_| TlsError::DecodeError)?;
        // info!("Cert request parsing");
        // TODO
        //let extensions = ServerExtension::parse_vector(buf)?;
        //info!("Cert request parsing done");

        Ok(Self {
            request_context: request_context.as_slice(),
        })
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CertificateRequest {
    pub(crate) request_context: Vec<u8, 256>,
}

impl<'a> From<CertificateRequestRef<'a>> for CertificateRequest {
    fn from(cert: CertificateRequestRef<'a>) -> Self {
        let mut request_context = Vec::new();
        request_context.extend_from_slice(cert.request_context);
        Self { request_context }
    }
}
