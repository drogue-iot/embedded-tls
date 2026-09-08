use crate::TlsError;
use digest::{KeyInit, Mac, Output, OutputSizeUser};
use typenum::Unsigned;

/// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
pub fn hkdf_extract<H: Mac + KeyInit>(salt: &[u8], ikm: &[u8]) -> Output<H> {
    let mut hmac = H::new_from_slice(salt).expect("hkdf extract");
    hmac.update(ikm);
    hmac.finalize().into_bytes()
}

/// HKDF-Expand: OKM = T(1) || T(2) || ...
pub fn hkdf_expand<H: Mac + KeyInit>(
    prk: &[u8],
    info: &[u8],
    length: usize,
    okm: &mut [u8],
) -> Result<(), TlsError> {
    let hash_len = <H as OutputSizeUser>::OutputSize::USIZE;
    if length > 255 * hash_len {
        return Err(TlsError::InternalError);
    }
    if okm.len() < length {
        return Err(TlsError::InternalError);
    }

    let mut t = heapless::Vec::<u8, 64>::new();
    let mut n: u8 = 1;
    let mut written = 0;

    while written < length {
        let mut hmac = H::new_from_slice(prk).map_err(|_| TlsError::CryptoError)?;
        hmac.update(&t);
        hmac.update(info);
        hmac.update(&[n]);

        let output = hmac.finalize().into_bytes();

        t.clear();
        t.extend_from_slice(&output)
            .map_err(|_| TlsError::InternalError)?;

        let copy_len = hash_len.min(length - written);
        okm[written..written + copy_len].copy_from_slice(&output[..copy_len]);
        written += copy_len;
        n += 1;
    }
    Ok(())
}

/// TLS 1.3 derive_secret = HKDF-Expand(secret, label, transcript_hash)
#[allow(dead_code)]
pub fn derive_secret<H: Mac + KeyInit>(
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
    out: &mut [u8],
) -> Result<(), TlsError> {
    let mut info = heapless::Vec::<u8, 80>::new();
    let label_len = (6 + label.len()) as u8;
    info.extend_from_slice(&label_len.to_be_bytes())
        .map_err(|_| TlsError::InternalError)?;
    info.extend_from_slice(b"tls13 ")
        .map_err(|_| TlsError::InternalError)?;
    info.extend_from_slice(label)
        .map_err(|_| TlsError::InternalError)?;
    info.extend_from_slice(&(transcript_hash.len() as u8).to_be_bytes())
        .map_err(|_| TlsError::InternalError)?;
    info.extend_from_slice(transcript_hash)
        .map_err(|_| TlsError::InternalError)?;

    hkdf_expand::<H>(secret, &info, out.len(), out)
}
