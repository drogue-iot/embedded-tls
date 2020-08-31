/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use mbedtls_sys::*;

use crate::private::{alloc_string_repeat, alloc_vec_repeat};
use crate::error::{Error, IntoResult, Result};
use crate::pk::Pk;
use crate::hash::Type as MdType;
use crate::rng::Random;

define!(
    #[c_ty(x509_csr)]
    /// Certificate Signing Request
    struct Csr;
    const init: fn() -> Self = x509_csr_init;
    const drop: fn(&mut Self) = x509_csr_free;
);

impl Csr {
    pub fn from_der(der: &[u8]) -> Result<Csr> {
        let mut ret = Self::init();
        unsafe { x509_csr_parse_der(&mut ret.inner, der.as_ptr(), der.len()) }.into_result()?;
        Ok(ret)
    }

    pub fn from_pem(pem: &[u8]) -> Result<Csr> {
        let mut ret = Self::init();
        unsafe { x509_csr_parse(&mut ret.inner, pem.as_ptr(), pem.len()) }.into_result()?;
        Ok(ret)
    }

    pub fn subject(&self) -> Result<String> {
        alloc_string_repeat(|buf, size| unsafe {
            x509_dn_gets(buf, size, &self.inner.subject)
        })
    }

    pub fn subject_raw(&self) -> Result<Vec<u8>> {
        alloc_vec_repeat(
            |buf, size| unsafe { x509_dn_gets(buf as _, size, &self.inner.subject) },
            false,
        )
    }

    pub fn public_key(&self) -> &Pk {
        unsafe { &*(&self.inner.pk as *const _ as *const _) }
    }

    pub fn as_der(&self) -> &[u8] {
        unsafe { ::core::slice::from_raw_parts(self.inner.raw.p, self.inner.raw.len) }
    }
}

impl fmt::Debug for Csr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match alloc_string_repeat(|buf, size| unsafe {
            x509_csr_info(buf, size, b"\0".as_ptr() as *const _, &self.inner)
        }) {
            Err(_) => Err(fmt::Error),
            Ok(s) => f.write_str(&s),
        }
    }
}

define!(
    #[c_ty(x509write_csr)]
    struct Builder<'a>;
    pub const new: fn() -> Self = x509write_csr_init;
    const drop: fn(&mut Self) = x509write_csr_free;
);

impl<'a> Builder<'a> {
    unsafe fn subject_with_nul_unchecked(&mut self, subject: &[u8]) -> Result<&mut Self> {
        x509write_csr_set_subject_name(&mut self.inner, subject.as_ptr() as *const _).into_result()?;
        Ok(self)
    }

    #[cfg(feature = "std")]
    pub fn subject(&mut self, subject: &str) -> Result<&mut Self> {
        match ::std::ffi::CString::new(subject) {
            Err(_) => Err(Error::X509InvalidName),
            Ok(s) => unsafe { self.subject_with_nul_unchecked(s.as_bytes_with_nul()) },
        }
    }

    pub fn subject_with_nul(&mut self, subject: &str) -> Result<&mut Self> {
        if subject.as_bytes().iter().any(|&c| c == 0) {
            unsafe { self.subject_with_nul_unchecked(subject.as_bytes()) }
        } else {
            Err(Error::X509InvalidName)
        }
    }

    pub fn key(&mut self, key: &'a mut Pk) -> &mut Self {
        unsafe { x509write_csr_set_key(&mut self.inner, key.into()) };
        self
    }

    pub fn signature_hash(&mut self, md: MdType) -> &mut Self {
        unsafe { x509write_csr_set_md_alg(&mut self.inner, md.into()) };
        self
    }

    pub fn key_usage(&mut self, usage: crate::x509::KeyUsage) -> Result<&mut Self> {
        let usage = usage.bits();
        if (usage & !0xfe) != 0 {
            // according to x509write_**crt**_set_key_usage
            return Err(Error::X509FeatureUnavailable);
        }

        unsafe { x509write_csr_set_key_usage(&mut self.inner, (usage & 0xfe) as u8) }.into_result()?;
        Ok(self)
    }

    pub fn extension(&mut self, oid: &[u8], val: &[u8]) -> Result<&mut Self> {
        unsafe {
            x509write_csr_set_extension(
                &mut self.inner,
                oid.as_ptr() as *const _,
                oid.len(),
                val.as_ptr(),
                val.len()
            )
        }.into_result()?;
        Ok(self)
    }

    pub fn write_der<'buf, F: Random>(
        &mut self,
        buf: &'buf mut [u8],
        rng: &mut F,
    ) -> Result<Option<&'buf [u8]>> {
        match unsafe {
            x509write_csr_der(
                &mut self.inner,
                buf.as_mut_ptr(),
                buf.len(),
                Some(F::call),
                rng.data_ptr(),
            )
            .into_result()
        } {
            Err(Error::Asn1BufTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_der_vec<F: Random>(&mut self, rng: &mut F) -> Result<Vec<u8>> {
        alloc_vec_repeat(
            |buf, size| unsafe {
                x509write_csr_der(&mut self.inner, buf, size, Some(F::call), rng.data_ptr())
            },
            true,
        )
    }

    pub fn write_pem<'buf, F: Random>(
        &mut self,
        buf: &'buf mut [u8],
        rng: &mut F,
    ) -> Result<Option<&'buf [u8]>> {
        match unsafe {
            x509write_csr_der(
                &mut self.inner,
                buf.as_mut_ptr(),
                buf.len(),
                Some(F::call),
                rng.data_ptr(),
            )
            .into_result()
        } {
            Err(Error::Base64BufferTooSmall) => Ok(None),
            Err(e) => Err(e),
            Ok(n) => Ok(Some(&buf[buf.len() - (n as usize)..])),
        }
    }

    pub fn write_pem_string<F: Random>(&mut self, rng: &mut F) -> Result<String> {
        alloc_string_repeat(|buf, size| unsafe {
            match x509write_csr_pem(
                &mut self.inner,
                buf as _,
                size,
                Some(F::call),
                rng.data_ptr(),
            ) {
                0 => crate::private::cstr_to_slice(buf as _).len() as _,
                r => r,
            }
        })
    }
}

// TODO
// x509write_csr_set_ns_cert_type
//

#[cfg(test)]
mod tests {
    use super::*;

    struct Test {
        key: Pk,
    }

    impl Test {
        fn new() -> Self {
            Test {
                key: Pk::from_private_key(crate::test_support::keys::PEM_SELF_SIGNED_KEY, None).unwrap(),
            }
        }

        fn builder<'a>(&'a mut self) -> Builder<'a> {
            let mut b = Builder::new();
            b.key(&mut self.key);
            b.subject_with_nul("CN=mbedtls.example\0").unwrap();
            b
        }
    }

    const TEST_PEM: &'static str = r"-----BEGIN CERTIFICATE REQUEST-----
MIICXzCCAUcCAQAwGjEYMBYGA1UEAwwPbWJlZHRscy5leGFtcGxlMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxYwIJgiVJigEPzgINDAYdxNvpeWrEh3Q
TZk5tIK975p5hXFKpSKVBtwRnfOaNHPV+ap8QSiWn0yS7tsUao8dUzJQXbVaT9Al
8uaj2MLzvFFiBsq7J4svBn6Q41xpFBW5vdQsNXP5Qg+0depSxyvuzaavaMaZNynz
B4r0KKxXd9W8qNFcWb/7BWFYgmw7TmJjIn0F/6pKrG75MUrj5Jc6cQMRfNuJrSjE
YpsBkG2eLWy5QBTboDtNnldB6vMR8X25ja25UqiMuvP1HY4OGPX3hYvDVX2IP67B
Y7i/hb/93SwQYWjH38lfSdHlC14FcOWVzWkICm+rEgUKolNy37Rw0wIDAQABoAAw
DQYJKoZIhvcNAQELBQADggEBAL4Lnz1NSYOnp8u1NShImiDDbyw8Vz+rfN9zQ8jd
61a+nazw72DdxKTxy3EFR7PN6/2Mb7N2qUum3Ha4Zg7MmUfzk+FdFu8ztd9kHqob
3Q4RJtZ9v35cEk0VyBRIWf0ldFRxth5/ZYEs0I9IIDBUjGFPoXQcZWr85E2DXKtK
iN0czdG0tdSPAsYn9cxulE66bJUtyB3QXxTgK8ZZ/IBmtl4FmmSbkG7DYP4AUjLY
hPWdcVWbny2G76eX3ZDCOpEY4Juxm2oiS6fWuQp4HTilhq+W9atgogzxjdleVU70
S8qlfwzPdie+Prd73sTapfFAUYei0t274xW/b0eWeo20QzI=
-----END CERTIFICATE REQUEST-----
";

    const TEST_DER: &'static [u8] = &[
        0x30, 0x82, 0x02, 0x5f, 0x30, 0x82, 0x01, 0x47, 0x02, 0x01, 0x00, 0x30, 0x1a, 0x31, 0x18,
        0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0f, 0x6d, 0x62, 0x65, 0x64, 0x74, 0x6c,
        0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82,
        0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xc5, 0x8c, 0x08,
        0x26, 0x08, 0x95, 0x26, 0x28, 0x04, 0x3f, 0x38, 0x08, 0x34, 0x30, 0x18, 0x77, 0x13, 0x6f,
        0xa5, 0xe5, 0xab, 0x12, 0x1d, 0xd0, 0x4d, 0x99, 0x39, 0xb4, 0x82, 0xbd, 0xef, 0x9a, 0x79,
        0x85, 0x71, 0x4a, 0xa5, 0x22, 0x95, 0x06, 0xdc, 0x11, 0x9d, 0xf3, 0x9a, 0x34, 0x73, 0xd5,
        0xf9, 0xaa, 0x7c, 0x41, 0x28, 0x96, 0x9f, 0x4c, 0x92, 0xee, 0xdb, 0x14, 0x6a, 0x8f, 0x1d,
        0x53, 0x32, 0x50, 0x5d, 0xb5, 0x5a, 0x4f, 0xd0, 0x25, 0xf2, 0xe6, 0xa3, 0xd8, 0xc2, 0xf3,
        0xbc, 0x51, 0x62, 0x06, 0xca, 0xbb, 0x27, 0x8b, 0x2f, 0x06, 0x7e, 0x90, 0xe3, 0x5c, 0x69,
        0x14, 0x15, 0xb9, 0xbd, 0xd4, 0x2c, 0x35, 0x73, 0xf9, 0x42, 0x0f, 0xb4, 0x75, 0xea, 0x52,
        0xc7, 0x2b, 0xee, 0xcd, 0xa6, 0xaf, 0x68, 0xc6, 0x99, 0x37, 0x29, 0xf3, 0x07, 0x8a, 0xf4,
        0x28, 0xac, 0x57, 0x77, 0xd5, 0xbc, 0xa8, 0xd1, 0x5c, 0x59, 0xbf, 0xfb, 0x05, 0x61, 0x58,
        0x82, 0x6c, 0x3b, 0x4e, 0x62, 0x63, 0x22, 0x7d, 0x05, 0xff, 0xaa, 0x4a, 0xac, 0x6e, 0xf9,
        0x31, 0x4a, 0xe3, 0xe4, 0x97, 0x3a, 0x71, 0x03, 0x11, 0x7c, 0xdb, 0x89, 0xad, 0x28, 0xc4,
        0x62, 0x9b, 0x01, 0x90, 0x6d, 0x9e, 0x2d, 0x6c, 0xb9, 0x40, 0x14, 0xdb, 0xa0, 0x3b, 0x4d,
        0x9e, 0x57, 0x41, 0xea, 0xf3, 0x11, 0xf1, 0x7d, 0xb9, 0x8d, 0xad, 0xb9, 0x52, 0xa8, 0x8c,
        0xba, 0xf3, 0xf5, 0x1d, 0x8e, 0x0e, 0x18, 0xf5, 0xf7, 0x85, 0x8b, 0xc3, 0x55, 0x7d, 0x88,
        0x3f, 0xae, 0xc1, 0x63, 0xb8, 0xbf, 0x85, 0xbf, 0xfd, 0xdd, 0x2c, 0x10, 0x61, 0x68, 0xc7,
        0xdf, 0xc9, 0x5f, 0x49, 0xd1, 0xe5, 0x0b, 0x5e, 0x05, 0x70, 0xe5, 0x95, 0xcd, 0x69, 0x08,
        0x0a, 0x6f, 0xab, 0x12, 0x05, 0x0a, 0xa2, 0x53, 0x72, 0xdf, 0xb4, 0x70, 0xd3, 0x02, 0x03,
        0x01, 0x00, 0x01, 0xa0, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0xbe, 0x0b, 0x9f, 0x3d, 0x4d,
        0x49, 0x83, 0xa7, 0xa7, 0xcb, 0xb5, 0x35, 0x28, 0x48, 0x9a, 0x20, 0xc3, 0x6f, 0x2c, 0x3c,
        0x57, 0x3f, 0xab, 0x7c, 0xdf, 0x73, 0x43, 0xc8, 0xdd, 0xeb, 0x56, 0xbe, 0x9d, 0xac, 0xf0,
        0xef, 0x60, 0xdd, 0xc4, 0xa4, 0xf1, 0xcb, 0x71, 0x05, 0x47, 0xb3, 0xcd, 0xeb, 0xfd, 0x8c,
        0x6f, 0xb3, 0x76, 0xa9, 0x4b, 0xa6, 0xdc, 0x76, 0xb8, 0x66, 0x0e, 0xcc, 0x99, 0x47, 0xf3,
        0x93, 0xe1, 0x5d, 0x16, 0xef, 0x33, 0xb5, 0xdf, 0x64, 0x1e, 0xaa, 0x1b, 0xdd, 0x0e, 0x11,
        0x26, 0xd6, 0x7d, 0xbf, 0x7e, 0x5c, 0x12, 0x4d, 0x15, 0xc8, 0x14, 0x48, 0x59, 0xfd, 0x25,
        0x74, 0x54, 0x71, 0xb6, 0x1e, 0x7f, 0x65, 0x81, 0x2c, 0xd0, 0x8f, 0x48, 0x20, 0x30, 0x54,
        0x8c, 0x61, 0x4f, 0xa1, 0x74, 0x1c, 0x65, 0x6a, 0xfc, 0xe4, 0x4d, 0x83, 0x5c, 0xab, 0x4a,
        0x88, 0xdd, 0x1c, 0xcd, 0xd1, 0xb4, 0xb5, 0xd4, 0x8f, 0x02, 0xc6, 0x27, 0xf5, 0xcc, 0x6e,
        0x94, 0x4e, 0xba, 0x6c, 0x95, 0x2d, 0xc8, 0x1d, 0xd0, 0x5f, 0x14, 0xe0, 0x2b, 0xc6, 0x59,
        0xfc, 0x80, 0x66, 0xb6, 0x5e, 0x05, 0x9a, 0x64, 0x9b, 0x90, 0x6e, 0xc3, 0x60, 0xfe, 0x00,
        0x52, 0x32, 0xd8, 0x84, 0xf5, 0x9d, 0x71, 0x55, 0x9b, 0x9f, 0x2d, 0x86, 0xef, 0xa7, 0x97,
        0xdd, 0x90, 0xc2, 0x3a, 0x91, 0x18, 0xe0, 0x9b, 0xb1, 0x9b, 0x6a, 0x22, 0x4b, 0xa7, 0xd6,
        0xb9, 0x0a, 0x78, 0x1d, 0x38, 0xa5, 0x86, 0xaf, 0x96, 0xf5, 0xab, 0x60, 0xa2, 0x0c, 0xf1,
        0x8d, 0xd9, 0x5e, 0x55, 0x4e, 0xf4, 0x4b, 0xca, 0xa5, 0x7f, 0x0c, 0xcf, 0x76, 0x27, 0xbe,
        0x3e, 0xb7, 0x7b, 0xde, 0xc4, 0xda, 0xa5, 0xf1, 0x40, 0x51, 0x87, 0xa2, 0xd2, 0xdd, 0xbb,
        0xe3, 0x15, 0xbf, 0x6f, 0x47, 0x96, 0x7a, 0x8d, 0xb4, 0x43, 0x32,
    ];

    #[test]
    fn write_der() {
        let mut t = Test::new();
        let output = t
            .builder()
            .signature_hash(MdType::Sha256)
            .write_der_vec(&mut crate::test_support::rand::test_rng())
            .unwrap();
        assert!(output == TEST_DER);
    }

    #[test]
    fn write_pem() {
        let mut t = Test::new();
        let output = t
            .builder()
            .signature_hash(MdType::Sha256)
            .write_pem_string(&mut crate::test_support::rand::test_rng())
            .unwrap();
        assert_eq!(output, TEST_PEM);
    }
}
