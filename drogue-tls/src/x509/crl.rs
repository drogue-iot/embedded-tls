/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;

use mbedtls_sys::*;

use crate::error::{IntoResult, Result};

define!(
    #[c_ty(x509_crl)]
    /// Certificate Revocation List
    struct Crl;
    pub const new: fn() -> Self = x509_crl_init;
    const drop: fn(&mut Self) = x509_crl_free;
    impl<'a> Into<ptr> {}
);

impl Crl {
    pub fn push_from_der(&mut self, der: &[u8]) -> Result<()> {
        unsafe {
            x509_crl_parse_der(&mut self.inner, der.as_ptr(), der.len())
                .into_result()
                .map(|_| ())
        }
    }

    pub fn push_from_pem(&mut self, pem: &[u8]) -> Result<()> {
        unsafe {
            x509_crl_parse(&mut self.inner, pem.as_ptr(), pem.len())
                .into_result()
                .map(|_| ())
        }
    }
}

impl fmt::Debug for Crl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match crate::private::alloc_string_repeat(|buf, size| unsafe {
            x509_crl_info(buf, size, b"\0".as_ptr() as *const _, &self.inner)
        }) {
            Err(_) => Err(fmt::Error),
            Ok(s) => f.write_str(&s),
        }
    }
}

// TODO
// x509_crl_parse_file
//
