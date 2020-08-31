/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;

use crate::error::{IntoResult, Result};

callback!(EntropySourceCallback(data: *mut c_uchar, size: size_t, out: *mut size_t) -> c_int);

define!(
    #[c_ty(entropy_context)]
    struct OsEntropy<'source>;
    pub const new: fn() -> Self = entropy_init;
    const drop: fn(&mut Self) = entropy_free;
);

#[cfg(feature = "threading")]
unsafe impl<'source> Sync for OsEntropy<'source> {}

impl<'source> OsEntropy<'source> {
    pub fn add_source<F: EntropySourceCallback>(
        &mut self,
        source: &'source mut F,
        threshold: size_t,
        strong: bool,
    ) -> Result<()> {
        unsafe {
            entropy_add_source(
                &mut self.inner,
                Some(F::call),
                source.data_ptr(),
                threshold,
                if strong {
                    ENTROPY_SOURCE_STRONG
                } else {
                    ENTROPY_SOURCE_WEAK
                }
            )
            .into_result()?
        };
        Ok(())
    }

    pub fn gather(&mut self) -> Result<()> {
        unsafe { entropy_gather(&mut self.inner) }.into_result()?;
        Ok(())
    }

    pub fn update_manual(&mut self, data: &[u8]) -> Result<()> {
        unsafe { entropy_update_manual(&mut self.inner, data.as_ptr(), data.len()) }.into_result()?;
        Ok(())
    }

    // TODO
    // entropy_write_seed_file
    // entropy_update_seed_file
    //
}

impl<'source> super::EntropyCallback for OsEntropy<'source> {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        entropy_func(user_data, data, len)
    }

    fn data_ptr(&mut self) -> *mut c_void {
        &mut self.inner as *mut _ as *mut _
    }
}
