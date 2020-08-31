/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
pub use mbedtls_sys::HMAC_DRBG_RESEED_INTERVAL as RESEED_INTERVAL;
use mbedtls_sys::{
    hmac_drbg_random, hmac_drbg_reseed, hmac_drbg_seed, hmac_drbg_seed_buf,
    hmac_drbg_set_prediction_resistance, hmac_drbg_update, HMAC_DRBG_PR_OFF, HMAC_DRBG_PR_ON,
};

use super::{EntropyCallback, RngCallback};
use crate::error::{IntoResult, Result};
use crate::hash::MdInfo;

define!(
    #[c_ty(hmac_drbg_context)]
    struct HmacDrbg<'entropy>;
    const init: fn() -> Self = hmac_drbg_init;
    const drop: fn(&mut Self) = hmac_drbg_free;
);

#[cfg(feature = "threading")]
unsafe impl<'entropy> Sync for HmacDrbg<'entropy> {}

impl<'entropy> HmacDrbg<'entropy> {
    pub fn new<F: EntropyCallback>(
        md_info: MdInfo,
        source: &'entropy mut F,
        additional_entropy: Option<&[u8]>,
    ) -> Result<HmacDrbg<'entropy>> {
        let mut ret = Self::init();
        unsafe {
            hmac_drbg_seed(
                &mut ret.inner,
                md_info.into(),
                Some(F::call),
                source.data_ptr(),
                additional_entropy
                    .map(<[_]>::as_ptr)
                    .unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            )
            .into_result()?
        };
        Ok(ret)
    }

    pub fn from_buf(md_info: MdInfo, entropy: &[u8]) -> Result<HmacDrbg<'entropy>> {
        let mut ret = Self::init();
        unsafe {
            hmac_drbg_seed_buf(
                &mut ret.inner,
                md_info.into(),
                entropy.as_ptr(),
                entropy.len()
            )
            .into_result()?
        };
        Ok(ret)
    }

    pub fn prediction_resistance(&self) -> bool {
        if self.inner.prediction_resistance == HMAC_DRBG_PR_OFF as mbedtls_sys::types::c_int {
            false
        } else {
            true
        }
    }

    pub fn set_prediction_resistance(&mut self, pr: bool) {
        unsafe {
            hmac_drbg_set_prediction_resistance(
                &mut self.inner,
                if pr {
                    HMAC_DRBG_PR_ON
                } else {
                    HMAC_DRBG_PR_OFF
                } as mbedtls_sys::types::c_int,
            )
        }
    }

    getter!(entropy_len() -> size_t = .entropy_len);
    setter!(set_entropy_len(len: size_t) = hmac_drbg_set_entropy_len);
    getter!(reseed_interval() -> c_int = .reseed_interval);
    setter!(set_reseed_interval(i: c_int) = hmac_drbg_set_reseed_interval);

    pub fn reseed(&mut self, additional_entropy: Option<&[u8]>) -> Result<()> {
        unsafe {
            hmac_drbg_reseed(
                &mut self.inner,
                additional_entropy
                    .map(<[_]>::as_ptr)
                    .unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            )
            .into_result()?
        };
        Ok(())
    }

    pub fn update(&mut self, entropy: &[u8]) {
        unsafe { hmac_drbg_update(&mut self.inner, entropy.as_ptr(), entropy.len()) };
    }

    // TODO:
    //
    // hmac_drbg_random_with_add
    // hmac_drbg_write_seed_file
    // hmac_drbg_update_seed_file
    //
}

impl<'entropy> RngCallback for HmacDrbg<'entropy> {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        hmac_drbg_random(user_data, data, len)
    }

    fn data_ptr(&mut self) -> *mut c_void {
        &mut self.inner as *mut _ as *mut _
    }
}
