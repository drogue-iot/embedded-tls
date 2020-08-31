/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::error::{IntoResult, Result};
use mbedtls_sys::*;

define!(
    #[c_ty(dhm_context)]
    #[repr(C)]
    struct Dhm;
    const init: fn() -> Self = dhm_init;
    const drop: fn(&mut Self) = dhm_free;
    impl<'a> Into<ptr> {}
);

impl Dhm {
    /// Takes both DER and PEM forms of FFDH parameters in `DHParams` format.
    ///
    /// When calling on PEM-encoded data, `params` must be NULL-terminated
    pub(crate) fn from_params(params: &[u8]) -> Result<Dhm> {
        let mut ret = Self::init();
        unsafe { dhm_parse_dhm(&mut ret.inner, params.as_ptr(), params.len()) }.into_result()?;
        Ok(ret)
    }
}
