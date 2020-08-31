/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::*;

define!(
    #[c_ty(x509_crt_profile)]
    #[repr(C)]
    struct Profile;
    impl<'a> Into<ptr> {}
);

extern "C" {
    #[link_name = "mbedtls_x509_crt_profile_default"]
    pub static DEFAULT: Profile;
    #[link_name = "mbedtls_x509_crt_profile_next"]
    pub static NEXT: Profile;
    #[link_name = "mbedtls_x509_crt_profile_suiteb"]
    pub static SUITE_B: Profile;
}
