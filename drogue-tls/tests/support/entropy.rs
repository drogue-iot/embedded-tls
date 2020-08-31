/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(all(feature = "std", not(feature = "rdrand")))]
pub fn entropy_new<'a>() -> crate::mbedtls::rng::OsEntropy<'a> {
    crate::mbedtls::rng::OsEntropy::new()
}

#[cfg(feature = "rdrand")]
pub fn entropy_new() -> crate::mbedtls::rng::Rdseed {
    crate::mbedtls::rng::Rdseed
}

#[cfg(all(not(feature = "std"), not(feature = "rdrand")))]
pub fn entropy_new() -> _UNABLE_TO_RUN_TEST_WITHOUT_ENTROPY_SOURCE_ {
    panic!("Unable to run test without entropy source")
}
