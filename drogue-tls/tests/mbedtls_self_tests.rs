/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

extern crate mbedtls;
extern crate mbedtls_sys;

#[cfg(any(not(feature = "std"), target_env = "sgx"))]
unsafe fn log(msg: *const mbedtls_sys::types::raw_types::c_char) {
    print!("{}", std::ffi::CStr::from_ptr(msg).to_string_lossy());
}

#[cfg(any(not(feature = "std"), target_env = "sgx"))]
fn rand() -> mbedtls_sys::types::raw_types::c_int {
    3 // Only used for RSA self test
}

#[cfg(any(not(feature = "std"), target_env = "sgx"))]
fn enable_self_test() {
    use std::sync::Once;

    static START: Once = Once::new();

    START.call_once(|| {
        // safe because synchronized
        unsafe { mbedtls::self_test::enable(rand, log) };
    });
}

#[cfg(all(feature = "std", not(target_env = "sgx")))]
fn enable_self_test() {}

macro_rules! tests {
    { $($(#[$m:meta])* fn $t:ident,)*} => {
        $(
        #[test]
        $(#[$m])*
        fn $t() {
            enable_self_test();
            unsafe {
                assert!(mbedtls::self_test::$t(1)==0);
            }
        }
        )*
    };
}

tests! {
    fn aes,
    fn arc4,
    fn base64,
    fn camellia,
    fn ccm,
    fn ctr_drbg,
    fn des,
    fn dhm,
    #[cfg(all(feature="std", not(target_env="sgx")))]
    fn entropy,
    fn gcm,
    fn hmac_drbg,
    fn md2,
    fn md4,
    fn md5,
    fn mpi,
    fn pkcs5,
    fn ripemd160,
    fn rsa,
    fn sha1,
    fn sha256,
    fn sha512,
    fn x509,
    fn xtea,
    fn nist_kw,
    fn cmac,
}

// these can't run concurrently
#[test]
fn ec_self_tests() {
    enable_self_test();
    unsafe {
        assert!(mbedtls::self_test::ecp(1) == 0);
        assert!(mbedtls::self_test::ecjpake(1) == 0);
    }
}
