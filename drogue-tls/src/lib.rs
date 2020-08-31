/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![no_std]

#![deny(warnings)]
#![allow(unused_doc_comments)]
//#![cfg_attr(not(feature = "std"), no_std)]

//#[cfg(all(not(feature = "std"), not(feature = "core_io")))]
//const ERROR: _MUST_USE_EITHER_STD_OR_CORE_IO_ = ();

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate core;
//#[cfg(not(feature = "std"))]
//extern crate core_io;
mod io;

#[cfg(feature = "std")]
extern crate yasna;

#[macro_use]
extern crate bitflags;
extern crate mbedtls_sys;

extern crate byteorder;

#[macro_use]
extern crate serde;
//extern crate serde_derive;

#[cfg(target_env = "sgx")]
extern crate rs_libc;

#[macro_use]
mod wrapper_macros;

#[cfg(feature="pkcs12_rc2")]
extern crate rc2;
#[cfg(feature="pkcs12_rc2")]
extern crate block_modes;

// ==============
//      API
// ==============
pub mod bignum;
mod error;
pub use crate::error::{Error, Result};
pub mod cipher;
pub mod ecp;
pub mod hash;
pub mod pk;
pub mod rng;
pub mod self_test;
pub mod ssl;
pub mod x509;

#[cfg(feature = "pkcs12")]
pub mod pkcs12;

// ==============
//    Utility
// ==============
mod private;

// needs to be pub for global visiblity
#[cfg(any(feature = "spin_threading", feature = "rust_threading"))]
#[doc(hidden)]
pub mod threading;

// needs to be pub for global visiblity
#[cfg(feature = "force_aesni_support")]
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn mbedtls_aesni_has_support(_what: u32) -> i32 {
    return 1;
}

// needs to be pub for global visiblity
#[cfg(feature = "force_aesni_support")]
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn mbedtls_internal_aes_encrypt(_ctx: *mut mbedtls_sys::types::raw_types::c_void,
                                               _input: *const u8,
                                               _output: *mut u8) -> i32 {
    panic!("AES-NI support is forced but the T-tables code was invoked")
}

// needs to be pub for global visiblity
#[cfg(feature = "force_aesni_support")]
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn mbedtls_internal_aes_decrypt(_ctx: *mut mbedtls_sys::types::raw_types::c_void,
                                               _input: *const u8,
                                               _output: *mut u8) -> i32 {
    panic!("AES-NI support is forced but the T-tables code was invoked")
}

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
#[cfg(test)]
mod mbedtls {
    pub use super::*;
}

#[cfg(not(feature = "std"))]
mod alloc_prelude {
    #![allow(unused)]
    pub(crate) use alloc::borrow::ToOwned;
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::string::String;
    pub(crate) use alloc::string::ToString;
    pub(crate) use alloc::vec::Vec;
}

#[cfg(all(feature="time", any(feature="custom_gmtime_r", feature="custom_time")))]
use mbedtls_sys::types::{time_t, tm};

#[cfg(any(feature = "custom_gmtime_r", feature = "custom_time"))]
extern crate chrono;

#[cfg(feature="custom_gmtime_r")]
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn mbedtls_platform_gmtime_r(tt: *const time_t, tp: *mut tm) -> *mut tm {
    use chrono::prelude::*;

    //0 means no TZ offset
    let naive = if tp.is_null() {
        return core::ptr::null_mut()
    } else {
        NaiveDateTime::from_timestamp(*tt, 0)
    };
    let utc = DateTime::<Utc>::from_utc(naive, Utc);

    let tp = &mut *tp;
    tp.tm_sec   = utc.second()   as i32;
    tp.tm_min   = utc.minute()   as i32;
    tp.tm_hour  = utc.hour()     as i32;
    tp.tm_mday  = utc.day()      as i32;
    tp.tm_mon   = utc.month0()   as i32;
    tp.tm_year  = utc.year()     as i32 - 1900;
    tp.tm_wday  = utc.weekday().num_days_from_monday() as i32;
    tp.tm_yday  = utc.ordinal0() as i32;
    tp.tm_isdst = 0;

    tp
}

#[cfg(feature="custom_time")]
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn mbedtls_time(tp: *mut time_t) -> time_t {
    let timestamp = chrono::Utc::now().timestamp() as time_t;
    if !tp.is_null() {
        *tp = timestamp;
    }
    timestamp
}
