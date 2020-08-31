/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use mbedtls_sys::types::raw_types::c_char;
use mbedtls_sys::types::raw_types::{c_int, c_uchar};
use mbedtls_sys::types::size_t;

use crate::error::{Error, IntoResult, Result};

pub trait UnsafeFrom<T>
where
    Self: Sized,
{
    unsafe fn from(_: T) -> Option<Self>;
}

pub fn alloc_vec_repeat<F>(mut f: F, data_at_end: bool) -> Result<Vec<u8>>
where
    F: FnMut(*mut c_uchar, size_t) -> c_int,
{
    /*
    Avoid allocating more than a limited amount of memory. In certain conditions
    with malformed datastructures, mbedtls may return a too-small error regardless of how much
    buffer space is provided. This causes a loop which terminates with a out of memory panic.
    */
    const MAX_VECTOR_ALLOCATION : usize = 4 * 1024 * 1024;

    let mut vec = Vec::with_capacity(2048 /* big because of bug in x509write */);
    loop {
        match f(vec.as_mut_ptr(), vec.capacity()).into_result() {
            Err(Error::Asn1BufTooSmall)
            | Err(Error::Base64BufferTooSmall)
            | Err(Error::EcpBufferTooSmall)
            | Err(Error::MpiBufferTooSmall)
            | Err(Error::NetBufferTooSmall)
            | Err(Error::OidBufTooSmall)
            | Err(Error::SslBufferTooSmall)
            | Err(Error::X509BufferTooSmall)
                if vec.capacity() < MAX_VECTOR_ALLOCATION =>
            {
                let cap = vec.capacity();
                vec.reserve(cap * 2)
            }
            Err(e) => return Err(e),
            Ok(n) => {
                if data_at_end {
                    let len = vec.capacity();
                    unsafe { vec.set_len(len) };
                    drop(vec.drain(..len - (n as usize)));
                } else {
                    unsafe { vec.set_len(n as usize) };
                }
                break;
            }
        }
    }
    vec.shrink_to_fit();
    Ok(vec)
}

pub fn alloc_string_repeat<F>(mut f: F) -> Result<String>
where
    F: FnMut(*mut c_char, size_t) -> c_int,
{
    let vec = alloc_vec_repeat(|b, s| f(b as _, s), false)?;
    String::from_utf8(vec).map_err(|e| e.utf8_error().into())
}

#[cfg(feature = "std")]
pub unsafe fn cstr_to_slice<'a>(ptr: *const c_char) -> &'a [u8] {
    ::std::ffi::CStr::from_ptr(ptr).to_bytes()
}

#[cfg(not(feature = "std"))]
pub unsafe fn cstr_to_slice<'a>(ptr: *const c_char) -> &'a [u8] {
    extern "C" {
        // this function is coming from the mbedtls C support lib
        fn strlen(s: *const c_char) -> size_t;
    }
    ::core::slice::from_raw_parts(ptr as *const _, strlen(ptr))
}

//#[cfg(not(feature = "std"))]
//use core_io::{Error as IoError, ErrorKind as IoErrorKind};
//#[cfg(feature = "std")]
//use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use crate::io::{Error as IoError};

pub fn error_to_io_error(e: Error) -> IoError<Error> {
    IoError::Other(e)
}
