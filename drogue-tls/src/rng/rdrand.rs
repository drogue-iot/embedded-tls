/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::slice::from_raw_parts_mut;

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

#[cfg(target_arch = "x86")]
use core::arch::x86_64::{_rdrand32_step as _rdrand_step, _rdseed32_step as _rdseed_step};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{_rdrand64_step as _rdrand_step, _rdseed64_step as _rdseed_step};

// Intel documentation claims that if hardware is working RDRAND will produce output
// after at most 10 attempts
const RDRAND_READ_ATTEMPTS: usize = 10;

// Intel does not document the number of times RDSEED might consecutively fail, but in
// example code uses 75 as the upper bound.
const RDSEED_READ_ATTEMPTS: usize = 75;

fn call_cpu_rng<T, F>(attempts: usize, intrin: unsafe fn(&mut T) -> i32, cast: F) -> Option<usize>
where
    T: Sized + Default,
    F: FnOnce(T) -> usize,
{
    assert_eq!(core::mem::size_of::<T>(), core::mem::size_of::<usize>());

    for _ in 0..attempts {
        let mut out = T::default();
        let status = unsafe { intrin(&mut out) };
        if status == 1 {
            return Some(cast(out));
        }
    }
    None
}

fn rdrand() -> Option<usize> {
    call_cpu_rng(RDRAND_READ_ATTEMPTS, _rdrand_step, |x| x as usize)
}

fn rdseed() -> Option<usize> {
    call_cpu_rng(RDSEED_READ_ATTEMPTS, _rdseed_step, |x| x as usize)
}

fn write_rng_to_slice(outbuf: &mut [u8], rng: fn() -> Option<usize>) -> c_int {
    let stepsize = core::mem::size_of::<usize>();

    for chunk in outbuf.chunks_mut(stepsize) {
        if let Some(val) = rng() {
            let buf = val.to_ne_bytes();
            let ptr = &buf[..chunk.len()];
            chunk.copy_from_slice(ptr);
        } else {
            return ::mbedtls_sys::ERR_ENTROPY_SOURCE_FAILED;
        }
    }
    0
}

use super::{EntropyCallback, RngCallback};

pub struct Entropy;

impl EntropyCallback for Entropy {
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let mut outbuf = from_raw_parts_mut(data, len);
        write_rng_to_slice(&mut outbuf, rdseed)
    }

    fn data_ptr(&mut self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}

pub struct Nrbg;

impl RngCallback for Nrbg {
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let mut outbuf = from_raw_parts_mut(data, len);
        write_rng_to_slice(&mut outbuf, rdrand)
    }

    fn data_ptr(&mut self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}
