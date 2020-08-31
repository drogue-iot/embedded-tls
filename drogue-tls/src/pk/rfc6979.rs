/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

use crate::rng::{HmacDrbg, Random, RngCallback};

use crate::error::Result;
use crate::bignum::Mpi;
use crate::hash::{MdInfo, Type};

fn generate_rfc6979_nonce(md: &MdInfo, x: &Mpi, q: &Mpi, digest_bytes: &[u8]) -> Result<Vec<u8>> {
    let q_bits = q.bit_length()?;
    let q_bytes = q.byte_length()?;

    let mut digest = Mpi::from_binary(&digest_bytes)?;

    if 8 * md.size() > q_bits {
        let shift_needed = 8 * md.size() - q_bits;
        digest >>= shift_needed;
    }

    while digest >= *q {
        digest -= q;
    }

    let mut x = x.to_binary_padded(q_bytes)?;
    let mut d = digest.to_binary_padded(q_bytes)?;
    x.append(&mut d);

    let mut drbg = HmacDrbg::from_buf(*md, &x).unwrap();

    let mut output = vec![0; q_bytes];

    loop {
        drbg.random(&mut output).unwrap();

        let mut v = Mpi::from_binary(&output)?;

        if 8 * output.len() > q_bits {
            let shift_needed = 8 * output.len() - q_bits;
            v >>= shift_needed;
        }

        if v < *q {
            /*
            For P-521 we must correct for a shift done in mbedtls_ecp_gen_keypair_base
            which is performed if the field is not a multiple of 8 bits.
            */
            if q_bits == 521 {
                v <<= 7;
            }
            return v.to_binary_padded(q_bytes);
        }
    }
}

pub(crate) struct Rfc6979Rng {
    pub k: Vec<u8>,
    pub k_read: usize,
    pub rng: HmacDrbg<'static>,
}

/// An RNG which first outputs the k for RFC 6797 followed by random data
impl Rfc6979Rng {
    pub fn new(
        md_type: Type,
        q: &Mpi,
        x: &Mpi,
        digest_bytes: &[u8],
        random_seed: &[u8],
    ) -> Result<Rfc6979Rng> {
        let md: MdInfo = match md_type.into() {
            Some(md) => md,
            None => panic!("no such digest"),
        };

        let k = generate_rfc6979_nonce(&md, x, q, digest_bytes)?;

        Ok(Rfc6979Rng {
            k: k,
            k_read: 0,
            rng: HmacDrbg::from_buf(md, random_seed)?,
        })
    }

    fn random_callback(&mut self, data: &mut [u8]) -> Result<()> {
        let avail_k = self.k.len() - self.k_read;

        if data.len() <= avail_k {
            let copying = data.len();
            data.copy_from_slice(&self.k[self.k_read..copying]);
            self.k_read += data.len();
            Ok(())
        } else {
            let (gets_k, gets_r) = data.split_at_mut(avail_k);
            gets_k.copy_from_slice(&self.k[self.k_read..]);
            self.k_read += avail_k;
            self.rng.random(gets_r)
        }
    }
}

impl RngCallback for Rfc6979Rng {
    unsafe extern "C" fn call(
        user_data: *mut c_void,
        data_ptr: *mut c_uchar,
        len: size_t,
    ) -> c_int {
        let rng: &mut Rfc6979Rng = (user_data as *mut Rfc6979Rng).as_mut().unwrap();
        let slice = ::core::slice::from_raw_parts_mut(data_ptr, len);
        let result = rng.random_callback(slice);
        if let Err(r) = result {
            r.to_int()
        } else {
            0
        }
    }

    fn data_ptr(&mut self) -> *mut c_void {
        self as *const _ as *mut _
    }
}
