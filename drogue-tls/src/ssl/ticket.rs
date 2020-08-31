/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::cipher::raw::CipherType;
use crate::error::{IntoResult, Result};
use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;

pub trait TicketCallback {
    unsafe extern "C" fn call_write(
        p_ticket: *mut c_void,
        session: *const ssl_session,
        start: *mut c_uchar,
        end: *const c_uchar,
        tlen: *mut size_t,
        lifetime: *mut u32,
    ) -> c_int;
    unsafe extern "C" fn call_parse(
        p_ticket: *mut c_void,
        session: *mut ssl_session,
        buf: *mut c_uchar,
        len: size_t,
    ) -> c_int;

    fn data_ptr(&mut self) -> *mut c_void;
}

define!(
    #[c_ty(ssl_ticket_context)]
    struct TicketContext<'rng>;
    const init: fn() -> Self = ssl_ticket_init;
    const drop: fn(&mut Self) = ssl_ticket_free;
);

impl<'rng> TicketContext<'rng> {
    pub fn new<F: crate::rng::Random>(
        rng: &'rng mut F,
        cipher: CipherType,
        lifetime: u32,
    ) -> Result<TicketContext<'rng>> {
        let mut ret = Self::init();
        unsafe {
            ssl_ticket_setup(
                &mut ret.inner,
                Some(F::call),
                rng.data_ptr(),
                cipher.into(),
                lifetime,
            )
        }
        .into_result()
        .map(|_| ret)
    }
}

impl<'rng> TicketCallback for TicketContext<'rng> {
    unsafe extern "C" fn call_write(
        p_ticket: *mut c_void,
        session: *const ssl_session,
        start: *mut c_uchar,
        end: *const c_uchar,
        tlen: *mut size_t,
        lifetime: *mut u32,
    ) -> c_int {
        ssl_ticket_write(p_ticket, session, start, end, tlen, lifetime)
    }

    unsafe extern "C" fn call_parse(
        p_ticket: *mut c_void,
        session: *mut ssl_session,
        buf: *mut c_uchar,
        len: size_t,
    ) -> c_int {
        ssl_ticket_parse(p_ticket, session, buf, len)
    }

    fn data_ptr(&mut self) -> *mut c_void {
        &mut self.inner as *mut _ as *mut _
    }
}
