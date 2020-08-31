/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

//#[cfg(feature = "std")]
//use std::io::{self, Read, Write};

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;

use crate::io::{self, Read, Write};
use crate::error::{Error, IntoResult, Result};
use core::result::Result as StdResult;
use crate::private::UnsafeFrom;
use crate::ssl::config::{AuthMode, Config, Version};
use crate::x509::{Crl, LinkedCertificate, VerifyError};

pub trait IoCallback {
    unsafe extern "C" fn call_recv(
        user_data: *mut c_void,
        data: *mut c_uchar,
        len: size_t,
    ) -> c_int;
    unsafe extern "C" fn call_send(
        user_data: *mut c_void,
        data: *const c_uchar,
        len: size_t,
    ) -> c_int;

    fn data_ptr(&mut self) -> *mut c_void;
}

impl<IO: Read + Write> IoCallback for IO {
    unsafe extern "C" fn call_recv(
        user_data: *mut c_void,
        data: *mut c_uchar,
        len: size_t,
    ) -> c_int {
        let len = if len > (c_int::max_value() as size_t) {
            c_int::max_value() as size_t
        } else {
            len
        };
        match (&mut *(user_data as *mut IO)).read(::core::slice::from_raw_parts_mut(data, len)) {
            Ok(i) => i as c_int,
            Err(_) => ::mbedtls_sys::ERR_NET_RECV_FAILED,
        }
    }

    unsafe extern "C" fn call_send(
        user_data: *mut c_void,
        data: *const c_uchar,
        len: size_t,
    ) -> c_int {
        let len = if len > (c_int::max_value() as size_t) {
            c_int::max_value() as size_t
        } else {
            len
        };
        match (&mut *(user_data as *mut IO)).write(::core::slice::from_raw_parts(data, len)) {
            Ok(i) => i as c_int,
            Err(_) => ::mbedtls_sys::ERR_NET_SEND_FAILED,
        }
    }

    fn data_ptr(&mut self) -> *mut c_void {
        self as *mut IO as *mut _
    }
}

define!(
    #[c_ty(ssl_context)]
    struct Context<'config>;
    const init: fn() -> Self = ssl_init;
    const drop: fn(&mut Self) = ssl_free;
    impl<'a> Into<ptr> {}
    impl<'a> UnsafeFrom<ptr> {}
);

pub struct Session<'ctx> {
    inner: &'ctx mut ssl_context,
}

#[cfg(feature = "threading")]
unsafe impl<'ctx> Send for Session<'ctx> {}

pub struct HandshakeContext<'ctx> {
    inner: &'ctx mut ssl_context,
}

impl<'config> Context<'config> {
    pub fn new(config: &'config Config) -> Result<Context<'config>> {
        let mut ret = Self::init();
        unsafe { ssl_setup(&mut ret.inner, config.into()) }
            .into_result()
            .map(|_| ret)
    }

    pub fn establish<'c, F: IoCallback>(
        &'c mut self,
        io: &'c mut F,
        hostname: Option<&str>,
    ) -> Result<Session<'c>> {
        unsafe {
            ssl_session_reset(&mut self.inner).into_result()?;
            self.set_hostname(hostname)?;

            ssl_set_bio(
                &mut self.inner,
                io.data_ptr(),
                Some(F::call_send),
                Some(F::call_recv),
                None,
            );
            match ssl_handshake(&mut self.inner).into_result() {
                Err(e) => {
                    // safely end borrow of io
                    ssl_set_bio(&mut self.inner, ::core::ptr::null_mut(), None, None, None);
                    Err(e)
                }
                Ok(_) => Ok(Session {
                    inner: &mut self.inner,
                }),
            }
        }
    }

    #[cfg(not(feature = "std"))]
    fn set_hostname(&mut self, hostname: Option<&str>) -> Result<()> {
        match hostname {
            Some(_) => Err(Error::SslBadInputData),
            None => Ok(()),
        }
    }

    #[cfg(feature = "std")]
    fn set_hostname(&mut self, hostname: Option<&str>) -> Result<()> {
        if self.inner.hostname != ::core::ptr::null_mut() {
            // potential MEMORY LEAK! See https://github.com/ARMmbed/mbedtls/issues/836
            self.inner.hostname = ::core::ptr::null_mut();
        }
        if let Some(s) = hostname {
            let cstr = ::std::ffi::CString::new(s).map_err(|_| Error::SslBadInputData)?;
            unsafe {
                ssl_set_hostname(&mut self.inner, cstr.as_ptr())
                    .into_result()
                    .map(|_| ())
            }
        } else {
            Ok(())
        }
    }

    pub fn verify_result(&self) -> StdResult<(), VerifyError> {
        match unsafe { ssl_get_verify_result(&self.inner) } {
            0 => Ok(()),
            flags => Err(VerifyError::from_bits_truncate(flags)),
        }
    }

    pub fn config(&self) -> &'config Config {
        unsafe { UnsafeFrom::from(self.inner.conf).expect("not null") }
    }
}

impl<'ctx> HandshakeContext<'ctx> {
    pub fn set_authmode(&mut self, am: AuthMode) {
        unsafe { ssl_set_hs_authmode(self.inner, am.into()) }
    }

    pub fn set_ca_list<C: Into<&'ctx mut LinkedCertificate>>(
        &mut self,
        list: Option<C>,
        crl: Option<&'ctx mut Crl>,
    ) {
        unsafe {
            ssl_set_hs_ca_chain(
                self.inner,
                list.map(Into::into)
                    .map(Into::into)
                    .unwrap_or(::core::ptr::null_mut()),
                crl.map(Into::into).unwrap_or(::core::ptr::null_mut()),
            )
        }
    }

    /// If this is never called, will use the set of private keys and
    /// certificates configured in the `Config` associated with this `Context`.
    /// If this is called at least once, all those are ignored and the set
    /// specified using this function is used.
    pub fn push_cert<C: Into<&'ctx mut LinkedCertificate>>(
        &mut self,
        chain: C,
        key: &'ctx mut crate::pk::Pk,
    ) -> Result<()> {
        unsafe {
            ssl_set_hs_own_cert(self.inner, chain.into().into(), key.into())
                .into_result()
                .map(|_| ())
        }
    }
}

impl<'ctx> ::core::ops::Deref for HandshakeContext<'ctx> {
    type Target = Context<'ctx>;

    fn deref(&self) -> &Context<'ctx> {
        unsafe { UnsafeFrom::from(&*self.inner as *const _).expect("not null") }
    }
}

impl<'ctx> UnsafeFrom<*mut ssl_context> for HandshakeContext<'ctx> {
    unsafe fn from(ctx: *mut ssl_context) -> Option<HandshakeContext<'ctx>> {
        ctx.as_mut().map(|ctx| HandshakeContext { inner: ctx })
    }
}

impl<'a> Session<'a> {
    /// Return the minor number of the negotiated TLS version
    pub fn minor_version(&self) -> i32 {
        self.inner.minor_ver
    }

    /// Return the major number of the negotiated TLS version
    pub fn major_version(&self) -> i32 {
        self.inner.major_ver
    }

    /// Return the number of bytes currently available to read that
    /// are stored in the Session's internal read buffer
    pub fn bytes_available(&self) -> usize {
        unsafe { ssl_get_bytes_avail(self.inner) }
    }

    pub fn version(&self) -> Version {
        let major = self.major_version();
        assert_eq!(major, 3);
        let minor = self.minor_version();
        match minor {
            0 => Version::Ssl3,
            1 => Version::Tls1_0,
            2 => Version::Tls1_1,
            3 => Version::Tls1_2,
            _ => unreachable!("unexpected TLS version")
        }
    }

    /// Return the 16-bit ciphersuite identifier.
    /// All assigned ciphersuites are listed by the IANA in
    /// https://www.iana.org/assignments/tls-parameters/tls-parameters.txt
    pub fn ciphersuite(&self) -> u16 {
        if self.inner.session == ::core::ptr::null_mut() {
            0
        } else {
            unsafe { self.inner.session.as_ref().unwrap().ciphersuite as u16 }
        }
    }

    pub fn peer_cert(&self) -> Option<crate::x509::certificate::Iter> {
        unsafe { UnsafeFrom::from(ssl_get_peer_cert(self.inner)) }
    }

    pub fn verify_result(&self) -> StdResult<(), VerifyError> {
        match unsafe { ssl_get_verify_result(self.inner) } {
            0 => Ok(()),
            flags => Err(VerifyError::from_bits_truncate(flags)),
        }
    }
}

impl<'a> Read for Session<'a> {
    type IoError = Error;
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize, Self::IoError> {
        match unsafe { ssl_read(self.inner, buf.as_mut_ptr(), buf.len()).into_result() } {
            Err(Error::SslPeerCloseNotify) => Ok(0),
            Err(e) => Err(crate::private::error_to_io_error(e)),
            Ok(i) => Ok(i as usize),
        }
    }
}

impl<'a> Write for Session<'a> {
    type IoError = Error;
    fn write(&mut self, buf: &[u8]) -> io::Result<usize, Self::IoError> {
        match unsafe { ssl_write(self.inner, buf.as_ptr(), buf.len()).into_result() } {
            Err(Error::SslPeerCloseNotify) => Ok(0),
            Err(e) => Err(crate::private::error_to_io_error(e)),
            Ok(i) => Ok(i as usize),
        }
    }

    fn flush(&mut self) -> io::Result<(), Self::IoError> {
        Ok(())
    }
}

impl<'a> Drop for Session<'a> {
    fn drop(&mut self) {
        unsafe {
            ssl_close_notify(self.inner);
            ssl_set_bio(self.inner, ::core::ptr::null_mut(), None, None, None);
        }
    }
}

// ssl_get_alpn_protocol
// ssl_get_max_frag_len
// ssl_get_record_expansion
// ssl_get_verify_result
// ssl_get_version
// ssl_renegotiate
// ssl_send_alert_message
// ssl_set_client_transport_id
// ssl_set_hs_psk
// ssl_set_timer_cb
//
// ssl_handshake_step
//
// CLIENT SIDE SESSIONS
// ssl_session_free
// ssl_session_init
// ssl_get_session
// ssl_set_session
//
// SERVER SIDE SESSIONS (ssl_conf_session_cache)
// ssl_cache_free
// ssl_cache_get
// ssl_cache_init
// ssl_cache_set
// ssl_cache_set_max_entries
//
// CIPHER SUITES
// ssl_ciphersuite_from_id
// ssl_ciphersuite_from_string
// ssl_ciphersuite_uses_ec
// ssl_ciphersuite_uses_psk
// ssl_get_ciphersuite_id
// ssl_get_ciphersuite_name
// ssl_get_ciphersuite_sig_pk_alg
// ssl_list_ciphersuites
//
// DTLS SERVER COOKIES (ssl_conf_dtls_cookies)
// ssl_cookie_check
// ssl_cookie_free
// ssl_cookie_init
// ssl_cookie_set_timeout
// ssl_cookie_setup
// ssl_cookie_write
//
// INTERNAL
// ssl_check_cert_usage
// ssl_check_curve
// ssl_check_sig_hash
// ssl_derive_keys
// ssl_dtls_replay_check
// ssl_dtls_replay_update
// ssl_fetch_input
// ssl_flush_output
// ssl_handshake_client_step
// ssl_handshake_free
// ssl_handshake_server_step
// ssl_handshake_wrapup
// ssl_hash_from_md_alg
// ssl_md_alg_from_hash
// ssl_optimize_checksum
// ssl_parse_certificate
// ssl_parse_change_cipher_spec
// ssl_parse_finished
// ssl_pk_alg_from_sig
// ssl_psk_derive_premaster
// ssl_read_record
// ssl_read_version
// ssl_recv_flight_completed
// ssl_resend
// ssl_reset_checksum
// ssl_send_fatal_handshake_failure
// ssl_send_flight_completed
// ssl_sig_from_pk
// ssl_transform_free
// ssl_write_certificate
// ssl_write_change_cipher_spec
// ssl_write_finished
// ssl_write_record
// ssl_write_version
//
