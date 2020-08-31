/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::slice::from_raw_parts;

use mbedtls_sys::types::raw_types::{c_char, c_int, c_uchar, c_uint, c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;

use crate::error::{Error, IntoResult, Result};
use core::result::Result as StdResult;
use crate::pk::dhparam::Dhm;
use crate::pk::Pk;
use crate::private::UnsafeFrom;
use crate::ssl::context::HandshakeContext;
use crate::ssl::ticket::TicketCallback;
use crate::x509::{certificate, Crl, LinkedCertificate, Profile, VerifyError};

extern "C" {
    fn calloc(n: usize, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

#[allow(non_camel_case_types)]
#[derive(Eq, PartialEq, PartialOrd, Ord, Debug, Copy, Clone)]
pub enum Version {
    Ssl3,
    Tls1_0,
    Tls1_1,
    Tls1_2,
    #[doc(hidden)]
    __NonExhaustive,
}

define!(
    #[c_ty(c_int)]
    enum Endpoint {
        Client = SSL_IS_CLIENT,
        Server = SSL_IS_SERVER,
    }
);

define!(
    #[c_ty(c_int)]
    enum Transport {
        /// TLS
        Stream = SSL_TRANSPORT_STREAM,
        /// DTLS
        Datagram = SSL_TRANSPORT_DATAGRAM,
    }
);

define!(
    #[c_ty(c_int)]
    enum Preset {
        Default = SSL_PRESET_DEFAULT,
        SuiteB = SSL_PRESET_SUITEB,
    }
);

define!(
    #[c_ty(c_int)]
    enum AuthMode {
        /// **INSECURE** on client, default on server
        None = SSL_VERIFY_NONE,
        /// **INSECURE**
        Optional = SSL_VERIFY_OPTIONAL,
        /// default on client
        Required = SSL_VERIFY_REQUIRED,
    }
);

define!(
    #[c_ty(c_int)]
    enum UseSessionTickets {
        Enabled = SSL_SESSION_TICKETS_ENABLED,
        Disabled = SSL_SESSION_TICKETS_DISABLED,
    }
);

callback!(DbgCallback:Sync(level: c_int, file: *const c_char, line: c_int, message: *const c_char) -> ());

define!(
    #[c_ty(ssl_config)]
    struct Config<'c>;
    const init: fn() -> Self = ssl_config_init;
    const drop: fn(&mut Self) = ssl_config_free;
    impl<'q> Into<ptr> {}
    impl<'q> UnsafeFrom<ptr> {}
);

#[cfg(feature = "threading")]
unsafe impl<'c> Sync for Config<'c> {}

impl<'c> Config<'c> {
    pub fn new(e: Endpoint, t: Transport, p: Preset) -> Self {
        let mut c = Config::init();
        unsafe {
            ssl_config_defaults(&mut c.inner, e.into(), t.into(), p.into());
        }
        c
    }

    // need bitfield support getter!(endpoint() -> Endpoint = field endpoint);
    setter!(set_endpoint(e: Endpoint) = ssl_conf_endpoint);
    // need bitfield support getter!(transport() -> Transport = field transport);
    setter!(set_transport(t: Transport) = ssl_conf_transport);
    // need bitfield support getter!(authmode() -> AuthMode = field authmode);
    setter!(set_authmode(am: AuthMode) = ssl_conf_authmode);
    getter!(read_timeout() -> u32 = .read_timeout);
    setter!(set_read_timeout(t: u32) = ssl_conf_read_timeout);

    fn check_c_list<T: Default + Eq>(list: &[T]) {
        assert!(list.last() == Some(&T::default()));
    }

    pub fn set_ciphersuites(&mut self, list: &'c [c_int]) {
        Self::check_c_list(list);
        unsafe { ssl_conf_ciphersuites(&mut self.inner, list.as_ptr()) }
    }

    pub fn set_ciphersuites_for_version(&mut self, list: &'c [c_int], major: c_int, minor: c_int) {
        Self::check_c_list(list);
        unsafe { ssl_conf_ciphersuites_for_version(&mut self.inner, list.as_ptr(), major, minor) }
    }

    pub fn set_curves(&mut self, list: &'c [ecp_group_id]) {
        Self::check_c_list(list);
        unsafe { ssl_conf_curves(&mut self.inner, list.as_ptr()) }
    }

    pub fn set_min_version(&mut self, version: Version) -> Result<()> {
        let minor = match version {
            Version::Ssl3 => 0,
            Version::Tls1_0 => 1,
            Version::Tls1_1 => 2,
            Version::Tls1_2 => 3,
            _ => { return Err(Error::SslBadHsProtocolVersion); }
        };

        unsafe { ssl_conf_min_version(&mut self.inner, 3, minor) };
        Ok(())
    }

    pub fn set_max_version(&mut self, version: Version) -> Result<()> {
        let minor = match version {
            Version::Ssl3 => 0,
            Version::Tls1_0 => 1,
            Version::Tls1_1 => 2,
            Version::Tls1_2 => 3,
            _ => { return Err(Error::SslBadHsProtocolVersion); }
        };
        unsafe { ssl_conf_max_version(&mut self.inner, 3, minor) };
        Ok(())
    }

    setter!(set_cert_profile(p: &'c Profile) = ssl_conf_cert_profile);

    /// Takes both DER and PEM forms of FFDH parameters in `DHParams` format.
    ///
    /// When calling on PEM-encoded data, `params` must be NULL-terminated
    pub fn set_dh_params(&mut self, params: &[u8]) -> Result<()> {
        let mut ctx = Dhm::from_params(params)?;
        unsafe {
            ssl_conf_dh_param_ctx(&mut self.inner, (&mut ctx).into())
                .into_result()
                .map(|_| ())
        }
    }

    pub fn set_ca_list<C: Into<&'c mut LinkedCertificate>>(
        &mut self,
        list: Option<C>,
        crl: Option<&'c mut Crl>,
    ) {
        unsafe {
            ssl_conf_ca_chain(
                &mut self.inner,
                list.map(Into::into)
                    .map(Into::into)
                    .unwrap_or(::core::ptr::null_mut()),
                crl.map(Into::into).unwrap_or(::core::ptr::null_mut()),
            )
        }
    }

    pub fn push_cert<C: Into<&'c mut LinkedCertificate>>(
        &mut self,
        chain: C,
        key: &'c mut Pk,
    ) -> Result<()> {
        unsafe {
            ssl_conf_own_cert(&mut self.inner, chain.into().into(), key.into())
                .into_result()
                .map(|_| ())
        }
    }

    pub fn certs(&'c self) -> KeyCertIter<'c> {
        KeyCertIter {
            key_cert: unsafe { UnsafeFrom::from(self.inner.key_cert as *const _) },
        }
    }

    /// Server only: configure callback to use for generating/interpreting session tickets.
    pub fn set_session_tickets_callback<F: TicketCallback>(&mut self, cb: &'c mut F) {
        unsafe {
            ssl_conf_session_tickets_cb(
                &mut self.inner,
                Some(F::call_write),
                Some(F::call_parse),
                cb.data_ptr(),
            )
        };
    }

    setter!(
        /// Client only: whether to remember and use session tickets
        set_session_tickets(u: UseSessionTickets) = ssl_conf_session_tickets
    );

    setter!(
        /// Client only: minimal FFDH group size
        set_ffdh_min_bitlen(bitlen: c_uint) = ssl_conf_dhm_min_bitlen
    );

    // TODO: The lifetime restrictions on HandshakeContext here are too strict.
    // Once we need something else, we might fix it.
    pub fn set_sni_callback<F: FnMut(&mut HandshakeContext, &[u8]) -> StdResult<(), ()>>(
        &mut self,
        cb: &'c mut F,
    ) {
        unsafe extern "C" fn sni_callback<
            F: FnMut(&mut HandshakeContext, &[u8]) -> StdResult<(), ()>,
        >(
            closure: *mut c_void,
            ctx: *mut ssl_context,
            name: *const c_uchar,
            name_len: size_t,
        ) -> c_int {
            let cb = &mut *(closure as *mut F);
            let mut ctx = UnsafeFrom::from(ctx).expect("valid context");
            let name = from_raw_parts(name, name_len);
            match cb(&mut ctx, name) {
                Ok(()) => 0,
                Err(()) => -1,
            }
        }

        unsafe { ssl_conf_sni(&mut self.inner, Some(sni_callback::<F>), cb as *mut F as _) }
    }

    // The docs for mbedtls_x509_crt_verify say "The [callback] should return 0 for anything but a
    // fatal error.", so verify callbacks should return Ok(()) for anything but a fatal error.
    // Report verification errors by updating the flags in VerifyError.
    pub fn set_verify_callback<F>(&mut self, cb: &'c mut F)
    where
        F: FnMut(&mut LinkedCertificate, i32, &mut VerifyError) -> Result<()>,
    {
        unsafe extern "C" fn verify_callback<F>(
            closure: *mut c_void,
            crt: *mut x509_crt,
            depth: c_int,
            flags: *mut u32,
        ) -> c_int
        where
            F: FnMut(&mut LinkedCertificate, i32, &mut VerifyError) -> Result<()>,
        {
            let cb = &mut *(closure as *mut F);
            let crt: &mut LinkedCertificate =
                UnsafeFrom::from(crt).expect("valid certificate");
            let mut verify_error = match VerifyError::from_bits(*flags) {
                Some(ve) => ve,
                // This can only happen if mbedtls is setting flags in VerifyError that are
                // missing from our definition.
                None => return ::mbedtls_sys::ERR_X509_BAD_INPUT_DATA,
            };
            let res = cb(crt, depth, &mut verify_error);
            *flags = verify_error.bits();
            match res {
                Ok(()) => 0,
                Err(e) => e.to_int(),
            }
        }

        unsafe {
            ssl_conf_verify(
                &mut self.inner,
                Some(verify_callback::<F>),
                cb as *mut F as _,
            )
        }
    }

    pub fn set_ca_callback<F>(&mut self, cb: &'c mut F)
        where
            F: FnMut(&LinkedCertificate, &mut ForeignOwnedCertListBuilder) -> Result<()>,
    {
        unsafe extern "C" fn ca_callback<F>(
            closure: *mut c_void,
            child: *const x509_crt,
            candidate_cas: *mut *mut x509_crt
        ) -> c_int
            where
                F: FnMut(&LinkedCertificate, &mut ForeignOwnedCertListBuilder) -> Result<()>,
        {
            let cb = &mut *(closure as *mut F);
            let child: &LinkedCertificate = UnsafeFrom::from(child).expect("valid child certificate");
            let mut cert_builder = ForeignOwnedCertListBuilder::new();
            match cb(child, &mut cert_builder) {
                Ok(()) => {
                    *candidate_cas = cert_builder.to_x509_crt_ptr();
                    0
                },
                Err(e) => e.to_int(),
            }
        }

        unsafe {
            ssl_conf_ca_cb(
                &mut self.inner,
                Some(ca_callback::<F>),
                cb as *mut F as _,
            )
        }
    }
}

/// Builds a linked list of x509_crt instances, all of which are owned by mbedtls. That is, the
/// memory for these certificates has been allocated by mbedtls, on the C heap. This is needed for
/// situations in which an mbedtls function takes ownership of a list of certs. The problem with
/// handing such functions a "normal" cert list such as certificate::LinkedCertificate or
/// certificate::List, is that those lists (at least partly) consist of memory allocated on the
/// rust-side and hence cannot be freed on the c-side.
pub struct ForeignOwnedCertListBuilder {
    cert_list: *mut x509_crt,
}

impl ForeignOwnedCertListBuilder {
    pub(crate) fn new() -> Self {
        let cert_list = unsafe { calloc(1, core::mem::size_of::<x509_crt>()) } as *mut x509_crt;
        if cert_list == ::core::ptr::null_mut() {
            panic!("Out of memory");
        }
        unsafe { ::mbedtls_sys::x509_crt_init(cert_list); }

        Self {
            cert_list
        }
    }

    pub fn push_back(&mut self, cert: &LinkedCertificate) {
        self.try_push_back(cert.as_der()).expect("cert is a valid DER-encoded certificate");
    }

    pub fn try_push_back(&mut self, cert: &[u8]) -> Result<()> {
        // x509_crt_parse_der will allocate memory for the cert on the C heap
        unsafe { x509_crt_parse_der(self.cert_list, cert.as_ptr(), cert.len()) }.into_result()?;
        Ok(())
    }

    // The memory pointed to by the return value is managed by mbedtls. If the return value is
    // dropped without handing it to an mbedtls-function that takes ownership of it, that memory
    // will be leaked.
    pub(crate) fn to_x509_crt_ptr(mut self) -> *mut x509_crt {
        let res = self.cert_list;
        self.cert_list = ::core::ptr::null_mut();
        res
    }
}

impl Drop for ForeignOwnedCertListBuilder {
    fn drop(&mut self) {
        unsafe {
            ::mbedtls_sys::x509_crt_free(self.cert_list);
            free(self.cert_list as *mut c_void);
        }
    }
}

setter_callback!(Config<'c>::set_rng(f: crate::rng::Random) = ssl_conf_rng);
setter_callback!(Config<'c>::set_dbg(f: DbgCallback) = ssl_conf_dbg);

define!(
    #[c_ty(ssl_key_cert)]
    struct KeyCert;
    impl<'a> UnsafeFrom<ptr> {}
);

pub struct KeyCertIter<'a> {
    key_cert: Option<&'a KeyCert>,
}

impl<'a> Iterator for KeyCertIter<'a> {
    type Item = (certificate::Iter<'a>, &'a Pk);

    fn next(&mut self) -> Option<Self::Item> {
        self.key_cert.take().map(|key_cert| unsafe {
            self.key_cert = UnsafeFrom::from(key_cert.inner.next as *const _);
            (
                UnsafeFrom::from(key_cert.inner.cert as *const _).expect("not null"),
                UnsafeFrom::from(key_cert.inner.key as *const _).expect("not null"),
            )
        })
    }
}

// TODO
// ssl_conf_export_keys_cb
// ssl_conf_dtls_cookies
// ssl_conf_dtls_anti_replay
// ssl_conf_dtls_badmac_limit
// ssl_conf_handshake_timeout
// ssl_conf_session_cache
// ssl_conf_psk
// ssl_conf_psk_cb
// ssl_conf_sig_hashes
// ssl_conf_alpn_protocols
// ssl_conf_fallback
// ssl_conf_encrypt_then_mac
// ssl_conf_extended_master_secret
// ssl_conf_arc4_support
// ssl_conf_max_frag_len
// ssl_conf_truncated_hmac
// ssl_conf_cbc_record_splitting
// ssl_conf_renegotiation
// ssl_conf_legacy_renegotiation
// ssl_conf_renegotiation_enforced
// ssl_conf_renegotiation_period
//
