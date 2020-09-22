use drogue_tls_sys::{ctr_drbg_random, ssl_conf_dbg, ssl_conf_rng, ssl_config_defaults, SSL_VERIFY_NONE, SSL_VERIFY_OPTIONAL, SSL_VERIFY_REQUIRED, SSL_VERIFY_UNSET, debug_set_threshold};

#[derive(Copy, Clone)]
pub enum Verify {
    None = SSL_VERIFY_NONE as isize,
    Optional = SSL_VERIFY_OPTIONAL as isize,
    Required = SSL_VERIFY_REQUIRED as isize,
    Unset = SSL_VERIFY_UNSET as isize,
}

use drogue_tls_sys::{SSL_IS_CLIENT, SSL_IS_SERVER};

pub enum Endpoint {
    Server = SSL_IS_SERVER as isize,
    Client = SSL_IS_CLIENT as isize,
}

use drogue_tls_sys::{SSL_TRANSPORT_DATAGRAM, SSL_TRANSPORT_STREAM};

pub enum Transport {
    Stream = SSL_TRANSPORT_STREAM as isize,
    Datagram = SSL_TRANSPORT_DATAGRAM as isize,
}

use drogue_tls_sys::{SSL_PRESET_DEFAULT, SSL_PRESET_SUITEB};

pub enum Preset {
    Default = SSL_PRESET_DEFAULT as isize,
    SuiteB = SSL_PRESET_SUITEB as isize,
}

use crate::rng::ctr_drbg::CtrDrbgContext;
use drogue_tls_sys::types::{c_char, c_int, c_void};
use drogue_tls_sys::{ssl_conf_authmode, ssl_config, ssl_config_free, ssl_config_init};

pub struct SslConfig(ssl_config);

impl SslConfig {
    pub(crate) fn inner(&self) -> &ssl_config {
        &self.0
    }

    pub(crate) fn inner_mut(&mut self) -> &mut ssl_config {
        &mut self.0
    }

    pub(crate) fn client(transport: Transport, preset: Preset) -> Result<Self, ()> {
        Self::new(Endpoint::Client, transport, preset)
    }

    pub(crate) fn server(transport: Transport, preset: Preset) -> Result<Self, ()> {
        Self::new(Endpoint::Server, transport, preset)
    }

    fn new(endpoint: Endpoint, transport: Transport, preset: Preset) -> Result<Self, ()> {
        let mut cfg = ssl_config::default();
        unsafe { ssl_config_init(&mut cfg) };
        let result = unsafe {
            ssl_config_defaults(
                &mut cfg,
                endpoint as c_int,
                transport as c_int,
                preset as c_int,
            )
        };

        unsafe {
            debug_set_threshold(4);
            ssl_conf_dbg(&mut cfg, Some(debug), 0 as _);
        }

        if result == 0 {
            Ok(Self(cfg))
        } else {
            Err(())
        }
    }

    pub fn authmode(&mut self, auth_mode: Verify) -> &mut Self {
        unsafe { ssl_conf_authmode(self.inner_mut(), auth_mode as c_int); }
        self
    }

    pub(crate) fn rng(&mut self, rng_ctx: &mut CtrDrbgContext) -> &mut Self {
        unsafe {
            ssl_conf_rng(
                self.inner_mut(),
                Some(ctr_drbg_random),
                rng_ctx.inner_mut() as *mut _,
            );
        }
        self
    }

    pub fn free(mut self) {
        unsafe { ssl_config_free(&mut self.0) };
    }

    pub fn new_context(&mut self) -> Result<SslContext,()> {
        let mut context = SslContext::default();
        context.setup(self)?;
        Ok(context)
    }
}

use core::str::{from_utf8, Utf8Error};
use crate::ssl::context::SslContext;

unsafe extern "C" fn debug(
    _context: *mut c_void,
    level: c_int,
    file_name: *const c_char,
    line: c_int,
    message: *const c_char,
) {
    let file_name = to_str(&file_name).unwrap();
    let message = to_dbg_str(message);
    match level {
        1 => {
            log::error!("{}:{}:{}", file_name, line, message);
        }
        2 => {
            log::debug!("{}:{}:{}", file_name, line, message);
        }
        3 => {
            log::debug!("{}:{}:{}", file_name, line, message);
        }
        4 => {
            log::trace!("{}:{}:{}", file_name, line, message);
        }
        _ => {}
    }
}

use heapless::consts::U512;

fn to_dbg_str(str: *const c_char) -> heapless::String<U512> {
    unsafe {
        let len = strlen(str);
        let str = core::slice::from_raw_parts(str, len);
        let mut str_o = heapless::String::new();
        for b in str.iter() {
            str_o.push(*b as char).unwrap();
        }
        str_o
    }
}

fn to_str(str: &*const c_char) -> Result<&str, Utf8Error> {
    unsafe {
        let len = strlen(*str);
        //let str = *str as *const u8;
        let str = core::slice::from_raw_parts(*str, len);
        from_utf8(str)
    }
}

#[inline]
unsafe fn strlen(p: *const c_char) -> usize {
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    n
}
