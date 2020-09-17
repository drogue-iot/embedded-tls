use drogue_tls_sys::{
    ssl_context, ssl_init, ssl_set_hostname, ssl_setup, ERR_SSL_ALLOC_FAILED, ERR_SSL_BAD_INPUT_DATA,
};


use crate::ffi::CStr;
use crate::platform::strlen;
use core::ptr::slice_from_raw_parts;
use core::str::from_utf8;
use drogue_tls_sys::types::c_char;
use heapless::consts::*;
use crate::ssl::config::SslConfig;

pub struct SslContext(ssl_context);

#[derive(Debug)]
pub enum HostnameError {
    AllocFailed,
    BadInputData,
    Unknown,
}

impl SslContext {
    pub(crate) fn inner(&self) -> *const ssl_context {
        &self.0
    }

    pub(crate) fn inner_mut(&mut self) -> *mut ssl_context {
        &mut self.0
    }

    pub fn new() -> Self {
        let mut ctx = ssl_context::default();
        unsafe { ssl_init(&mut ctx) };
        Self(ctx)
    }

    pub fn setup(&mut self, config: &SslConfig) -> Result<(), ()> {
        let result = unsafe {
            ssl_setup(self.inner_mut(), config.inner())
        };

        if result != 0 {
            Err(())
        } else {
            Ok(())
        }
    }

    pub fn set_hostname(&mut self, hostname: &str) -> Result<(), HostnameError> {
        let hostname_cstr: CStr<U255> = CStr::new(hostname);
        match unsafe { ssl_set_hostname(self.inner_mut(), hostname_cstr.c_str()) } {
            0 => Ok(()),
            ERR_SSL_BAD_INPUT_DATA => Err(HostnameError::BadInputData),
            ERR_SSL_ALLOC_FAILED => Err(HostnameError::AllocFailed),
            _ => Err(HostnameError::Unknown),
        }
    }

    pub fn get_hostname(&self) -> &str {
        let str: *const c_char = unsafe { (*self.inner()).hostname };
        let slice = unsafe { &(*slice_from_raw_parts(str, strlen(str))) };
        from_utf8(slice).unwrap()
    }
}

impl Default for SslContext {
    fn default() -> Self {
        Self::new()
    }
}
