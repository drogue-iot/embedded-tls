use drogue_tls_sys::{ssl_context, ssl_init, ssl_set_hostname};

use heapless::{
    String,
    ArrayLength,
    consts::*,
};
use core::fmt::Write;
use drogue_tls_sys::types::c_char;
use crate::ffi::CStr;
use core::ptr::slice_from_raw_parts;
use crate::platform::strlen;
use core::str::from_utf8;

pub struct SslContext(
    ssl_context
);

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

    pub fn set_hostname(&mut self, hostname: &str) {
        let hostname_cstr: CStr<U255> = CStr::new(hostname);
        let result = unsafe {
            ssl_set_hostname(
                self.inner_mut(),
                hostname_cstr.c_str()
            )
        };
    }

    pub fn get_hostname(&self) -> &str {
       let str: *const c_char = unsafe { (*self.inner()).hostname };
        let slice = unsafe { &(*slice_from_raw_parts( str, strlen(str))) };
        from_utf8(slice ).unwrap()
    }
}

