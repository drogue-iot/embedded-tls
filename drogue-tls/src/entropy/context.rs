use crate::entropy::EntropySource;
use drogue_tls_sys::types::c_int;
use drogue_tls_sys::{entropy_add_source, entropy_context, entropy_init, ENTROPY_SOURCE_STRONG};

pub struct EntropyContext(entropy_context);

impl EntropyContext {
    pub(crate) fn inner(&self) -> *const entropy_context {
        &self.0
    }

    pub(crate) fn inner_mut(&mut self) -> *mut entropy_context {
        &mut self.0
    }

    pub fn new() -> Self {
        let mut ctx = entropy_context::default();
        unsafe { entropy_init(&mut ctx) };
        Self(ctx)
    }

    pub fn add_source<E>(&mut self, source: E)
    where
        E: EntropySource,
    {
        unsafe {
            entropy_add_source(
                self.inner_mut(),
                Some(source.get_f()),
                0 as _,
                0,
                ENTROPY_SOURCE_STRONG as c_int,
            )
        };
    }
}

impl Default for EntropyContext {
    fn default() -> Self {
        Self::new()
    }
}
