use crate::entropy::EntropyContext;
use drogue_tls_sys::{ctr_drbg_context, ctr_drbg_init, ctr_drbg_seed, entropy_func};

pub struct CtrDrbgContext(ctr_drbg_context);

impl CtrDrbgContext {
    pub(crate) fn inner(&self) -> *const ctr_drbg_context {
        &self.0
    }

    pub(crate) fn inner_mut(&mut self) -> *mut ctr_drbg_context {
        &mut self.0
    }

    pub fn new() -> Self {
        let mut ctx = ctr_drbg_context::default();
        unsafe {
            ctr_drbg_init(&mut ctx);
        }
        Self(ctx)
    }

    pub fn seed(&mut self, entropy: &mut EntropyContext) -> Result<(), ()> {
        let result = unsafe {
            ctr_drbg_seed(
                &mut self.0,
                Some(entropy_func),
                entropy.inner_mut() as *mut _,
                core::ptr::null(),
                0,
            )
        };

        if result == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Default for CtrDrbgContext {
    fn default() -> Self {
        Self::new()
    }
}
