mod alloc;
mod cortex_m_alloc;

use crate::platform::alloc::layout::Layout;
use crate::platform::cortex_m_alloc::CortexMHeap;
use drogue_tls_sys::{platform_set_calloc_free, platform_set_vsnprintf, platform_set_snprintf};
use drogue_tls_sys::types::{c_char, c_int};
use core::ffi::c_void;
use crate::entropy::EntropyContext;
use crate::rng::ctr_drbg::CtrDrbgContext;
use crate::ssl::config::{SslConfig, Transport, Preset};

use drogue_ffi_compat::{vsnprintf, snprintf};
use core::mem::size_of;

static mut ALLOCATOR: Option<CortexMHeap> = Option::None;

pub struct SslPlatform {
    entropy_context: EntropyContext,
    ctr_drbg_context: CtrDrbgContext,
}

extern "C" {
    fn platform_snprintf(s: *mut c_char,
                         n: usize,
                         format: *const c_char,
                         ...) -> c_int;
}

impl SslPlatform {
    pub fn setup(start: usize, size: usize) -> Option<Self> {
        unsafe {
            platform_set_vsnprintf(Some(vsnprintf));
            platform_set_snprintf(Some(snprintf));
            if ALLOCATOR.is_some() {
                // Allocator already setup, only a singleton of the SslPlatform
                // is allowed, someone else has it.
                return None;
            }
        }
        let heap = CortexMHeap::empty();
        unsafe {
            heap.init(start, size);
            ALLOCATOR.replace(heap);
        }
        unsafe { platform_set_calloc_free(Some(platform_calloc_f), Some(platform_free_f)) };
        Some(Self {
            entropy_context: EntropyContext::default(),
            ctr_drbg_context: CtrDrbgContext::default(),
        })
    }

    pub fn entropy_context(&self) -> &EntropyContext {
        &self.entropy_context
    }

    pub fn entropy_context_mut(&mut self) -> &mut EntropyContext {
        &mut self.entropy_context
    }

    pub fn seed_rng(&mut self) -> Result<(), ()> {
        self.ctr_drbg_context.seed(&mut self.entropy_context)
    }

    pub fn new_client_config(&mut self, transport: Transport, preset: Preset) -> Result<SslConfig, ()> {
        let mut config = SslConfig::client(transport, preset)?;
        config.rng(&mut self.ctr_drbg_context);
        Ok(config)
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn strlen(p: *const c_char) -> usize {
    let mut n = 0;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

extern "C" fn platform_calloc_f(count: usize, size: usize) -> *mut c_void {
    let requested_size = count * size;
    let header_size = 2 * size_of::<usize>();
    let total_size = header_size + requested_size;
    let layout = Layout::from_size_align(total_size, 4)
        .unwrap()
        .pad_to_align();

    unsafe {
        if let Some(ref alloc) = ALLOCATOR {
            let mut ptr = alloc.alloc(layout) as *mut usize;
            if ptr.is_null() {
                log::error!("failed to allocate {} from {}", requested_size, alloc.free());
                return core::ptr::null_mut();
            }
            *ptr = layout.size();
            ptr = ptr.add(1);
            *ptr = layout.align();
            ptr = ptr.add(1);
            let mut zeroing = ptr as *mut u8;
            for _ in 0..requested_size {
                zeroing.write(0);
                zeroing = zeroing.add(1);
            }
            ptr as *mut c_void
        } else {
            log::error!("No allocator");
            core::ptr::null_mut::<c_void>()
        }
    }
}

extern "C" fn platform_free_f(ptr: *mut c_void) {
    if ptr as u32 == 0  {
        return
    }
    unsafe {
        if let Some(ref alloc) = ALLOCATOR {
            let mut ptr = ptr as *mut usize;
            ptr = ptr.offset(-1);
            let align = *ptr;
            ptr = ptr.offset(-1);
            let size = *ptr;
            alloc.dealloc(
                ptr as *mut u8,
                Layout::from_size_align(size, align).unwrap(),
            );
        }
    }
}

