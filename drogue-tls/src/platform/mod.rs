//dd#[inline]

mod alloc;
mod cortex_alloc;

use drogue_tls_sys::types::{c_char, c_void};
use drogue_tls_sys::{platform_set_calloc_free};
use crate::platform::cortex_alloc::CortexMHeap;
use crate::platform::alloc::layout::Layout;

#[no_mangle]
pub extern "C" fn strlen(p: *const c_char) -> usize {
    let mut n = 0;
    unsafe {
        while *p.offset(n as isize) != 0 {
            n += 1;
        }
    }
    log::info!("strlen = {}", n);
    n
}

//use self::alloc::CortexMHeap;

//static ALLOCATOR: CortexMHeap = CortexMHeap::empty();
static mut ALLOCATOR: Option<CortexMHeap> = Option::None;

pub fn setup_platform(start: usize, size: usize) {
    let mut heap = CortexMHeap::empty();
    unsafe {
        heap.init(start, size);
        ALLOCATOR.replace(heap);
    }
    unsafe { platform_set_calloc_free(Some(platform_calloc_f), Some(platform_free_f)) };
}


extern "C" fn platform_calloc_f(count: usize, size: usize) -> *mut c_void {
    unsafe {
        if let Some(ref alloc) = ALLOCATOR {
            let requested_size = count * size;
            let header_size = 2 * 4;
            let total_size = header_size + requested_size;
            let layout = Layout::from_size_align(total_size, 4).unwrap().pad_to_align();
            log::info!("calloc {} ({}+({}*{})) from free: {} used: {} -- {}",
                total_size,
                header_size,
                count,
                size,
                alloc.free(),
                alloc.used(),
                layout.size());

            let mut ptr = alloc.alloc(layout) as *mut usize;
            *ptr = layout.size();
            ptr = ptr.offset(1);
            *ptr = layout.align();
            ptr = ptr.offset(1);
            ptr as *mut c_void
            //0 as *mut c_void
        } else {
            0 as *mut c_void
        }
    }
}

extern "C" fn platform_free_f(ptr: *mut c_void) {
    unsafe {
        if let Some(ref alloc) = ALLOCATOR {
            let mut ptr = ptr as *mut usize;
            ptr = ptr.offset(-1);
            let align = *ptr;
            ptr = ptr.offset( -1 );
            let size = *ptr;
            alloc.dealloc( ptr as *mut u8, Layout::from_size_align(size, align).unwrap());
        }
    }
    log::info!("free {}", ptr as u32);
}