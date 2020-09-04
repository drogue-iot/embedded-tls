use core::any::Any;
use drogue_tls_sys::entropy_source_state;
use drogue_tls_sys::types::{c_void, c_int, c_uchar};

pub type entropy_f = unsafe extern "C" fn(
    data: *mut c_void,
    output: *mut c_uchar,
    len: usize,
    olen: *mut usize,
) -> c_int;

pub trait EntropySource
{
    fn get_f(&self) -> entropy_f;
}

pub struct StaticEntropySource;

impl EntropySource for StaticEntropySource {
    fn get_f(&self) -> entropy_f {
        f_source
    }
}

extern "C" fn f_source(data: *mut c_void, output: *mut c_uchar, len: usize, olen: *mut usize) -> c_int {
    log::info!("asking for entropy");
    for n in 0..len {
        unsafe {
            *output.offset(n as isize) = b'A';
        }
    }
    unsafe { *olen = len };
    log::info!("provided {}", unsafe{ *olen } );
    0
}



