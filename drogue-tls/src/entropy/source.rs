use drogue_tls_sys::types::{c_int, c_uchar, c_void};

#[allow(non_camel_case_types)]
pub type entropy_f = unsafe extern "C" fn(
    data: *mut c_void,
    output: *mut c_uchar,
    len: usize,
    olen: *mut usize,
) -> c_int;

pub trait EntropySource {
    fn get_f(&self) -> entropy_f;
}

pub struct StaticEntropySource;

impl EntropySource for StaticEntropySource {
    fn get_f(&self) -> entropy_f {
        f_source
    }
}

extern "C" fn f_source(
    _data: *mut c_void,
    output: *mut c_uchar,
    len: usize,
    olen: *mut usize,
) -> c_int {
    for n in 0..len {
        unsafe {
            *output.add(n) = b'A';
        }
    }
    unsafe { *olen = len };
    0
}
