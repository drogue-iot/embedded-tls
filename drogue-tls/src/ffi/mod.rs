use drogue_tls_sys::types::c_char;
use heapless::{ArrayLength, Vec};

pub(crate) struct CStr<N: ArrayLength<c_char>> {
    vec: Vec<c_char, N>,
}

impl<N: ArrayLength<c_char>> CStr<N> {
    pub(crate) fn new(str: &str) -> Self {
        let mut vec: Vec<c_char, N> = Vec::from_slice(&str.as_bytes()).unwrap();
        vec.push(0u8).unwrap();
        Self { vec }
    }

    pub(crate) fn c_str(&self) -> *const c_char {
        let slice: &[u8] = self.vec.as_ref();
        slice.as_ptr()
    }
}
