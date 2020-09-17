#![allow(non_camel_case_types)]
#![allow(dead_code)]

pub type int8_t = i8;
pub type int16_t = i16;
pub type int32_t = i32;
pub type int64_t = i64;
pub type uint8_t = u8;
pub type uint16_t = u16;
pub type uint32_t = u32;
pub type uint64_t = u64;
pub type size_t = usize;
pub type ssize_t = isize;
pub type intptr_t = isize;
pub type uintptr_t = usize;
pub type ptrdiff_t = isize;

pub use raw_types::*;

pub mod raw_types {
    //pub type c_char = i8;
    pub type c_char = u8;
    pub type c_schar = i8;
    pub type c_uchar = u8;

    pub type c_int = i32;
    pub type c_uint = u32;

    pub type c_long = i32;
    pub type c_ulong = u32;

    pub type c_longlong = i64;
    pub type c_ulonglong = u64;

    pub type c_void = core::ffi::c_void;
    pub type va_list = drogue_ffi_compat::va_list;
    /*
    #[repr(u8)]
    pub enum c_void {
        #[doc(hidden)]
        __variant1,
        #[doc(hidden)]
        __variant2,
    }
     */
}

