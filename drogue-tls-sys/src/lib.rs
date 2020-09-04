#![allow(clippy::redundant_static_lifetimes)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![no_std]

pub mod types;
pub mod bindings;
pub use bindings::*;
//include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub const ECDSA_MAX_LEN: u32 = 3 + 2 * ( 2 + 66 );

