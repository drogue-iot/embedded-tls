#![no_std]
#![allow(dead_code)]

pub mod types;
pub mod bindings;
pub use bindings::*;

pub const ECDSA_MAX_LEN: u32 = 3 + 2 * ( 2 + 66 );

