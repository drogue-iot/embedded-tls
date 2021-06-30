use crate::buffer::*;
use core::fmt::{Debug, Formatter};

pub struct ApplicationData<'a> {
    pub(crate) header: [u8; 5],
    pub(crate) data: CryptoBuffer<'a>,
}

impl<'a> Debug for ApplicationData<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "ApplicationData {:x?}", self.data.len())
    }
}

impl<'a> ApplicationData<'a> {
    pub fn new(rx_buf: CryptoBuffer<'a>, header: [u8; 5]) -> ApplicationData<'a> {
        Self {
            header,
            data: rx_buf,
        }
    }
}