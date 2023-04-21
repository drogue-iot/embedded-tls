/// Maximum plaintext fragment length
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MaxFragmentLength {
    /// 512 bytes
    Bits9 = 1,
    /// 1024 bytes
    Bits10 = 2,
    /// 2048 bytes
    Bits11 = 3,
    /// 4096 bytes
    Bits12 = 4,
}
