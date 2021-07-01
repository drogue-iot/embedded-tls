#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MaxFragmentLength {
    Bits9 = 1,
    Bits10 = 2,
    Bits11 = 3,
    Bits12 = 4,
}
