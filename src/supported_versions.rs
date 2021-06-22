use heapless::{consts::*, Vec};

pub type ProtocolVersion = u16;
pub type ProtocolVersions = Vec<ProtocolVersion, U16>;

pub const TLS13: ProtocolVersion = 0x0304;
