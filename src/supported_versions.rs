use heapless::Vec;

pub type ProtocolVersion = u16;
pub type ProtocolVersions = Vec<ProtocolVersion, 16>;

pub const TLS13: ProtocolVersion = 0x0304;
