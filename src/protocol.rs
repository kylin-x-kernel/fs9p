//! 9P protocol constants and data types.

/// Special values used by the protocol.
pub const NO_FID: u32 = 0xFFFF_FFFF;
pub const NO_TAG: u16 = 0xFFFF;

pub const TVERSION: u8 = 100;
pub const RVERSION: u8 = 101;
pub const TATTACH: u8 = 104;
pub const RATTACH: u8 = 105;
pub const RERROR: u8 = 107;
pub const RLERROR: u8 = 7;
pub const TWALK: u8 = 110;
pub const RWALK: u8 = 111;
pub const TOPEN: u8 = 112;
pub const ROPEN: u8 = 113;
pub const TCREATE: u8 = 114;
pub const RCREATE: u8 = 115;
pub const TREAD: u8 = 116;
pub const RREAD: u8 = 117;
pub const TWRITE: u8 = 118;
pub const RWRITE: u8 = 119;
pub const TCLUNK: u8 = 120;
pub const RCLUNK: u8 = 121;
pub const TLOPEN: u8 = 12;
pub const RLOPEN: u8 = 13;
pub const TREADDIR: u8 = 40;
pub const RREADDIR: u8 = 41;

pub const OREAD: u8 = 0;
#[allow(dead_code)]
pub const OWRITE: u8 = 1;
#[allow(dead_code)]
pub const ORDWR: u8 = 2;

pub const DMDIR: u32 = 0x8000_0000;

pub const DEFAULT_MSIZE: u32 = 16384;

/// Qid identifies a file within a 9P server.
#[derive(Clone, Copy, Debug)]
pub struct Qid {
    pub(crate) type_: u8,
    pub(crate) _version: u32,
    pub(crate) _path: u64,
}
