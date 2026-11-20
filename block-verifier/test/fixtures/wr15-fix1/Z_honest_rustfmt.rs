const BIND_VKEY_UNSET: [u32; 8] = [0u32; 8];
const BIND_VKEY: [u32; 8] = [
    0x0000_0001,
    2,
    3u32,
    0x4,
    5,
    6,
    7,
    8, // trailing
];
#[cfg(feature = "measurement-only")]
const BIND_MEASUREMENT_VKEY: [u32; 8] = [0x4249_4e44, 0, 0, 0, 0, 0, 0, 1];
fn main() { let _ = BIND_VKEY; }
