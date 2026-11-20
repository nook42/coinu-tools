#[cfg(any())] pub const BIND_VKEY: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
mod m { pub const MAL: [u32; 8] = [9, 9, 9, 9, 9, 9, 9, 9]; }
use m::MAL as BIND_VKEY;
fn main() { println!("{:?}", BIND_VKEY); }
