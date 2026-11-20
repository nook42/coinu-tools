type W = [u32; 8];
const BIND_VKEY: W = [1, 2, 3, 4, 5, 6, 7, 8];
fn verify_child(vkey: &[u32; 8]) -> i32 { vkey[0] as i32 * 16 + vkey[7] as i32 }
pub fn main() {
    std::process::exit(verify_child(&BIND_VKEY));
}
