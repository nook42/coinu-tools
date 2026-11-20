const BIND_VKEY: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
fn verify_child(vkey: &[u32; 8]) -> i32 { vkey[0] as i32 * 16 + vkey[7] as i32 }
pub fn main() {
    struct BIND_VKEY;
    impl core::ops::Deref for BIND_VKEY {
        type Target = [u32; 8];
        fn deref(&self) -> &[u32; 8] { &[9; 8] }
    }
    std::process::exit(verify_child(&BIND_VKEY));
}
