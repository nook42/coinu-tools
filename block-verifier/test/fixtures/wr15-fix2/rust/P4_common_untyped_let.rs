fn verify_child(vkey: &[u32; 8]) -> i32 { vkey[0] as i32 * 16 + vkey[7] as i32 }
fn common_main(child_vkey: [u32; 8], child_vkey_unset: [u32; 8]) -> i32 {
    assert_ne!(child_vkey, child_vkey_unset, "child vkey not pinned");
    let child_vkey = [9u32; 8];
    verify_child(&child_vkey)
}
pub fn main() {
    std::process::exit(common_main([1, 2, 3, 4, 5, 6, 7, 8], [0; 8]));
}
