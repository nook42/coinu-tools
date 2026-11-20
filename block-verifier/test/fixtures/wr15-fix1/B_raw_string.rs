const R: &str = r#"x"y"#; // const BIND_VKEY: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const S: &str = " // "; const BIND_VKEY: [u32; 8] = [9, 9, 9, 9, 9, 9, 9, 9];
#[allow(dead_code)] fn _u() { let _ = (R, S); }
fn main() { println!("{:?}", BIND_VKEY); }
