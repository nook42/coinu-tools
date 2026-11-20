macro_rules ! mk { ($n:ident) => { const $n: [u32; 8] = [9; 8]; } }
mk!(BIND_VKEY);
#[allow(dead_code)]
fn _shadow() -> [u32; 8] { const BIND_VKEY: [u32; 8] = [1, 2, 3, 4, 5, 6, 7, 8]; BIND_VKEY }

fn main() { println!("{:?}", BIND_VKEY); }
