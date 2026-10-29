use base64::{engine::general_purpose::STANDARD, Engine as _};
use hex_literal::hex;
// hexa decimal to byte
fn main() {
    let data: Vec<u8> = vec![1,2,3,4,5];
    println!("{}", STANDARD.encode(&data));

    let data: [u8; 4] = hex!("01020304");
    println!("{:?}", data);
}
