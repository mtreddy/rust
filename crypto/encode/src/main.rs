extern crate base64;
use hex_literal::hex;
// hexa decimal to byte
fn main() {
    let data: Vec<u8> = vec![1,2,3,4,5];
    println!("{}", base64::encode(&data));

    let data: [u8; 4] = hex!("01020304");
}
