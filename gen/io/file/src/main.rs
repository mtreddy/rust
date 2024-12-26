use std::env;
use std::fs;
// To run: cargo run print test.txt
fn main() {
    let args: Vec<String> = env::args().collect();
    let query = &args[1];
    let fpath = &args[2];
    let cont = fs::read_to_string(fpath).expect("Should be able to read file contents");
    println!("Text:{cont}")
}
