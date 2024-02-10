use sha2::{Sha256, Digest};

fn main() {
    //Create object to sha256
    let mut sha2 = Sha256::new();
    // input is in bytes
    let inp1 = b"your name";
    // call update
    sha2.update(inp1);
    // append more data
    sha2.update("your email");
    // Finalize
    let sha = sha2.finalize();
    println!("Binary hash: {:?}", sha);
}
