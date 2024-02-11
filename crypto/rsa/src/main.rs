use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rand::Rng;
use data_encoding::HEXUPPER;
fn main() {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let pr = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate key");
    let pb = RsaPublicKey::from(&pr);

    //Encrypt
    let data = b"Rsa test";
    let enc_data = pb.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("Failed to encrypt");
    let dec_data = pr.decrypt(Pkcs1v15Encrypt, &enc_data).expect("Failed to decrypt");
    println!("{}", HEXUPPER.encode(&dec_data));

}
