// AES-256-GCM: authenticated encryption (confidentiality + integrity).
//
// Inputs:  key (32 bytes), nonce (12 bytes, MUST be unique per key),
//          plaintext, optional AAD (authenticated but not encrypted)
// Output:  ciphertext || 16-byte auth tag
//
// Decryption fails if the key, nonce, ciphertext, tag or AAD were changed.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

fn main() {
    // Generate a random 256-bit key
    let key = Aes256Gcm::generate_key(OsRng);
    println!("key:        {}", hex::encode(key));
    let cipher = Aes256Gcm::new(&key);

    // Random 96-bit nonce; never reuse a nonce with the same key
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    println!("nonce:      {}", hex::encode(nonce));

    // 1. Basic encrypt / decrypt
    let plaintext = b"your name";
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).expect("encrypt");
    // Last 16 bytes are the auth tag
    println!("ciphertext: {}", hex::encode(&ciphertext));

    let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).expect("decrypt");
    println!("decrypted:  {}", String::from_utf8_lossy(&decrypted));

    // 2. Tampering with the ciphertext is detected
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 1;
    println!("tampered ciphertext decrypts: {}", cipher.decrypt(&nonce, tampered.as_ref()).is_ok());

    // 3. Associated data (AAD): e.g. a header that must stay readable but untampered
    let nonce2 = Aes256Gcm::generate_nonce(&mut OsRng);
    let aad = b"user-id:42";
    let ct = cipher
        .encrypt(&nonce2, Payload { msg: b"your email", aad })
        .expect("encrypt with aad");
    let ok = cipher.decrypt(&nonce2, Payload { msg: &ct, aad });
    let bad = cipher.decrypt(&nonce2, Payload { msg: &ct, aad: b"user-id:43" });
    println!("aad match decrypts:    {}", ok.is_ok());
    println!("aad mismatch decrypts: {}", bad.is_ok());

    // 4. Using a fixed key / nonce from bytes (e.g. loaded from config or a KDF like PBKDF2)
    let key_bytes = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, b"fixed key demo".as_ref()).expect("encrypt");
    println!("fixed-key ciphertext: {}", hex::encode(&ct));
}
