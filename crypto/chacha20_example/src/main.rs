// ChaCha20 (RFC 8439): a stream cipher built only from add, rotate and xor
// ("ARX"). Fast in software, constant-time by design, no lookup tables,
// so it is the usual alternative to AES on CPUs without AES hardware.
//
// State: 16 x u32 words
//   [ "expa" "nd 3" "2-by" "te k" ]   constants
//   [ key0   key1   key2   key3   ]   256-bit key
//   [ key4   key5   key6   key7   ]
//   [ counter nonce0 nonce1 nonce2 ]  32-bit block counter, 96-bit nonce
//
// block(counter) = state + 20 rounds(state)  -> 64 bytes of keystream
// ciphertext     = plaintext XOR keystream
//
// ChaCha20 alone only gives confidentiality. ChaCha20-Poly1305 adds a
// Poly1305 tag for integrity, like AES-GCM. Use that in practice.

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

// ---------- 1. ChaCha20 from scratch ----------

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let word = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]); // "expand 32-byte k"
    for i in 0..8 {
        init[4 + i] = word(&key[4 * i..4 * i + 4]);
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = word(&nonce[4 * i..4 * i + 4]);
    }

    let mut s = init;
    for _ in 0..10 {
        // column rounds
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        // diagonal rounds
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }

    // Adding the input back makes the block function non-invertible.
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

/// Encrypt or decrypt (same operation) starting at block `counter`.
fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    data.chunks(64)
        .enumerate()
        .flat_map(|(i, chunk)| {
            let ks = block(key, counter + i as u32, nonce);
            chunk.iter().zip(ks).map(|(b, k)| b ^ k).collect::<Vec<_>>()
        })
        .collect()
}

fn main() {
    // RFC 8439 section 2.4.2 test vector
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let nonce = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    println!("== 1. ChaCha20 from scratch ==");
    let ct = chacha20_xor(&key, 1, &nonce, plaintext);
    println!("ciphertext: {}", hex::encode(&ct));
    println!("decrypts:   {}", String::from_utf8_lossy(&chacha20_xor(&key, 1, &nonce, &ct)));

    println!("\n== 2. chacha20 crate (raw stream cipher) ==");
    let mut buf = plaintext.to_vec();
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.seek(64u32); // start at block counter 1, as the RFC vector does
    cipher.apply_keystream(&mut buf);
    println!("matches from-scratch version: {}", buf == ct);
    // No integrity: flipping a ciphertext bit silently flips the same plaintext bit.
    buf[0] ^= 0x01;
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.seek(64u32);
    cipher.apply_keystream(&mut buf);
    println!("tampered decrypts to:         {:?} (no error!)", String::from_utf8_lossy(&buf[..20]));

    println!("\n== 3. ChaCha20-Poly1305 (AEAD) ==");
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let aead = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bit, never reuse with the same key
    let aad = b"header: v1";
    let ct = aead.encrypt(&nonce, Payload { msg: b"your name", aad }).expect("encrypt");
    println!("ciphertext + 16-byte tag: {}", hex::encode(&ct));
    let pt = aead.decrypt(&nonce, Payload { msg: &ct, aad }).expect("decrypt");
    println!("decrypted:                {}", String::from_utf8_lossy(&pt));
    let mut tampered = ct.clone();
    tampered[0] ^= 1;
    println!("tampered ciphertext ok:   {}", aead.decrypt(&nonce, Payload { msg: &tampered, aad }).is_ok());
    println!("wrong aad ok:             {}", aead.decrypt(&nonce, Payload { msg: &ct, aad: b"header: v2" }).is_ok());

    println!("\n== 4. XChaCha20-Poly1305 (192-bit nonce) ==");
    // A 24-byte nonce is large enough to pick at random for every message
    // without worrying about collisions, which makes nonce handling much simpler.
    let xaead = XChaCha20Poly1305::new(&XChaCha20Poly1305::generate_key(&mut OsRng));
    let xnonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = xaead.encrypt(&xnonce, b"your email".as_ref()).expect("encrypt");
    println!("nonce: {} ({} bytes)", hex::encode(xnonce), xnonce.len());
    println!("decrypted: {}", String::from_utf8_lossy(&xaead.decrypt(&xnonce, ct.as_ref()).expect("decrypt")));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_block_vector() {
        // RFC 8439 section 2.3.2
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let nonce = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let expected = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
                        d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
        assert_eq!(hex::encode(block(&key, 1, &nonce)), expected);
    }

    #[test]
    fn matches_crate_on_multiple_blocks() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let data: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let mut expected = data.clone();
        ChaCha20::new(&key.into(), &nonce.into()).apply_keystream(&mut expected);
        assert_eq!(chacha20_xor(&key, 0, &nonce, &data), expected);
    }
}
