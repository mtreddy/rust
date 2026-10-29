// AES modes of operation demo: ECB, CBC, CFB, OFB, CTR.
// The modes are implemented by hand in modes.rs (see the diagrams there);
// this file shows what each one looks like in practice and where each one breaks.

mod modes;

use aes::cipher::KeyInit;
use aes::Aes256;
use modes::*;
use rand::{rngs::OsRng, RngCore};

fn random_block() -> Block {
    let mut b = [0u8; BLOCK];
    OsRng.fill_bytes(&mut b);
    b
}

/// Print ciphertext one 16-byte block per line so repeated blocks are easy to spot.
fn show_blocks(label: &str, data: &[u8]) {
    println!("{label}:");
    for (i, b) in data.chunks(BLOCK).enumerate() {
        println!("  block {i}: {}", hex::encode(b));
    }
}

fn main() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let aes = Aes256::new(&key.into());

    // Three identical 16-byte blocks, like a repeated pattern in an image or file.
    let repeated = b"ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!";

    println!("== ECB: identical blocks leak ==");
    let ct = ecb_encrypt(&aes, repeated);
    show_blocks("ECB ciphertext", &ct);
    // Block 3 is pure PKCS#7 padding (16 x 0x10), since 48 is already a multiple of 16.
    assert_eq!(ecb_decrypt(&aes, &ct).unwrap(), repeated);
    println!("  -> blocks 0, 1, 2 are identical: the pattern is visible.\n");

    println!("== CBC: chaining hides patterns ==");
    let iv = random_block();
    let ct = cbc_encrypt(&aes, &iv, repeated);
    show_blocks("CBC ciphertext", &ct);
    println!("  -> all blocks differ. decrypts: {:?}", String::from_utf8_lossy(&cbc_decrypt(&aes, &iv, &ct).unwrap()));

    // CBC bit-flipping: no key needed. Flipping bits of the IV flips the same
    // bits of plaintext block 0. Flipping C_i would do the same to block i+1.
    let msg = b"pay=0100;to=bob;memo=rent";
    let mut iv2 = random_block();
    let ct = cbc_encrypt(&aes, &iv2, msg);
    let (from, to) = (b"0100", b"9999");
    for i in 0..4 {
        iv2[4 + i] ^= from[i] ^ to[i]; // "pay=" is 4 bytes, so the amount starts at offset 4
    }
    let forged = cbc_decrypt(&aes, &iv2, &ct).unwrap();
    println!("  bit-flip attack on IV: {:?} -> {:?}\n", String::from_utf8_lossy(msg), String::from_utf8_lossy(&forged));

    let text = b"Stream modes need no padding: 38 bytes";

    println!("== CFB: self-synchronising stream ==");
    let iv = random_block();
    let ct = cfb_encrypt(&aes, &iv, text);
    println!("  plaintext {} bytes -> ciphertext {} bytes (CBC would give {})", text.len(), ct.len(), pad(text).len());
    let mut corrupted = ct.clone();
    corrupted[0] ^= 0xff;
    let pt = cfb_decrypt(&aes, &iv, &corrupted);
    println!("  1 byte corrupted in block 0 -> {:?}", String::from_utf8_lossy(&pt));
    println!("  (block 0 has 1 bad byte, block 1 is garbled, block 2 recovers)\n");

    println!("== OFB: precomputable keystream, 1-to-1 bit errors ==");
    let iv = random_block();
    let ct = ofb_apply(&aes, &iv, text);
    let mut corrupted = ct.clone();
    corrupted[0] ^= b'S' ^ b'Z';
    println!("  1 byte changed -> {:?}", String::from_utf8_lossy(&ofb_apply(&aes, &iv, &corrupted)));
    println!("  (only that byte changes: errors don't spread, but data is malleable)\n");

    println!("== CTR: parallel, random access, nonce must never repeat ==");
    let mut counter = [0u8; BLOCK];
    OsRng.fill_bytes(&mut counter[..12]); // 96-bit nonce || 32-bit counter starting at 0
    let ct = ctr_apply(&aes, &counter, text);
    println!("  decrypts: {:?}", String::from_utf8_lossy(&ctr_apply(&aes, &counter, &ct)));
    // Random access: decrypt only block 2 by starting at counter + 2.
    let mut c2 = u128::from_be_bytes(counter);
    c2 += 2;
    println!("  block 2 alone: {:?}", String::from_utf8_lossy(&ctr_apply(&aes, &c2.to_be_bytes(), &ct[32..])));

    // Nonce reuse: C1 ^ C2 = P1 ^ P2, so knowing one plaintext reveals the other.
    let p1 = b"salary: alice 120000";
    let p2 = b"salary: bob   95000!";
    let c1 = ctr_apply(&aes, &counter, p1);
    let c2 = ctr_apply(&aes, &counter, p2);
    let recovered: Vec<u8> = c1.iter().zip(&c2).zip(p1).map(|((a, b), p)| a ^ b ^ p).collect();
    println!("  nonce reused: attacker knows p1, recovers p2 = {:?} without the key", String::from_utf8_lossy(&recovered));

    println!("\nNone of these modes detect tampering -> prefer AES-GCM (../aes_gcm_example).");
}
