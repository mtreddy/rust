// Block cipher modes of operation, written by hand on top of single-block AES.
//
// AES itself only encrypts ONE 16-byte block: E_k(block) -> block.
// A "mode" defines how to use that to encrypt messages of any length.
//
// Notation below:  P_i plaintext block, C_i ciphertext block, E = AES encrypt,
//                  D = AES decrypt, ^ = XOR, IV = initialisation vector.
//
// | mode | padding | parallel enc | parallel dec | needs D | IV / nonce rule         |
// |------|---------|--------------|--------------|---------|-------------------------|
// | ECB  | yes     | yes          | yes          | yes     | none (that's the issue) |
// | CBC  | yes     | no           | yes          | yes     | random + unpredictable  |
// | CFB  | no      | no           | yes          | no      | unique (random is fine) |
// | OFB  | no      | no           | no           | no      | unique, never reused    |
// | CTR  | no      | yes          | yes          | no      | unique, never reused    |
//
// None of these modes detect tampering. Use an AEAD (AES-GCM, see
// ../aes_gcm_example, or ChaCha20-Poly1305) unless you add a MAC yourself.
//
// Works with Aes128 / Aes192 / Aes256: the mode logic doesn't depend on key size.

use aes::cipher::{consts::U16, generic_array::GenericArray, BlockDecrypt, BlockEncrypt};

pub const BLOCK: usize = 16;
pub type Block = [u8; BLOCK];

fn encrypt_block<C: BlockEncrypt<BlockSize = U16>>(c: &C, b: &Block) -> Block {
    let mut g = GenericArray::clone_from_slice(b);
    c.encrypt_block(&mut g);
    g.into()
}

fn decrypt_block<C: BlockDecrypt<BlockSize = U16>>(c: &C, b: &Block) -> Block {
    let mut g = GenericArray::clone_from_slice(b);
    c.decrypt_block(&mut g);
    g.into()
}

fn xor(a: &Block, b: &Block) -> Block {
    std::array::from_fn(|i| a[i] ^ b[i])
}

fn blocks(data: &[u8]) -> impl Iterator<Item = Block> + '_ {
    data.chunks_exact(BLOCK).map(|c| c.try_into().unwrap())
}

// ---------- PKCS#7 padding (for ECB and CBC) ----------
//
// ECB and CBC can only process whole blocks, so the plaintext is padded.
// PKCS#7 appends N bytes each with value N (1..=16). If the data is already a
// multiple of 16, a full block of 0x10 is added, so unpadding is never ambiguous.
//   "HELLO" -> "HELLO" + 0x0b * 11

pub fn pad(data: &[u8]) -> Vec<u8> {
    let n = BLOCK - data.len() % BLOCK;
    let mut out = data.to_vec();
    out.extend(std::iter::repeat(n as u8).take(n));
    out
}

pub fn unpad(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let n = *data.last().ok_or("empty input")? as usize;
    if n == 0 || n > BLOCK || n > data.len() || data[data.len() - n..].iter().any(|&b| b as usize != n) {
        // Careful: telling an attacker *why* decryption failed (bad padding vs
        // bad data) creates a "padding oracle" that can decrypt CBC entirely.
        return Err("invalid padding");
    }
    Ok(data[..data.len() - n].to_vec())
}

// ---------- ECB: Electronic Codebook ----------
//
//   C_i = E(P_i)            P_i = D(C_i)
//
//   P1      P2      P3
//   |       |       |
//  [E]     [E]     [E]
//   |       |       |
//   C1      C2      C3
//
// Every block is encrypted independently with the same key, so identical
// plaintext blocks give identical ciphertext blocks. Patterns in the data
// (images, repeated fields) stay visible: the famous "ECB penguin".
// Blocks can also be reordered, removed or replayed without detection.
// Never use ECB for more than one block of data.

pub fn ecb_encrypt<C: BlockEncrypt<BlockSize = U16>>(c: &C, plaintext: &[u8]) -> Vec<u8> {
    blocks(&pad(plaintext)).flat_map(|p| encrypt_block(c, &p)).collect()
}

pub fn ecb_decrypt<C: BlockDecrypt<BlockSize = U16>>(c: &C, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.is_empty() || ciphertext.len() % BLOCK != 0 {
        return Err("ciphertext must be a non-empty multiple of 16 bytes");
    }
    unpad(&blocks(ciphertext).flat_map(|b| decrypt_block(c, &b)).collect::<Vec<_>>())
}

// ---------- CBC: Cipher Block Chaining ----------
//
//   C_0 = IV
//   C_i = E(P_i ^ C_{i-1})        P_i = D(C_i) ^ C_{i-1}
//
//        P1          P2
//        |           |
//  IV -->^    +----->^
//        |    |      |
//       [E]   |     [E]
//        |    |      |
//        C1 --+      C2
//
// Each block depends on all previous ones, so equal blocks encrypt differently.
// - The IV must be random and unpredictable (a predictable IV allowed the BEAST
//   attack on TLS 1.0). It's not secret: it's sent alongside the ciphertext.
// - Encryption is sequential; decryption can run in parallel.
// - Malleable: flipping bit j of C_{i-1} flips bit j of P_i (and garbles P_{i-1}).
// - Without a MAC, a padding oracle lets an attacker decrypt everything.

pub fn cbc_encrypt<C: BlockEncrypt<BlockSize = U16>>(c: &C, iv: &Block, plaintext: &[u8]) -> Vec<u8> {
    let mut prev = *iv;
    let mut out = Vec::new();
    for p in blocks(&pad(plaintext)) {
        prev = encrypt_block(c, &xor(&p, &prev));
        out.extend_from_slice(&prev);
    }
    out
}

pub fn cbc_decrypt<C: BlockDecrypt<BlockSize = U16>>(c: &C, iv: &Block, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ciphertext.is_empty() || ciphertext.len() % BLOCK != 0 {
        return Err("ciphertext must be a non-empty multiple of 16 bytes");
    }
    let mut prev = *iv;
    let mut out = Vec::new();
    for cb in blocks(ciphertext) {
        out.extend_from_slice(&xor(&decrypt_block(c, &cb), &prev));
        prev = cb;
    }
    unpad(&out)
}

// ---------- CFB: Cipher Feedback (CFB-128) ----------
//
//   C_0 = IV
//   C_i = P_i ^ E(C_{i-1})        P_i = C_i ^ E(C_{i-1})
//
//  IV       +-------+
//   |       |       |
//  [E]      |      [E]
//   |       |       |
//  P1 ->^   |  P2 ->^
//       |   |       |
//       C1 -+       C2
//
// Turns the block cipher into a self-synchronising stream cipher:
// - No padding: the last block is simply truncated.
// - Only AES *encrypt* is used, even for decryption.
// - The keystream depends on the previous ciphertext, so a corrupted ciphertext
//   block garbles that block and the next one, then decryption recovers.
// - The IV must be unique per message under a key (random is fine).

pub fn cfb_encrypt<C: BlockEncrypt<BlockSize = U16>>(c: &C, iv: &Block, plaintext: &[u8]) -> Vec<u8> {
    let mut prev = *iv;
    let mut out = Vec::with_capacity(plaintext.len());
    for p in plaintext.chunks(BLOCK) {
        let ks = encrypt_block(c, &prev);
        let ct: Vec<u8> = p.iter().zip(ks).map(|(a, b)| a ^ b).collect();
        if ct.len() == BLOCK {
            prev = ct.as_slice().try_into().unwrap();
        }
        out.extend(ct);
    }
    out
}

pub fn cfb_decrypt<C: BlockEncrypt<BlockSize = U16>>(c: &C, iv: &Block, ciphertext: &[u8]) -> Vec<u8> {
    let mut prev = *iv;
    let mut out = Vec::with_capacity(ciphertext.len());
    for cb in ciphertext.chunks(BLOCK) {
        let ks = encrypt_block(c, &prev);
        out.extend(cb.iter().zip(ks).map(|(a, b)| a ^ b));
        if cb.len() == BLOCK {
            prev = cb.try_into().unwrap();
        }
    }
    out
}

// ---------- OFB: Output Feedback ----------
//
//   O_0 = IV,  O_i = E(O_{i-1})
//   C_i = P_i ^ O_i               P_i = C_i ^ O_i   (same operation)
//
//  IV -> [E] -> O1 -> [E] -> O2 -> [E] -> O3 ...
//               |             |
//          P1 ->^        P2 ->^
//               |             |
//               C1            C2
//
// The keystream only depends on key + IV, never on the data, so it could be
// computed ahead of time. A flipped ciphertext bit flips exactly one plaintext
// bit (no error spreading), which also makes it fully malleable.
// Reusing an IV with the same key reuses the keystream:
//   C1 ^ C2 = P1 ^ P2   -> leaks plaintext. The IV must never repeat.

pub fn ofb_apply<C: BlockEncrypt<BlockSize = U16>>(c: &C, iv: &Block, data: &[u8]) -> Vec<u8> {
    let mut o = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(BLOCK) {
        o = encrypt_block(c, &o);
        out.extend(chunk.iter().zip(o).map(|(a, b)| a ^ b));
    }
    out
}

// ---------- CTR: Counter ----------
//
//   K_i = E(counter_block + i)    (128-bit big-endian increment)
//   C_i = P_i ^ K_i               P_i = C_i ^ K_i   (same operation)
//
//  ctr+0    ctr+1    ctr+2
//   |        |        |
//  [E]      [E]      [E]
//   |        |        |
//  P1 ->^   P2 ->^   P3 ->^
//       |        |        |
//       C1       C2       C3
//
// The modern default for non-AEAD use, and the basis of AES-GCM.
// - Fully parallel in both directions, and you can decrypt any block directly
//   (random access) by computing its counter.
// - No padding, only AES encrypt is used.
// - Same rule as OFB: a (key, counter) pair must never be reused. Typical layout:
//   96-bit random/unique nonce || 32-bit block counter.

pub fn ctr_apply<C: BlockEncrypt<BlockSize = U16>>(c: &C, counter: &Block, data: &[u8]) -> Vec<u8> {
    let start = u128::from_be_bytes(*counter);
    data.chunks(BLOCK)
        .enumerate()
        .flat_map(|(i, chunk)| {
            let ks = encrypt_block(c, &start.wrapping_add(i as u128).to_be_bytes());
            chunk.iter().zip(ks).map(|(a, b)| a ^ b).collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    // Test vectors from NIST SP 800-38A, Appendix F (AES-128).
    use super::*;
    use aes::cipher::KeyInit;
    use aes::{Aes128, Aes256};

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn setup() -> (Aes128, Vec<u8>, Block) {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                    30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        let iv = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        (Aes128::new_from_slice(&key).unwrap(), pt, iv)
    }

    #[test]
    fn ecb_nist() {
        let (c, pt, _) = setup();
        let ct = ecb_encrypt(&c, &pt);
        // NIST vectors have no padding: compare the first 64 bytes; the 5th block is padding.
        assert_eq!(hex::encode(&ct[..64]), "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf\
                                             43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
        assert_eq!(ecb_decrypt(&c, &ct).unwrap(), pt);
    }

    #[test]
    fn cbc_nist() {
        let (c, pt, iv) = setup();
        let ct = cbc_encrypt(&c, &iv, &pt);
        assert_eq!(hex::encode(&ct[..64]), "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2\
                                             73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");
        assert_eq!(cbc_decrypt(&c, &iv, &ct).unwrap(), pt);
    }

    #[test]
    fn cfb_nist() {
        let (c, pt, iv) = setup();
        let ct = cfb_encrypt(&c, &iv, &pt);
        assert_eq!(hex::encode(&ct), "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b\
                                      26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6");
        assert_eq!(cfb_decrypt(&c, &iv, &ct), pt);
    }

    #[test]
    fn ofb_nist() {
        let (c, pt, iv) = setup();
        let ct = ofb_apply(&c, &iv, &pt);
        assert_eq!(hex::encode(&ct), "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825\
                                      9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e");
        assert_eq!(ofb_apply(&c, &iv, &ct), pt);
    }

    #[test]
    fn ctr_nist() {
        let (c, pt, _) = setup();
        let ctr = h("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").try_into().unwrap();
        let ct = ctr_apply(&c, &ctr, &pt);
        assert_eq!(hex::encode(&ct), "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff\
                                      5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee");
        assert_eq!(ctr_apply(&c, &ctr, &ct), pt);
    }

    #[test]
    fn roundtrip_odd_lengths_aes256() {
        let c = Aes256::new_from_slice(&[7u8; 32]).unwrap();
        let iv = [9u8; 16];
        for len in [0, 1, 15, 16, 17, 33, 100] {
            let m: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(ecb_decrypt(&c, &ecb_encrypt(&c, &m)).unwrap(), m);
            assert_eq!(cbc_decrypt(&c, &iv, &cbc_encrypt(&c, &iv, &m)).unwrap(), m);
            assert_eq!(cfb_decrypt(&c, &iv, &cfb_encrypt(&c, &iv, &m)), m);
            assert_eq!(ofb_apply(&c, &iv, &ofb_apply(&c, &iv, &m)), m);
            assert_eq!(ctr_apply(&c, &iv, &ctr_apply(&c, &iv, &m)), m);
            assert_eq!(cfb_encrypt(&c, &iv, &m).len(), len); // stream modes: no expansion
        }
    }

    #[test]
    fn padding() {
        assert_eq!(pad(b"HELLO").len(), 16);
        assert_eq!(pad(&[0u8; 16]).len(), 32);
        assert_eq!(unpad(&pad(b"HELLO")).unwrap(), b"HELLO");
        let mut bad = pad(b"HELLO");
        bad[15] = 3;
        assert!(unpad(&bad).is_err());
    }
}
