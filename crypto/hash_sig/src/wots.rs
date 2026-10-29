// WOTS+ (Winternitz one-time signature), as used inside XMSS and SPHINCS+.
//
// Lamport signs 1 bit per secret. WOTS signs log2(W) bits per secret using
// hash chains, making signatures ~4x smaller at the cost of more hashing:
//
//   sk_i --H--> . --H--> . ... --H--> pk_i        (W-1 steps per chain)
//
// sign:   split the digest into base-W digits b_i; reveal chain_i at step b_i
// verify: hash each sig_i the remaining (W-1-b_i) steps; must reach pk_i
//
// Problem: anyone can hash *forward*, turning a signature for digit b into
// one for b+1. Fix: append a checksum = sum(W-1-b_i). Raising any message
// digit lowers the checksum, which would require hashing *backward* (inverting H).

use crate::hash::{th, Address, Hash, Tag, N};

pub const W: u32 = 16;
const LOG_W: usize = 4;
const LEN1: usize = N * 8 / LOG_W; // 64 message digits
const LEN2: usize = 3; // checksum digits: max 64*15 = 960 < 16^3
pub const LEN: usize = LEN1 + LEN2; // 67 chains

pub type Signature = [Hash; LEN];

/// Base-W digits of the message digest followed by its checksum digits.
fn digits(msg: &Hash) -> [u32; LEN] {
    let mut d = [0u32; LEN];
    for (i, byte) in msg.iter().enumerate() {
        d[2 * i] = (byte >> 4) as u32;
        d[2 * i + 1] = (byte & 0x0f) as u32;
    }
    let csum: u32 = d[..LEN1].iter().map(|x| W - 1 - x).sum();
    d[LEN1] = (csum >> 8) & 0xf;
    d[LEN1 + 1] = (csum >> 4) & 0xf;
    d[LEN1 + 2] = csum & 0xf;
    d
}

fn chain(mut x: Hash, start: u32, steps: u32, seed: &Hash, mut adrs: Address) -> Hash {
    for j in start..start + steps {
        adrs.step = j;
        x = th(Tag::Chain, seed, adrs, &x);
    }
    x
}

fn secret(sk_seed: &Hash, key: u32, chain: u32) -> Hash {
    th(Tag::Prf, sk_seed, Address { key, chain, step: 0 }, &[])
}

fn compress(ends: &[Hash; LEN], seed: &Hash, key: u32) -> Hash {
    th(Tag::WotsPk, seed, Address { key, ..Default::default() }, ends.concat().as_slice())
}

/// Public key for one-time key `key`: hash of all 67 chain ends.
pub fn public_key(sk_seed: &Hash, pub_seed: &Hash, key: u32) -> Hash {
    let ends = std::array::from_fn(|i| {
        let adrs = Address { key, chain: i as u32, step: 0 };
        chain(secret(sk_seed, key, i as u32), 0, W - 1, pub_seed, adrs)
    });
    compress(&ends, pub_seed, key)
}

pub fn sign(msg: &Hash, sk_seed: &Hash, pub_seed: &Hash, key: u32) -> Signature {
    let d = digits(msg);
    std::array::from_fn(|i| {
        let adrs = Address { key, chain: i as u32, step: 0 };
        chain(secret(sk_seed, key, i as u32), 0, d[i], pub_seed, adrs)
    })
}

/// Recompute the public key from a signature; verification compares it to the real one.
pub fn public_key_from_sig(sig: &Signature, msg: &Hash, pub_seed: &Hash, key: u32) -> Hash {
    let d = digits(msg);
    let ends = std::array::from_fn(|i| {
        let adrs = Address { key, chain: i as u32, step: 0 };
        chain(sig[i], d[i], W - 1 - d[i], pub_seed, adrs)
    });
    compress(&ends, pub_seed, key)
}
