// Lamport one-time signature (1979): the simplest hash-based signature.
//
// keygen: 256 pairs of random secrets (sk[i][0], sk[i][1]); pk[i][b] = H(sk[i][b])
// sign:   d = H(msg); for each bit i of d, reveal sk[i][d_i]
// verify: check H(sig[i]) == pk[i][d_i] for all 256 bits
//
// Security only needs H to be one-way. A quantum computer (Grover) only
// halves the security level, so SHA-256 still gives ~128-bit security.
// Each key must sign ONE message: every signature reveals half the secrets.

use crate::hash::{sha256, Hash, N};
use rand::{rngs::OsRng, RngCore};

const BITS: usize = N * 8;

pub struct SecretKey([[Hash; 2]; BITS]);
pub struct PublicKey(pub [[Hash; 2]; BITS]);
pub struct Signature(pub [Hash; BITS]);

fn bit(d: &Hash, i: usize) -> usize {
    ((d[i / 8] >> (7 - i % 8)) & 1) as usize
}

pub fn keygen() -> (SecretKey, PublicKey) {
    let mut sk = [[[0u8; N]; 2]; BITS];
    for pair in sk.iter_mut() {
        OsRng.fill_bytes(&mut pair[0]);
        OsRng.fill_bytes(&mut pair[1]);
    }
    let pk = sk.map(|[a, b]| [sha256(&a), sha256(&b)]);
    (SecretKey(sk), PublicKey(pk))
}

pub fn sign(sk: &SecretKey, msg: &[u8]) -> Signature {
    let d = sha256(msg);
    Signature(std::array::from_fn(|i| sk.0[i][bit(&d, i)]))
}

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    let d = sha256(msg);
    (0..BITS).all(|i| sha256(&sig.0[i]) == pk.0[i][bit(&d, i)])
}

/// How many of the 512 secrets an observer has learned from these signatures.
pub fn revealed_secrets(msgs: &[&[u8]]) -> usize {
    let mut seen = [[false; 2]; BITS];
    for m in msgs {
        let d = sha256(m);
        for (i, s) in seen.iter_mut().enumerate() {
            s[bit(&d, i)] = true;
        }
    }
    seen.iter().flatten().filter(|&&b| b).count()
}
