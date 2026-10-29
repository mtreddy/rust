// Fiat-Shamir transcript: hashes everything the verifier would have seen so far
// into a challenge scalar. This replaces the verifier's random challenge
// (same idea as ../fiat_shamir, now over an elliptic curve).
//
// Rule of thumb ("strong Fiat-Shamir"): hash the domain/protocol name, ALL public
// parameters (generators, statement/public keys) and ALL commitments. Leaving
// any of them out has caused real-world forgeries (e.g. "Frozen Heart", 2022).

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

pub struct Transcript(Sha512);

impl Transcript {
    pub fn new(domain: &[u8]) -> Self {
        let mut t = Transcript(Sha512::new());
        t.append(b"domain", domain);
        t
    }

    /// Length-prefixed (label, value) so different inputs can't hash the same.
    pub fn append(&mut self, label: &[u8], data: &[u8]) {
        for part in [label, data] {
            self.0.update((part.len() as u64).to_le_bytes());
            self.0.update(part);
        }
    }

    pub fn append_point(&mut self, label: &[u8], p: &RistrettoPoint) {
        self.append(label, p.compress().as_bytes());
    }

    /// 512-bit hash reduced mod the group order: a uniform challenge scalar.
    pub fn challenge(self) -> Scalar {
        Scalar::from_hash(self.0)
    }
}
