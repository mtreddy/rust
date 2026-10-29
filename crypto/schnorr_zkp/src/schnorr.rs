// Schnorr proof of knowledge of a discrete logarithm, on Ristretto255.
//
// Statement: "I know x such that P = x*G", without revealing x.
//
//   Prover                                Verifier
//   k random, R = k*G     ----- R ----->
//                         <---- c -----   c random
//   s = k + c*x           ----- s ----->  check  s*G == R + c*P
//
// Why the check works:  s*G = (k + c*x)*G = k*G + c*(x*G) = R + c*P
//
// The three properties of a zero-knowledge proof (a "sigma protocol"):
// - Completeness: an honest prover always passes (the equation above).
// - Special soundness: two accepting answers (c1, s1), (c2, s2) for the SAME R
//   reveal x = (s1 - s2) / (c1 - c2). So anyone who can answer two challenges
//   must know x -> a cheater can only guess c in advance (chance 1 / 2^252).
//   This is also why reusing a nonce k leaks the private key (Sony PS3, 2010).
// - Zero-knowledge: a simulator WITHOUT x can produce transcripts (R, c, s) that
//   look exactly like real ones: pick c, s first, then set R = s*G - c*P.
//   So a transcript teaches the verifier nothing it couldn't make by itself.
//
// Ristretto255 is a prime-order group built from Curve25519, so there are no
// small-subgroup / cofactor pitfalls that raw Ed25519 points have.

use crate::transcript::Transcript;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

pub struct KeyPair {
    x: Scalar,
    pub p: RistrettoPoint,
}

impl KeyPair {
    pub fn generate() -> Self {
        let x = Scalar::random(&mut OsRng);
        KeyPair { x, p: x * G }
    }

    // ----- interactive protocol -----

    /// Step 1: commitment. Returns the secret nonce k and R = k*G.
    pub fn commit(&self) -> (Scalar, RistrettoPoint) {
        let k = Scalar::random(&mut OsRng);
        (k, k * G)
    }

    /// Step 3: response s = k + c*x. The nonce k must never be used twice.
    pub fn respond(&self, k: &Scalar, c: &Scalar) -> Scalar {
        k + c * self.x
    }

    // ----- non-interactive (Fiat-Shamir) -----

    /// Proof bound to `context` (a session id, or a message to get a signature).
    pub fn prove(&self, context: &[u8]) -> Proof {
        let (k, r) = self.commit();
        let c = challenge(&self.p, &r, context);
        Proof { r, s: self.respond(&k, &c) }
    }

    /// A Schnorr signature is exactly a NIZK proof of knowledge of x with the
    /// message in the challenge hash.
    pub fn sign(&self, msg: &[u8]) -> Proof {
        self.prove(msg)
    }
}

/// Step 4: verifier's check.
pub fn verify_interactive(p: &RistrettoPoint, r: &RistrettoPoint, c: &Scalar, s: &Scalar) -> bool {
    s * G == r + c * p
}

pub struct Proof {
    pub r: RistrettoPoint,
    pub s: Scalar,
}

/// Strong Fiat-Shamir challenge: c = H(domain, G, P, R, context).
fn challenge(p: &RistrettoPoint, r: &RistrettoPoint, context: &[u8]) -> Scalar {
    let mut t = Transcript::new(b"schnorr-zkp/dlog/v1");
    t.append_point(b"G", &G);
    t.append_point(b"P", p);
    t.append_point(b"R", r);
    t.append(b"context", context);
    t.challenge()
}

pub fn verify(p: &RistrettoPoint, proof: &Proof, context: &[u8]) -> bool {
    verify_interactive(p, &proof.r, &challenge(p, &proof.r, context), &proof.s)
}

// ----- the security arguments, as code -----

/// Zero-knowledge simulator: makes a valid-looking transcript for P with no secret.
/// (It only works because it picks c itself, which a real verifier never allows.)
pub fn simulate(p: &RistrettoPoint) -> (RistrettoPoint, Scalar, Scalar) {
    let c = Scalar::random(&mut OsRng);
    let s = Scalar::random(&mut OsRng);
    (s * G - c * p, c, s)
}

/// Special-soundness extractor: two answers for the same R give the secret.
pub fn extract(c1: &Scalar, s1: &Scalar, c2: &Scalar, s2: &Scalar) -> Scalar {
    (s1 - s2) * (c1 - c2).invert()
}

// ----- what goes wrong with weak Fiat-Shamir -----

/// BROKEN: challenge hashes only R and forgets the public key P.
fn weak_challenge(r: &RistrettoPoint) -> Scalar {
    let mut t = Transcript::new(b"schnorr-zkp/weak");
    t.append_point(b"R", r);
    t.challenge()
}

pub fn verify_weak(p: &RistrettoPoint, proof: &Proof) -> bool {
    verify_interactive(p, &proof.r, &weak_challenge(&proof.r), &proof.s)
}

/// Forge a "proof" for a public key nobody knows the secret of:
/// fix R and s first, compute c = H(R), then solve s*G = R + c*P for P.
pub fn forge_weak() -> (RistrettoPoint, Proof) {
    let r = RistrettoPoint::random(&mut OsRng);
    let s = Scalar::random(&mut OsRng);
    let c = weak_challenge(&r);
    let p = c.invert() * (s * G - r);
    (p, Proof { r, s })
}
