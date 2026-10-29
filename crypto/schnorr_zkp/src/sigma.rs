// Two more sigma protocols built from the same commit / challenge / response pattern.

use crate::transcript::Transcript;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use sha2::Sha512;

/// A second generator with NO known discrete log relative to G, obtained by
/// hashing to the curve ("nothing up my sleeve"). If anyone knew h = log_G(H),
/// Pedersen commitments below would not be binding.
pub fn h() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(b"schnorr-zkp/generator-H")
}

// ---------- Chaum-Pedersen: discrete-log equality (DLEQ) ----------
//
// Statement: A = x*G and B = x*H use the SAME secret x.
//   k random, R1 = k*G, R2 = k*H
//   c = H(G, H, A, B, R1, R2)
//   s = k + c*x
//   verify: s*G == R1 + c*A  and  s*H == R2 + c*B
//
// One response s answers both equations, which is only possible if both
// points share the exponent. Used in VRFs, verifiable decryption and
// verifiable shuffles, and to prove a Diffie-Hellman result was computed correctly.

pub struct DleqProof {
    pub r1: RistrettoPoint,
    pub r2: RistrettoPoint,
    pub s: Scalar,
}

fn dleq_challenge(hh: &RistrettoPoint, a: &RistrettoPoint, b: &RistrettoPoint, r1: &RistrettoPoint, r2: &RistrettoPoint) -> Scalar {
    let mut t = Transcript::new(b"schnorr-zkp/dleq/v1");
    for (label, p) in [(b"G", &G), (b"H", hh), (b"A", a), (b"B", b)] {
        t.append_point(label, p);
    }
    t.append_point(b"R1", r1);
    t.append_point(b"R2", r2);
    t.challenge()
}

pub fn dleq_prove(x: &Scalar, hh: &RistrettoPoint) -> (RistrettoPoint, RistrettoPoint, DleqProof) {
    let (a, b) = (x * G, x * hh);
    let k = Scalar::random(&mut OsRng);
    let (r1, r2) = (k * G, k * hh);
    let c = dleq_challenge(hh, &a, &b, &r1, &r2);
    (a, b, DleqProof { r1, r2, s: k + c * x })
}

pub fn dleq_verify(hh: &RistrettoPoint, a: &RistrettoPoint, b: &RistrettoPoint, pf: &DleqProof) -> bool {
    let c = dleq_challenge(hh, a, b, &pf.r1, &pf.r2);
    pf.s * G == pf.r1 + c * a && pf.s * hh == pf.r2 + c * b
}

// ---------- Pedersen commitment + proof of knowledge of the opening ----------
//
// Commit to a value v with blinding r:   C = v*G + r*H
// - Hiding:  r is random, so C reveals nothing about v.
// - Binding: opening C to a different v' would reveal log_G(H).
// - Additively homomorphic: C(v1, r1) + C(v2, r2) = C(v1 + v2, r1 + r2).
//
// Proof (Okamoto): "I know v, r with C = v*G + r*H", revealing neither.
//   k1, k2 random, T = k1*G + k2*H
//   c = H(G, H, C, T)
//   s1 = k1 + c*v,  s2 = k2 + c*r
//   verify: s1*G + s2*H == T + c*C

pub struct OpeningProof {
    pub t: RistrettoPoint,
    pub s1: Scalar,
    pub s2: Scalar,
}

pub fn commit(v: &Scalar, r: &Scalar) -> RistrettoPoint {
    v * G + r * h()
}

fn opening_challenge(c: &RistrettoPoint, t: &RistrettoPoint) -> Scalar {
    let mut tr = Transcript::new(b"schnorr-zkp/pedersen-opening/v1");
    tr.append_point(b"G", &G);
    tr.append_point(b"H", &h());
    tr.append_point(b"C", c);
    tr.append_point(b"T", t);
    tr.challenge()
}

pub fn prove_opening(v: &Scalar, r: &Scalar) -> (RistrettoPoint, OpeningProof) {
    let c = commit(v, r);
    let (k1, k2) = (Scalar::random(&mut OsRng), Scalar::random(&mut OsRng));
    let t = k1 * G + k2 * h();
    let e = opening_challenge(&c, &t);
    (c, OpeningProof { t, s1: k1 + e * v, s2: k2 + e * r })
}

pub fn verify_opening(c: &RistrettoPoint, pf: &OpeningProof) -> bool {
    let e = opening_challenge(c, &pf.t);
    pf.s1 * G + pf.s2 * h() == pf.t + e * c
}
