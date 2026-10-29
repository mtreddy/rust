// KZG polynomial commitments from scratch on BN254 (Kate, Zaverucha, Goldberg 2010).
// Only curve arithmetic and the pairing come from arkworks; polynomials,
// commit, open and verify are written here.
//
// Setup (trusted):  secret tau, publish  SRS = (G, tau*G, tau^2*G, ..., tau^d*G;  H, tau*H)
//                   G in G1, H in G2. Then tau ("toxic waste") must be destroyed.
// Commit:           C = sum f_i * (tau^i * G) = f(tau) * G      (one 32-byte point)
// Open at z:        y = f(z);  q(X) = (f(X) - y) / (X - z);  proof = q(tau) * G
//                   q is a polynomial ONLY IF y really equals f(z) (factor theorem).
// Verify:           e(C - y*G, H) == e(proof, tau*H - z*H)
//                   i.e.  f(tau) - y == q(tau) * (tau - z),  checked "in the exponent".
//
// Part 2 uses KZG the way PLONK does: commit to polynomials encoding a witness,
// get a random challenge, and check a polynomial identity at that single point.

use ark_bn254::{Bn254, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::{FftField, Field, One, PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

// ---------- polynomials over Fr (coefficients, lowest degree first) ----------

#[derive(Clone, Debug, PartialEq)]
pub struct Poly(pub Vec<Fr>);

impl Poly {
    fn trim(mut self) -> Self {
        while self.0.last().is_some_and(|c| c.is_zero()) {
            self.0.pop();
        }
        self
    }

    pub fn x_minus(z: Fr) -> Self {
        Poly(vec![-z, Fr::one()])
    }

    /// X^n - 1: zero exactly on the n-th roots of unity.
    pub fn vanishing(n: usize) -> Self {
        let mut c = vec![Fr::zero(); n + 1];
        c[0] = -Fr::one();
        c[n] = Fr::one();
        Poly(c)
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|c| c.is_zero())
    }

    /// Horner's rule.
    pub fn eval(&self, x: Fr) -> Fr {
        self.0.iter().rev().fold(Fr::zero(), |acc, c| acc * x + c)
    }

    pub fn add(&self, o: &Poly) -> Poly {
        let n = self.0.len().max(o.0.len());
        let get = |p: &Poly, i| p.0.get(i).copied().unwrap_or_default();
        Poly((0..n).map(|i| get(self, i) + get(o, i)).collect()).trim()
    }

    pub fn scale(&self, k: Fr) -> Poly {
        Poly(self.0.iter().map(|c| *c * k).collect()).trim()
    }

    pub fn sub(&self, o: &Poly) -> Poly {
        self.add(&o.scale(-Fr::one()))
    }

    pub fn mul(&self, o: &Poly) -> Poly {
        if self.0.is_empty() || o.0.is_empty() {
            return Poly(vec![]);
        }
        let mut out = vec![Fr::zero(); self.0.len() + o.0.len() - 1];
        for (i, a) in self.0.iter().enumerate() {
            for (j, b) in o.0.iter().enumerate() {
                out[i + j] += *a * b;
            }
        }
        Poly(out).trim()
    }

    /// Long division: self = q * d + r with deg r < deg d.
    pub fn div_rem(&self, d: &Poly) -> (Poly, Poly) {
        let d = d.clone().trim();
        let lead_inv = d.0.last().expect("division by zero polynomial").inverse().unwrap();
        let mut r = self.clone().trim().0;
        if r.len() < d.0.len() {
            return (Poly(vec![]), Poly(r));
        }
        let mut q = vec![Fr::zero(); r.len() - d.0.len() + 1];
        for i in (0..q.len()).rev() {
            let coef = r[i + d.0.len() - 1] * lead_inv;
            q[i] = coef;
            for (j, dc) in d.0.iter().enumerate() {
                r[i + j] -= coef * dc;
            }
        }
        (Poly(q).trim(), Poly(r).trim())
    }

    /// Lagrange interpolation through (xs[i], ys[i]). O(n^2), fine for small n (FFT in practice).
    pub fn interpolate(xs: &[Fr], ys: &[Fr]) -> Poly {
        let mut acc = Poly(vec![]);
        for (i, (xi, yi)) in xs.iter().zip(ys).enumerate() {
            let mut basis = Poly(vec![Fr::one()]);
            let mut denom = Fr::one();
            for (j, xj) in xs.iter().enumerate() {
                if i != j {
                    basis = basis.mul(&Poly::x_minus(*xj));
                    denom *= *xi - xj;
                }
            }
            acc = acc.add(&basis.scale(*yi * denom.inverse().unwrap()));
        }
        acc
    }
}

// ---------- KZG ----------

pub struct Srs {
    pub g1_powers: Vec<G1>, // tau^i * G for i = 0..=d
    pub h: G2,
    pub tau_h: G2,
}

/// Trusted setup. Real systems compute this in a multi-party ceremony so nobody learns tau;
/// here the caller passes tau so the demo can show what happens if it leaks.
pub fn setup(max_degree: usize, tau: Fr) -> Srs {
    let g = G1::generator();
    let mut powers = Vec::with_capacity(max_degree + 1);
    let mut t = Fr::one();
    for _ in 0..=max_degree {
        powers.push(g * t);
        t *= tau;
    }
    Srs { g1_powers: powers, h: G2::generator(), tau_h: G2::generator() * tau }
}

/// C = f(tau) * G, computed without knowing tau. (An MSM in production code.)
pub fn commit(srs: &Srs, f: &Poly) -> G1 {
    assert!(f.0.len() <= srs.g1_powers.len(), "polynomial degree exceeds SRS");
    f.0.iter().zip(&srs.g1_powers).map(|(c, p)| *p * c).sum()
}

/// Opening proof that f(z) = y.
pub fn open(srs: &Srs, f: &Poly, z: Fr) -> (Fr, G1) {
    let y = f.eval(z);
    let (q, r) = f.sub(&Poly(vec![y])).div_rem(&Poly::x_minus(z));
    debug_assert!(r.is_zero(), "f(X) - f(z) is always divisible by (X - z)");
    (y, commit(srs, &q))
}

/// e(C - y*G, H) == e(proof, tau*H - z*H)
pub fn verify(srs: &Srs, c: &G1, z: Fr, y: Fr, proof: &G1) -> bool {
    let lhs = Bn254::pairing(*c - G1::generator() * y, srs.h);
    let rhs = Bn254::pairing(*proof, srs.tau_h - srs.h * z);
    lhs == rhs
}

/// Fiat-Shamir: hash commitments (and other context) into a field element.
fn challenge(label: &[u8], points: &[&G1]) -> Fr {
    let mut h = Sha256::new();
    h.update(label);
    for p in points {
        let mut buf = Vec::new();
        p.serialize_compressed(&mut buf).unwrap();
        h.update(buf);
    }
    Fr::from_le_bytes_mod_order(&h.finalize())
}

/// Batch opening of several polynomials at ONE point with one proof (PLONK does this):
/// combine h = f_0 + gamma*f_1 + gamma^2*f_2 ..., open h. Verifier combines the
/// commitments the same way (commitments are additively homomorphic).
pub fn batch_open(srs: &Srs, polys: &[&Poly], cs: &[&G1], z: Fr) -> (Vec<Fr>, G1) {
    let gamma = challenge(b"kzg/batch", cs);
    let mut h = Poly(vec![]);
    let mut g = Fr::one();
    for f in polys {
        h = h.add(&f.scale(g));
        g *= gamma;
    }
    let ys = polys.iter().map(|f| f.eval(z)).collect();
    (ys, open(srs, &h, z).1)
}

pub fn batch_verify(srs: &Srs, cs: &[&G1], z: Fr, ys: &[Fr], proof: &G1) -> bool {
    let gamma = challenge(b"kzg/batch", cs);
    let (mut c, mut y, mut g) = (G1::zero(), Fr::zero(), Fr::one());
    for (ci, yi) in cs.iter().zip(ys) {
        c += **ci * g;
        y += *yi * g;
        g *= gamma;
    }
    verify(srs, &c, z, y, proof)
}

// ---------- Part 2: a tiny PLONK-style proof: "every entry of my vector is a bit" ----------
//
// Witness: v = (v_0 .. v_{n-1}), hidden.
// Encode:  f(X) with f(w^i) = v_i on the n-th roots of unity w^i (interpolation).
// Claim:   v_i in {0,1} for all i  <=>  f(x) * (f(x) - 1) = 0 on every w^i
//                                   <=>  f(X)(f(X) - 1) = q(X) * (X^n - 1)  for some polynomial q.
// Protocol:
//   1. prover commits C_f, C_q
//   2. zeta = H(C_f, C_q)                       (Fiat-Shamir, after the commitments!)
//   3. prover opens f and q at zeta (one batched proof)
//   4. verifier checks  f(zeta)(f(zeta) - 1) == q(zeta) * (zeta^n - 1)
// By Schwartz-Zippel, a false identity holds at a random zeta with prob <= deg / |Fr| ~ 2^-250.
//
// Hiding: f alone would leak a combination of the v_i when opened at zeta. Adding
// (b0 + b1 X) * (X^n - 1) with random b0, b1 changes nothing on the roots of unity
// (X^n - 1 is zero there) but makes f(zeta) uniformly random. PLONK does exactly this.

pub struct BitProof {
    pub c_f: G1,
    pub c_q: G1,
    pub f_zeta: Fr,
    pub q_zeta: Fr,
    pub opening: G1,
}

pub fn domain(n: usize) -> Vec<Fr> {
    let w = Fr::get_root_of_unity(n as u64).expect("n must be a power of two <= 2^28");
    (0..n).scan(Fr::one(), |acc, _| {
        let cur = *acc;
        *acc *= w;
        Some(cur)
    }).collect()
}

/// Honest prover. Returns None if the witness isn't all bits (q wouldn't be a polynomial).
pub fn prove_bits(srs: &Srs, values: &[u64]) -> Option<BitProof> {
    let (f, q) = bits_polys(values, true);
    let q = q?;
    Some(finish_bit_proof(srs, &f, &q))
}

/// Builds f (blinded) and q = f(f-1) / (X^n - 1); q is None if the division leaves a remainder.
fn bits_polys(values: &[u64], blind: bool) -> (Poly, Option<Poly>) {
    let n = values.len();
    let ys: Vec<Fr> = values.iter().map(|&v| Fr::from(v)).collect();
    let mut f = Poly::interpolate(&domain(n), &ys);
    if blind {
        let r = Poly(vec![Fr::rand(&mut OsRng), Fr::rand(&mut OsRng)]);
        f = f.add(&r.mul(&Poly::vanishing(n)));
    }
    let num = f.mul(&f.sub(&Poly(vec![Fr::one()])));
    let (q, rem) = num.div_rem(&Poly::vanishing(n));
    (f, rem.is_zero().then_some(q))
}

fn finish_bit_proof(srs: &Srs, f: &Poly, q: &Poly) -> BitProof {
    let (c_f, c_q) = (commit(srs, f), commit(srs, q));
    let zeta = challenge(b"bits/zeta", &[&c_f, &c_q]);
    let (ys, opening) = batch_open(srs, &[f, q], &[&c_f, &c_q], zeta);
    BitProof { c_f, c_q, f_zeta: ys[0], q_zeta: ys[1], opening }
}

pub fn verify_bits(srs: &Srs, n: usize, p: &BitProof) -> bool {
    let zeta = challenge(b"bits/zeta", &[&p.c_f, &p.c_q]);
    let openings_ok = batch_verify(srs, &[&p.c_f, &p.c_q], zeta, &[p.f_zeta, p.q_zeta], &p.opening);
    let identity_ok = p.f_zeta * (p.f_zeta - Fr::one()) == p.q_zeta * (zeta.pow([n as u64]) - Fr::one());
    openings_ok && identity_ok
}

// ---------- demo ----------

pub fn demo() {
    let tau = Fr::rand(&mut OsRng);
    let srs = setup(32, tau);
    println!("-- trusted setup: SRS with tau^0..tau^32 in G1, plus H, tau*H in G2 --");

    // f(X) = 3X^3 + 2X + 5
    let f = Poly(vec![Fr::from(5u64), Fr::from(2u64), Fr::zero(), Fr::from(3u64)]);
    let c = commit(&srs, &f);
    let size = |p: &G1| p.compressed_size();
    println!("\n-- commit / open / verify: f(X) = 3X^3 + 2X + 5 --");
    println!("commitment C = f(tau)*G: {} bytes, independent of degree", size(&c));
    let z = Fr::from(2u64);
    let (y, proof) = open(&srs, &f, z);
    println!("open at z = 2: y = {y} (3*8 + 4 + 5 = 33), proof {} bytes", size(&proof));
    println!("verify f(2) = 33:   {}", verify(&srs, &c, z, y, &proof));
    println!("verify f(2) = 34:   {}", verify(&srs, &c, z, y + Fr::one(), &proof));

    // Cheating needs q(X) = (f(X) - 34) / (X - 2), but that division leaves a remainder.
    let (_, rem) = f.sub(&Poly(vec![Fr::from(34u64)])).div_rem(&Poly::x_minus(z));
    assert_eq!(rem, Poly(vec![-Fr::one()])); // remainder = f(2) - 34 = -1
    println!("(f - 34) / (X - 2) leaves remainder f(2) - 34 = -1 -> no polynomial quotient exists");

    // ...unless you know tau: then q(tau) = (f(tau) - y') / (tau - z) is just a number.
    let forged = G1::generator() * ((f.eval(tau) - Fr::from(34u64)) * (tau - z).inverse().unwrap());
    println!("forge with leaked tau, f(2) = 34: {}  <- why the setup's toxic waste must be destroyed", verify(&srs, &c, z, Fr::from(34u64), &forged));

    println!("\n-- batch: open f and g at one point with a single proof --");
    let g = Poly(vec![Fr::from(7u64), Fr::from(1u64)]); // X + 7
    let cg = commit(&srs, &g);
    let (ys, bproof) = batch_open(&srs, &[&f, &g], &[&c, &cg], z);
    println!("f(2) = {}, g(2) = {}, one proof: {}", ys[0], ys[1], batch_verify(&srs, &[&c, &cg], z, &ys, &bproof));

    println!("\n-- PLONK-style: prove a hidden 8-entry vector is all bits --");
    let honest = [1, 0, 1, 1, 0, 0, 1, 0];
    let p = prove_bits(&srs, &honest).unwrap();
    let total = 3 * size(&p.c_f) + 2 * p.f_zeta.compressed_size();
    println!("proof = C_f, C_q, f(zeta), q(zeta), opening: {total} bytes");
    println!("verify honest vector:           {}", verify_bits(&srs, 8, &p));

    let cheat = [1, 0, 2, 1, 0, 0, 1, 0];
    println!("honest prover with a 2 in it:   {}", if prove_bits(&srs, &cheat).is_none() { "can't build q (remainder != 0)" } else { "built?!" });
    // A cheater commits to the quotient anyway, ignoring the remainder.
    let (f_bad, _) = bits_polys(&cheat, true);
    let num = f_bad.mul(&f_bad.sub(&Poly(vec![Fr::one()])));
    let (q_bad, _) = num.div_rem(&Poly::vanishing(8));
    let forged = finish_bit_proof(&srs, &f_bad, &q_bad);
    println!("cheater's proof (ignoring rem): {}", verify_bits(&srs, 8, &forged));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srs() -> Srs {
        setup(32, Fr::rand(&mut OsRng))
    }

    #[test]
    fn poly_division_and_interpolation() {
        let f = Poly(vec![Fr::from(5u64), Fr::from(2u64), Fr::zero(), Fr::from(3u64)]);
        let d = Poly(vec![Fr::from(1u64), Fr::from(1u64)]);
        let (q, r) = f.div_rem(&d);
        assert_eq!(q.mul(&d).add(&r), f);
        let xs = domain(8);
        let ys: Vec<Fr> = (0..8u64).map(Fr::from).collect();
        let p = Poly::interpolate(&xs, &ys);
        assert!(xs.iter().zip(&ys).all(|(x, y)| p.eval(*x) == *y));
    }

    #[test]
    fn open_verify() {
        let s = srs();
        let f = Poly((1..=10u64).map(Fr::from).collect());
        let c = commit(&s, &f);
        let z = Fr::rand(&mut OsRng);
        let (y, pi) = open(&s, &f, z);
        assert!(verify(&s, &c, z, y, &pi));
        assert!(!verify(&s, &c, z, y + Fr::one(), &pi));
        assert!(!verify(&s, &c, z + Fr::one(), y, &pi));
    }

    #[test]
    fn batch() {
        let s = srs();
        let (f, g) = (Poly(vec![Fr::from(1u64), Fr::from(2u64)]), Poly(vec![Fr::from(9u64)]));
        let (cf, cg) = (commit(&s, &f), commit(&s, &g));
        let z = Fr::from(5u64);
        let (ys, pi) = batch_open(&s, &[&f, &g], &[&cf, &cg], z);
        assert!(batch_verify(&s, &[&cf, &cg], z, &ys, &pi));
        assert!(!batch_verify(&s, &[&cf, &cg], z, &[ys[0], ys[1] + Fr::one()], &pi));
    }

    #[test]
    fn bit_vector_proof() {
        let s = srs();
        let p = prove_bits(&s, &[1, 1, 0, 1]).unwrap();
        assert!(verify_bits(&s, 4, &p));
        assert!(prove_bits(&s, &[1, 3, 0, 1]).is_none());
        // blinding doesn't change the values on the domain
        let (f, _) = bits_polys(&[1, 0, 1, 1], true);
        let vals: Vec<Fr> = domain(4).iter().map(|x| f.eval(*x)).collect();
        assert_eq!(vals, [1u64, 0, 1, 1].map(Fr::from).to_vec());
    }
}
