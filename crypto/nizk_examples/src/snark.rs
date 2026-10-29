// zk-SNARK: Groth16 on BN254, written with arkworks.
// (Same proof system ZoKrates uses in ../zokrates, but defined directly in Rust.)
//
// Pipeline:
//   1. Circuit   - the statement as R1CS constraints: rows of  <a,w> * <b,w> = <c,w>
//                  over a witness vector w = (1, public inputs, private inputs, temporaries)
//   2. Setup     - per-circuit trusted setup -> proving key (pk) + verifying key (vk).
//                  The randomness ("toxic waste") must be destroyed: whoever keeps it
//                  can forge proofs. Real deployments use multi-party ceremonies.
//   3. Prove     - pk + public inputs + private witness -> proof (3 group elements, 128 B)
//   4. Verify    - vk + public inputs + proof -> bool (3 pairings, ~ms, independent of circuit size)
//
// "Succinct": proof size and verify time don't grow with the circuit.
// "Zero-knowledge": the proof is randomised and reveals nothing about private inputs.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use rand::rngs::OsRng;

// ---------- circuit 1: the asecuritysite / ZoKrates example ----------
//
// Public a, b, c, y. Private x. Statement: a*x^2 + b*x + c == y.
// R1CS (each constraint is ONE multiplication):
//   x * x = x2
//   (a*x2 + b*x + c) * 1 = y     -> needs a*x2 and b*x: two more multiplications
#[derive(Clone)]
pub struct Quadratic {
    pub a: Fr,
    pub b: Fr,
    pub c: Fr,
    pub y: Fr,
    pub x: Option<Fr>, // None during setup: the circuit shape doesn't depend on the witness
}

impl ConstraintSynthesizer<Fr> for Quadratic {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs, in this order, are what the verifier supplies.
        let a = FpVar::new_input(cs.clone(), || Ok(self.a))?;
        let b = FpVar::new_input(cs.clone(), || Ok(self.b))?;
        let c = FpVar::new_input(cs.clone(), || Ok(self.c))?;
        let y = FpVar::new_input(cs.clone(), || Ok(self.y))?;
        // Private witness: only the prover knows it.
        let x = FpVar::new_witness(cs, || self.x.ok_or(SynthesisError::AssignmentMissing))?;

        let lhs = &a * &x * &x + &b * &x + &c;
        // Asserting (not returning a bool): a wrong x can't produce a proof at all.
        lhs.enforce_equal(&y)
    }
}

// ---------- circuit 2: knowledge of a factorisation ----------
//
// Public N. Private p, q. Statement: p * q == N, p != 1, q != 1.
// "!= 1" uses the standard trick: prove (p - 1) has an inverse, i.e. is non-zero.
#[derive(Clone)]
pub struct Factors {
    pub n: Fr,
    pub p: Option<Fr>,
    pub q: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Factors {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let n = FpVar::new_input(cs.clone(), || Ok(self.n))?;
        let p = FpVar::new_witness(cs.clone(), || self.p.ok_or(SynthesisError::AssignmentMissing))?;
        let q = FpVar::new_witness(cs, || self.q.ok_or(SynthesisError::AssignmentMissing))?;
        (&p * &q).enforce_equal(&n)?;
        p.enforce_not_equal(&FpVar::one())?;
        q.enforce_not_equal(&FpVar::one())
    }
}

pub fn constraint_count<C: ConstraintSynthesizer<Fr>>(circuit: C) -> usize {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.num_constraints()
}

pub fn demo() {
    let mut rng = OsRng;
    let fr = |v: u64| Fr::from(v);

    println!("-- circuit: a*x^2 + b*x + c == y (a=3, b=1, c=4, y=8; secret x=1) --");
    let shape = Quadratic { a: fr(3), b: fr(1), c: fr(4), y: fr(8), x: None };
    println!("R1CS constraints: {}", constraint_count(Quadratic { x: Some(fr(1)), ..shape.clone() }));

    // Setup only needs the circuit shape, not the secret.
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(shape.clone(), &mut rng).unwrap();
    let proof = Groth16::<Bn254>::prove(&pk, Quadratic { x: Some(fr(1)), ..shape.clone() }, &mut rng).unwrap();
    println!("proof size: {} bytes (compressed)", proof.compressed_size());
    println!("pk size: {} bytes, vk size: {} bytes", pk.compressed_size(), vk.compressed_size());

    let public = [fr(3), fr(1), fr(4), fr(8)];
    println!("verify (y=8):          {}", Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap());
    let wrong = [fr(3), fr(1), fr(4), fr(9)];
    println!("same proof for y=9:    {}", Groth16::<Bn254>::verify(&vk, &wrong, &proof).unwrap());
    // A cheating prover with a wrong x: the constraints aren't satisfied, so
    // arkworks refuses to build a proof (in release mode the proof would just fail to verify).
    let bad = Quadratic { x: Some(fr(2)), ..shape };
    println!("constraints hold for x=2: {}", satisfied(bad));

    println!("\n-- circuit: I know p, q (both != 1) with p*q == N, N = 3233 --");
    let shape = Factors { n: fr(3233), p: None, q: None };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(shape.clone(), &mut rng).unwrap();
    let proof = Groth16::<Bn254>::prove(&pk, Factors { p: Some(fr(61)), q: Some(fr(53)), ..shape.clone() }, &mut rng).unwrap();
    println!("verify:                       {}", Groth16::<Bn254>::verify(&vk, &[fr(3233)], &proof).unwrap());
    println!("trivial 1 * 3233 satisfies:   {}", satisfied(Factors { p: Some(fr(1)), q: Some(fr(3233)), ..shape }));
}

/// Would an honest proof be possible with this witness? Checks every R1CS row
/// <a_i, w> * <b_i, w> == <c_i, w> by hand, with w = (1, public inputs, witness).
pub fn satisfied<C: ConstraintSynthesizer<Fr>>(circuit: C) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    if circuit.generate_constraints(cs.clone()).is_err() {
        // The witness can't even be computed, e.g. "p != 1" needs 1/(p - 1) and p = 1.
        return false;
    }
    cs.finalize();
    let m = cs.to_matrices().unwrap();
    let cs = cs.borrow().unwrap();
    let w: Vec<Fr> = cs.instance_assignment.iter().chain(&cs.witness_assignment).copied().collect();
    let dot = |row: &Vec<(Fr, usize)>| row.iter().map(|(coeff, i)| *coeff * w[*i]).sum::<Fr>();
    (0..m.num_constraints).all(|i| dot(&m.a[i]) * dot(&m.b[i]) == dot(&m.c[i]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quadratic_roundtrip() {
        let mut rng = OsRng;
        let c = Quadratic { a: Fr::from(3), b: Fr::from(1), c: Fr::from(4), y: Fr::from(8), x: None };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c.clone(), &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, Quadratic { x: Some(Fr::from(1)), ..c.clone() }, &mut rng).unwrap();
        let ins = [Fr::from(3), Fr::from(1), Fr::from(4), Fr::from(8)];
        assert!(Groth16::<Bn254>::verify(&vk, &ins, &proof).unwrap());
        assert!(!Groth16::<Bn254>::verify(&vk, &[Fr::from(3), Fr::from(1), Fr::from(4), Fr::from(9)], &proof).unwrap());
        assert!(!satisfied(Quadratic { x: Some(Fr::from(2)), ..c }));
    }

    #[test]
    fn factors_reject_trivial() {
        let n = Fr::from(3233);
        assert!(satisfied(Factors { n, p: Some(Fr::from(61)), q: Some(Fr::from(53)) }));
        assert!(!satisfied(Factors { n, p: Some(Fr::from(1)), q: Some(n) }));
        assert!(!satisfied(Factors { n, p: Some(Fr::from(60)), q: Some(Fr::from(53)) }));
    }
}
