// Use case: prove "I am at least 18" without revealing your birth year.
// Every R1CS row is written by hand here, so you can see exactly what the
// proof checks. (snark.rs uses arkworks gadgets that generate rows for you.)
//
// Roles
//   Issuer   (e.g. a government ID office) knows Alice's birth year B, picks a
//            random salt S, and publishes/signs the credential commitment
//                C = MiMC_S(B) + B
//            Alice stores (B, S). The commitment hides B (S is random) and binds
//            Alice to one B (she can't find another (B', S') with the same C).
//   Alice    proves to a website, in zero knowledge:
//                "I know (B, S) with Hash(B, S) = C  and  Y - B >= 18"
//   Website  checks the proof against public (C, Y = 2026, M = 18). It learns
//            nothing about B except that the statement is true.
//
// Witness vector w = (1, C, Y, M | B, S, round values..., bits d0..d7)
//                    └ public ─┘   └────────── private ──────────┘
//
// Circuit sections
//   1. Hash:   MiMC-7, 91 rounds. Each round t = x + S + c_i (free, linear),
//              then x' = t^7 using 4 multiplications:
//                  t*t = t2,  t2*t2 = t4,  t4*t2 = t6,  t6*t = x'
//              plus 1 row checking (x + S + B) * 1 = C.
//   2. Age:    D = Y - B - M must be in [0, 256). Field elements wrap around:
//              an under-age D = -8 is really p - 8, a 254-bit number. So
//              decompose D into 8 bits:
//                  d_i * (1 - d_i) = 0         (each d_i is 0 or 1)  x 8 rows
//                  (sum 2^i d_i) * 1 = Y - B - M                      x 1 row
//              8 bits can only represent 0..255, so D can't be "negative".
//
// MiMC is used because it's simple to write as R1CS. Production systems use
// Poseidon (fewer rows) and audited gadgets; this is for learning.

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_groth16::Groth16;
use ark_relations::lc;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ark_snark::SNARK;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const ROUNDS: usize = 91; // ceil(log_7(p)) for BN254: enough rounds for x^7 MiMC
const AGE_BITS: usize = 8;

/// Round constants: "nothing up my sleeve" values derived by hashing.
fn round_constants() -> Vec<Fr> {
    (0..ROUNDS)
        .map(|i| Fr::from_le_bytes_mod_order(&Sha256::digest(format!("age-proof/mimc/{i}"))))
        .collect()
}

/// Native (outside the circuit) commitment, computed by the issuer.
pub fn commit(birth_year: Fr, salt: Fr) -> Fr {
    let mut x = birth_year;
    for c in round_constants() {
        x = (x + salt + c).pow([7u64]);
    }
    x + salt + birth_year // MiMC encryption output (x + key), plus feed-forward of B
}

// ---------- a tiny R1CS builder that remembers variable names ----------

/// A linear combination together with its value (None during setup).
#[derive(Clone)]
struct Wire {
    lc: LinearCombination<Fr>,
    val: Option<Fr>,
}

struct Builder {
    cs: ConstraintSystemRef<Fr>,
    inst_names: Vec<String>,
    wit_names: Vec<String>,
    sections: Vec<(String, usize, usize)>, // (label, first row, end row)
}

impl Builder {
    fn new(cs: ConstraintSystemRef<Fr>) -> Self {
        Builder { cs, inst_names: vec!["1".into()], wit_names: vec![], sections: vec![] }
    }

    fn input(&mut self, name: &str, v: Fr) -> Result<Wire, SynthesisError> {
        let var = self.cs.new_input_variable(|| Ok(v))?;
        self.inst_names.push(name.into());
        Ok(Wire { lc: lc!() + var, val: Some(v) })
    }

    fn witness(&mut self, name: &str, v: Option<Fr>) -> Result<Wire, SynthesisError> {
        let var = self.cs.new_witness_variable(|| v.ok_or(SynthesisError::AssignmentMissing))?;
        self.wit_names.push(name.into());
        Ok(Wire { lc: lc!() + var, val: v })
    }

    /// One R1CS row: allocate out = a * b and enforce  a * b = out.
    fn mul(&mut self, name: &str, a: &Wire, b: &Wire) -> Result<Wire, SynthesisError> {
        let out = self.witness(name, a.val.zip(b.val).map(|(x, y)| x * y))?;
        self.cs.enforce_constraint(a.lc.clone(), b.lc.clone(), out.lc.clone())?;
        Ok(out)
    }

    /// One R1CS row: enforce  a * 1 = b  (a linear equality costs a row too).
    fn equal(&mut self, a: &Wire, b: &Wire) -> Result<(), SynthesisError> {
        self.cs.enforce_constraint(a.lc.clone(), lc!() + Variable::One, b.lc.clone())
    }

    fn section<T>(&mut self, label: &str, f: impl FnOnce(&mut Self) -> Result<T, SynthesisError>) -> Result<T, SynthesisError> {
        let start = self.cs.num_constraints();
        let out = f(self)?;
        self.sections.push((label.into(), start, self.cs.num_constraints()));
        Ok(out)
    }
}

// Linear operations: no rows, they just build bigger linear combinations.
fn add(a: &Wire, b: &Wire) -> Wire {
    Wire { lc: &a.lc + &b.lc, val: a.val.zip(b.val).map(|(x, y)| x + y) }
}
fn sub(a: &Wire, b: &Wire) -> Wire {
    Wire { lc: &a.lc - &b.lc, val: a.val.zip(b.val).map(|(x, y)| x - y) }
}
fn add_const(a: &Wire, c: Fr) -> Wire {
    Wire { lc: a.lc.clone() + (c, Variable::One), val: a.val.map(|x| x + c) }
}
fn scale(a: &Wire, c: Fr) -> Wire {
    Wire { lc: &a.lc * c, val: a.val.map(|x| x * c) }
}

// ---------- the circuit ----------

#[derive(Clone)]
pub struct AgeCircuit {
    // public
    pub commitment: Fr,
    pub current_year: Fr,
    pub min_age: Fr,
    // private
    pub birth_year: Option<Fr>,
    pub salt: Option<Fr>,
    /// false = the BUGGY version that forgets the range check
    pub range_check: bool,
}

impl AgeCircuit {
    fn build(self, cs: ConstraintSystemRef<Fr>) -> Result<Builder, SynthesisError> {
        let mut b = Builder::new(cs);
        let c_pub = b.input("C", self.commitment)?;
        let y = b.input("Y", self.current_year)?;
        let m = b.input("M", self.min_age)?;
        let birth = b.witness("B", self.birth_year)?;
        let salt = b.witness("S", self.salt)?;

        // 1. C == MiMC_S(B) + B
        b.section("hash: C = MiMC_S(B) + B", |b| {
            let mut x = birth.clone();
            for (i, c) in round_constants().into_iter().enumerate() {
                let t = add_const(&add(&x, &salt), c); // free
                let t2 = b.mul(&format!("t2_{i}"), &t, &t)?;
                let t4 = b.mul(&format!("t4_{i}"), &t2, &t2)?;
                let t6 = b.mul(&format!("t6_{i}"), &t4, &t2)?;
                x = b.mul(&format!("x_{}", i + 1), &t6, &t)?;
            }
            b.equal(&add(&add(&x, &salt), &birth), &c_pub)
        })?;

        // 2. D = Y - B - M in [0, 2^8)
        if self.range_check {
            b.section("age: Y - B - M in [0, 256)", |b| {
                let d = sub(&sub(&y, &birth), &m); // free
                let d_bits = d.val.map(|v| v.into_bigint());
                let mut sum = Wire { lc: lc!(), val: Some(Fr::from(0u64)) };
                for i in 0..AGE_BITS {
                    let bit_val = d_bits.as_ref().map(|bits| Fr::from(bits.get_bit(i) as u64));
                    let bit = b.witness(&format!("d{i}"), bit_val)?;
                    // d_i * (1 - d_i) = 0
                    let one_minus = add_const(&scale(&bit, -Fr::from(1u64)), Fr::from(1u64));
                    b.cs.enforce_constraint(bit.lc.clone(), one_minus.lc, lc!())?;
                    sum = add(&sum, &scale(&bit, Fr::from(1u64 << i)));
                }
                b.equal(&sum, &d)
            })?;
        }
        Ok(b)
    }
}

impl ConstraintSynthesizer<Fr> for AgeCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        self.build(cs).map(|_| ())
    }
}

// ---------- inspecting the R1CS ----------

/// Render one linear combination, e.g. "c0 + B + S" or "Y - M - B".
/// Index 0 is the constant-1 variable; round constants are shown by name.
fn fmt_lc(row: &[(Fr, usize)], name: &dyn Fn(usize) -> String, consts: &[Fr]) -> String {
    if row.is_empty() {
        return "0".into();
    }
    let term = |(c, i): &(Fr, usize)| {
        // Show p - k as -k so negative coefficients are readable.
        let (neg, mag) = if (-*c).into_bigint().num_bits() < c.into_bigint().num_bits() { (true, -*c) } else { (false, *c) };
        let body = match (*i, consts.iter().position(|k| *k == mag)) {
            (0, Some(r)) => format!("c{r}"),
            (0, None) => mag.to_string(),
            (_, _) if mag == Fr::from(1u64) => name(*i),
            _ => format!("{mag}·{}", name(*i)),
        };
        (neg, body)
    };
    let mut out = String::new();
    for (k, t) in row.iter().enumerate() {
        let (neg, body) = term(t);
        out += &match (k, neg) {
            (0, false) => body,
            (0, true) => format!("-{body}"),
            (_, false) => format!(" + {body}"),
            (_, true) => format!(" - {body}"),
        };
    }
    out
}

/// Print a section summary and selected rows as  (a) * (b) = (c)  with named variables.
fn print_r1cs(circuit: AgeCircuit, show: &[std::ops::Range<usize>]) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let b = circuit.build(cs.clone()).unwrap();
    cs.finalize();
    let m = cs.to_matrices().unwrap();
    let n_inst = m.num_instance_variables;
    let name = |i: usize| if i < n_inst { b.inst_names[i].clone() } else { b.wit_names[i - n_inst].clone() };
    let consts = round_constants();
    let fmt = |row: &Vec<(Fr, usize)>| fmt_lc(row, &name, &consts);

    println!("witness w = ({} | {} ...)", b.inst_names.join(", "), b.wit_names[..2].join(", "));
    println!("variables: {} public (incl. 1), {} private; rows: {}", n_inst, m.num_witness_variables, m.num_constraints);
    for (label, start, end) in &b.sections {
        println!("  {:<30} {:>4} rows  (#{start}..#{})", label, end - start, end - 1);
    }
    for range in show {
        println!("  ...");
        for i in range.clone() {
            println!("  #{i:<3} ({}) * ({}) = ({})", fmt(&m.a[i]), fmt(&m.b[i]), fmt(&m.c[i]));
        }
    }
}

/// Check every row  <a,w> * <b,w> = <c,w>  for a concrete witness.
pub fn satisfied(circuit: AgeCircuit) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    if circuit.generate_constraints(cs.clone()).is_err() {
        return false;
    }
    cs.finalize();
    let m = cs.to_matrices().unwrap();
    let cs = cs.borrow().unwrap();
    let w: Vec<Fr> = cs.instance_assignment.iter().chain(&cs.witness_assignment).copied().collect();
    let dot = |row: &Vec<(Fr, usize)>| row.iter().map(|(c, i)| *c * w[*i]).sum::<Fr>();
    (0..m.num_constraints).all(|i| dot(&m.a[i]) * dot(&m.b[i]) == dot(&m.c[i]))
}

// ---------- demo ----------

pub fn demo() {
    let mut rng = OsRng;
    let (year, min_age) = (Fr::from(2026u64), Fr::from(18u64));
    let random_salt = || Fr::from_le_bytes_mod_order(&rand::random::<[u8; 32]>());

    // Issuer creates credentials.
    let (alice_b, alice_s) = (Fr::from(1990u64), random_salt());
    let alice_c = commit(alice_b, alice_s);
    let (bob_b, bob_s) = (Fr::from(2015u64), random_salt()); // Bob is 11
    let bob_c = commit(bob_b, bob_s);
    println!("issuer: Alice's credential C = {}", alice_c);

    let circuit = |c, b, s, range_check| AgeCircuit {
        commitment: c,
        current_year: year,
        min_age,
        birth_year: b,
        salt: s,
        range_check,
    };
    let alice = circuit(alice_c, Some(alice_b), Some(alice_s), true);

    println!("\n-- the R1CS --");
    // Round 0 of the hash (rows 0..4), the last hash row, and the whole age section.
    let hash_rows = ROUNDS * 4 + 1;
    print_r1cs(alice.clone(), &[0..4, hash_rows - 1..hash_rows, hash_rows..hash_rows + 3, hash_rows + 7..hash_rows + 9]);

    println!("\n-- Alice (born 1990) proves age >= 18 --");
    let shape = circuit(alice_c, None, None, true); // setup needs only the shape
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(shape, &mut rng).unwrap();
    let proof = Groth16::<Bn254>::prove(&pk, alice.clone(), &mut rng).unwrap();
    let public = [alice_c, year, min_age];
    println!("website sees only (C, 2026, 18) + 128-byte proof");
    println!("verify:                          {}", Groth16::<Bn254>::verify(&vk, &public, &proof).unwrap());
    println!("same proof with Bob's C:         {}", Groth16::<Bn254>::verify(&vk, &[bob_c, year, min_age], &proof).unwrap());
    println!("same proof claiming age >= 50:   {}", Groth16::<Bn254>::verify(&vk, &[alice_c, year, Fr::from(50u64)], &proof).unwrap());
    println!("Alice can satisfy age >= 50:     {}", satisfied(AgeCircuit { min_age: Fr::from(50u64), ..alice.clone() }));
    println!("Alice lies, says born 1980:      {}", satisfied(circuit(alice_c, Some(Fr::from(1980u64)), Some(alice_s), true)));

    println!("\n-- Bob (born 2015, age 11) tries --");
    let bob = circuit(bob_c, Some(bob_b), Some(bob_s), true);
    println!("correct circuit satisfiable:     {}", satisfied(bob));
    println!("  (D = 2026 - 2015 - 18 = -7 = p - 7: its low 8 bits don't add back up to D)");

    println!("\n-- BUG: the same circuit without the range check --");
    let buggy_shape = circuit(bob_c, None, None, false);
    let (pk_bug, vk_bug) = Groth16::<Bn254>::circuit_specific_setup(buggy_shape, &mut rng).unwrap();
    let bob_bug = circuit(bob_c, Some(bob_b), Some(bob_s), false);
    println!("buggy circuit satisfiable:       {}", satisfied(bob_bug.clone()));
    let forged = Groth16::<Bn254>::prove(&pk_bug, bob_bug, &mut rng).unwrap();
    println!("11-year-old's proof verifies:    {}", Groth16::<Bn254>::verify(&vk_bug, &[bob_c, year, min_age], &forged).unwrap());
    println!("  -> without the range check nothing constrains Y - B - M at all.");
    println!("     Under-constrained circuits are the #1 real-world SNARK bug.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(b: u64, s: u64, range_check: bool) -> AgeCircuit {
        let (b, s) = (Fr::from(b), Fr::from(s));
        AgeCircuit {
            commitment: commit(b, s),
            current_year: Fr::from(2026u64),
            min_age: Fr::from(18u64),
            birth_year: Some(b),
            salt: Some(s),
            range_check,
        }
    }

    #[test]
    fn boundaries() {
        assert!(satisfied(c(2008, 7, true))); // exactly 18
        assert!(!satisfied(c(2009, 7, true))); // 17
        assert!(satisfied(c(1771, 7, true))); // D = 237, fits in 8 bits
        assert!(!satisfied(c(1700, 7, true))); // D = 308, too old for 8 bits (documented limit)
    }

    #[test]
    fn wrong_salt_or_commitment_fails() {
        let mut x = c(1990, 7, true);
        x.salt = Some(Fr::from(8u64));
        assert!(!satisfied(x));
    }

    #[test]
    fn buggy_circuit_accepts_minor() {
        assert!(!satisfied(c(2015, 7, true)));
        assert!(satisfied(c(2015, 7, false)));
    }

    #[test]
    fn row_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c(1990, 7, true).generate_constraints(cs.clone()).unwrap();
        assert_eq!(cs.num_constraints(), ROUNDS * 4 + 1 + AGE_BITS + 1);
    }

    #[test]
    fn groth16_roundtrip() {
        let mut rng = OsRng;
        let x = c(1990, 7, true);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(x.clone(), &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, x.clone(), &mut rng).unwrap();
        assert!(Groth16::<Bn254>::verify(&vk, &[x.commitment, x.current_year, x.min_age], &proof).unwrap());
    }
}
