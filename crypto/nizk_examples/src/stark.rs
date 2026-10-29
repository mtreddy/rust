// zk-STARK style proof with Winterfell: prove a long computation was done correctly.
//
// Computation (a MiMC-like hash chain over a 128-bit prime field):
//     s_0 = start,   s_{i+1} = s_i^3 + 42,   result = s_{n-1}
//
// Pipeline:
//   1. Execution trace  - table of every intermediate state (here 1 column, n rows)
//   2. AIR              - polynomial constraints every pair of rows must satisfy:
//                           transition:  next - (cur^3 + 42) = 0
//                           boundary:    row 0 = start, row n-1 = result
//   3. Prover           - interpolates the trace as a polynomial, evaluates it on a
//                         larger domain (blowup), commits with a Merkle tree (hashes),
//                         and uses FRI to prove the constraint quotient is a low-degree
//                         polynomial, which is only possible if the constraints hold
//                         on every row
//   4. Verifier         - checks a few random Merkle openings + FRI: polylog(n) work
//
// Properties: no trusted setup (transparent), only hash functions (plausibly
// post-quantum), proof ~tens of KB, verification much faster than re-running.
//
// Note: Winterfell proves computational INTEGRITY; its proofs are not
// zero-knowledge (the trace isn't masked). Here everything is public anyway: the
// point is that the verifier doesn't have to re-run 65,536 steps. Production
// zk-STARKs add randomised trace masking to also hide private inputs.

use std::time::Instant;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension, PartitionOptions,
    Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
};

type Hasher = Blake3_256<BaseElement>;

pub fn run_computation(start: BaseElement, n: usize) -> BaseElement {
    let mut s = start;
    for _ in 1..n {
        s = s.exp(3) + BaseElement::new(42);
    }
    s
}

fn build_trace(start: BaseElement, n: usize) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(1, n);
    trace.fill(|state| state[0] = start, |_, state| state[0] = state[0].exp(3u32.into()) + BaseElement::new(42));
    trace
}

// ---------- AIR: the constraints ----------

#[derive(Clone, Copy)]
pub struct PublicInputs {
    pub start: BaseElement,
    pub result: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.start, self.result]
    }
}

pub struct ChainAir {
    context: AirContext<BaseElement>,
    pub_inputs: PublicInputs,
}

impl Air for ChainAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        // One transition constraint of degree 3 (cur^3), two boundary assertions.
        let degrees = vec![TransitionConstraintDegree::new(3)];
        ChainAir { context: AirContext::new(trace_info, degrees, 2, options), pub_inputs }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current()[0];
        result[0] = frame.next()[0] - (cur.exp(3u32.into()) + E::from(42u32));
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.trace_length() - 1;
        vec![Assertion::single(0, 0, self.pub_inputs.start), Assertion::single(0, last, self.pub_inputs.result)]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// ---------- Prover: mostly Winterfell defaults ----------

struct ChainProver {
    options: ProofOptions,
}

impl Prover for ChainProver {
    type BaseField = BaseElement;
    type Air = ChainAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Hasher;
    type VC = MerkleTree<Hasher>;
    type RandomCoin = DefaultRandomCoin<Hasher>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Hasher, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> = DefaultConstraintCommitment<E, Hasher, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> = DefaultConstraintEvaluator<'a, ChainAir, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        PublicInputs { start: trace.get(0, 0), result: trace.get(0, trace.length() - 1) }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = BaseElement>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<BaseElement>,
        domain: &StarkDomain<BaseElement>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = BaseElement>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_columns: usize,
        domain: &StarkDomain<BaseElement>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(composition_poly_trace, num_columns, domain, partition_options)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a ChainAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, coefficients)
    }
}

fn options() -> ProofOptions {
    ProofOptions::new(
        32,                   // queries: more -> more security, bigger proof
        8,                    // blowup factor of the low-degree extension
        0,                    // grinding (proof-of-work) bits
        FieldExtension::None, // f128 is big enough without an extension field
        8,                    // FRI folding factor
        31,                   // FRI max remainder degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

pub fn prove(start: BaseElement, n: usize) -> (PublicInputs, Proof) {
    let trace = build_trace(start, n);
    let prover = ChainProver { options: options() };
    let pub_inputs = prover.get_pub_inputs(&trace);
    (pub_inputs, prover.prove(trace).expect("proving failed"))
}

pub fn verify(proof: Proof, pub_inputs: PublicInputs) -> bool {
    let min = AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<ChainAir, Hasher, DefaultRandomCoin<Hasher>, MerkleTree<Hasher>>(proof, pub_inputs, &min).is_ok()
}

pub fn demo() {
    let start = BaseElement::new(3);
    let n = 1 << 16; // 65,536 steps (trace length must be a power of two)

    let t = Instant::now();
    let result = run_computation(start, n);
    let rerun = t.elapsed();

    let t = Instant::now();
    let (pub_inputs, proof) = prove(start, n);
    let prove_time = t.elapsed();
    assert_eq!(pub_inputs.result, result);
    let size = proof.to_bytes().len();
    println!("-- s_(i+1) = s_i^3 + 42 for {n} steps, start = 3 --");
    println!("result:            {result}");
    println!("proof size:        {size} bytes, conjectured security {} bits", proof.conjectured_security::<Hasher>().bits());
    println!("prove time:        {prove_time:.2?}");

    let t = Instant::now();
    let ok = verify(proof.clone(), pub_inputs);
    println!("verify:            {ok} in {:.2?} (re-running the computation: {rerun:.2?})", t.elapsed());

    let lie = PublicInputs { result: result + BaseElement::ONE, ..pub_inputs };
    println!("claim result + 1:  {}", verify(proof, lie));
    println!("(re-running costs grow linearly with the steps; verify grows polylogarithmically)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stark_roundtrip_and_wrong_claims() {
        let start = BaseElement::new(5);
        let (pi, proof) = prove(start, 1 << 10);
        assert_eq!(pi.result, run_computation(start, 1 << 10));
        assert!(verify(proof.clone(), pi));
        assert!(!verify(proof.clone(), PublicInputs { result: pi.result + BaseElement::ONE, ..pi }));
        assert!(!verify(proof, PublicInputs { start: BaseElement::new(6), ..pi }));
    }
}
