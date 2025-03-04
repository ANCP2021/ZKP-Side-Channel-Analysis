// To run, use this command: 
// 1. cargo build
// 2. cargo run --bin merkle

// Some code explainations done in multiplication.rs file, check there

use sha2::{Digest, Sha256};
use winterfell::{
	math::{fields::f128::BaseElement, FieldElement},
	Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
	TransitionConstraintDegree, CompositionPoly, CompositionPolyTrace,
	DefaultConstraintCommitment, DefaultTraceLde, Prover, StarkDomain,
	TraceTable, TracePolyTable, PartitionOptions, AuxRandElements,
	DefaultConstraintEvaluator, ConstraintCompositionCoefficients,
	crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
	matrix::ColMatrix,
	AcceptableOptions, FieldExtension, BatchingMethod,
};

fn compute_sha256_words(data: &str) -> [u32; 8] {
	let mut hasher = Sha256::new();
	hasher.update(data.as_bytes());
	let result = hasher.finalize();
	let mut words = [0u32; 8];
	for i in 0..8 {
		words[i] = u32::from_be_bytes([
			result[4 * i],
			result[4 * i + 1],
			result[4 * i + 2],
			result[4 * i + 3],
		]);
	}
	words
}

fn hash_pair(left: [u32; 8], right: [u32; 8]) -> [u32; 8] {
	let mut bytes = Vec::with_capacity(8 * 4 * 2);
	for &w in left.iter() {
		bytes.extend(&w.to_be_bytes());
	}
	for &w in right.iter() {
		bytes.extend(&w.to_be_bytes());
	}
	compute_sha256_words(&String::from_utf8_lossy(&bytes))
}

// 9 columns (columns 0..7 are the hash words, column 8 is a flag) and 8 rows, so,
// - row 0 - store the hash of the leaf
// - row 1 - store the result of hash_pair(hl1, hl2)
// - row 2 - store the result of hash_pair(row1, h34)
// - row 3..7 - simply propagate the final hash
fn build_merkle_trace() -> TraceTable<BaseElement> {
	let l1 = "L1";
	let l2 = "L2";
	let l3 = "L3";
	let l4 = "L4";

	let hl1 = compute_sha256_words(l1);
	let hl2 = compute_sha256_words(l2);
	let hl3 = compute_sha256_words(l3);
	let hl4 = compute_sha256_words(l4);

	let h34 = hash_pair(hl3, hl4);

	let leaf_hash = hl2;
	let inter_hash = hash_pair(hl1, leaf_hash);
	let final_hash = hash_pair(inter_hash, h34);

	let mut trace = TraceTable::new(9, 8);
	trace.fill(
		|state| {
			for i in 0..8 {
				state[i] = BaseElement::new(leaf_hash[i] as u128);
			}
			state[8] = BaseElement::ONE;
		},
		|step, state| {
			if step == 0 {
				for i in 0..8 {
					state[i] = BaseElement::new(inter_hash[i] as u128);
				}
				state[8] = BaseElement::ONE;
			} else if step == 1 {
				for i in 0..8 {
					state[i] = BaseElement::new(final_hash[i] as u128);
				}
				state[8] = BaseElement::ONE;
			} else {
				for i in 0..8 {
					state[i] = state[i];
				}
				state[8] = BaseElement::ZERO;
			}
		},
	);
	trace
}

pub struct MerkleAir {
	context: AirContext<BaseElement>,
}

impl Air for MerkleAir {
	type BaseField = BaseElement;
	type PublicInputs = ();

	fn new(trace_info: TraceInfo, _pub_inputs: (), options: ProofOptions) -> Self {
		// 1 constraint per column, all degree 2
		let degrees = vec![TransitionConstraintDegree::new(2); 9];
		// 1 assert per word
		let num_assertions = 8;
		Self {
			context: AirContext::new(trace_info, degrees, num_assertions, options),
		}
	}

	fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(&self, frame: &EvaluationFrame<E>, _periodic_values: &[E], out: &mut [E]) {
		let one = E::from(1u32);
		let flag = frame.current()[8];
		// enforce that once flag is 0, the values are constant
		for i in 0..8 {
			out[i] = (one - flag) * (frame.next()[i] - frame.current()[i]);
		}
		// if current flag is 0 then next flag must be 0 too
		out[8] = flag * frame.next()[8] - frame.next()[8];
	}
	
	fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
		let last_step = self.trace_length() - 1;

		let expected = [
			2979419580u32,
			3741653137u32,
			1409103455u32,
			1378847554u32,
			2286745112u32,
			1103954196u32,
			1149985725u32,
			320578323u32,
		];

		let mut assertions = Vec::new();
		for (i, &word) in expected.iter().enumerate() {
			assertions.push(Assertion::single(i, last_step, BaseElement::new(word as u128)));
		}
		assertions
	}

	fn context(&self) -> &AirContext<Self::BaseField> {
		&self.context
	}
}

struct MerkleProver {
	options: ProofOptions,
}

impl MerkleProver {
	pub fn new(options: ProofOptions) -> Self {
		Self { options }
	}
}

impl Prover for MerkleProver {
	type BaseField = BaseElement;
	type Air = MerkleAir;
	type Trace = TraceTable<Self::BaseField>;
	type HashFn = Blake3_256<Self::BaseField>;
	type VC = MerkleTree<Self::HashFn>;
	type RandomCoin = DefaultRandomCoin<Self::HashFn>;
	type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
	type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> = DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
	type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> = DefaultConstraintEvaluator<'a, Self::Air, E>;

	fn get_pub_inputs(&self, _trace: &Self::Trace) -> () {
		()
	}

	fn options(&self) -> &ProofOptions {
		&self.options
	}

	fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(&self, trace_info: &TraceInfo, main_trace: &ColMatrix<Self::BaseField>, domain: &StarkDomain<Self::BaseField>, partition_option: PartitionOptions) -> (Self::TraceLde<E>, TracePolyTable<E>) {
		DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
	}

	fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(&self, composition_poly_trace: CompositionPolyTrace<E>, num_constraint_composition_columns: usize, domain: &StarkDomain<Self::BaseField>, partition_options: PartitionOptions) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
		DefaultConstraintCommitment::new(
			composition_poly_trace,
			num_constraint_composition_columns,
			domain,
			partition_options,
		)
	}

	fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(&self, air: &'a Self::Air, aux_rand_elements: Option<AuxRandElements<E>>, composition_coefficients: ConstraintCompositionCoefficients<E>) -> Self::ConstraintEvaluator<'a, E> {
		DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
	}
}

fn main() {
	let trace = build_merkle_trace();

	// for debugging
	let mut final_hash = [BaseElement::ZERO; 8];
	for i in 0..8 {
		final_hash[i] = trace.get(i, 2);
	}
	println!("Computed Merkle root: {:?}", final_hash);

	// set proof options
	let options = ProofOptions::new(
		32, // number of queries
		8,  // blowup factor
		0,  // grinding factor
		FieldExtension::None,
		8,  // FRI folding factor
		31, // FRI max remainder polynomial degree
		BatchingMethod::Linear,
		BatchingMethod::Linear,
	);

	let prover = MerkleProver::new(options);
	let proof = prover.prove(trace).expect("Proof generation failed");

	let min_opts = AcceptableOptions::MinConjecturedSecurity(95);
	let pub_inputs = ();
	assert!(
		winterfell::verify::<MerkleAir, Blake3_256<BaseElement>, DefaultRandomCoin<Blake3_256<BaseElement>>, MerkleTree<Blake3_256<BaseElement>>>(
			proof,
			pub_inputs,
			&min_opts,
		)
		.is_ok(),
		"Merkle proof verification failed!"
	);
	println!("Merkle proof verified successfully!");
}
