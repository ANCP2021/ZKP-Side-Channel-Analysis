// To run, use this command: 
// 1. cargo build
// 2. cargo run --bin sha256

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

// build a trace for SHA256 computation
//
// - use the sha2 crate to compute the SHA256 hash of Hello World!
// - build a trace table with 9 columns: 8 for the hash words and a flag column for the same reason as multiplication
pub fn build_sha256_trace(data: &str) -> TraceTable<BaseElement> {
	// compute sha256
	let mut hasher = Sha256::new();
	hasher.update(data);
	let result = hasher.finalize();

	// convert the 32-byte hash into 8 u32 words
	let mut hash_words = [0u32; 8];
	for i in 0..8 {
		hash_words[i] = u32::from_be_bytes([
			result[4 * i],
			result[4 * i + 1],
			result[4 * i + 2],
			result[4 * i + 3],
		]);
	}

	// create a trace table with 9 columns and 8 rows
	// columns 0..7 store the hash words, column 8 is a flag
	let mut trace = TraceTable::new(9, 8);
	trace.fill(
		|state| {
			for i in 0..8 {
				state[i] = BaseElement::new(hash_words[i] as u128);
			}
			state[8] = BaseElement::ONE;
		},
		|step, state| {
			if step == 0 {
				for i in 0..8 {
					state[i] = state[i];
				}
				state[8] = BaseElement::ZERO;
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

pub struct Sha256Air {
	context: AirContext<BaseElement>,
}

impl Air for Sha256Air {
	type BaseField = BaseElement;
	type PublicInputs = ();

	fn new(trace_info: TraceInfo, _pub_inputs: (), options: ProofOptions) -> Self {
		// 9 transition constraints for each column
		let degrees = vec![TransitionConstraintDegree::new(1); 9];
		// need one assertion per hash word, which is 8
		let num_assertions = 8;
		Self {
			context: AirContext::new(trace_info, degrees, num_assertions, options),
		}
	}

	fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(&self, frame: &EvaluationFrame<E>, _periodic_values: &[E], out: &mut [E]) {
		// for columns 0..7, next = current
		for i in 0..8 {
			out[i] = frame.next()[i] - frame.current()[i];
		}
		// for the flag column. next flag must be 0.
		out[8] = frame.next()[8];
	}

	// check that in the last row the eight hash words equal the expected values, precomputed
	fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
		let last_step = self.trace_length() - 1;
		let expected = [
			BaseElement::new(0x7f83b165u128),
			BaseElement::new(0x7ff1fc53u128),
			BaseElement::new(0xb92dc181u128),
			BaseElement::new(0x48a1d65du128),
			BaseElement::new(0xfc2d4b1fu128),
			BaseElement::new(0xa3d67728u128),
			BaseElement::new(0x4addd200u128),
			BaseElement::new(0x126d9069u128),
		];
		let mut assertions = Vec::new();
		for (i, &exp) in expected.iter().enumerate() {
			assertions.push(Assertion::single(i, last_step, exp));
		}
		assertions
	}

	fn context(&self) -> &AirContext<Self::BaseField> {
		&self.context
	}
}

// basically same structure as the multiplication
struct Sha256Prover {
	options: ProofOptions,
}

impl Sha256Prover {
	pub fn new(options: ProofOptions) -> Self {
		Self { options }
	}
}

impl Prover for Sha256Prover {
	type BaseField = BaseElement;
	type Air = Sha256Air;
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
	let data = "Hello World!";
	let trace = build_sha256_trace(data);

	// debugging help
	let mut computed_hash = [BaseElement::ZERO; 8];
	for i in 0..8 {
		computed_hash[i] = trace.get(i, 0);
	}
	println!("Computed SHA256 hash: {:?}", computed_hash);

	// same proof options
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
	let prover = Sha256Prover::new(options);
	let proof = prover.prove(trace).expect("Proof generation failed");

	let min_opts = AcceptableOptions::MinConjecturedSecurity(95);
	let pub_inputs = ();
	assert!(
		winterfell::verify::<Sha256Air, Blake3_256<BaseElement>, DefaultRandomCoin<Blake3_256<BaseElement>>, MerkleTree<Blake3_256<BaseElement>>>(
			proof,
			pub_inputs,
			&min_opts,
		)
		.is_ok(),
		"SHA256 proof verification failed!"
	);
	println!("SHA256 proof verified successfully!");
}
