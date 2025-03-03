// To run, use this command: 
// 1. cargo build
// 2. cargo run --bin multiplication

// Code heavily followed documentation: https://docs.rs/winterfell/0.12.0/winterfell/index.html#examples

use winterfell::{
	math::{fields::f128::BaseElement, FieldElement},
	TraceTable,
	Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
	TransitionConstraintDegree,
	CompositionPoly, CompositionPolyTrace, DefaultConstraintCommitment,
	DefaultTraceLde, Prover, StarkDomain, Trace, TracePolyTable,
	PartitionOptions, AuxRandElements, DefaultConstraintEvaluator, ConstraintCompositionCoefficients,
	crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
	matrix::ColMatrix,
	AcceptableOptions, FieldExtension, BatchingMethod,
};

// build a trace with length 8 using three columns:
// - Column 0: running value
// - Column 1: secret multiplier b
// - Column 2: a flag that is 1 at the multiplication transition and 0 thereafter, 
// 				due to winterfell requireing minimum 8 rows but only 2 are needed, this is tracked for evaluate_transition
pub fn build_multiplication_trace(a: BaseElement, b: BaseElement) -> TraceTable<BaseElement> {
	let mut trace = TraceTable::new(3, 8);

	trace.fill(
		|state| {
			state[0] = a;
			state[1] = b;
			state[2] = BaseElement::ONE; // flag set to 1
		},
		|step, state| {
			if step == 0 {
				let prod = state[0] * state[1];
				state[0] = prod;              // update running value to a * b
				state[1] = state[1];          // propagate b
				state[2] = BaseElement::ZERO; // turn off flag
			} else {
				// for steps 1...7, simply propagate
				state[0] = state[0];
				state[1] = state[1];
				state[2] = BaseElement::ZERO; // flag remains off
			}
		},
	);
	trace
}

// the AIR struct, contains metadata, see implementation next
pub struct MultiplicationAir {
	context: AirContext<BaseElement>,
}

impl Air for MultiplicationAir {
	type BaseField = BaseElement;
	type PublicInputs = ();

	fn new(trace_info: TraceInfo, _pub_inputs: (), options: ProofOptions) -> Self {

		// three transition constraints
		let degrees = vec![
			TransitionConstraintDegree::new(2), // constraint on column 0 (multiplication)
			TransitionConstraintDegree::new(1), // constraint on column 1 (constant)
			TransitionConstraintDegree::new(1), // constraint on column 2 (flag)
		];
		let num_assertions = 1; // only check final value

		MultiplicationAir {
			context: AirContext::new(trace_info, degrees, num_assertions, options),
		}
	}

	fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(&self, frame: &EvaluationFrame<E>, _periodic_values: &[E], out: &mut [E]) {
		let flag = frame.current()[2];

		// makes sure the computation is done if expected
		let expected_next = flag * (frame.current()[0] * frame.current()[1]) + (E::from(1u32) - flag) * frame.current()[0];
		out[0] = frame.next()[0] - expected_next;

		// enforce that column 1 (b) remains constant
		out[1] = frame.next()[1] - frame.current()[1];

		// enforce flag behavior: next flag must be 0
		out[2] = frame.next()[2];
	}

	fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
		let last_step = self.trace_length() - 1;
		vec![Assertion::single(0, last_step, BaseElement::new(15))]
	}

	fn context(&self) -> &AirContext<Self::BaseField> {
		&self.context
	}
}

// lines 95 - 160 might have things that seem useless such as get_pub_inputs since there are no public inputs,
// but they are needed for rust to compile with winterfell
struct MultiplicationProver {
	options: ProofOptions,
}

impl MultiplicationProver {
	pub fn new(options: ProofOptions) -> Self {
		Self { options }
	}
}

impl Prover for MultiplicationProver {
	type BaseField = BaseElement;
	type Air = MultiplicationAir;
	type Trace = winterfell::TraceTable<Self::BaseField>;
	type HashFn = Blake3_256<Self::BaseField>;
	type VC = MerkleTree<Self::HashFn>;
	type RandomCoin = DefaultRandomCoin<Self::HashFn>;
	type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
		DefaultTraceLde<E, Self::HashFn, Self::VC>;
	type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
		DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
	type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
		DefaultConstraintEvaluator<'a, Self::Air, E>;

	// No public inputs
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
	// secret inputs (e.g., a = 3 and b = 5).
	let a = BaseElement::new(3);
	let b = BaseElement::new(5);

	// build the trace with 8 rows
	let trace = build_multiplication_trace(a, b);
	let trace_length = trace.length();
	let final_value = trace.get(0, trace_length - 1);
	println!("Computed product: {:?}", final_value);

	// set proof options, these are from https://docs.rs/winterfell/0.12.0/winterfell/index.html#examples for ~96-bit security level.
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

	let prover = MultiplicationProver::new(options);
	let proof = prover.prove(trace).unwrap();

	let min_opts = AcceptableOptions::MinConjecturedSecurity(95);
	let pub_inputs = ();

	assert!(winterfell::verify::<MultiplicationAir,
								  Blake3_256<BaseElement>,
								  DefaultRandomCoin<Blake3_256<BaseElement>>,
								  MerkleTree<Blake3_256<BaseElement>>
								  >(proof, pub_inputs, &min_opts).is_ok());
}
