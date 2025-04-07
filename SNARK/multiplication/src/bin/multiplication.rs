// [dependencies]
// ark-bn254 = "0.3"
// ark-groth16 = "0.3"
// ark-relations = "0.3"
// ark-std = "0.3"
// ark-r1cs-std = "0.3"
// rand = "0.8"
// sha2 = "0.10"

use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_relations::lc;
use ark_std::test_rng;
//use std::ops::Mul;
use std::env;
use std::process;

/// This struct defines multiplication circuit for SNARK
struct MultiplicationCircuit {
    // Private inputs
    a: Option<Fr>,
    b: Option<Fr>,

    // Public input: expected product of a and b
    product: Option<Fr>,
}

/// Implement the constraint system for our circuit.
impl ConstraintSynthesizer<Fr> for MultiplicationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate the private witness 'a'
        let a_var = cs.new_witness_variable(|| {
            self.a.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate the private witness 'b'
        let b_var = cs.new_witness_variable(|| {
            self.b.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate the public input 'product'
        let product_var = cs.new_input_variable(|| {
            self.product.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce the multiplication constraint: a * b = product
        cs.enforce_constraint(
            lc!() + a_var,
            lc!() + b_var,
            lc!() + product_var,
        )?;

        Ok(())
    }
}

fn main() {
    let rng = &mut test_rng();

    // Define secret inputs: a = 3 and b = 5
    //let a = Fr::from(3u32);
    //let b = Fr::from(5u32);
    let args: Vec<String> = env::args().collect();
	if args.len() != 3 {
		eprintln!("Usage: {} <a> <b>", args[0]);
		process::exit(1);
	}
	let a_val: u128 = args[1].parse().expect("Failed to parse a as an integer");
	let b_val: u128 = args[2].parse().expect("Failed to parse b as an integer");

	let a = Fr::from(a_val);
	let b = Fr::from(b_val);

    // Compute the expected product
    let product = Fr::from(15);//a.mul(b);

    // Create an instance of the circuit with the witness values
    let circuit = MultiplicationCircuit {
        a: Some(a),
        b: Some(b),
        product: Some(product),
    };

    // Trusted Setup Phase: Generate the SNARK proving and verification keys using an empty circuit
    let empty_circuit = MultiplicationCircuit {
        a: None,
        b: None,
        product: None,
    };

    let params = generate_random_parameters::<Bn254, _, _>(empty_circuit, rng)
        .expect("Parameter generation failed");

    // Prepare the verification key for efficient verification.
    let pvk = prepare_verifying_key(&params.vk);

    // Proof Generation: Create a SNARK proof using the circuit with actual witness values
    let proof = create_random_proof(circuit, &params, rng)
        .expect("Proof generation failed");

    // Verification: Verify the proof by providing the public input (the product)
    // Public inputs in same order they were allocated

    // let wrong_product = Fr::from(10u32); // Incorrect product for testing
    
    let public_inputs = vec![product];
    // let public_inputs = vec![wrong_product];

    let is_valid = verify_proof(&pvk, &proof, &public_inputs)
        .expect("Proof verification failed");

    println!("SNARK proof is valid: {}", is_valid);
}
