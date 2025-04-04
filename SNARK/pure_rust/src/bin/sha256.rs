// [dependencies]
// ark-std = "0.4"
// ark-relations = "0.4"
// ark-r1cs-std = "0.4"
// ark-crypto-primitives = { version = "0.4", features = ["r1cs", "crh"] }
// ark-groth16 = "0.4"
// ark-bn254 = "0.4"
// ark-snark = "0.4"
// sha2 = "0.10"
// rand = "0.8"

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_crypto_primitives::crh::constraints::CRHSchemeGadget;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, prepare_verifying_key, Proof};
use ark_r1cs_std::{alloc::AllocVar, prelude::*, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::{rand::SeedableRng, vec::Vec};
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use ark_r1cs_std::prelude::*;
use ark_crypto_primitives::crh::sha256::constraints::UnitVar;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_r1cs_std::fields::fp::FpVar;


struct Sha256Circuit {
    pub preimage: Option<[u8; 64]>,
    pub image: Option<[u8; 32]>, // Expected hash output
}

impl ConstraintSynthesizer<Fr> for Sha256Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate the preimage as a witness.
        let preimage_bytes = self.preimage.unwrap_or([0u8; 64]);
        let preimage_var = UInt8::<Fr>::new_witness_vec(cs.clone(), &preimage_bytes)?;

        // Allocate a unit variable constant instead of using `()`.
        let params_var = UnitVar::new_constant(cs.clone(), ())?;
        
        // Evaluate SHA256 using the allocated unit parameter.
        let hash_var = Sha256Gadget::evaluate(&params_var, &preimage_var)?;

        // Allocate the expected hash as public inputs.
        let image_bytes = self.image.unwrap_or([0u8; 32]);
        let image_var = UInt8::<Fr>::new_input_vec(cs, &image_bytes)?;

        // Enforce that the computed hash equals the provided hash.
        for (computed, expected) in hash_var.0.iter().zip(image_var.iter()) {
            computed.enforce_equal(expected)?;
        }

        Ok(())
    }
}



fn main() {
    let mut rng = StdRng::seed_from_u64(42u64);

    let preimage = [42u8; 64];
    let hash = Sha256::digest(&preimage);
    
    let circuit = Sha256Circuit {
        preimage: Some(preimage),
        image: Some(hash.try_into().unwrap()), // 32 bytes
    };
    
    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();
    let pvk = prepare_verifying_key(&params.vk);
    
    let proof_circuit = Sha256Circuit {
        preimage: Some(preimage),
        image: Some(hash.try_into().unwrap()),
    };
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(proof_circuit, &params, &mut rng).unwrap();
    
    let public_inputs = hash.iter().map(|b| Fr::from(*b as u128)).collect::<Vec<_>>();
    println!("Public inputs len: {}", public_inputs.len()); // should be 32

    let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs);
    match is_valid {
        Ok(valid) => println!("Proof is valid? {}", valid),
        Err(e) => println!("Verification error: {:?}", e),
    }
}
