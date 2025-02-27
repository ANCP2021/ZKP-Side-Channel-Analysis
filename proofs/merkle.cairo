// To run, use this command: 
// cargo run --bin cairo-run -- --single-file proofs/merkle.cairo --available-gas 100000000

use core::felt252;
use core::byte_array::ByteArray;
use core::sha256::compute_sha256_byte_array;
use core::to_byte_array::{FormatAsByteArray, AppendFormattedToByteArray};
use debug::PrintTrait;
use core::debug::print_byte_array_as_string;


//---------------------------------------------------------------------
// sha256: Computes the SHA-256 hash of the input ByteArray.
// - data: the input data to be hashed (as a ByteArray).
// Returns a ByteArray representing the SHA-256 hash in ASCII form.
//---------------------------------------------------------------------
fn sha256(data: ByteArray) -> ByteArray {
    let base: NonZero<u32> = 10;
    let [n0, n1, n2, n3, n4, n5, n6, n7] = compute_sha256_byte_array(@data);
    let n0 = n0.format_as_byte_array(base);
    let n1 = n1.format_as_byte_array(base);
    let n2 = n2.format_as_byte_array(base);
    let n3 = n3.format_as_byte_array(base);
    let n4 = n4.format_as_byte_array(base);
    let n5 = n5.format_as_byte_array(base);
    let n6 = n6.format_as_byte_array(base);
    let n7 = n7.format_as_byte_array(base);
    let result = n0 + n1 + n2 + n3 + n4 + n5 + n6 + n7;
    //print_byte_array_as_string(@result);
    return result;
}

//---------------------------------------------------------------------
// hash_pair: Concatenates two ByteArrays and returns the SHA-256 hash of the result.
// - left: the left ByteArray.
// - right: the right ByteArray.
// Returns a ByteArray representing the SHA-256 hash of the concatenated ByteArrays.
//---------------------------------------------------------------------
fn hash_pair(left: ByteArray, right: ByteArray) -> ByteArray {
    let combined = left + right;
    return sha256(combined);
}

//---------------------------------------------------------------------
// verify_merkle_proof: Verifies a Merkle proof.
// - leaf_data: the original data for the leaf (as a ByteArray).
// - proof: an array of two ByteArrays representing the sibling hashes.
// - expected_root: the known Merkle root.
// Returns 1 (true) if the proof is valid, 0 (false) otherwise.
//---------------------------------------------------------------------
fn verify_merkle_proof(leaf_data: ByteArray, proof: [ByteArray; 2], expected_root: ByteArray) -> felt252 {
    // Step 0: Get proof arguments
    let [proof0, proof1] = proof;
    // Step 1: Compute the hash of the leaf data.
    let current_hash = sha256(leaf_data);
    // Step 2: For the first level, L2 is the right child and its sibling (proof[0]) is on the left.
    let current_hash = hash_pair(proof0, current_hash);
    // Step 3: For the next level, the computed hash is on the left and the provided sibling proof[1] is on the right.
    let current_hash = hash_pair(current_hash, proof1);
    // Check if the computed hash equals the expected Merkle root.
    if (current_hash == expected_root) {
        return 1;
    }
    return 0;
}

//---------------------------------------------------------------------
// main: Builds a simple Merkle tree for four leaves, creates a Merkle
// proof for one leaf, and verifies that proof.  TODO: Make complex.
//---------------------------------------------------------------------
fn main() {
    // --- Step 1: Build the Merkle Tree ---
    let mut L1 = "";
    L1.append_byte(0x4c);
    L1.append_byte(0x31); 
    let mut L2 = "";
    L2.append_byte(0x4c);
    L2.append_byte(0x32);
    let mut L3 = "";
    L3.append_byte(0x4c);
    L3.append_byte(0x33);
    let mut L4 = "";
    L4.append_byte(0x4c);
    L4.append_byte(0x34);

    // Compute the leaf hashes.
    let hL1 = sha256(L1.clone());
    let hL2 = sha256(L2.clone());
    let hL3 = sha256(L3.clone());
    let hL4 = sha256(L4.clone());

    // Compute the internal node hashes.
    let H12 = hash_pair(hL1.clone(), hL2.clone());  // Parent of L1 and L2.
    let H34 = hash_pair(hL3.clone(), hL4.clone());  // Parent of L3 and L4.

    // Compute the Merkle root.
    let merkle_root = hash_pair(H12.clone(), H34.clone());
    //print_byte_array_as_string(@merkle_root);
    //let merkle_root = 0x10745523952184420590209545652512226505463215274857121971113115021405672960292637;

    // --- Step 2: Create a Merkle Proof for L2 ---
    // To prove L2 is in the tree, the proof consists of:
    //   1. Its sibling hash (hL1) at the leaf level.
    //   2. The hash of the other branch (H34) at the next level.
    let proof = [hL1.clone(), H34.clone()];

    // --- Step 3: Verify the Merkle Proof ---
    let is_valid = verify_merkle_proof(L2.clone(), proof, merkle_root);
    // Verify the proof
    assert(is_valid == 1, 0);
}
