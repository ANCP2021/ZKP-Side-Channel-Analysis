// To run, use this command: 
// cargo run --bin cairo-run -- --single-file proofs/merkle.cairo --available-gas 100000000

use core::felt252;
use core::byte_array::ByteArray;
use core::sha256::compute_sha256_byte_array;
use core::to_byte_array::{FormatAsByteArray, AppendFormattedToByteArray};
use debug::PrintTrait;
use core::debug::print_byte_array_as_string;


//---------------------------------------------------------------------
// format_u32_as_fixed_hex: Formats a u32 as a hexadecimal ByteArray with zero padding to ensure exactly 8 hex digits.
// - n: the u32 value to format.
// Returns: a ByteArray of exactly 8 ASCII characters representing the
//          hex value of n (with leading zeros if needed).
//---------------------------------------------------------------------
fn format_u32_as_fixed_hex(n: u32) -> ByteArray {
    let base: NonZero<u32> = 16;
    let hex = n.format_as_byte_array(base);
    let len = hex.len();
    if (len < 8) {
        let pad_count = 8 - len;
        let mut padded = "";
        let mut i = 0;
        while (i < pad_count) {
            padded = padded + "0";
            i = i + 1;
        }
        padded = padded + hex;
        return padded;
    }
    return hex;
}


//---------------------------------------------------------------------
// sha256: Computes the SHA-256 hash of the input ByteArray.
// - data: the input data to be hashed (as a ByteArray).
// Returns a ByteArray representing the SHA-256 hash in ASCII form.
//---------------------------------------------------------------------
fn sha256(data: ByteArray) -> ByteArray {
    let [n0, n1, n2, n3, n4, n5, n6, n7] = compute_sha256_byte_array(@data);
    let n0 = format_u32_as_fixed_hex(n0);
    let n1 = format_u32_as_fixed_hex(n1);
    let n2 = format_u32_as_fixed_hex(n2);
    let n3 = format_u32_as_fixed_hex(n3);
    let n4 = format_u32_as_fixed_hex(n4);
    let n5 = format_u32_as_fixed_hex(n5);
    let n6 = format_u32_as_fixed_hex(n6);
    let n7 = format_u32_as_fixed_hex(n7);
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
    // Usually datablocks, update this later
    let L1 = "L1";
    let L2 = "L2";
    let L3 = "L3";
    let L4 = "L4";

    // Compute the leaf hashes.
    let hL1 = sha256(L1.clone());
    let hL2 = sha256(L2.clone());
    let hL3 = sha256(L3.clone());
    let hL4 = sha256(L4.clone());

    // Compute the internal node hashes.
    let _H12 = hash_pair(hL1.clone(), hL2.clone());  // Parent of L1 and L2.
    let H34 = hash_pair(hL3.clone(), hL4.clone());  // Parent of L3 and L4.

    // Compute the Merkle root.
    //let merkle_root = hash_pair(H12.clone(), H34.clone());

    // Precomputed Markle root.
    let merkle_root = "63442ffc2d48a92c8ba746659331f273748ccede648b27f4eacf00cb0786c439";

    // --- Step 2: Create a Merkle Proof for L2 ---
    // To prove L2 is in the tree, the proof consists of:
    //   1. Its sibling hash (hL1) at the leaf level.
    //   2. The hash of the other branch (H34) at the next level.
    let proof = [hL1.clone(), H34.clone()];

    // --- Step 3: Verify the Merkle Proof ---
    let is_valid = verify_merkle_proof(L2.clone(), proof, merkle_root);
    // Verify the proof
    assert(is_valid == 1, 'Merkle proof failed!');
}
