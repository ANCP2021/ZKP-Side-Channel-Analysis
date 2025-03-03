// To run, use this command: 
// cargo run --bin cairo-run -- --single-file proofs/sha256.cairo --available-gas 1100000

use core::sha256::compute_sha256_byte_array;

// Main function
fn main() {
    let data = "Hello World!";
    let hash = compute_sha256_byte_array(@data);

    let expected = [0x7f83b165, 0x7ff1fc53, 0xb92dc181, 0x48a1d65d, 0xfc2d4b1f, 0xa3d67728, 0x4addd200, 0x126d9069];

    // Verify the proof
    assert(hash == expected, 'SHA256 proof failed!');
    
}

