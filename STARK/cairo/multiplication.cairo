// To run, use this command: 
// cargo run --bin cairo-run -- --single-file proofs/multiplication.cairo

// Main function
fn main() {
    let a = 3;
    let b = 5;
    let c = a * b;
    
    // Verify the proof
    assert(c == 15, 'Multiplication proof failed!');
}
