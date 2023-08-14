extern crate rewards_proof;

use curve25519_dalek::scalar::Scalar;
use rewards_proof::api::{setup, linear_proof, linear_verify, range_proof, range_verify};

fn linear_proof_example() {
    let n: usize = 64;
    // a and b are the vectors for which we want to prove c = <a,b>
    // a is a private vector, b is a public vector
    let mut rng = rand::thread_rng();
    let a: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let b: Vec<_> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

    let (ps_gen, bp_gen) = setup(n);

    // Prover
    let (proof, commitments) = linear_proof(
        &ps_gen, 
        &bp_gen, 
        a, 
        b.clone(), 
        n, 
    );

    // Verification
    let result = linear_verify(
        proof, 
        b,
        commitments.0,
        commitments.1, 
        commitments.2,
        commitments.3,
    );

    if result {
        println!("Linear Proof sucessfully verified");
    } else {
        println!("Linear Proof cannot be verified!");
    }
}

fn range_proof_example() {
    // currently we check a range of 0..2^8 -> 0..256
    let sum_of_counters: u64 = 254;
    let (ps_gen, bp_gen) = setup(64);

    // Prove
    let (proof, commitments) = range_proof(
        &ps_gen, 
        &bp_gen, 
        sum_of_counters, 
        8,
    );

    // Verification
    let result = range_verify(
        &ps_gen, 
        &bp_gen, 
        proof, 
        commitments, 
        8, 
    );

    if result {
        println!("Range Proof sucessfully verified");
    } else {
        println!("Range Proof cannot be verified!");
    }
}


fn main() {
    range_proof_example();
    linear_proof_example();
}
