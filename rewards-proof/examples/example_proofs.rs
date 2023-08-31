extern crate rewards_proof;

use bulletproofs::{PedersenGens, BulletproofGens, RangeProof};
use curve25519_dalek::{scalar::Scalar, ristretto::CompressedRistretto};
use rewards_proof::api::{setup, linear_proof, linear_verify, range_proof, range_verify, range_verify_multiple};

#[allow(dead_code)]
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

    let proof_in_bytes = proof.to_bytes().len() * 32;
    let proof_in_kbytes = proof_in_bytes / 1024;
    println!("Size of linearproof: {proof_in_kbytes} kB");

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

#[allow(dead_code)]
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

    let proof_in_bytes = proof.to_bytes().len() * 32;
    let proof_in_kbytes = proof_in_bytes / 1024;
    println!("Size of rangeproof: {proof_in_kbytes} kB");

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

#[allow(dead_code)]
fn verify_multiple_range_proofs(number_of_proofs: usize) {
    // preprocessing
    let value: u64 = 254;
    let limit_range_proof: usize = 8; // 2^8 is the limit

    let mut ps_generators: Vec<PedersenGens> = vec![];
    let mut bp_generators: Vec<BulletproofGens> = vec![];
    let mut range_proofs: Vec<RangeProof> = vec![];
    let mut range_proof_commitments: Vec<CompressedRistretto> = vec![];

    // generate number_of_users proofs
    for _x in 0..number_of_proofs {
        // we need a maximum of 64-bit rangeproofs
        let (ps_gen, bp_gen) = setup(64);
        ps_generators.push(ps_gen);
        bp_generators.push(bp_gen.clone());

        // create multiple range proofs
        let (proof, commitments) = range_proof(&ps_gen, &bp_gen, value, limit_range_proof);
        range_proofs.push(proof.clone());
        range_proof_commitments.push(commitments);
    }

    let result = range_verify_multiple(ps_generators.clone(), 
                                       bp_generators.clone(), 
                                       range_proofs.clone(), 
                                       range_proof_commitments.clone(), 
                                       8, 
                                       number_of_proofs);

    if result {
        println!("Range Proofs sucessfully verified");
    } else {
        println!("Range Proof cannot be verified!");
    }
}

fn main() {
    //range_proof_example();
    //linear_proof_example();
    verify_multiple_range_proofs(10);
}
