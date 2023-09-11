extern crate rewards_proof;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use rand::Rng;
use rewards_proof::api::{
    linear_proof, linear_verify, range_proof, range_verify, range_verify_multiple,
    rewards_proof_generation, rewards_proof_setup, setup, rewards_proof_verification,
};

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
    let (proof, commitments) = linear_proof(&ps_gen, &bp_gen, a, b.clone(), n);

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
    let (proof, commitments) = range_proof(&ps_gen, &bp_gen, sum_of_counters, 8);

    let proof_in_bytes = proof.to_bytes().len() * 32;
    let proof_in_kbytes = proof_in_bytes / 1024;
    println!("Size of rangeproof: {proof_in_kbytes} kB");

    // Verification
    let result = range_verify(&ps_gen, &bp_gen, proof, commitments, 8);

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

    let result = range_verify_multiple(
        ps_generators.clone(),
        bp_generators.clone(),
        range_proofs.clone(),
        range_proof_commitments.clone(),
        8,
        number_of_proofs,
    );

    if result {
        println!("Range Proofs sucessfully verified");
    } else {
        println!("Range Proof cannot be verified!");
    }
}

#[allow(dead_code)]
fn rewards_proof_example() {
    let mut rng = rand::thread_rng();
    let incentive_catalog_size: u64 = 64;
    let (pedersen_gens, bulletproof_gens) = rewards_proof_setup(incentive_catalog_size);

    // public value
    let policy_vector: Vec<u64> = (0..incentive_catalog_size).map(|_| rng.gen_range(0, 10)).collect();
    let policy_vector_scalar: Vec<Scalar> = policy_vector
        .clone()
        .into_iter()
        .map(|u64_value| Scalar::from(u64_value))
        .collect();
    // private value
    let state: Vec<u64> = (0..incentive_catalog_size).map(|_| rng.gen_range(0, 10)).collect();
    let state_scalar: Vec<Scalar> = state
        .clone()
        .into_iter()
        .map(|u64_value| Scalar::from(u64_value))
        .collect();

    // reward = <state, policy_vector>
    let reward: u64 = state
        .iter()
        .zip(policy_vector.iter())
        .map(|(x, y)| x.checked_mul(*y))
        .flatten()
        .sum();

    println!("Policy vector: {:?}", policy_vector);
    println!("State: {:?}", state);
    println!("Reward: {:?}", reward);

    // generate rewards proof
    let (range_proof, linear_proof, range_comm, linear_comm) = rewards_proof_generation(
        pedersen_gens.clone(),
        bulletproof_gens.clone(),
        reward,
        state_scalar,
        policy_vector_scalar.clone(),
        incentive_catalog_size,
    );

    // verify rewards proof
    if rewards_proof_verification(pedersen_gens, bulletproof_gens, range_proof, range_comm, linear_proof, policy_vector_scalar, linear_comm) {
        println!("Rewards proof verification successfull!");
    } else {
        println!("Rewards proof verification failed!");
    }
}

fn main() {
    //range_proof_example();
    //linear_proof_example();
    //verify_multiple_range_proofs(10);
    rewards_proof_example();
}
